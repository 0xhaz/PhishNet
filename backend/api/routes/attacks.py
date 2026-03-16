import json
import logging

from fastapi import APIRouter, HTTPException
from database import get_db
from detectors.token_detector import TokenPhishingDetector
from detectors.pool_detector import PoolPhishingDetector
from detectors.refund_detector import RefundPhishingDetector
from core.obfuscation_analyzer import ObfuscationAnalyzer
from core.call_analyzer import VulnerableCallFinder
from core.data_fetcher import EthDataFetcher

router = APIRouter(tags=["attacks"])
logger = logging.getLogger(__name__)

token_detector = TokenPhishingDetector()
pool_detector = PoolPhishingDetector()
refund_detector = RefundPhishingDetector()
data_fetcher = EthDataFetcher()


@router.get("/attacks")
def list_attacks(page: int = 1, limit: int = 50, year: int | None = None):
    offset = (page - 1) * limit
    with get_db() as db:
        if year:
            rows = db.execute(
                "SELECT * FROM attacks WHERE data_year = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (year, limit, offset),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
    return [dict(r) for r in rows]


@router.get("/attacks/timeline")
def attacks_timeline(year: int | None = None):
    with get_db() as db:
        if year:
            # Single year: group by month within that year
            rows = db.execute("""
                SELECT
                    CAST(data_year AS TEXT) || '-' || substr(timestamp, 6, 2) as month,
                    attack_type,
                    COUNT(*) as count,
                    ROUND(SUM(loss_eth), 2) as total_loss_eth,
                    ROUND(SUM(loss_usd), 2) as total_loss_usd
                FROM attacks
                WHERE data_year = ?
                GROUP BY month, attack_type
                ORDER BY month ASC
            """, (year,)).fetchall()
        else:
            # All years: construct proper year-month from data_year + month portion
            rows = db.execute("""
                SELECT
                    CAST(data_year AS TEXT) || '-' || substr(timestamp, 6, 2) as month,
                    attack_type,
                    COUNT(*) as count,
                    ROUND(SUM(loss_eth), 2) as total_loss_eth,
                    ROUND(SUM(loss_usd), 2) as total_loss_usd
                FROM attacks
                GROUP BY CAST(data_year AS TEXT) || '-' || substr(timestamp, 6, 2), attack_type
                ORDER BY month ASC
            """).fetchall()
    return [dict(r) for r in rows]


@router.get("/attacks/years")
def available_years():
    """Return list of years that have data."""
    with get_db() as db:
        rows = db.execute(
            "SELECT DISTINCT data_year FROM attacks ORDER BY data_year"
        ).fetchall()
    return [r["data_year"] for r in rows]


@router.get("/attacks/by-bot/{address}")
def attacks_by_bot(address: str):
    addr = address.lower()
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM attacks WHERE lower(victim_bot_address) = ? ORDER BY timestamp DESC LIMIT 50",
            (addr,),
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/attacks/{attack_id}")
def get_attack(attack_id: int):
    with get_db() as db:
        row = db.execute("SELECT * FROM attacks WHERE id = ?", (attack_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Attack not found")

    attack = dict(row)
    block = attack.get("block_number", 0) or 0
    malicious = attack.get("malicious_contract", "") or ""
    source = attack.get("source_contract", "") or ""
    victim = attack.get("victim_bot_address", "") or ""
    recipient = attack.get("attacker_address", "") or ""
    loss = attack.get("loss_eth", 0) or 0

    attack["kill_chain"] = {
        "steps": [
            {
                "step": 1, "action": "deploy", "tx": "", "block": max(block - 2, 0),
                "contract": malicious,
            },
            {
                "step": 2, "action": "lure", "tx": "", "block": max(block - 1, 0),
                "target": victim,
                "contract": source,
            },
            {
                "step": 3, "action": "drain", "tx": attack.get("tx_hash", ""),
                "block": block,
                "amount": f"{loss:.2f} ETH",
                "contract": victim,
                "target": recipient,
            },
        ],
        "total_loss": f"{loss:.2f} ETH",
        "detection_window": "2 blocks (~24s)",
    }
    return attack


@router.post("/analyze/{address}")
def analyze_address(address: str):
    addr = address.lower()
    signals = []
    risk_score = 0

    with get_db() as db:
        # Check if it's a known flagged contract
        flagged = db.execute(
            "SELECT * FROM flagged_contracts WHERE lower(address) = ?", (addr,)
        ).fetchone()
        if flagged:
            flagged = dict(flagged)
            risk_score = flagged.get("risk_score", 0)
            raw = flagged.get("detection_signals", "[]")
            try:
                signals = json.loads(raw) if isinstance(raw, str) else raw
            except (json.JSONDecodeError, TypeError):
                signals = []
            return {
                "address": address,
                "risk_score": risk_score,
                "detection_signals": signals,
                "contract_type": flagged.get("contract_type", "unknown"),
                "status": flagged.get("status", "unknown"),
                "targeted_bot": flagged.get("targeted_bot", ""),
            }

        # Check if it's a known vulnerable bot
        bot = db.execute(
            "SELECT * FROM vulnerable_bots WHERE lower(address) = ?", (addr,)
        ).fetchone()
        if bot:
            bot = dict(bot)
            attack_count = bot.get("attack_count", 0)
            vuln = bot.get("vulnerability_type", "")
            if vuln in ("tx_origin", "both"):
                signals.append("tx.origin vulnerability detected")
                risk_score += 40
            if vuln in ("unvalidated_call", "both"):
                signals.append("Unvalidated external CALL")
                risk_score += 30
            if attack_count > 0:
                signals.append(f"Previously attacked ({attack_count} incidents)")
                risk_score += 20
            if bot.get("is_active"):
                signals.append("Contract is currently active")
                risk_score += 10
            return {
                "address": address,
                "risk_score": min(risk_score, 100),
                "detection_signals": signals,
                "contract_type": "mev_bot",
                "status": "at_risk" if risk_score >= 50 else "monitoring",
                "targeted_bot": "",
            }

        # Check if address appears as attacker in any attack
        attacker_count = db.execute(
            "SELECT COUNT(*) FROM attacks WHERE lower(attacker_address) = ? OR lower(malicious_contract) = ?",
            (addr, addr),
        ).fetchone()[0]
        if attacker_count > 0:
            signals.append(f"Linked to {attacker_count} drain transaction(s)")
            risk_score = 90
            return {
                "address": address,
                "risk_score": risk_score,
                "detection_signals": signals,
                "contract_type": "attacker",
                "status": "confirmed_attack",
                "targeted_bot": "",
            }

    # --- Not in DB: run live on-chain detection modules ---
    return _run_live_detection(address)


@router.post("/analyze/{address}/deep")
def deep_analysis(address: str):
    """Run bytecode-level obfuscation + vulnerable CALL analysis (SKANF Sections 3.2-3.3)."""
    try:
        bytecode = data_fetcher.get_contract_bytecode(address)
    except Exception as e:
        logger.warning(f"Failed to fetch bytecode for {address}: {e}")
        return {
            "address": address,
            "bytecode_size": 0,
            "obfuscation": None,
            "call_analysis": None,
            "error": "Could not fetch bytecode — contract may have self-destructed or address is an EOA",
        }

    if len(bytecode) < 2:
        return {
            "address": address,
            "bytecode_size": 0,
            "obfuscation": None,
            "call_analysis": None,
            "error": "No bytecode at address — likely an EOA or self-destructed contract",
        }

    # Module A: Obfuscation analysis (Section 3.2)
    obf = ObfuscationAnalyzer(bytecode).analyze()
    obf_result = {
        "level": obf.obfuscation_level,
        "score": obf.obfuscation_score,
        "signals": obf.signals,
        "metrics": {
            "total_jumps": obf.total_jumps,
            "direct_jumps": obf.direct_jumps,
            "indirect_jumps": obf.indirect_jumps,
            "total_jumpdests": obf.total_jumpdests,
            "reachable_jumpdests": obf.reachable_jumpdests,
            "unreachable_jumpdests": obf.unreachable_jumpdests,
            "dead_code_bytes": obf.dead_code_bytes,
            "code_density": round(obf.code_density, 3),
            "function_selectors": obf.function_selectors,
        },
    }

    # Module B: Vulnerable CALL analysis (Section 3.3)
    calls = VulnerableCallFinder(bytecode).analyze()
    call_result = {
        "total_calls": calls.total_calls,
        "vulnerable_count": len(calls.vulnerable_calls),
        "risk_score": calls.risk_score,
        "auth_type": calls.auth_type,
        "signals": calls.signals,
        "call_summary": calls.call_summary,
        "vulnerable_calls": [
            {
                "offset": f"0x{vc.offset:04x}",
                "opcode": vc.opcode,
                "risk_score": vc.risk_score,
                "risk_factors": vc.risk_factors,
                "has_auth_guard": vc.has_auth_guard,
            }
            for vc in calls.vulnerable_calls[:10]  # cap at 10 for response size
        ],
    }

    return {
        "address": address,
        "bytecode_size": len(bytecode),
        "obfuscation": obf_result,
        "call_analysis": call_result,
    }


def _run_live_detection(address: str) -> dict:
    """Run all 3 SKANF detection modules against an unknown address."""
    results = []

    # Module 1: Token-based detection
    try:
        token_report = token_detector.analyze_contract(address)
        if token_report.risk_score > 0:
            results.append({
                "module": "token",
                "score": token_report.risk_score,
                "signals": token_report.detection_signals,
                "type": "token",
                "extra": {
                    "suspicious_calls": token_report.suspicious_calls,
                    "targeted_bots": token_report.targeted_bots,
                },
            })
    except Exception as e:
        logger.warning(f"Token detector failed for {address}: {e}")

    # Module 2: Pool-based detection
    try:
        pool_report = pool_detector.analyze_pool(address)
        if pool_report.risk_score > 0:
            results.append({
                "module": "pool",
                "score": pool_report.risk_score,
                "signals": pool_report.detection_signals,
                "type": "pool",
                "extra": {
                    "token0": pool_report.token0,
                    "token1": pool_report.token1,
                },
            })
    except Exception as e:
        logger.warning(f"Pool detector failed for {address}: {e}")

    # Module 3: Refund-based detection
    try:
        refund_report = refund_detector.analyze_refund_contract(address)
        if refund_report.risk_score > 0:
            results.append({
                "module": "refund",
                "score": refund_report.risk_score,
                "signals": refund_report.detection_signals,
                "type": "refund_recipient",
                "extra": {
                    "has_suspicious_fallback": refund_report.has_suspicious_fallback,
                    "is_refund_recipient": refund_report.is_refund_recipient,
                },
            })
    except Exception as e:
        logger.warning(f"Refund detector failed for {address}: {e}")

    if not results:
        return {
            "address": address,
            "risk_score": 0,
            "detection_signals": ["No suspicious patterns detected by any module"],
            "contract_type": "unknown",
            "status": "clear",
            "targeted_bot": "",
            "modules": [],
        }

    # Pick the highest-scoring module as the primary classification
    best = max(results, key=lambda r: r["score"])
    all_signals = []
    for r in results:
        module_label = r["module"].upper()
        for s in r["signals"]:
            all_signals.append(f"[{module_label}] {s}")

    targeted_bot = ""
    for r in results:
        bots = r.get("extra", {}).get("targeted_bots", [])
        if bots:
            targeted_bot = bots[0]
            break

    return {
        "address": address,
        "risk_score": best["score"],
        "detection_signals": all_signals,
        "contract_type": best["type"],
        "status": "suspicious" if best["score"] >= 40 else "low_risk",
        "targeted_bot": targeted_bot,
        "modules": [
            {"module": r["module"], "score": r["score"], "signals": r["signals"]}
            for r in results
        ],
    }
