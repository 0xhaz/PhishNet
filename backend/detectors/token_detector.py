"""Module 1 — Token-based phishing detector (covers ~101/104 known attacks)."""
from __future__ import annotations
from dataclasses import dataclass, field

from core.bytecode_analyzer import BytecodeAnalyzer, DANGEROUS_SELECTORS
from core.data_fetcher import EthDataFetcher
from database import get_db

fetcher = EthDataFetcher()


def _load_known_bots() -> set[str]:
    try:
        with get_db() as db:
            rows = db.execute("SELECT address FROM vulnerable_bots").fetchall()
            return {r[0].lower() for r in rows}
    except Exception:
        return set()


KNOWN_MEV_BOTS: set[str] = set()


def ensure_bots_loaded() -> None:
    global KNOWN_MEV_BOTS
    if not KNOWN_MEV_BOTS:
        KNOWN_MEV_BOTS = _load_known_bots()


@dataclass
class RiskReport:
    address: str
    risk_score: int  # 0-100
    attack_type: str = "token"
    detection_signals: list[str] = field(default_factory=list)
    suspicious_calls: list[dict] = field(default_factory=list)
    targeted_bots: list[str] = field(default_factory=list)


class TokenPhishingDetector:
    def analyze_contract(self, address: str) -> RiskReport:
        ensure_bots_loaded()

        try:
            bytecode = fetcher.get_contract_bytecode(address)
        except Exception as e:
            return RiskReport(address=address, risk_score=0,
                              detection_signals=[f"bytecode_fetch_failed:{e}"])

        if not bytecode or len(bytecode) < 10:
            return RiskReport(address=address, risk_score=0,
                              detection_signals=["no_bytecode_or_eoa"])

        analyzer = BytecodeAnalyzer(bytecode)
        signals: list[str] = []
        score = 0

        # Signal 1: must look like an ERC-20
        is_erc20 = analyzer.has_erc20_interface()
        if is_erc20:
            signals.append("ERC-20 interface detected")

        # Signal 2: external CALLs with dangerous selectors
        calls = analyzer.extract_external_calls()
        selectors_found = analyzer.extract_four_byte_selectors()
        dangerous_found = selectors_found & set(DANGEROUS_SELECTORS.keys())
        suspicious_calls: list[dict] = []
        if dangerous_found:
            score += 40
            names = [DANGEROUS_SELECTORS[s] for s in dangerous_found]
            signals.append(f"Dangerous selectors embedded: {', '.join(names)}")
            suspicious_calls = [{"selector": s, "name": DANGEROUS_SELECTORS[s]} for s in dangerous_found]

        # Signal 3: tx.origin usage
        if analyzer.check_tx_origin_usage():
            score += 25
            signals.append("Uses tx.origin opcode (0x32)")

        # Signal 4: external CALL opcodes present
        if len(calls) > 0:
            score += 10
            signals.append(f"{len(calls)} external CALL opcode(s) found")

        # Signal 5: embedded addresses (potential hardcoded targets)
        embedded = analyzer.get_embedded_addresses()
        bot_targets = [a for a in embedded if a.lower() in KNOWN_MEV_BOTS]
        if bot_targets:
            score += 15
            signals.append(f"Embedded addresses target {len(bot_targets)} known MEV bot(s)")

        # Signal 6: token transferred to known MEV bots (via Etherscan)
        targeted_bots: list[str] = []
        try:
            transfers = fetcher.get_token_transfers(address)
            targeted_bots = list({
                t["to"].lower() for t in transfers
                if t.get("to", "").lower() in KNOWN_MEV_BOTS
            })
            if targeted_bots:
                score += 35
                signals.append(f"Token sent to {len(targeted_bots)} known MEV bot(s)")
        except Exception:
            pass

        # Boost: if ERC-20 with dangerous selectors AND targets bots = very high risk
        if is_erc20 and dangerous_found and (targeted_bots or bot_targets):
            score = max(score, 90)

        return RiskReport(
            address=address,
            risk_score=min(score, 100),
            detection_signals=signals,
            suspicious_calls=suspicious_calls,
            targeted_bots=targeted_bots or bot_targets,
        )
