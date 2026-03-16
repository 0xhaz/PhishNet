"""
Analytics endpoints — Cost vs Security, Attacker Network, Attack Evolution.
"""
from fastapi import APIRouter
from database import get_db
from excluded_addresses import EXCLUDED_ADDRESSES

router = APIRouter(tags=["analytics"])

_placeholders = ",".join("?" for _ in EXCLUDED_ADDRESSES)
_excluded_list = list(EXCLUDED_ADDRESSES)


# ─── Cost vs Security (SKANF Section 7.1) ────────────────────────────────────

# Gas costs from SKANF paper Table 6 (Section 7.1)
SECURITY_METHODS = {
    "tx_origin": {
        "label": "tx.origin check",
        "gas_per_call": 2,
        "monthly_gas": 80_000,
        "monthly_usd": 0.30,
        "security_level": "vulnerable",
        "description": "Checks tx.origin == owner. Costs ~2 gas per check but is bypassable via callback phishing.",
    },
    "msg_sender": {
        "label": "msg.sender check",
        "gas_per_call": 2,
        "monthly_gas": 80_000,
        "monthly_usd": 0.30,
        "security_level": "moderate",
        "description": "Checks msg.sender == owner. Same gas cost as tx.origin but immune to callback phishing. Still vulnerable if owner key is compromised.",
    },
    "ecrecover": {
        "label": "ECDSA signature verification",
        "gas_per_call": 3_000,
        "monthly_gas": 120_000_000,
        "monthly_usd": 450.00,
        "security_level": "strong",
        "description": "Verifies a cryptographic signature per transaction. Prevents callback and replay attacks.",
    },
    "create2_verify": {
        "label": "CREATE2 factory verification",
        "gas_per_call": 112_500,
        "monthly_gas": 4_500_000_000,
        "monthly_usd": 16_875.00,
        "security_level": "maximum",
        "description": "Only allows calls from a pre-computed CREATE2 address. Prevents all known phishing vectors but costs ~56x more per call.",
    },
}


@router.get("/analytics/cost-security")
def cost_security():
    """Return cost vs security comparison data (SKANF Section 7.1)."""
    with get_db() as db:
        # Real data: how many bots use tx.origin and what they've lost
        tx_origin_bots = db.execute(
            f"SELECT COUNT(*) FROM vulnerable_bots WHERE vulnerability_type = 'tx_origin' AND address NOT IN ({_placeholders})",
            _excluded_list,
        ).fetchone()[0]

        total_bots = db.execute(
            f"SELECT COUNT(*) FROM vulnerable_bots WHERE address NOT IN ({_placeholders})",
            _excluded_list,
        ).fetchone()[0]

        total_loss = db.execute(
            f"SELECT COALESCE(SUM(loss_eth), 0) FROM attacks WHERE victim_bot_address NOT IN ({_placeholders})",
            _excluded_list,
        ).fetchone()[0]

        # Average attacks per bot
        avg_attacks = db.execute(
            f"SELECT AVG(attack_count) FROM vulnerable_bots WHERE attack_count > 0 AND address NOT IN ({_placeholders})",
            _excluded_list,
        ).fetchone()[0] or 0

    return {
        "methods": SECURITY_METHODS,
        "real_data": {
            "tx_origin_bots": tx_origin_bots,
            "total_bots": total_bots,
            "tx_origin_pct": round(tx_origin_bots / max(total_bots, 1) * 100, 1),
            "total_loss_eth": round(total_loss, 2),
            "avg_attacks_per_bot": round(avg_attacks, 1),
            "gas_saved_per_bot_usd": round(SECURITY_METHODS["msg_sender"]["monthly_usd"] - SECURITY_METHODS["tx_origin"]["monthly_usd"], 2),
            "avg_loss_per_bot_eth": round(total_loss / max(tx_origin_bots, 1), 2),
        },
    }


# ─── Attacker Network ────────────────────────────────────────────────────────

@router.get("/analytics/attacker-network")
def attacker_network(min_attacks: int = 3, limit: int = 50):
    """Build attacker → victim graph for network visualization."""
    with get_db() as db:
        # Find top attacker addresses (by number of distinct victims)
        attackers = db.execute(
            f"""SELECT attacker_address,
                       COUNT(*) as attack_count,
                       COUNT(DISTINCT victim_bot_address) as victim_count,
                       ROUND(SUM(loss_eth), 2) as total_loss_eth,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen
                FROM attacks
                WHERE attacker_address != ''
                  AND victim_bot_address NOT IN ({_placeholders})
                GROUP BY attacker_address
                HAVING COUNT(*) >= ?
                ORDER BY victim_count DESC, attack_count DESC
                LIMIT ?""",
            _excluded_list + [min_attacks, limit],
        ).fetchall()

        nodes = []
        edges = []
        seen_nodes = set()

        for row in attackers:
            r = dict(row)
            addr = r["attacker_address"]
            if addr in seen_nodes:
                continue
            seen_nodes.add(addr)
            nodes.append({
                "id": addr,
                "type": "attacker",
                "attack_count": r["attack_count"],
                "victim_count": r["victim_count"],
                "total_loss_eth": r["total_loss_eth"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            })

            # Get this attacker's victims
            victims = db.execute(
                f"""SELECT victim_bot_address,
                           COUNT(*) as times_attacked,
                           ROUND(SUM(loss_eth), 2) as loss_eth
                    FROM attacks
                    WHERE attacker_address = ?
                      AND victim_bot_address NOT IN ({_placeholders})
                    GROUP BY victim_bot_address
                    ORDER BY loss_eth DESC
                    LIMIT 20""",
                [addr] + _excluded_list,
            ).fetchall()

            for v in victims:
                vd = dict(v)
                victim_addr = vd["victim_bot_address"]
                if victim_addr not in seen_nodes:
                    seen_nodes.add(victim_addr)
                    nodes.append({
                        "id": victim_addr,
                        "type": "victim",
                        "attack_count": vd["times_attacked"],
                        "total_loss_eth": vd["loss_eth"],
                    })
                edges.append({
                    "source": addr,
                    "target": victim_addr,
                    "attack_count": vd["times_attacked"],
                    "loss_eth": vd["loss_eth"],
                })

        # Also find shared victims (bots attacked by multiple attackers)
        shared = db.execute(
            f"""SELECT victim_bot_address, COUNT(DISTINCT attacker_address) as attacker_count
                FROM attacks
                WHERE attacker_address != ''
                  AND victim_bot_address NOT IN ({_placeholders})
                GROUP BY victim_bot_address
                HAVING COUNT(DISTINCT attacker_address) >= 2
                ORDER BY attacker_count DESC
                LIMIT 20""",
            _excluded_list,
        ).fetchall()

    return {
        "nodes": nodes,
        "edges": edges,
        "shared_victims": [dict(r) for r in shared],
        "summary": {
            "total_attackers": len([n for n in nodes if n["type"] == "attacker"]),
            "total_victims": len([n for n in nodes if n["type"] == "victim"]),
            "total_edges": len(edges),
        },
    }


# ─── Attack Evolution Timeline ───────────────────────────────────────────────

@router.get("/analytics/evolution")
def attack_evolution():
    """Year-over-year attack sophistication metrics."""
    with get_db() as db:
        yearly = db.execute(
            f"""SELECT data_year,
                       COUNT(*) as total_attacks,
                       COUNT(DISTINCT victim_bot_address) as unique_victims,
                       COUNT(DISTINCT attacker_address) as unique_attackers,
                       ROUND(SUM(loss_eth), 2) as total_loss_eth,
                       ROUND(AVG(loss_eth), 4) as avg_loss_eth,
                       ROUND(MAX(loss_eth), 2) as max_loss_eth,
                       MIN(timestamp) as first_attack,
                       MAX(timestamp) as last_attack
                FROM attacks
                WHERE victim_bot_address NOT IN ({_placeholders})
                GROUP BY data_year
                ORDER BY data_year""",
            _excluded_list,
        ).fetchall()

        # Monthly breakdown for each year
        monthly = db.execute(
            f"""SELECT data_year,
                       substr(timestamp, 1, 7) as month,
                       COUNT(*) as count,
                       ROUND(SUM(loss_eth), 2) as loss_eth
                FROM attacks
                WHERE victim_bot_address NOT IN ({_placeholders})
                GROUP BY data_year, substr(timestamp, 1, 7)
                ORDER BY month""",
            _excluded_list,
        ).fetchall()

        # Repeat attacker rate per year
        repeat_attackers = db.execute(
            f"""SELECT data_year,
                       COUNT(*) as repeat_count
                FROM (
                    SELECT data_year, attacker_address
                    FROM attacks
                    WHERE attacker_address != ''
                      AND victim_bot_address NOT IN ({_placeholders})
                    GROUP BY data_year, attacker_address
                    HAVING COUNT(*) >= 5
                )
                GROUP BY data_year""",
            _excluded_list,
        ).fetchall()
        repeat_map = {r["data_year"]: r["repeat_count"] for r in repeat_attackers}

        # Top attacker per year
        top_per_year = db.execute(
            f"""SELECT data_year, attacker_address, COUNT(*) as cnt,
                       ROUND(SUM(loss_eth), 2) as loss_eth
                FROM attacks
                WHERE attacker_address != ''
                  AND victim_bot_address NOT IN ({_placeholders})
                GROUP BY data_year, attacker_address
                ORDER BY data_year, cnt DESC""",
            _excluded_list,
        ).fetchall()

        top_map = {}
        for r in top_per_year:
            yr = r["data_year"]
            if yr not in top_map:
                top_map[yr] = {
                    "address": r["attacker_address"],
                    "attacks": r["cnt"],
                    "loss_eth": r["loss_eth"],
                }

    years = []
    for row in yearly:
        r = dict(row)
        yr = r["data_year"]
        r["serial_attackers"] = repeat_map.get(yr, 0)
        r["top_attacker"] = top_map.get(yr, None)
        years.append(r)

    return {
        "years": years,
        "monthly": [dict(r) for r in monthly],
    }
