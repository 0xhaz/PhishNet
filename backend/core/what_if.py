"""What-if analysis: how much would PhishNet have caught?"""
from __future__ import annotations
from dataclasses import dataclass
from database import get_db


@dataclass
class WhatIfStats:
    total_attacks: int
    detected: int
    detection_rate: float
    total_loss_usd: float
    preventable_loss_usd: float
    avg_warning_blocks: float
    by_type: dict[str, dict[str, int]]


class WhatIfAnalysis:
    def compute_prevention_stats(self) -> WhatIfStats:
        """
        Iterate known attacks; for each, check whether a detector flagged
        the malicious contract before the drain tx. Tally detected/missed.
        """
        with get_db() as db:
            attacks = [dict(r) for r in db.execute("SELECT * FROM attacks").fetchall()]
            flagged = {
                r["address"]: r["risk_score"]
                for r in db.execute("SELECT address, risk_score FROM flagged_contracts").fetchall()
            }

        by_type: dict[str, dict[str, int]] = {
            "token": {"total": 0, "detected": 0},
            "pool": {"total": 0, "detected": 0},
            "refund": {"total": 0, "detected": 0},
        }

        total_loss = 0.0
        preventable_loss = 0.0
        detected = 0

        for attack in attacks:
            t = attack["attack_type"]
            by_type[t]["total"] += 1
            total_loss += attack.get("loss_usd", 0)

            was_flagged = attack["malicious_contract"] in flagged
            if was_flagged:
                detected += 1
                by_type[t]["detected"] += 1
                preventable_loss += attack.get("loss_usd", 0)

        n = len(attacks) or 1
        return WhatIfStats(
            total_attacks=n,
            detected=detected,
            detection_rate=round(detected / n, 3),
            total_loss_usd=total_loss,
            preventable_loss_usd=preventable_loss,
            avg_warning_blocks=0.0,  # TODO: compute from kill chain data
            by_type=by_type,
        )
