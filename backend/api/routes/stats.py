from fastapi import APIRouter
from database import get_db
from excluded_addresses import EXCLUDED_ADDRESSES

router = APIRouter(tags=["stats"])

_placeholders = ",".join("?" for _ in EXCLUDED_ADDRESSES)
_excluded_list = list(EXCLUDED_ADDRESSES)


def _year_clause(year: int | None, alias: str = "") -> tuple[str, list]:
    """Return (SQL fragment, params) for optional year filtering."""
    prefix = f"{alias}." if alias else ""
    if year:
        return f"AND {prefix}data_year = ?", [year]
    return "", []


@router.get("/stats")
def get_stats(year: int | None = None):
    yr_sql, yr_params = _year_clause(year)
    yr_sql_a, yr_params_a = _year_clause(year, "a")

    _where = f"WHERE victim_bot_address NOT IN ({_placeholders}) {yr_sql}"
    _where_a = f"WHERE a.victim_bot_address NOT IN ({_placeholders}) {yr_sql_a}"

    with get_db() as db:
        total_attacks = db.execute(
            f"SELECT COUNT(*) FROM attacks {_where}",
            _excluded_list + yr_params,
        ).fetchone()[0]
        total_loss_eth = db.execute(
            f"SELECT COALESCE(SUM(loss_eth), 0) FROM attacks {_where}",
            _excluded_list + yr_params,
        ).fetchone()[0]
        total_loss_usd = db.execute(
            f"SELECT COALESCE(SUM(loss_usd), 0) FROM attacks {_where}",
            _excluded_list + yr_params,
        ).fetchone()[0]
        if year:
            bots_at_risk = db.execute(
                f"""SELECT COUNT(DISTINCT victim_bot_address) FROM attacks
                    WHERE victim_bot_address NOT IN ({_placeholders})
                      AND data_year = ?""",
                _excluded_list + [year],
            ).fetchone()[0]
        else:
            bots_at_risk = db.execute(
                f"SELECT COUNT(*) FROM vulnerable_bots WHERE is_active = 1 AND attack_count > 0 AND address NOT IN ({_placeholders})",
                _excluded_list,
            ).fetchone()[0]

        # What-if: attacked bots that had prior flagged contracts
        total_attacked_bots = db.execute(
            f"SELECT COUNT(DISTINCT victim_bot_address) FROM attacks {_where}",
            _excluded_list + yr_params,
        ).fetchone()[0]
        detected_bots = db.execute(
            f"""SELECT COUNT(DISTINCT a.victim_bot_address) FROM attacks a
                {_where_a}
                  AND EXISTS (SELECT 1 FROM flagged_contracts fc
                              WHERE lower(fc.targeted_bot) = lower(a.victim_bot_address))""",
            _excluded_list + yr_params_a,
        ).fetchone()[0]
        detection_rate = round(detected_bots / total_attacked_bots, 3) if total_attacked_bots else 0

        # Preventable loss = loss from attacks on detected bots
        preventable = db.execute(
            f"""SELECT COALESCE(SUM(a.loss_eth), 0), COALESCE(SUM(a.loss_usd), 0)
                FROM attacks a
                {_where_a}
                  AND EXISTS (SELECT 1 FROM flagged_contracts fc
                              WHERE lower(fc.targeted_bot) = lower(a.victim_bot_address))""",
            _excluded_list + yr_params_a,
        ).fetchone()

        by_type = {}
        for attack_type in ("token", "pool", "refund"):
            total = db.execute(
                f"SELECT COUNT(*) FROM attacks {_where} AND attack_type = ?",
                _excluded_list + yr_params + [attack_type],
            ).fetchone()[0]
            detected = db.execute(
                f"""SELECT COUNT(*) FROM attacks a
                    {_where_a}
                      AND a.attack_type = ?
                      AND EXISTS (SELECT 1 FROM flagged_contracts fc
                                  WHERE lower(fc.targeted_bot) = lower(a.victim_bot_address))""",
                _excluded_list + yr_params_a + [attack_type],
            ).fetchone()[0]
            by_type[attack_type] = {"total": total, "detected": detected}

        if year:
            flagged_alerts = db.execute(
                "SELECT COUNT(*) FROM flagged_contracts WHERE status = 'alert' AND data_year = ?",
                (year,),
            ).fetchone()[0]
        else:
            flagged_alerts = db.execute(
                "SELECT COUNT(*) FROM flagged_contracts WHERE status = 'alert'"
            ).fetchone()[0]

    return {
        "total_attacks": total_attacks,
        "total_loss_eth": total_loss_eth,
        "total_loss_usd": total_loss_usd,
        "bots_at_risk": bots_at_risk,
        "preventable_loss_usd": preventable[1],
        "preventable_loss_eth": preventable[0],
        "detection_rate": detection_rate,
        "flagged_alerts": flagged_alerts,
        "by_type": by_type,
    }
