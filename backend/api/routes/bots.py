from fastapi import APIRouter, HTTPException
from database import get_db
from excluded_addresses import EXCLUDED_ADDRESSES

router = APIRouter(tags=["bots"])

_placeholders = ",".join("?" for _ in EXCLUDED_ADDRESSES)
_excluded_list = list(EXCLUDED_ADDRESSES)


@router.get("/bots")
def list_bots(limit: int = 20, offset: int = 0, year: int | None = None):
    with get_db() as db:
        if year:
            rows = db.execute(
                f"""SELECT b.* FROM vulnerable_bots b
                    WHERE b.address NOT IN ({_placeholders})
                      AND b.attack_count > 0
                      AND b.address IN (
                          SELECT DISTINCT victim_bot_address FROM attacks WHERE data_year = ?
                      )
                    ORDER BY b.current_balance_eth DESC LIMIT ? OFFSET ?""",
                _excluded_list + [year, limit, offset],
            ).fetchall()
        else:
            rows = db.execute(
                f"SELECT * FROM vulnerable_bots WHERE address NOT IN ({_placeholders}) AND attack_count > 0 ORDER BY current_balance_eth DESC LIMIT ? OFFSET ?",
                _excluded_list + [limit, offset],
            ).fetchall()
    return [dict(r) for r in rows]


@router.get("/bots/{address}")
def get_bot(address: str):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vulnerable_bots WHERE address = ?", (address,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Bot not found")
    return dict(row)
