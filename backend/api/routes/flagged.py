import json

from fastapi import APIRouter
from database import get_db
from core.data_fetcher import EthDataFetcher

router = APIRouter(tags=["flagged"])

_fetcher = EthDataFetcher()


def _parse_row(r):
    d = dict(r)
    if isinstance(d.get("detection_signals"), str):
        try:
            d["detection_signals"] = json.loads(d["detection_signals"])
        except (json.JSONDecodeError, TypeError):
            d["detection_signals"] = []
    return d


@router.get("/flagged")
def list_flagged(year: int | None = None):
    with get_db() as db:
        if year:
            rows = db.execute(
                "SELECT * FROM flagged_contracts WHERE data_year = ? ORDER BY risk_score DESC",
                (year,),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM flagged_contracts ORDER BY risk_score DESC"
            ).fetchall()
    return [_parse_row(r) for r in rows]


@router.get("/flagged/by-bot/{address}")
def flagged_by_bot(address: str):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM flagged_contracts WHERE targeted_bot = ? ORDER BY risk_score DESC",
            (address,),
        ).fetchall()
    return [_parse_row(r) for r in rows]


@router.get("/flagged/{address}/deployer")
def get_deployer_info(address: str):
    """Get deployer for a contract and find other contracts by the same deployer."""
    addr = address.lower()
    with get_db() as db:
        # Check if we already have deployer in DB
        row = db.execute(
            "SELECT deployer, deployer_contract_count FROM flagged_contracts WHERE LOWER(address) = ?",
            (addr,),
        ).fetchone()

        deployer = row["deployer"] if row and row["deployer"] else None

        # If not in DB, try to fetch from chain
        if not deployer:
            try:
                deployer = _fetcher.get_contract_deployer(addr)
            except Exception:
                deployer = None

            # Cache in DB if found
            if deployer:
                db.execute(
                    "UPDATE flagged_contracts SET deployer = ? WHERE LOWER(address) = ?",
                    (deployer, addr),
                )
                db.commit()

        if not deployer:
            return {"deployer": None, "related_contracts": [], "deployer_contract_count": 0}

        # Find other flagged contracts by the same deployer
        related = db.execute(
            """SELECT address, risk_score, contract_type, status, targeted_bot,
                      detection_signals, data_year, deployed_at
               FROM flagged_contracts
               WHERE LOWER(deployer) = ? AND LOWER(address) != ?
               ORDER BY risk_score DESC""",
            (deployer.lower(), addr),
        ).fetchall()

        return {
            "deployer": deployer,
            "deployer_contract_count": row["deployer_contract_count"] if row else len(related) + 1,
            "related_contracts": [_parse_row(r) for r in related],
        }
