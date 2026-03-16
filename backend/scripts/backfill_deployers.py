"""
Backfill deployer addresses for existing flagged_contracts using Etherscan API.

Usage:
  python scripts/backfill_deployers.py
  python scripts/backfill_deployers.py --batch 50   # process N contracts per run
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

sys.path.insert(0, str(Path(__file__).parent.parent))
from database import get_db

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"


def backfill(batch_size: int = 0) -> None:
    import httpx

    if not ETHERSCAN_API_KEY:
        sys.exit("ERROR: set ETHERSCAN_API_KEY in .env")

    with get_db() as db:
        rows = db.execute(
            "SELECT id, address FROM flagged_contracts WHERE deployer = '' OR deployer IS NULL"
        ).fetchall()

        if not rows:
            print("All flagged contracts already have deployer info.")
            return

        total = len(rows)
        if batch_size > 0:
            rows = rows[:batch_size]

        print(f"Backfilling deployer for {len(rows)}/{total} contracts...")

        with httpx.Client(timeout=15) as client:
            filled = 0
            for i, row in enumerate(rows):
                address = row["address"]
                try:
                    resp = client.get(ETHERSCAN_BASE, params={
                        "chainid": "1",
                        "module": "contract",
                        "action": "getcontractcreation",
                        "contractaddresses": address,
                        "apikey": ETHERSCAN_API_KEY,
                    })
                    data = resp.json()
                    if data.get("status") == "1" and data.get("result"):
                        deployer = data["result"][0].get("contractCreator", "")
                        if deployer:
                            db.execute(
                                "UPDATE flagged_contracts SET deployer = ? WHERE id = ?",
                                (deployer.lower(), row["id"]),
                            )
                            filled += 1
                            print(f"  [{i+1}/{len(rows)}] {address[:10]}... → {deployer[:10]}...")
                        else:
                            print(f"  [{i+1}/{len(rows)}] {address[:10]}... → no creator found")
                    else:
                        print(f"  [{i+1}/{len(rows)}] {address[:10]}... → API: {data.get('message', 'error')}")
                except Exception as e:
                    print(f"  [{i+1}/{len(rows)}] {address[:10]}... → error: {e}")

                # Etherscan free tier: 5 req/s
                if (i + 1) % 4 == 0:
                    time.sleep(1)

            db.commit()

        # Update deployer_contract_count for all deployers
        db.execute("""
            UPDATE flagged_contracts
            SET deployer_contract_count = (
                SELECT COUNT(*) FROM flagged_contracts f2
                WHERE f2.deployer = flagged_contracts.deployer
                  AND flagged_contracts.deployer != ''
            )
            WHERE deployer != '' AND deployer IS NOT NULL
        """)
        db.commit()

        print(f"\nDone. Filled {filled}/{len(rows)} deployer addresses.")
        # Show top serial deployers
        top = db.execute("""
            SELECT deployer, COUNT(*) as cnt
            FROM flagged_contracts
            WHERE deployer != '' AND deployer IS NOT NULL
            GROUP BY deployer
            HAVING cnt > 1
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()
        if top:
            print("\nTop serial deployers:")
            for r in top:
                print(f"  {r['deployer']}: {r['cnt']} contracts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=int, default=0, help="Limit to N contracts per run")
    args = parser.parse_args()
    backfill(args.batch)
