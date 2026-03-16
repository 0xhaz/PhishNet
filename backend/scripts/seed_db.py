"""
Seed the SQLite database — initialise schema and optionally enrich
Dune-sourced records via Etherscan.

Data pipeline:
  1. scrape_bot_addresses.py   → data/seed/known_mev_bots.json
  2. inject_bot_addresses.py   → patch Dune SQL files with bot addresses
  3. run_dune_queries.py       → execute Dune queries, populate attacks/flagged_contracts
  4. THIS SCRIPT               → init DB schema + optional Etherscan enrichment

Usage:
  python scripts/seed_db.py              # init schema only
  python scripts/seed_db.py --enrich     # also call Etherscan to fill gaps in existing records
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from dotenv import load_dotenv

if TYPE_CHECKING:
    import httpx

load_dotenv(Path(__file__).parent.parent / ".env")

sys.path.insert(0, str(Path(__file__).parent.parent))
from database import get_db, init_db

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
ETHERSCAN_BASE = "https://api.etherscan.io/api"


# ─── Etherscan enrichment helpers ─────────────────────────────────────────────

def etherscan_get(client: httpx.Client, params: dict) -> dict | list | None:
    params["apikey"] = ETHERSCAN_API_KEY
    try:
        resp = client.get(ETHERSCAN_BASE, params=params, timeout=15)
        data = resp.json()
        if data.get("status") == "1":
            return data["result"]
    except Exception as e:
        print(f"  Etherscan error: {e}")
    return None


def enrich_attacks(db, client: httpx.Client) -> None:
    """Fill missing block_number / timestamp / attacker_address for attacks from Etherscan."""
    rows = db.execute(
        "SELECT id, tx_hash, block_number, timestamp, attacker_address FROM attacks"
    ).fetchall()

    enriched = 0
    for row in rows:
        tx_hash = row["tx_hash"]
        if not tx_hash:
            continue

        needs_update = not row["block_number"] or not row["timestamp"] or not row["attacker_address"]
        if not needs_update:
            continue

        block_number = row["block_number"]
        timestamp = row["timestamp"]
        attacker = row["attacker_address"]

        # Get tx details
        result = etherscan_get(client, {
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": tx_hash,
        })
        if result:
            if not block_number:
                block_number = int(result.get("blockNumber", "0x0"), 16)
            if not attacker:
                attacker = result.get("from", "")

        # Get timestamp from block
        if block_number and not timestamp:
            block = etherscan_get(client, {
                "module": "proxy",
                "action": "eth_getBlockByNumber",
                "tag": hex(block_number),
                "boolean": "false",
            })
            if block:
                timestamp = int(block.get("timestamp", "0x0"), 16)

        db.execute(
            """UPDATE attacks
               SET block_number = ?, timestamp = ?, attacker_address = ?
               WHERE id = ?""",
            (block_number, timestamp, attacker, row["id"]),
        )
        enriched += 1

        if enriched % 5 == 0:
            import time; time.sleep(1)  # 5 req/s rate limit

    db.commit()
    print(f"  Enriched {enriched}/{len(rows)} attack records.")


def enrich_vulnerable_bots(db, client: httpx.Client) -> None:
    """Add current ETH balance and activity status via Etherscan."""
    rows = db.execute("SELECT address FROM vulnerable_bots").fetchall()

    enriched = 0
    for row in rows:
        address = row["address"]
        if not address:
            continue

        # Get current balance
        result = etherscan_get(client, {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
        })
        balance = None
        if result is not None:
            balance = int(result) / 1e18

        # Check if contract is still active
        txlist = etherscan_get(client, {
            "module": "account",
            "action": "txlist",
            "address": address,
            "page": "1",
            "offset": "1",
            "sort": "desc",
        })
        is_active = bool(txlist)
        first_seen = txlist[0].get("timeStamp") if txlist else None

        updates = []
        params = []
        if balance is not None:
            updates.append("current_balance_eth = ?")
            params.append(balance)
        if is_active:
            updates.append("is_active = 1")
        if first_seen:
            updates.append("first_seen = ?")
            params.append(first_seen)

        if updates:
            params.append(address)
            db.execute(
                f"UPDATE vulnerable_bots SET {', '.join(updates)} WHERE address = ?",
                params,
            )
            enriched += 1

        if enriched % 5 == 0:
            import time; time.sleep(1)

    db.commit()
    print(f"  Enriched {enriched}/{len(rows)} bot records.")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Initialise PhishNet database and optionally enrich records via Etherscan."
    )
    parser.add_argument("--enrich", action="store_true",
                        help="Call Etherscan API to fill missing fields in existing records")
    args = parser.parse_args()

    if args.enrich and not ETHERSCAN_API_KEY:
        print("WARNING: --enrich requested but ETHERSCAN_API_KEY not set. Skipping enrichment.")
        args.enrich = False

    print("Initialising database …")
    init_db()

    with get_db() as db:
        attack_count = db.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        bot_count = db.execute("SELECT COUNT(*) FROM vulnerable_bots").fetchone()[0]
        flagged_count = db.execute("SELECT COUNT(*) FROM flagged_contracts").fetchone()[0]
        print(f"Current DB: {attack_count} attacks, {bot_count} bots, {flagged_count} flagged contracts.")

    if args.enrich:
        import httpx
        with get_db() as db:
            with httpx.Client(timeout=15) as client:
                print("\nEnriching attacks via Etherscan …")
                enrich_attacks(db, client)
                print("Enriching bot balances via Etherscan …")
                enrich_vulnerable_bots(db, client)

    if attack_count == 0:
        print("\nNo attack data yet. To populate, run:")
        print("  python scripts/run_dune_queries.py --year 2021")
        print("  python scripts/run_dune_queries.py --year 2022")
        print("  ... etc, or use --all-years for the full range.")

    print("\nDone.")


if __name__ == "__main__":
    main()
