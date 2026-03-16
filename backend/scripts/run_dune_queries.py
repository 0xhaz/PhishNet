"""
Execute Dune Analytics queries and write results to the SQLite database.

Prerequisites:
  pip install dune-client
  export DUNE_API_KEY=your_key

Workflow:
  1. First run: use --upload-only to get manual upload instructions.
     Create queries in the Dune UI, then cache IDs with --set-id.
  2. Subsequent runs: execute queries and persist results to SQLite.

Usage:
  python scripts/run_dune_queries.py --year 2021          # run all queries for 2021
  python scripts/run_dune_queries.py --year 2021 --query 1  # run query 01 only for 2021
  python scripts/run_dune_queries.py --all-years            # run 2021 through current year
  python scripts/run_dune_queries.py --upload-only          # print manual upload instructions
  python scripts/run_dune_queries.py --set-id 01_token_phishing_candidates 12345
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

from dune_client.client import DuneClient
from dune_client.models import ExecutionState
from dune_client.query import QueryBase

sys.path.insert(0, str(Path(__file__).parent.parent))
from database import get_db, init_db

DUNE_API_KEY = os.getenv("DUNE_API_KEY", "")
QUERIES_DIR = Path(__file__).parent.parent / "data" / "dune_queries"

# After first upload, paste the returned query IDs here.
# Set to None to force a fresh upload.
QUERY_IDS: dict[str, int | None] = {
    "01_token_phishing_candidates": None,
    "02_drain_transactions": None,
    "03_attack_timeline": None,
    "04_vulnerable_bots_ranked": None,
}

# Base parameters (dates are overridden by --year or --start-date/--end-date)
DEFAULT_PARAMS = {
    "start_date": "2021-01-01",
    "end_date": "2021-12-31",
}

# Year range for --all-years
FIRST_YEAR = 2021

IDS_CACHE = Path(__file__).parent.parent / "data" / "dune_query_ids.json"


def load_cached_ids() -> dict[str, int | None]:
    if IDS_CACHE.exists():
        return json.loads(IDS_CACHE.read_text())
    return QUERY_IDS.copy()


def save_cached_ids(ids: dict[str, int | None]) -> None:
    IDS_CACHE.write_text(json.dumps(ids, indent=2))


def print_manual_upload_instructions(queries_dir: Path, names: list[str]) -> None:
    """
    Dune's query creation API requires a paid plan.
    Print step-by-step instructions for manually creating queries in the UI.
    """
    print("\n" + "="*60)
    print("ACTION REQUIRED — Manual query creation in Dune UI")
    print("="*60)
    print("The free Dune plan does not support query creation via API.")
    print("Create each query manually at https://dune.com/queries/new\n")
    for name in names:
        sql_path = queries_dir / f"{name}.sql"
        print(f"  Query: {name}")
        print(f"  SQL file: {sql_path}")
        print(f"  → Paste the SQL, click Save, copy the query ID from the URL")
        print(f"    e.g. https://dune.com/queries/12345  →  ID = 12345")
        print()
    print(f"Then cache each ID with --set-id:")
    for name in names:
        print(f"  python scripts/run_dune_queries.py --set-id {name} <paste_id_here>")
    print()


def execute_and_wait(client: DuneClient, query_id: int, params: dict) -> list[dict]:
    """Execute a query with parameters, poll until done, return rows."""
    from dune_client.query import QueryBase
    from dune_client.types import QueryParameter

    query = QueryBase(
        query_id=query_id,
        params=[
            QueryParameter.text_type(name=k, value=v)
            for k, v in params.items()
        ],
    )
    print(f"  Executing query {query_id} …", end="", flush=True)
    execution = client.execute_query(query)
    execution_id = execution.execution_id

    while True:
        status = client.get_execution_status(execution_id)
        state = status.state
        print(".", end="", flush=True)
        if state == ExecutionState.COMPLETED:
            print(" done.")
            break
        elif state in (ExecutionState.FAILED, ExecutionState.CANCELLED):
            print(f" {state}!")
            return []
        time.sleep(3)

    # Paginate results to avoid "result too large" errors
    PAGE_SIZE = 5000
    all_rows: list[dict] = []
    offset = 0
    while True:
        result = client.get_execution_results(execution_id, limit=PAGE_SIZE, offset=offset)
        rows = result.result.rows if result.result else []
        all_rows.extend(rows)
        if len(rows) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
        print(f"  … fetched {len(all_rows)} rows so far", flush=True)

    print(f"  → {len(all_rows)} rows returned.")
    return all_rows


# ─── Persist results to SQLite ────────────────────────────────────────────────

def _build_detection_signals(row: dict) -> list[str]:
    """Build a list of human-readable detection signals from query 01 columns."""
    signals = []
    signals.append("first_transfer_to_known_bot")

    blocks = int(row.get("blocks_until_lure", 9999))
    if blocks <= 5:
        signals.append(f"instant_lure ({blocks} blocks)")
    elif blocks <= 20:
        signals.append(f"fast_lure ({blocks} blocks)")
    elif blocks <= 100:
        signals.append(f"quick_lure ({blocks} blocks)")

    transfers = int(row.get("total_transfers", 0))
    if transfers <= 5:
        signals.append(f"minimal_transfers ({transfers})")
    elif transfers <= 20:
        signals.append(f"low_transfers ({transfers})")

    holders = int(row.get("unique_holders", 0))
    if holders <= 3:
        signals.append(f"very_few_holders ({holders})")
    elif holders <= 10:
        signals.append(f"few_holders ({holders})")

    deployer_count = int(row.get("deployer_contract_count", 0))
    if deployer_count >= 10:
        signals.append(f"serial_deployer ({deployer_count} contracts)")
    elif deployer_count >= 3:
        signals.append(f"multi_deployer ({deployer_count} contracts)")

    return signals


def _risk_status(score: int) -> str:
    if score >= 70:
        return "alert"
    if score >= 40:
        return "watching"
    return "clear"


def persist_phishing_candidates(rows: list[dict], data_year: int) -> None:
    """Store query 01 results as flagged_contracts entries."""
    with get_db() as db:
        db.execute("DELETE FROM flagged_contracts WHERE data_year = ?", (data_year,))
        for row in rows:
            score = int(row.get("risk_score", 50))
            signals = _build_detection_signals(row)
            status = _risk_status(score)
            db.execute(
                """
                INSERT OR IGNORE INTO flagged_contracts
                    (address, deployed_at, contract_type, risk_score,
                     detection_signals, targeted_bot, status, data_year,
                     deployer, deployer_contract_count)
                VALUES (?, ?, 'token', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.get("token_address", ""),
                    row.get("deployed_at", ""),
                    score,
                    json.dumps(signals),
                    row.get("targeted_bot", ""),
                    status,
                    data_year,
                    row.get("deployer", ""),
                    int(row.get("deployer_contract_count", 0)),
                ),
            )
        db.commit()
    print(f"  Persisted {len(rows)} phishing candidates to flagged_contracts (year={data_year}).")


def persist_drain_transactions(rows: list[dict], data_year: int) -> None:
    """Store query 02 results as confirmed attacks."""
    with get_db() as db:
        # Clear previous data for this year (idempotent re-runs)
        db.execute("DELETE FROM attacks WHERE data_year = ?", (data_year,))
        for row in rows:
            db.execute(
                """
                INSERT OR IGNORE INTO attacks
                    (tx_hash, block_number, timestamp, attack_type,
                     attacker_address, victim_bot_address, malicious_contract,
                     source_contract, loss_eth, loss_usd, previously_known, data_year)
                VALUES (?, ?, ?, 'token', ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    row.get("tx_hash", ""),
                    row.get("block_number", 0),
                    row.get("block_time", ""),
                    row.get("recipient", ""),
                    row.get("bot_address", ""),
                    row.get("attacker_contract", ""),
                    row.get("source_contract", ""),
                    float(row.get("eth_amount", 0)),
                    float(row.get("approx_usd", 0)),
                    data_year,
                ),
            )
        db.commit()
    print(f"  Persisted {len(rows)} drain transactions to attacks (year={data_year}).")


def persist_timeline(rows: list[dict], data_year: int) -> None:
    # Timeline rows are already covered by the attacks table.
    # Just print for now; the API computes timeline on the fly.
    print(f"  Timeline: {len(rows)} monthly buckets for {data_year} (no direct DB action needed).")


def persist_vulnerable_bots(rows: list[dict], data_year: int) -> None:
    with get_db() as db:
        for row in rows:
            db.execute(
                """
                INSERT OR REPLACE INTO vulnerable_bots
                    (address, first_seen, vulnerability_type, total_loss_eth,
                     current_balance_eth, attack_count, is_active, obfuscation_level)
                VALUES (?, NULL, 'tx_origin', ?, ?, ?, 1, 'unknown')
                """,
                (
                    row.get("address", ""),
                    float(row.get("total_loss_eth", 0)),
                    float(row.get("approx_balance_eth", 0)),
                    int(row.get("attack_count", 0)),
                ),
            )
        db.commit()
    print(f"  Persisted {len(rows)} vulnerable bots (year={data_year}).")


PERSISTERS = {
    "01_token_phishing_candidates": persist_phishing_candidates,
    "02_drain_transactions": persist_drain_transactions,
    "03_attack_timeline": persist_timeline,
    "04_vulnerable_bots_ranked": persist_vulnerable_bots,
}


# ─── Year helpers ─────────────────────────────────────────────────────────────

def year_to_date_range(year: int) -> tuple[str, str]:
    """Return (start_date, end_date) strings for a given year."""
    return f"{year}-01-01", f"{year}-12-31"


def run_queries_for_year(
    client: DuneClient,
    ids: dict[str, int | None],
    names: list[str],
    year: int,
    base_params: dict,
) -> None:
    """Execute all selected queries for a single year and persist results."""
    start_date, end_date = year_to_date_range(year)
    params = {**base_params, "start_date": start_date, "end_date": end_date}

    print(f"\n{'#'*60}")
    print(f"# YEAR {year}  ({start_date} → {end_date})")
    print(f"{'#'*60}")

    for name in names:
        sql_path = QUERIES_DIR / f"{name}.sql"
        if not sql_path.exists():
            print(f"SKIP {name}: SQL file not found at {sql_path}")
            continue

        print(f"\n{'='*60}")
        print(f"Query: {name}  (ID: {ids[name]})  Year: {year}")

        rows = execute_and_wait(client, ids[name], params)

        if rows:
            PERSISTERS[name](rows, data_year=year)
        else:
            print(f"  No results for {name} in {year}.")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Execute Dune Analytics queries year-by-year and persist to SQLite."
    )
    parser.add_argument("--query", type=int, help="Run only query N (1-4)")
    parser.add_argument("--upload-only", action="store_true",
                        help="Print manual upload instructions and exit (free plan workaround)")
    parser.add_argument("--set-id", nargs=2, metavar=("NAME", "ID"),
                        help="Cache a query ID: --set-id 01_token_phishing_candidates 12345")

    # Year-based date controls
    year_group = parser.add_mutually_exclusive_group()
    year_group.add_argument("--year", type=int,
                            help="Run queries for a single year (e.g. --year 2021)")
    year_group.add_argument("--all-years", action="store_true",
                            help=f"Run queries for every year from {FIRST_YEAR} to current")
    year_group.add_argument("--start-date",
                            help="Custom start date (YYYY-MM-DD). Must pair with --end-date.")

    parser.add_argument("--end-date",
                        help="Custom end date (YYYY-MM-DD). Must pair with --start-date.")

    args = parser.parse_args()

    if not DUNE_API_KEY:
        sys.exit("ERROR: set DUNE_API_KEY environment variable.")

    ids = load_cached_ids()

    # --set-id: cache a manually obtained query ID and exit
    if args.set_id:
        name, qid = args.set_id
        ids[name] = int(qid)
        save_cached_ids(ids)
        print(f"Saved: {name} → {qid}")
        return

    # Determine which queries to run
    names = sorted(QUERY_IDS.keys())
    if args.query:
        prefix = f"{args.query:02d}_"
        names = [n for n in names if n.startswith(prefix)]
        if not names:
            sys.exit(f"No query matching index {args.query}")

    # --upload-only: print manual creation instructions (free plan can't create via API)
    if args.upload_only:
        missing = [n for n in names if not ids.get(n)]
        if missing:
            print_manual_upload_instructions(QUERIES_DIR, missing)
        else:
            print("All query IDs already cached:")
            print(json.dumps({k: ids[k] for k in names}, indent=2))
        return

    # Check all IDs are set before executing
    missing_ids = [n for n in names if not ids.get(n)]
    if missing_ids:
        print("ERROR: missing query IDs for:", missing_ids)
        print("Run with --upload-only to see instructions, then use --set-id to cache IDs.")
        sys.exit(1)

    client = DuneClient(api_key=DUNE_API_KEY)
    base_params = {}

    init_db()

    # Determine years to process
    if args.all_years:
        current_year = datetime.now().year
        years = list(range(FIRST_YEAR, current_year + 1))
        print(f"Running queries for years: {years}")
        for year in years:
            run_queries_for_year(client, ids, names, year, base_params)

    elif args.year:
        run_queries_for_year(client, ids, names, args.year, base_params)

    elif args.start_date and args.end_date:
        # Custom date range — extract year from start_date for data_year
        data_year = int(args.start_date[:4])
        params = {**base_params, "start_date": args.start_date, "end_date": args.end_date}
        print(f"\nCustom range: {args.start_date} → {args.end_date} (data_year={data_year})")
        for name in names:
            sql_path = QUERIES_DIR / f"{name}.sql"
            if not sql_path.exists():
                print(f"SKIP {name}: SQL file not found at {sql_path}")
                continue
            print(f"\n{'='*60}")
            print(f"Query: {name}  (ID: {ids[name]})")
            rows = execute_and_wait(client, ids[name], params)
            if rows:
                PERSISTERS[name](rows, data_year=data_year)

    else:
        # Default: run for 2021 only
        print("No --year or --all-years specified. Defaulting to --year 2021.")
        run_queries_for_year(client, ids, names, FIRST_YEAR, base_params)

    print("\nDone.")


if __name__ == "__main__":
    main()
