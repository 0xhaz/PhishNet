"""
Replace the placeholder known_bots CTE in all Dune SQL files with either:
  (a) inline VALUES from data/seed/known_mev_bots.json, or
  (b) a reference to an uploaded Dune dataset (much shorter SQL).

Modes:
  --inline          Embed addresses directly in SQL (default, produces large files)
  --dataset NAME    Reference a Dune dataset table (e.g. --dataset haz/known_mev_bots)
  --export-csv      Export addresses as CSV for manual Dune upload
  --upload          Upload CSV to Dune via API (requires DUNE_API_KEY)

Usage:
  python scripts/inject_bot_addresses.py --dataset haz/known_mev_bots
  python scripts/inject_bot_addresses.py --inline --limit 100
  python scripts/inject_bot_addresses.py --export-csv
  python scripts/inject_bot_addresses.py --upload
  python scripts/inject_bot_addresses.py --check
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

SEED_FILE = Path(__file__).parent.parent / "data" / "seed" / "known_mev_bots.json"
QUERIES_DIR = Path(__file__).parent.parent / "data" / "dune_queries"
CSV_OUT = Path(__file__).parent.parent / "data" / "seed" / "known_mev_bots.csv"

# Marker that wraps the generated CTE block in each SQL file so we can
# replace it on subsequent runs without touching surrounding SQL.
BEGIN_MARKER = "-- <<BEGIN KNOWN_BOTS>>"
END_MARKER = "-- <<END KNOWN_BOTS>>"


def load_entries() -> list[dict]:
    """Load raw entries (address + label + source) from the seed JSON."""
    data = json.loads(SEED_FILE.read_text())
    seen: set[str] = set()
    entries = []
    for entry in data:
        addr = entry["address"].strip().lower()
        if addr == "0x" + "0" * 40:
            continue
        if not re.fullmatch(r"0x[0-9a-f]{40}", addr):
            continue
        if addr not in seen:
            seen.add(addr)
            entries.append({
                "address": addr,
                "label": entry.get("label", "unknown"),
                "source": entry.get("source", ""),
            })
    return entries


def load_addresses(entries: list[dict] | None = None) -> list[str]:
    if entries is None:
        entries = load_entries()
    return [e["address"] for e in entries]


# ─── Inline mode (embed VALUES in SQL) ──────────────────────────────────────

def build_inline_cte(addresses: list[str]) -> str:
    rows = ",\n            ".join(f"({addr})" for addr in addresses)
    return f"""{BEGIN_MARKER}
known_bots AS (
    -- Auto-generated from data/seed/known_mev_bots.json ({len(addresses)} addresses)
    -- Re-run scripts/inject_bot_addresses.py to refresh.
    SELECT address FROM (VALUES
            {rows}
    ) AS t(address)
), {END_MARKER}"""


# ─── Dataset mode (reference uploaded Dune table) ───────────────────────────

def build_dataset_cte(dataset_ref: str, count: int) -> str:
    """
    Produce a known_bots CTE that reads from an uploaded Dune dataset.
    dataset_ref should be like 'haz/known_mev_bots' → dune.haz.known_mev_bots
    The CSV stores hex addresses without 0x prefix, so we use from_hex() to
    convert to varbinary for JOIN compatibility with ethereum.logs / traces.
    """
    # Convert 'namespace/table' to 'dune.namespace.table'
    parts = dataset_ref.split("/")
    if len(parts) == 2:
        table = f"dune.{parts[0]}.{parts[1]}"
    else:
        table = f"dune.{dataset_ref}"

    return f"""{BEGIN_MARKER}
known_bots AS (
    -- Reads from uploaded Dune dataset: {table}
    -- Upload via: python scripts/inject_bot_addresses.py --upload
    -- Total addresses in dataset: {count}
    SELECT from_hex(address) AS address FROM {table}
), {END_MARKER}"""


# ─── SQL patching ───────────────────────────────────────────────────────────

def patch_sql(sql: str, new_cte_body: str) -> str:
    """Replace the known_bots CTE between BEGIN/END markers."""
    if BEGIN_MARKER in sql:
        pattern = re.compile(
            re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER),
            re.DOTALL,
        )
        return pattern.sub(new_cte_body, sql)

    # Fallback: find known_bots CTE by scanning for balanced parens
    start_token = "known_bots AS ("
    start = sql.find(start_token)
    if start == -1:
        with_pos = sql.find("WITH ")
        if with_pos == -1:
            return sql
        insert_at = with_pos + len("WITH ")
        return sql[:insert_at] + new_cte_body + ",\n\n" + sql[insert_at:]

    depth = 0
    i = start + len("known_bots AS ")
    end = i
    while end < len(sql):
        if sql[end] == "(":
            depth += 1
        elif sql[end] == ")":
            depth -= 1
            if depth == 0:
                end += 1
                break
        end += 1

    return sql[:start] + new_cte_body + sql[end:]


# ─── CSV export & upload ────────────────────────────────────────────────────

def export_csv(entries: list[dict], limit: int = 0) -> str:
    """Generate CSV content. Addresses stored WITHOUT 0x prefix for Dune from_hex()."""
    if limit > 0:
        entries = entries[:limit]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["address", "label", "source"])
    for e in entries:
        # Strip 0x prefix — Dune's from_hex() expects raw hex
        writer.writerow([e["address"][2:], e["label"], e["source"]])
    return buf.getvalue()


def upload_to_dune(csv_content: str, table_name: str = "known_mev_bots") -> None:
    """Upload CSV to Dune as a dataset via the API."""
    api_key = os.getenv("DUNE_API_KEY", "")
    if not api_key:
        sys.exit("ERROR: DUNE_API_KEY not set. Cannot upload.")

    from dune_client.client import DuneClient
    client = DuneClient(api_key=api_key)
    client.upload_csv(
        table_name=table_name,
        data=csv_content,
        description="Known MEV bot addresses for PhishNet phishing detection queries.",
    )
    print(f"Uploaded dataset as '{table_name}' to Dune.")
    print(f"Reference in SQL as: dune.<your_username>.{table_name}")


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Inject bot addresses into Dune SQL files (inline or dataset mode)"
    )
    parser.add_argument("--check", action="store_true", help="Validate only, don't write")
    parser.add_argument("--limit", type=int, default=0,
                        help="Use only the first N addresses (0 = all)")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--inline", action="store_true",
                            help="Embed addresses directly in SQL (default if no --dataset)")
    mode_group.add_argument("--dataset", type=str, metavar="NAMESPACE/TABLE",
                            help="Use Dune dataset reference (e.g. haz/known_mev_bots)")

    parser.add_argument("--export-csv", action="store_true",
                        help="Export addresses as CSV for manual Dune upload")
    parser.add_argument("--upload", action="store_true",
                        help="Upload CSV to Dune via API (requires DUNE_API_KEY)")
    args = parser.parse_args()

    entries = load_entries()
    total = len(entries)

    if args.limit > 0:
        entries = entries[:args.limit]
    print(f"Using {len(entries)}/{total} addresses from {SEED_FILE.name}")

    # ── Export CSV ──
    if args.export_csv or args.upload:
        csv_content = export_csv(entries)
        CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
        CSV_OUT.write_text(csv_content)
        print(f"Exported {len(entries)} addresses to {CSV_OUT}")

        if args.upload:
            upload_to_dune(csv_content)
        elif not args.dataset and not args.inline:
            print("\nTo upload to Dune, run:")
            print("  python scripts/inject_bot_addresses.py --upload")
            print("\nThen patch SQL files to reference the dataset:")
            print("  python scripts/inject_bot_addresses.py --dataset YOUR_USERNAME/known_mev_bots")
            return

    # ── Build CTE ──
    addresses = load_addresses(entries)

    if args.dataset:
        new_cte = build_dataset_cte(args.dataset, len(addresses))
        mode_label = f"dataset ({args.dataset})"
    else:
        new_cte = build_inline_cte(addresses)
        mode_label = f"inline ({len(addresses)} addresses)"

    # ── Patch SQL files ──
    sql_files = sorted(QUERIES_DIR.glob("*.sql"))
    if not sql_files:
        sys.exit(f"No SQL files found in {QUERIES_DIR}")

    for sql_path in sql_files:
        original = sql_path.read_text()
        patched = patch_sql(original, new_cte)

        if patched == original:
            print(f"  {sql_path.name}: no change needed")
            continue

        if args.check:
            print(f"  {sql_path.name}: would be patched (--check mode)")
            continue

        sql_path.write_text(patched)
        print(f"  {sql_path.name}: patched [{mode_label}]")

    if not args.check:
        print(f"\nDone. Mode: {mode_label}")
        if args.dataset:
            print("SQL files now reference the Dune dataset — no inline addresses.")
        else:
            print("Re-paste the updated SQL files into Dune.")


if __name__ == "__main__":
    main()
