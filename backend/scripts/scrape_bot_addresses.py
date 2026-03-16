"""
Scrape known MEV bot addresses from two open-source repositories:

  1. flashbots/mev-inspect-rs  — src/addresses.rs  (archived Rust repo)
  2. manifoldfinance/mev-corpus — packages/mev-known-bots (data dump)

Outputs: backend/data/seed/known_mev_bots.json
  [
    {"address": "0x...", "label": "...", "source": "flashbots|mev-corpus"}
  ]

Usage:
  python scripts/scrape_bot_addresses.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

OUT_PATH = Path(__file__).parent.parent / "data" / "seed" / "known_mev_bots.json"

# ─── Flashbots mev-inspect-rs ────────────────────────────────────────────────
# The repo is archived but the raw file is still accessible.
FLASHBOTS_ADDRESSES_URL = (
    "https://raw.githubusercontent.com/flashbots/mev-inspect-rs"
    "/master/src/addresses.rs"
)

# Matches lines like:
#   m.insert(address!("aabbcc..."), "Sandwich Bot");
# address! macro takes a 40-hex string WITHOUT leading 0x
_FLASHBOTS_RE = re.compile(
    r'address!\("([0-9a-fA-F]{40})"\)[^"]*"([^"]+)"',
)
# Also catch bare H160::from_str / hex_literal patterns
_HEX_ADDR_RE = re.compile(r'"(0x[0-9a-fA-F]{40})"')


def fetch_flashbots_addresses(client: httpx.Client) -> list[dict]:
    print("Fetching flashbots/mev-inspect-rs addresses.rs …")
    resp = client.get(FLASHBOTS_ADDRESSES_URL, follow_redirects=True)
    if resp.status_code != 200:
        print(f"  WARNING: got HTTP {resp.status_code}, skipping.")
        return []

    text = resp.text
    results: list[dict] = []

    # Primary pattern: address!("hex") -> "label"
    for match in _FLASHBOTS_RE.finditer(text):
        addr = "0x" + match.group(1).lower()
        label = match.group(2)
        results.append({"address": addr, "label": label, "source": "flashbots"})

    # Fallback: any quoted 0x address in the file not already found
    found_addrs = {r["address"] for r in results}
    for match in _HEX_ADDR_RE.finditer(text):
        addr = match.group(1).lower()
        if addr not in found_addrs:
            results.append({"address": addr, "label": "unknown", "source": "flashbots"})
            found_addrs.add(addr)

    print(f"  → {len(results)} addresses extracted.")
    return results


# ─── manifoldfinance/mev-corpus ──────────────────────────────────────────────
# The repo has several candidate paths for the bot address list.
# We try them in order and take the first that works.
MEV_CORPUS_CANDIDATES = [
    # packages/mev-known-bots variants
    "https://raw.githubusercontent.com/manifoldfinance/mev-corpus/master/packages/mev-known-bots/data/bots.json",
    "https://raw.githubusercontent.com/manifoldfinance/mev-corpus/master/packages/mev-known-bots/index.json",
    "https://raw.githubusercontent.com/manifoldfinance/mev-corpus/master/packages/mev-known-bots/bots.json",
    # top-level data files
    "https://raw.githubusercontent.com/manifoldfinance/mev-corpus/master/data/bots.json",
    "https://raw.githubusercontent.com/manifoldfinance/mev-corpus/master/mev-known-bots.json",
    # plain text list
    "https://raw.githubusercontent.com/manifoldfinance/mev-corpus/master/packages/mev-known-bots/data/bots.txt",
]


def fetch_mev_corpus_addresses(client: httpx.Client) -> list[dict]:
    print("Fetching manifoldfinance/mev-corpus bot addresses …")

    for url in MEV_CORPUS_CANDIDATES:
        resp = client.get(url, follow_redirects=True)
        if resp.status_code == 200:
            print(f"  Found data at: {url}")
            return _parse_mev_corpus_response(resp, url)

    # Last resort: fetch the repo tree via GitHub API and look for address files
    print("  Trying GitHub API tree …")
    tree_url = "https://api.github.com/repos/manifoldfinance/mev-corpus/git/trees/master?recursive=1"
    tree_resp = client.get(tree_url, follow_redirects=True)
    if tree_resp.status_code == 200:
        tree = tree_resp.json().get("tree", [])
        for node in tree:
            path: str = node.get("path", "")
            if "bot" in path.lower() and path.endswith((".json", ".txt", ".csv")):
                raw_url = f"https://raw.githubusercontent.com/manifoldfinance/mev-corpus/master/{path}"
                print(f"  Trying {raw_url}")
                r = client.get(raw_url, follow_redirects=True)
                if r.status_code == 200:
                    parsed = _parse_mev_corpus_response(r, raw_url)
                    if parsed:
                        return parsed

    print("  WARNING: could not fetch mev-corpus addresses.")
    return []


def _parse_mev_corpus_response(resp: httpx.Response, url: str) -> list[dict]:
    results: list[dict] = []

    if url.endswith(".json"):
        try:
            data = resp.json()
            # Accept: list of strings, list of objects, or object mapping
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and re.match(r"0x[0-9a-fA-F]{40}", item):
                        results.append({"address": item.lower(), "label": "mev-corpus", "source": "mev-corpus"})
                    elif isinstance(item, dict):
                        addr = item.get("address") or item.get("addr") or ""
                        label = item.get("label") or item.get("name") or "mev-corpus"
                        if re.match(r"0x[0-9a-fA-F]{40}", addr):
                            results.append({"address": addr.lower(), "label": label, "source": "mev-corpus"})
            elif isinstance(data, dict):
                for addr, label in data.items():
                    if re.match(r"0x[0-9a-fA-F]{40}", addr):
                        results.append({
                            "address": addr.lower(),
                            "label": label if isinstance(label, str) else "mev-corpus",
                            "source": "mev-corpus",
                        })
        except Exception as e:
            print(f"  JSON parse error: {e}")

    elif url.endswith(".csv"):
        # flashbots.csv format (from manifoldfinance/mev-corpus):
        #   tx_hash, date, from_address (no 0x), value, value, to_address (no 0x), ...
        # Addresses are 40-hex-char tokens in any column.
        import csv, io
        seen_in_file: set[str] = set()
        for row in csv.reader(io.StringIO(resp.text)):
            for cell in row:
                cell = cell.strip()
                # Match bare 40-hex addresses (no 0x prefix)
                if re.fullmatch(r"[0-9a-fA-F]{40}", cell):
                    addr = "0x" + cell.lower()
                    if addr not in seen_in_file:
                        seen_in_file.add(addr)
                        results.append({"address": addr, "label": "mev-corpus", "source": "mev-corpus"})
                # Also match 0x-prefixed addresses if present
                elif re.fullmatch(r"0x[0-9a-fA-F]{40}", cell, re.IGNORECASE):
                    addr = cell.lower()
                    if addr not in seen_in_file:
                        seen_in_file.add(addr)
                        results.append({"address": addr, "label": "mev-corpus", "source": "mev-corpus"})

    else:  # plain text — one address per line
        for line in resp.text.splitlines():
            line = line.strip()
            if re.match(r"0x[0-9a-fA-F]{40}", line):
                results.append({"address": line.lower(), "label": "mev-corpus", "source": "mev-corpus"})
            elif re.match(r"[0-9a-fA-F]{40}", line):
                results.append({"address": "0x" + line.lower(), "label": "mev-corpus", "source": "mev-corpus"})

    print(f"  → {len(results)} addresses extracted.")
    return results


# ─── Bonus: zeromev top searchers ────────────────────────────────────────────
# zeromev exposes per-block MEV data. We can't bulk-list all bots, but we can
# collect addresses by scanning the last N blocks for sandwich/arb senders.
# Only runs if --zeromev flag is passed (slow).

ZEROMEV_API = "https://data.zeromev.org/v1/mevBlock"


def fetch_zeromev_addresses(client: httpx.Client, num_blocks: int = 50) -> list[dict]:
    print(f"Fetching zeromev top searchers from last {num_blocks} blocks …")
    results: list[dict] = []
    seen: set[str] = set()

    # Get latest block number from Etherscan (free, no key needed for this)
    block_resp = client.get(
        "https://api.etherscan.io/api?module=proxy&action=eth_blockNumber",
        follow_redirects=True,
    )
    latest_block = int(block_resp.json().get("result", "0x0"), 16)
    if not latest_block:
        print("  Could not fetch latest block, skipping zeromev.")
        return []

    for block in range(latest_block - num_blocks, latest_block, 10):
        try:
            resp = client.get(f"{ZEROMEV_API}?block_number={block}", follow_redirects=True)
            if resp.status_code != 200:
                continue
            for entry in resp.json():
                addr = entry.get("address_from", "")
                mev_type = entry.get("mev_type", "")
                if addr and addr not in seen:
                    seen.add(addr)
                    results.append({"address": addr.lower(), "label": f"zeromev:{mev_type}", "source": "zeromev"})
        except Exception:
            pass

    print(f"  → {len(results)} addresses extracted.")
    return results


# ─── Merge and deduplicate ────────────────────────────────────────────────────

def merge(lists: list[list[dict]]) -> list[dict]:
    seen: dict[str, dict] = {}
    for entries in lists:
        for e in entries:
            addr = e["address"]
            if addr not in seen:
                seen[addr] = e
            else:
                # Prefer entries with a real label
                if seen[addr]["label"] in ("unknown", "mev-corpus") and e["label"] not in ("unknown", "mev-corpus"):
                    seen[addr]["label"] = e["label"]
    return sorted(seen.values(), key=lambda x: x["address"])


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    use_zeromev = "--zeromev" in sys.argv

    with httpx.Client(timeout=30, headers={"User-Agent": "PhishNet/0.1"}) as client:
        flashbots = fetch_flashbots_addresses(client)
        corpus = fetch_mev_corpus_addresses(client)
        zeromev = fetch_zeromev_addresses(client) if use_zeromev else []

    combined = merge([flashbots, corpus, zeromev])

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(combined, indent=2))
    print(f"\nSaved {len(combined)} unique addresses → {OUT_PATH}")


if __name__ == "__main__":
    main()
