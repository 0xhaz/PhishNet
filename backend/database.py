"""SQLite connection and table initialisation."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "phishnet.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY,
    tx_hash TEXT,
    block_number INTEGER,
    timestamp DATETIME,
    attack_type TEXT,
    attacker_address TEXT,
    victim_bot_address TEXT,
    malicious_contract TEXT,
    source_contract TEXT,
    loss_eth REAL,
    loss_usd REAL,
    previously_known BOOLEAN,
    data_year INTEGER
);

CREATE TABLE IF NOT EXISTS vulnerable_bots (
    id INTEGER PRIMARY KEY,
    address TEXT UNIQUE,
    first_seen DATETIME,
    vulnerability_type TEXT,
    total_loss_eth REAL,
    current_balance_eth REAL,
    attack_count INTEGER,
    is_active BOOLEAN,
    obfuscation_level TEXT
);

CREATE TABLE IF NOT EXISTS flagged_contracts (
    id INTEGER PRIMARY KEY,
    address TEXT UNIQUE,
    deployed_at DATETIME,
    contract_type TEXT,
    risk_score INTEGER,
    detection_signals TEXT,
    targeted_bot TEXT,
    status TEXT,
    data_year INTEGER,
    deployer TEXT DEFAULT '',
    deployer_contract_count INTEGER DEFAULT 0
);
"""


def get_db() -> sqlite3.Connection:
    import os
    db_path = DB_PATH
    # Vercel has a read-only filesystem — copy DB to /tmp on first use
    if os.environ.get("VERCEL"):
        tmp_db = Path("/tmp/phishnet.db")
        if not tmp_db.exists():
            import shutil
            shutil.copy2(DB_PATH, tmp_db)
        db_path = tmp_db
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.executescript(SCHEMA)
