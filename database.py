import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pandas as pd

DB_PATH = Path(__file__).parent / "chainshield.db"
THREAT_CSV = Path(__file__).parent / "data" / "threat_indicators.csv"


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tx_cache (
                address    TEXT    NOT NULL,
                chain_id   INTEGER NOT NULL,
                fetched_at INTEGER NOT NULL,
                payload    TEXT    NOT NULL,
                PRIMARY KEY (address, chain_id)
            );
            CREATE TABLE IF NOT EXISTS threat_indicators (
                address  TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                label    TEXT,
                source   TEXT
            );
        """)
    seed_indicators()


def seed_indicators(path=THREAT_CSV):
    """Replace the threat table with the CSV contents (removes delisted addresses)."""
    df = pd.read_csv(path, dtype=str).fillna("")
    df["address"] = df["address"].str.strip().str.lower()
    df = df.drop_duplicates(subset="address", keep="first")
    rows = list(df[["address", "category", "label", "source"]].itertuples(index=False, name=None))
    with get_conn() as conn:
        conn.execute("DELETE FROM threat_indicators")
        conn.executemany("INSERT INTO threat_indicators VALUES (?, ?, ?, ?)", rows)


def load_indicators() -> dict:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM threat_indicators").fetchall()
    return {r["address"]: dict(r) for r in rows}


def get_cached(address: str, chain_id: int):
    """Return (fetched_at, transactions) or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM tx_cache WHERE address = ? AND chain_id = ?",
            (address, chain_id)).fetchone()
    return (row["fetched_at"], json.loads(row["payload"])) if row else None


def save_cache(address: str, chain_id: int, fetched_at: int, transactions: list):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO tx_cache VALUES (?, ?, ?, ?)",
                     (address, chain_id, fetched_at, json.dumps(transactions)))