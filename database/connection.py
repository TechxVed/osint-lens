"""
database/connection.py

Opens the SQLite connection and ensures the schema exists. Kept
separate from repository.py so "how do we connect" and "what queries do
we run" are two clearly separate concerns.
"""

import sqlite3
from pathlib import Path

from database.schema import SCHEMA_SQL

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "osint_lens.db"


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  # lets us access columns by name, e.g. row["target"]
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()
