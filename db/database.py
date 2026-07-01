import sqlite3
import os
from config import DB_PATH, SCHEMA_PATH


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with open(SCHEMA_PATH, "r") as f:
        schema = f.read()
    conn = get_db()
    conn.executescript(schema)
    conn.commit()
    conn.close()
    print("[DB] Schema applied.")


def fetchall(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_db()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetchone(sql: str, params: tuple = ()) -> dict | None:
    conn = get_db()
    row = conn.execute(sql, params).fetchone()
    conn.close()
    return dict(row) if row else None


def execute(sql: str, params: tuple = ()) -> int:
    """Execute a write statement. Returns lastrowid."""
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    lastrowid = cur.lastrowid
    conn.close()
    return lastrowid


def executemany(sql: str, params_list: list[tuple]) -> None:
    conn = get_db()
    conn.executemany(sql, params_list)
    conn.commit()
    conn.close()