"""SQLite storage for scan history."""
import sqlite3
from contextlib import closing
from pathlib import Path

DB = Path(__file__).with_name("scans.db")


def _run(sql, args=(), fetch=False):
    with closing(sqlite3.connect(DB)) as c:
        c.row_factory = sqlite3.Row
        cur = c.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()] if fetch else None
        c.commit()
        return rows, cur.lastrowid


def init_db():
    _run("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        records INTEGER, seconds REAL, malicious INTEGER, status TEXT,
        missed INTEGER, false_alarms INTEGER, accuracy REAL)""")


def save_scan(r):
    _, new_id = _run(
        "INSERT INTO scans (records, seconds, malicious, status, missed, false_alarms, accuracy) VALUES (?,?,?,?,?,?,?)",
        (r["records"], r["seconds"], r["malicious"], r["status"], r["missed"], r["false_alarms"], r["accuracy"]))
    return new_id


def list_scans(limit=100):
    rows, _ = _run("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,), fetch=True)
    return rows


def clear_scans():
    _run("DELETE FROM scans")
