import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.environ.get("DB_PATH", "data/cyberscan.db")


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            completed_at TEXT,
            findings_json TEXT,
            error TEXT
        );
    """)
    conn.commit()
    conn.close()


def create_scan(scan_id: str, url: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO scans (id, url, status, created_at) VALUES (?, ?, 'running', ?)",
        (scan_id, url, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def update_scan_complete(scan_id: str, findings: list):
    conn = get_db()
    conn.execute(
        "UPDATE scans SET status='complete', completed_at=?, findings_json=? WHERE id=?",
        (datetime.utcnow().isoformat(), json.dumps(findings), scan_id),
    )
    conn.commit()
    conn.close()


def update_scan_error(scan_id: str, error: str):
    conn = get_db()
    conn.execute(
        "UPDATE scans SET status='error', completed_at=?, error=? WHERE id=?",
        (datetime.utcnow().isoformat(), error, scan_id),
    )
    conn.commit()
    conn.close()


def get_scan(scan_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    if result.get("findings_json"):
        result["findings"] = json.loads(result["findings_json"])
    else:
        result["findings"] = []
    return result


def get_all_scans():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, url, status, created_at, completed_at FROM scans ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
