"""SQLite tabanli olay ve alarm depolama katmani."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER,
    service TEXT NOT NULL,
    dest_port INTEGER,
    event_type TEXT NOT NULL,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    reasons TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_time ON alerts(source_ip, timestamp);
"""


def _now() -> str:
    # SQLite'in datetime('now', '-N seconds') fonksiyonuyla dogrudan
    # karsilastirilabilmesi icin "YYYY-MM-DD HH:MM:SS" (UTC) formatinda tutuyoruz.
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def get_conn(db_path=None):
    conn = sqlite3.connect(str(db_path or config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path=None):
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)


def log_event(source_ip, service, event_type, source_port=None, dest_port=None,
              payload=None, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO events (timestamp, source_ip, source_port, service, "
            "dest_port, event_type, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_now(), source_ip, source_port, service, dest_port, event_type, payload),
        )


def log_alert(source_ip, score, severity, reasons, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO alerts (timestamp, source_ip, score, severity, reasons) "
            "VALUES (?, ?, ?, ?, ?)",
            (_now(), source_ip, score, severity, json.dumps(reasons, ensure_ascii=False)),
        )


def get_recent_events(source_ip=None, since_seconds=None, db_path=None):
    query = "SELECT * FROM events"
    clauses, params = [], []
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    if since_seconds:
        clauses.append("timestamp >= datetime('now', ?)")
        params.append(f"-{since_seconds} seconds")
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY timestamp DESC"
    with get_conn(db_path) as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def get_all_alerts(limit=200, db_path=None):
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def has_prior_alert(source_ip, db_path=None):
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE source_ip = ?", (source_ip,)
        ).fetchone()
        return row["c"] > 0


def summary_stats(db_path=None):
    with get_conn(db_path) as conn:
        total_events = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"
        ).fetchall()
        top_ips = conn.execute(
            "SELECT source_ip, COUNT(*) c FROM events GROUP BY source_ip "
            "ORDER BY c DESC LIMIT 10"
        ).fetchall()
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "by_severity": {r["severity"]: r["c"] for r in by_severity},
            "top_ips": [(r["source_ip"], r["c"]) for r in top_ips],
        }
