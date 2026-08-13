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

CREATE TABLE IF NOT EXISTS waf_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    method TEXT,
    path TEXT,
    score INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    reasons TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    target TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_guess TEXT,
    banner TEXT,
    finding TEXT,
    severity TEXT
);

CREATE TABLE IF NOT EXISTS mtd_rotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    component TEXT NOT NULL,
    old_identity TEXT,
    new_identity TEXT NOT NULL,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_time ON alerts(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_waf_ip_time ON waf_events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_target_time ON scan_findings(target, timestamp);
CREATE INDEX IF NOT EXISTS idx_mtd_component_time ON mtd_rotations(component, timestamp);
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


def log_waf_event(source_ip, method, path, score, blocked, reasons, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO waf_events (timestamp, source_ip, method, path, score, "
            "blocked, reasons) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_now(), source_ip, method, path, score, int(blocked),
             json.dumps(reasons, ensure_ascii=False)),
        )


def get_waf_events(limit=200, db_path=None):
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM waf_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def waf_summary_stats(db_path=None):
    with get_conn(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) c FROM waf_events").fetchone()["c"]
        blocked = conn.execute(
            "SELECT COUNT(*) c FROM waf_events WHERE blocked = 1"
        ).fetchone()["c"]
        return {"total_requests": total, "blocked_requests": blocked}


def log_scan_finding(target, port, service_guess, banner, finding, severity, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO scan_findings (timestamp, target, port, service_guess, "
            "banner, finding, severity) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_now(), target, port, service_guess, banner, finding, severity),
        )


def get_scan_findings(target=None, limit=200, db_path=None):
    query = "SELECT * FROM scan_findings"
    params = []
    if target:
        query += " WHERE target = ?"
        params.append(target)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with get_conn(db_path) as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def log_mtd_rotation(component, new_identity, old_identity=None, reason=None, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO mtd_rotations (timestamp, component, old_identity, "
            "new_identity, reason) VALUES (?, ?, ?, ?, ?)",
            (_now(), component, old_identity, new_identity, reason),
        )


def get_mtd_rotations(component=None, limit=200, db_path=None):
    query = "SELECT * FROM mtd_rotations"
    params = []
    if component:
        query += " WHERE component = ?"
        params.append(component)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with get_conn(db_path) as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def mtd_summary_stats(db_path=None):
    with get_conn(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) c FROM mtd_rotations").fetchone()["c"]
        by_component = conn.execute(
            "SELECT component, COUNT(*) c FROM mtd_rotations GROUP BY component"
        ).fetchall()
        return {
            "total_rotations": total,
            "by_component": {r["component"]: r["c"] for r in by_component},
        }


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
