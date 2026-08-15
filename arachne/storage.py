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

CREATE TABLE IF NOT EXISTS soar_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    playbook TEXT,
    reason TEXT,
    outcome TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS blocklist (
    ip TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    reason TEXT,
    playbook TEXT,
    severity TEXT
);

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id TEXT PRIMARY KEY,
    location TEXT,
    version TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    total_events INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mesh_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    sensor_id TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT,
    event_count INTEGER NOT NULL DEFAULT 0,
    remote_addr TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_time ON alerts(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_waf_ip_time ON waf_events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_target_time ON scan_findings(target, timestamp);
CREATE INDEX IF NOT EXISTS idx_mtd_component_time ON mtd_rotations(component, timestamp);
CREATE INDEX IF NOT EXISTS idx_soar_target_time ON soar_actions(target, timestamp);
CREATE INDEX IF NOT EXISTS idx_mesh_sensor_time ON mesh_log(sensor_id, timestamp);
"""

# Sonradan eklenen sutunlar: mevcut veritabanlarini bozmadan yukseltmek icin.
# Format: (tablo, sutun, SQL tipi)
_MIGRATIONS = [
    ("events", "sensor_id", "TEXT"),
]


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


def _apply_migrations(conn):
    """Eski veritabanlarini yeni sutunlarla uyumlu hale getirir.

    SQLite'in `ALTER TABLE ... ADD COLUMN` komutu vardir ama "sutun zaten
    varsa atla" secenegi yoktur. Bu yuzden once PRAGMA ile mevcut sutunlari
    okuyup karsilastiriyoruz. Boylece Faz 1'den beri kullanilan bir
    veritabani, veri kaybi olmadan Faz 9'a yukseltilebilir."""
    for table, column, sql_type in _MIGRATIONS:
        try:
            existing = {row["name"] for row in
                        conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")
        except sqlite3.Error:
            # Migrasyon hatasi sistemi durdurmamali - yeni sutun yoksa
            # ilgili ozellik devre disi kalir ama cekirdek calismaya devam eder.
            pass


def init_db(db_path=None):
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)
        _apply_migrations(conn)


def log_event(source_ip, service, event_type, source_port=None, dest_port=None,
              payload=None, sensor_id=None, db_path=None):
    with get_conn(db_path) as conn:
        try:
            conn.execute(
                "INSERT INTO events (timestamp, source_ip, source_port, service, "
                "dest_port, event_type, payload, sensor_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (_now(), source_ip, source_port, service, dest_port, event_type,
                 payload, sensor_id),
            )
        except sqlite3.OperationalError:
            # sensor_id sutunu yoksa (cok eski bir veritabani) sutunsuz yaz
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


# --- Faz 7: SOAR denetim kaydi ---------------------------------------------

def log_soar_action(action, target, playbook=None, reason=None, outcome="uygulandi",
                    detail=None, db_path=None):
    """Her otomatik mudahale eylemini denetim kaydina yazar.

    Otomatik bir sistemin en onemli ozelligi, verdigi her karari sonradan
    aciklayabilmesidir. Bu tablo, 'sistem neden bu IP'yi engelledi?'
    sorusunun tek dogru cevap kaynagidir."""
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO soar_actions (timestamp, action, target, playbook, "
            "reason, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_now(), action, target, playbook, reason, outcome, detail),
        )


def get_soar_actions(target=None, limit=200, db_path=None):
    query = "SELECT * FROM soar_actions"
    params = []
    if target:
        query += " WHERE target = ?"
        params.append(target)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_conn(db_path) as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def soar_summary_stats(db_path=None):
    with get_conn(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) c FROM soar_actions").fetchone()["c"]
        awaiting = conn.execute(
            "SELECT COUNT(*) c FROM soar_actions WHERE outcome = 'onay-bekliyor'"
        ).fetchone()["c"]
        by_action = conn.execute(
            "SELECT action, COUNT(*) c FROM soar_actions GROUP BY action"
        ).fetchall()
        return {
            "total_actions": total,
            "awaiting_approval": awaiting,
            "by_action": {r["action"]: r["c"] for r in by_action},
        }


# --- Faz 7: Kalici engelleme listesi ----------------------------------------
# Engellemeler veritabaninda tutulur, sadece bellekte DEGIL. Sebep: honeypot
# ve panel ayri sureclerde calisir; bellekteki bir liste diger surecten
# gorunmez. Gercek bir yaptirim mekanizmasinin surecten bagimsiz olmasi
# gerekir - bu, canli test sirasinda fark edilen ve duzeltilen bir eksikti.

def add_block(ip, duration_seconds, reason=None, playbook=None,
              severity="medium", db_path=None):
    """Engellemeyi kalici olarak kaydeder. Mevcut engel daha uzunsa korunur."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT expires_at FROM blocklist WHERE ip = ? "
            "AND expires_at > datetime('now')", (ip,)
        ).fetchone()
        new_expiry_sql = f"datetime('now', '+{int(duration_seconds)} seconds')"
        if row:
            # En uzun engel kazanir
            conn.execute(
                f"UPDATE blocklist SET expires_at = MAX(expires_at, {new_expiry_sql}), "
                "reason = COALESCE(?, reason), playbook = COALESCE(?, playbook), "
                "severity = COALESCE(?, severity), duration_seconds = ? WHERE ip = ?",
                (reason, playbook, severity, int(duration_seconds), ip),
            )
        else:
            conn.execute(
                "INSERT OR REPLACE INTO blocklist (ip, blocked_at, expires_at, "
                f"duration_seconds, reason, playbook, severity) "
                f"VALUES (?, ?, {new_expiry_sql}, ?, ?, ?, ?)",
                (ip, _now(), int(duration_seconds), reason, playbook, severity),
            )


def remove_block(ip, db_path=None):
    with get_conn(db_path) as conn:
        cursor = conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
        return cursor.rowcount > 0


def is_ip_blocked(ip, db_path=None):
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM blocklist WHERE ip = ? AND expires_at > datetime('now')",
            (ip,),
        ).fetchone()
        return row is not None


def get_active_blocks(db_path=None):
    """Suresi dolmamis engellemeler; suresi dolanlari da temizler."""
    with get_conn(db_path) as conn:
        conn.execute("DELETE FROM blocklist WHERE expires_at <= datetime('now')")
        rows = conn.execute(
            "SELECT *, CAST((julianday(expires_at) - julianday('now')) * 86400 AS INTEGER) "
            "AS remaining_seconds FROM blocklist WHERE expires_at > datetime('now') "
            "ORDER BY expires_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def clear_blocks(db_path=None):
    with get_conn(db_path) as conn:
        conn.execute("DELETE FROM blocklist")


# --- Faz 9: Sensor agi ------------------------------------------------------

# Bir sensorun "cevrimici" sayilmasi icin son gorulme suresi (saniye)
SENSOR_ONLINE_WINDOW = 120


def register_sensor(sensor_id, location=None, version=None, event_count=0, db_path=None):
    """Sensoru kaydeder ya da mevcut kaydini gunceller (upsert)."""
    now = _now()
    with get_conn(db_path) as conn:
        existing = conn.execute(
            "SELECT sensor_id, total_events FROM sensors WHERE sensor_id = ?",
            (sensor_id,),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE sensors SET last_seen = ?, location = COALESCE(?, location), "
                "version = COALESCE(?, version), total_events = ? WHERE sensor_id = ?",
                (now, location, version, existing["total_events"] + event_count, sensor_id),
            )
        else:
            conn.execute(
                "INSERT INTO sensors (sensor_id, location, version, first_seen, "
                "last_seen, total_events) VALUES (?, ?, ?, ?, ?, ?)",
                (sensor_id, location, version, now, now, event_count),
            )


def get_sensors(db_path=None):
    """Kayitli sensorleri, cevrimici durumlariyla birlikte dondurur."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT *, CAST((julianday('now') - julianday(last_seen)) * 86400 AS INTEGER) "
            "AS seconds_since_seen FROM sensors ORDER BY last_seen DESC"
        ).fetchall()
    sensors = []
    for row in rows:
        data = dict(row)
        seconds = data.get("seconds_since_seen") or 0
        data["online"] = seconds <= SENSOR_ONLINE_WINDOW
        sensors.append(data)
    return sensors


def log_mesh_event(sensor_id, status, detail=None, event_count=0,
                   remote_addr=None, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO mesh_log (timestamp, sensor_id, status, detail, "
            "event_count, remote_addr) VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), sensor_id, status, detail, event_count, remote_addr),
        )


def get_mesh_events(limit=100, db_path=None):
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM mesh_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def mesh_summary_stats(db_path=None):
    sensors = get_sensors(db_path=db_path)
    with get_conn(db_path) as conn:
        rejected = conn.execute(
            "SELECT COUNT(*) c FROM mesh_log WHERE status = 'reddedildi'"
        ).fetchone()["c"]
        accepted = conn.execute(
            "SELECT COUNT(*) c FROM mesh_log WHERE status = 'kabul'"
        ).fetchone()["c"]
    return {
        "sensor_count": len(sensors),
        "online_count": sum(1 for s in sensors if s.get("online")),
        "total_reports_accepted": accepted,
        "total_reports_rejected": rejected,
        "total_mesh_events": sum(s.get("total_events", 0) for s in sensors),
    }


def alerts_timeline(buckets=12, bucket_minutes=5, db_path=None):
    """Son `buckets * bucket_minutes` dakikayi esit dilimlere bolup her
    dilimdeki alarm sayisini dondurur (liste, en eskiden en yeniye siralı).
    Canli paneldeki 'Alarm Zaman Cizelgesi' mini grafigini besler."""
    total_minutes = buckets * bucket_minutes
    edges = [total_minutes - k * bucket_minutes for k in range(buckets + 1)]
    with get_conn(db_path) as conn:
        counts = []
        for i in range(buckets):
            start, end = edges[i], edges[i + 1]
            row = conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE timestamp > datetime('now', ?) "
                "AND timestamp <= datetime('now', ?)",
                (f"-{start} minutes", f"-{end} minutes"),
            ).fetchone()
            counts.append(row["c"])
        return counts


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
