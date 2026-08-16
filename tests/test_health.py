"""Faz 31 - Sensor sagligi & telemetri testleri."""
from arachne.mesh import health


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


# --- packet_loss -----------------------------------------------------------

def test_packet_loss_empty_is_zero():
    r = health.packet_loss([])
    assert r == {"expected": 0, "received": 0, "lost": 0, "loss_pct": 0.0}


def test_packet_loss_perfect_sequence():
    r = health.packet_loss([1, 2, 3, 4, 5])
    assert r["expected"] == 5
    assert r["received"] == 5
    assert r["lost"] == 0
    assert r["loss_pct"] == 0.0


def test_packet_loss_with_gaps():
    # 1..10 bekleniyor, 3 tanesi (4,7,9) eksik -> %30 kayip
    r = health.packet_loss([1, 2, 3, 5, 6, 8, 10])
    assert r["expected"] == 10
    assert r["received"] == 7
    assert r["lost"] == 3
    assert r["loss_pct"] == 30.0


def test_packet_loss_dupes_counted_once():
    # Tekrarlar tek paket sayilir; 1..3 tam -> kayip yok
    r = health.packet_loss([1, 1, 2, 2, 3, 3])
    assert r["expected"] == 3
    assert r["received"] == 3
    assert r["lost"] == 0


# --- SensorHealth: heartbeat / status --------------------------------------

def test_online_after_recent_heartbeat():
    clock = _FakeClock()
    sh = health.SensorHealth(heartbeat_timeout_sec=30, clock=clock)
    sh.record_heartbeat("s1", seq=1)
    clock.advance(5)
    rep = sh.sensor_report("s1")
    assert rep["status"] == "online"
    assert rep["last_heartbeat_age_sec"] == 5


def test_offline_after_timeout():
    clock = _FakeClock()
    sh = health.SensorHealth(heartbeat_timeout_sec=30, clock=clock)
    sh.record_heartbeat("s1")
    clock.advance(45)
    rep = sh.sensor_report("s1")
    assert rep["status"] == "offline"
    assert rep["uptime_pct"] < 100.0


def test_unknown_sensor_reports_offline():
    sh = health.SensorHealth()
    rep = sh.sensor_report("ghost")
    assert rep["status"] == "offline"
    assert rep["last_heartbeat_age_sec"] is None
    assert rep["events_seen"] == 0


def test_degraded_on_packet_loss():
    clock = _FakeClock()
    sh = health.SensorHealth(heartbeat_timeout_sec=30, clock=clock)
    sh.record_heartbeat("s1")
    # 1..20 bekleniyor ama cok bosluk var -> >%5 kayip
    for seq in [1, 2, 3, 4, 5, 20]:
        sh.record_event("s1", seq=seq)
    clock.advance(2)
    rep = sh.sensor_report("s1")
    assert rep["status"] == "degraded"
    assert rep["packet_loss_pct"] > 5.0


def test_degraded_on_integrity_failure():
    clock = _FakeClock()
    sh = health.SensorHealth(clock=clock)
    sh.record_heartbeat("s1")
    sh.record_event("s1", seq=1, integrity_ok=True)
    sh.record_event("s1", seq=2, integrity_ok=False)
    rep = sh.sensor_report("s1")
    assert rep["status"] == "degraded"
    assert rep["integrity_failures"] == 1
    assert rep["integrity_ok"] is False


def test_events_seen_counter():
    sh = health.SensorHealth()
    sh.record_heartbeat("s1")
    for _ in range(4):
        sh.record_event("s1")
    rep = sh.sensor_report("s1")
    assert rep["events_seen"] == 4


# --- fleet_report ----------------------------------------------------------

def test_fleet_report_mixed_fleet():
    clock = _FakeClock()
    sh = health.SensorHealth(heartbeat_timeout_sec=30, clock=clock)
    # online sensor
    sh.record_heartbeat("online-1")
    # degraded sensor (butunluk hatasi)
    sh.record_heartbeat("degraded-1")
    sh.record_event("degraded-1", integrity_ok=False)
    # offline sensor (eski heartbeat)
    sh.record_heartbeat("offline-1")
    clock.advance(60)
    # yeni bir online heartbeat (offline saymamak icin)
    sh.record_heartbeat("online-1")
    sh.record_heartbeat("degraded-1")

    fleet = sh.fleet_report()
    assert fleet["online"] == 1
    assert fleet["degraded"] == 1
    assert fleet["offline"] == 1
    assert 0.0 <= fleet["fleet_health_pct"] <= 100.0
    assert "sensor" in fleet["summary_tr"]
    assert len(fleet["sensors"]) == 3


def test_empty_fleet():
    sh = health.SensorHealth()
    fleet = sh.fleet_report()
    assert fleet["online"] == 0
    assert fleet["fleet_health_pct"] == 0.0
    assert fleet["sensors"] == []
