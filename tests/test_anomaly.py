"""Faz 15 - Anomali ve flood tespiti testleri."""
from arachne.detection import anomaly


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def test_flood_detected_on_burst():
    clock = _FakeClock()
    det = anomaly.FloodDetector(short_window=10, flood_threshold=20,
                                zscore_threshold=3.0, clock=clock)
    # Once normal bir baseline olustur
    for _ in range(5):
        det.record("203.0.113.5")
        clock.advance(2)
    det.evaluate("203.0.113.5")
    # Simdi ani patlama
    for _ in range(40):
        det.record("203.0.113.5")
        clock.advance(0.1)
    result = det.evaluate("203.0.113.5")
    assert result["flood"] is True
    assert result["short_count"] >= 20


def test_no_flood_on_normal_traffic():
    clock = _FakeClock()
    det = anomaly.FloodDetector(short_window=10, flood_threshold=20, clock=clock)
    for _ in range(5):
        det.record("203.0.113.6")
        clock.advance(3)
    result = det.evaluate("203.0.113.6")
    assert result["flood"] is False


def test_evaluate_unknown_ip():
    det = anomaly.FloodDetector()
    result = det.evaluate("203.0.113.99")
    assert result["flood"] is False
    assert result["short_rate"] == 0


def test_top_talkers():
    clock = _FakeClock()
    det = anomaly.FloodDetector(short_window=60, clock=clock)
    for _ in range(10):
        det.record("203.0.113.10")
    for _ in range(3):
        det.record("203.0.113.11")
    talkers = det.top_talkers()
    assert talkers[0]["source_ip"] == "203.0.113.10"
    assert talkers[0]["recent_count"] == 10


def test_distribution_anomaly_flags_rare_service():
    # Populasyonda herkes http'ye gidiyor, bu kaynak sadece mysql'i doverken
    population = {"http-admin": 500, "ssh": 50, "mysql": 5}
    source = {"services": {"mysql": 10}}
    result = anomaly.distribution_anomaly(source, population)
    assert result["anomaly_score"] > 0
    assert "mysql" in result["rare_services"]


def test_distribution_anomaly_normal_behavior():
    population = {"http-admin": 500, "ssh": 400}
    source = {"services": {"http-admin": 10}}
    result = anomaly.distribution_anomaly(source, population)
    assert result["anomaly_score"] == 0.0


def test_build_baseline():
    events = [
        {"service": "ssh", "event_type": "connect", "dest_port": 2222},
        {"service": "ssh", "event_type": "data", "dest_port": 2222},
        {"service": "ftp", "event_type": "connect", "dest_port": 2121},
    ]
    baseline = anomaly.build_baseline(events)
    assert baseline["services"]["ssh"] == 2
    assert baseline["total_events"] == 3
    assert baseline["ports"][2222] == 2
