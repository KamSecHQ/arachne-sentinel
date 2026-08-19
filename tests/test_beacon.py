"""Faz 41 - Sifreli C2 beacon (zamanlama) tespiti testleri."""
from arachne.adaptive import beacon


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def test_perfect_beacon_detected():
    # 60sn'de bir, jitter yok -> temiz beacon.
    ts = [i * 60.0 for i in range(12)]
    res = beacon.beacon_score(ts)
    assert res["is_beacon"] is True
    assert abs(res["period_sec"] - 60.0) < 1.0
    assert res["regularity"] > 0.9
    assert res["confidence"] > 0.8


def test_jittered_beacon_detected():
    # 60sn taban + deterministik kucuk jitter (+/- ~%10) -> hala beacon.
    base = 60.0
    jitters = [0, 5, -4, 6, -5, 3, -6, 4, -3, 5, -4]
    ts = [0.0]
    for j in jitters:
        ts.append(ts[-1] + base + j)
    res = beacon.beacon_score(ts)
    assert res["is_beacon"] is True
    assert abs(res["period_sec"] - base) < 12.0
    assert 0 < res["jitter_pct"] < 50


def test_irregular_human_traffic_not_beacon():
    # Cok duzensiz araliklar -> beacon degil.
    ts = [0.0, 3.0, 40.0, 41.0, 200.0, 205.0, 900.0, 905.0]
    res = beacon.beacon_score(ts)
    assert res["is_beacon"] is False
    assert res["regularity"] < 0.5


def test_insufficient_events():
    res = beacon.beacon_score([0.0, 60.0, 120.0])  # 3 olay, min 6'nin altinda
    assert res["is_beacon"] is False
    assert "yetersiz" in res["reason"].lower()


def test_empty_and_single_timestamp():
    empty = beacon.beacon_score([])
    assert empty["is_beacon"] is False
    assert empty["period_sec"] is None
    single = beacon.beacon_score([1000.0])
    assert single["is_beacon"] is False


def test_detect_period_basic():
    intervals = [60.0, 60.0, 60.0, 60.0, 60.0]
    assert abs(beacon.detect_period(intervals) - 60.0) < 0.5


def test_detect_period_with_jitter():
    intervals = [58.0, 62.0, 59.0, 61.0, 60.0, 63.0, 57.0]
    p = beacon.detect_period(intervals)
    assert 55.0 <= p <= 65.0


def test_detect_period_empty():
    assert beacon.detect_period([]) == 0.0


def test_monitor_records_and_evaluates_beacon():
    clock = _FakeClock()
    mon = beacon.BeaconMonitor(min_events=6, clock=clock)
    for _ in range(10):
        mon.record("198.51.100.7")
        clock.advance(30.0)  # her 30sn'de bir call-home
    res = mon.evaluate("198.51.100.7")
    assert res["source_ip"] == "198.51.100.7"
    assert res["is_beacon"] is True
    assert abs(res["period_sec"] - 30.0) < 1.0


def test_monitor_min_events_gate():
    clock = _FakeClock()
    mon = beacon.BeaconMonitor(min_events=6, clock=clock)
    # Sadece 4 olay: duzenli olsa bile min_events kapisi beacon ilan etmez.
    for _ in range(4):
        mon.record("198.51.100.8")
        clock.advance(30.0)
    res = mon.evaluate("198.51.100.8")
    assert res["is_beacon"] is False


def test_monitor_unknown_source():
    mon = beacon.BeaconMonitor()
    res = mon.evaluate("203.0.113.200")
    assert res["is_beacon"] is False
    assert res["period_sec"] is None


def test_determinism_same_input_same_output():
    ts = [i * 45.0 for i in range(9)]
    assert beacon.beacon_score(ts) == beacon.beacon_score(list(ts))
