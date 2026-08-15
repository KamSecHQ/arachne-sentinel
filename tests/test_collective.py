"""Faz 29 - Kolektif savunma & gosterge paylasimi testleri."""
from arachne.adaptive import collective


def test_to_stix_like_shape_and_id():
    ind = {"kind": "ip", "value": "203.0.113.5"}
    obj = collective.to_stix_like(ind)
    assert obj["type"] == "indicator"
    assert obj["spec_version"] == "2.1"
    assert obj["id"].startswith("indicator--")
    assert obj["pattern"] == "[ipv4-addr:value = '203.0.113.5']"
    assert "malicious-activity" in obj["labels"]
    # valid_from gecilmedikce ciktida olmamali (wallclock yok).
    assert "valid_from" not in obj


def test_to_stix_like_deterministic_id():
    ind = {"kind": "fingerprint", "value": "ja3:abcdef"}
    a = collective.to_stix_like(ind)
    b = collective.to_stix_like(ind)
    assert a["id"] == b["id"]  # ayni deger -> ayni id
    other = collective.to_stix_like({"kind": "fingerprint", "value": "ja3:zzz"})
    assert other["id"] != a["id"]


def test_to_stix_like_unknown_kind_and_valid_from():
    obj = collective.to_stix_like({"kind": "weird", "value": "X"},
                                  valid_from="2026-08-15T00:00:00Z")
    assert obj["pattern"] == "[x-arachne:weird = 'X']"
    assert obj["valid_from"] == "2026-08-15T00:00:00Z"


def test_share_indicator_immunizes_fleet():
    cd = collective.CollectiveDefense()
    for s in ["s1", "s2", "s3", "s4"]:
        cd.register_sensor(s)
    out = cd.share_indicator("s1", {"kind": "token", "value": "tok-1"})
    assert out["newly_added"] is True
    assert out["first_reported_by"] == "s1"
    # Paylasan disindaki 3 sensor bagisik oldu.
    assert out["immunized_sensors"] == 3
    assert out["stix"]["type"] == "indicator"


def test_is_known_bad_true_and_false():
    cd = collective.CollectiveDefense()
    cd.register_sensor("s1")
    cd.share_indicator("s1", {"kind": "ip", "value": "198.51.100.9"})
    hit = cd.is_known_bad("198.51.100.9")
    assert hit["known"] is True
    assert hit["first_reported_by"] == "s1"
    assert hit["kind"] == "ip"
    miss = cd.is_known_bad("10.0.0.1")
    assert miss["known"] is False
    assert miss["first_reported_by"] is None


def test_share_indicator_deduplicates():
    cd = collective.CollectiveDefense()
    cd.register_sensor("s1")
    cd.register_sensor("s2")
    first = cd.share_indicator("s1", {"kind": "ip", "value": "1.2.3.4"})
    dup = cd.share_indicator("s2", {"kind": "ip", "value": "1.2.3.4"})
    assert first["newly_added"] is True
    assert dup["newly_added"] is False
    # Ilk paylasan korunur.
    assert dup["first_reported_by"] == "s1"
    assert cd.immunity_report()["shared_indicators"] == 1


def test_share_indicator_auto_registers_sensor():
    cd = collective.CollectiveDefense()
    cd.share_indicator("rogue-but-ours", {"kind": "token", "value": "t"})
    rep = cd.immunity_report()
    assert rep["total_sensors"] == 1
    assert rep["contributing_sensors"] == 1


def test_immunity_report_coverage():
    cd = collective.CollectiveDefense()
    for s in ["s1", "s2", "s3", "s4"]:
        cd.register_sensor(s)
    cd.share_indicator("s1", {"kind": "ip", "value": "a"})
    cd.share_indicator("s2", {"kind": "ip", "value": "b"})
    rep = cd.immunity_report()
    assert rep["total_sensors"] == 4
    assert rep["contributing_sensors"] == 2
    assert rep["coverage_pct"] == 50.0
    assert rep["shared_indicators"] == 2
    assert "surunun bagisikligi" in rep["herd_immunity_note_tr"]


def test_propagation_savings():
    cd = collective.CollectiveDefense()
    for s in ["s1", "s2", "s3", "s4", "s5"]:
        cd.register_sensor(s)
    cd.share_indicator("s1", {"kind": "ip", "value": "a"})
    cd.share_indicator("s2", {"kind": "ip", "value": "b"})
    sav = cd.propagation_savings()
    # 2 gosterge * 5 sensor = 10 naif kesif; kolektif = 2; onlenen = 8.
    assert sav["naive_cost"] == 10
    assert sav["collective_cost"] == 2
    assert sav["independent_rediscoveries_avoided"] == 8
    assert 0.0 < sav["savings_ratio"] <= 1.0


def test_propagation_savings_empty_pool():
    cd = collective.CollectiveDefense()
    sav = cd.propagation_savings()
    assert sav["naive_cost"] == 0
    assert sav["independent_rediscoveries_avoided"] == 0
    assert sav["savings_ratio"] == 0.0
