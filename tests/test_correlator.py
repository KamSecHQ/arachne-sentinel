"""Faz 34 - AI (deterministik) korelasyon motoru testleri."""
from arachne.intel import correlator as co


def _events():
    return [
        {"id": 1, "timestamp": "2026-08-15 10:00:00", "source_ip": "203.0.113.5",
         "service": "http", "event_type": "scan", "payload": "/admin/backup/",
         "dest_port": 80},
        {"id": 2, "timestamp": "2026-08-15 10:05:00", "source_ip": "203.0.113.5",
         "service": "http", "event_type": "request",
         "payload": "' OR 1=1 --", "dest_port": 80},
        {"id": 3, "timestamp": "2026-08-15 10:10:00", "source_ip": "203.0.113.5",
         "service": "ssh", "event_type": "login",
         "payload": "eval($_POST['x'])", "dest_port": 22},
        {"id": 4, "timestamp": "2026-08-15 10:12:00", "source_ip": "203.0.113.9",
         "service": "http", "event_type": "request",
         "payload": "sqlmap UNION SELECT", "dest_port": 80},
        {"id": 5, "timestamp": "2026-08-15 11:30:00", "source_ip": "198.51.100.7",
         "service": "ftp", "event_type": "connect", "payload": "anonymous",
         "dest_port": 21},
    ]


class _FakeClock:
    def __call__(self):
        return 1723716000.0


def test_correlate_returns_expected_keys():
    result = co.correlate_events(_events())
    assert set(result) >= {"campaigns", "incidents", "summary_tr"}


def test_campaign_groups_shared_subnet():
    result = co.correlate_events(_events())
    ids = {c["id"]: c for c in result["campaigns"]}
    camp = ids["campaign:203.0.113.5"]
    assert camp["member_ips"] == ["203.0.113.5", "203.0.113.9"]
    assert camp["event_count"] == 4


def test_lone_attacker_is_its_own_campaign():
    result = co.correlate_events(_events())
    members = [c["member_ips"] for c in result["campaigns"]]
    assert ["198.51.100.7"] in members


def test_chain_is_ordered_by_time():
    result = co.correlate_events(_events())
    camp = next(c for c in result["campaigns"]
                if c["id"] == "campaign:203.0.113.5")
    # Zaman sirasi: dizin tarama (Kesif) -> SQLi (Somuru) -> web shell (Kurulum).
    chain = camp["chain"]
    assert chain == ["Kesif", "Sömürü", "Kurulum"]


def test_first_and_last_seen():
    result = co.correlate_events(_events())
    camp = next(c for c in result["campaigns"]
                if c["id"] == "campaign:203.0.113.5")
    assert camp["first_seen"] == "2026-08-15 10:00:00"
    assert camp["last_seen"] == "2026-08-15 10:12:00"


def test_confidence_monotonic_in_signal_count():
    low = co.confidence_from_signals(1, 1, 0, False)
    high = co.confidence_from_signals(8, 4, 3600, True)
    assert 0.0 <= low <= high <= 1.0
    assert high > low
    assert high == 1.0


def test_confidence_bounds():
    assert co.confidence_from_signals(0, 0, 0, False) == 0.0
    assert co.confidence_from_signals(1000, 100, 1e9, True) == 1.0


def test_merge_low_level_combines_weak_signals():
    single_ip = [e for e in _events() if e["source_ip"] == "203.0.113.5"]
    merged = co.merge_low_level(single_ip)
    assert merged["attacker"] == "203.0.113.5"
    assert merged["event_count"] == 3
    assert merged["distinct_services"] == 2  # http + ssh
    assert merged["severity_estimate"] in {"low", "medium", "high", "critical"}
    assert "dusuk seviyeli" in merged["narrative_tr"]


def test_merge_low_level_empty():
    merged = co.merge_low_level([])
    assert merged["event_count"] == 0
    assert merged["attacker"] is None
    assert merged["severity_estimate"] == "low"


def test_incidents_one_per_attacker():
    result = co.correlate_events(_events())
    attackers = {i["attacker"] for i in result["incidents"]}
    assert attackers == {"203.0.113.5", "203.0.113.9", "198.51.100.7"}


def test_injected_clock_sets_generated_at_but_not_correlation():
    clock = _FakeClock()
    with_clock = co.correlate_events(_events(), clock=clock)
    without = co.correlate_events(_events())
    assert with_clock["generated_at"] == 1723716000.0
    # Saat korelasyon icerigini degistirmez (deterministiklik).
    assert with_clock["campaigns"] == without["campaigns"]


def test_summary_declares_deterministic_nature():
    result = co.correlate_events(_events())
    assert "DETERMINISTIK" in result["summary_tr"]


def test_empty_events():
    result = co.correlate_events([])
    assert result["campaigns"] == []
    assert result["incidents"] == []
