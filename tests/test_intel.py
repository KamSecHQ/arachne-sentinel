"""Faz 6 - Tehdit istihbarati, profilleme ve STIX export testleri."""
import json

from arachne.intel import attck, geo, profiler, stix_export


# --- MITRE ATT&CK eslemesi --------------------------------------------------

def test_sqli_maps_to_t1190_with_cwe_and_capec():
    """ATT&CK'te SQLi icin ayri teknik YOKTUR - dogru yaklasim T1190 + CWE."""
    mapping = attck.map_attack_class("SQL Injection")
    assert mapping["attck"] == ["T1190"]
    assert "CWE-89" in mapping["cwe"]
    assert "CAPEC-66" in mapping["capec"]
    assert mapping["kill_chain_phase"] == "exploitation"


def test_path_traversal_does_not_cite_deprecated_capec_213():
    """CAPEC-213 kullanimdan kaldirildi; canli ID'ler kullanilmali."""
    mapping = attck.map_attack_class("Path Traversal")
    assert "CAPEC-213" not in mapping["capec"]
    assert "CAPEC-126" in mapping["capec"]


def test_obfuscation_uses_current_stealth_tactic_name():
    """ATT&CK v19'da TA0005 'Defense Evasion' -> 'Stealth' olarak degisti."""
    info = attck.technique_info("T1027.010")
    assert info["tactic"] == "Stealth"
    assert info["name"] == "Command Obfuscation"


def test_technique_info_returns_valid_attack_url():
    info = attck.technique_info("T1595.003")
    assert info["url"] == "https://attack.mitre.org/techniques/T1595/003/"


def test_kill_chain_progress_advances_with_exploitation():
    recon = attck.kill_chain_progress(["reconnaissance"])
    exploit = attck.kill_chain_progress(["reconnaissance", "exploitation"])
    assert exploit["stage_index"] > recon["stage_index"]
    assert exploit["progress_pct"] > recon["progress_pct"]
    assert exploit["total_stages"] == 7


def test_furthest_kill_chain_phase_picks_most_advanced():
    assert attck.furthest_kill_chain_phase(
        ["reconnaissance", "installation", "delivery"]
    ) == "installation"


# --- Cografi siniflandirma --------------------------------------------------

def test_geo_marks_loopback_as_lab():
    result = geo.geo_for_ip("127.0.0.1")
    assert result["scope"] == "loopback"
    assert result["precision"] == "lab"
    assert "lab" in result["precision_tr"].lower()


def test_geo_labels_precision_honestly_for_public_ip():
    """Sehir seviyesi dogruluk iddia ETMEMELIYIZ - sadece bolge tahmini."""
    result = geo.geo_for_ip("8.8.8.8")
    assert result["scope"] == "public"
    assert result["precision"] in ("region-estimate", "unknown")
    if result["precision"] == "region-estimate":
        assert "tahmin" in result["precision_tr"].lower()


def test_geo_is_deterministic_for_same_ip():
    """Ayni IP her zaman ayni noktada gorunmeli (harita titremesin)."""
    a = geo.geo_for_ip("203.0.113.45")
    b = geo.geo_for_ip("203.0.113.45")
    assert a["lat"] == b["lat"] and a["lon"] == b["lon"]


def test_geo_separates_different_ips_in_same_region():
    a = geo.geo_for_ip("203.0.113.10")
    b = geo.geo_for_ip("203.0.113.200")
    assert (a["lat"], a["lon"]) != (b["lat"], b["lon"])


def test_geo_handles_invalid_input_gracefully():
    result = geo.geo_for_ip("gecersiz")
    assert result["scope"] == "invalid"
    assert result["precision"] == "unknown"


# --- Davranissal profilleme -------------------------------------------------

def _events(ip, count, gap_seconds, service="ssh", payload=None, start_minute=0):
    """Duzenli araliklarla olay uretir (zamanlama testleri icin)."""
    out = []
    for i in range(count):
        total_seconds = start_minute * 60 + i * gap_seconds
        minute, second = divmod(total_seconds, 60)
        hour, minute = divmod(minute, 60)
        out.append({
            "id": i, "source_ip": ip, "service": service,
            "event_type": "connect", "dest_port": 2222, "payload": payload,
            "timestamp": f"2026-08-14 {10 + hour:02d}:{minute:02d}:{second:02d}",
        })
    return out


def test_timing_analysis_detects_machine_rhythm():
    """Sabit araliklarla gelen istekler = otomatik arac."""
    events = _events("203.0.113.1", 10, gap_seconds=2)
    timing = profiler.timing_analysis(events)
    assert timing["machine_like"] is True
    assert timing["stdev_gap"] < 1.0


def test_timing_analysis_detects_irregular_human_rhythm():
    events = []
    for i, offset in enumerate([0, 3, 47, 55, 130, 133, 250]):
        minute, second = divmod(offset, 60)
        events.append({
            "id": i, "service": "ssh", "event_type": "connect", "payload": None,
            "timestamp": f"2026-08-14 10:{minute:02d}:{second:02d}",
        })
    timing = profiler.timing_analysis(events)
    assert timing["machine_like"] is False


def test_timing_analysis_handles_single_event():
    timing = profiler.timing_analysis(_events("203.0.113.2", 1, 0))
    assert timing["sample_size"] == 0
    assert timing["machine_like"] is False


def test_behavioral_signature_ignores_ip_address():
    """Ayni davranis, farkli IP -> AYNI parmak izi. Modulun tum amaci bu."""
    a = _events("203.0.113.10", 8, gap_seconds=2, service="ssh")
    b = _events("198.51.100.20", 8, gap_seconds=2, service="ssh")
    assert profiler.behavioral_signature(a) == profiler.behavioral_signature(b)


def test_behavioral_signature_differs_for_different_services():
    a = _events("203.0.113.10", 8, gap_seconds=2, service="ssh")
    b = _events("203.0.113.10", 8, gap_seconds=2, service="mysql")
    assert profiler.behavioral_signature(a) != profiler.behavioral_signature(b)


def test_build_profile_classifies_automated_scanner():
    events = _events("203.0.113.30", 25, gap_seconds=1)
    profile = profiler.build_profile("203.0.113.30", events, alerts=[])
    assert profile["threat_class"] == "otomatik-tarayici"
    assert profile["automated"] is True
    assert profile["threat_class_reason"]  # gerekce ASLA bos olmamali


def test_build_profile_classifies_targeted_actor():
    events = []
    for service in ("ssh", "ftp", "mysql", "http-admin"):
        events.extend(_events("203.0.113.40", 4, gap_seconds=17, service=service))
    alerts = [{"severity": "critical", "score": 115, "source_ip": "203.0.113.40"}]
    profile = profiler.build_profile("203.0.113.40", events, alerts)
    assert profile["threat_class"] == "hedefli-saldirgan"


def test_profile_similarity_is_high_for_identical_behavior():
    a = profiler.build_profile("203.0.113.50", _events("203.0.113.50", 10, 2), [])
    b = profiler.build_profile("198.51.100.50", _events("198.51.100.50", 10, 2), [])
    assert profiler.profile_similarity(a, b) >= 0.75


def test_correlate_campaigns_groups_identical_attackers():
    """Faz 6'nin ana iddiasi: farkli IP'ler tek kampanya olarak birlestirilir."""
    profiles = [
        profiler.build_profile(ip, _events(ip, 10, 2), [])
        for ip in ("203.0.113.60", "203.0.113.61", "198.51.100.62")
    ]
    campaigns = profiler.correlate_campaigns(profiles)
    assert len(campaigns) == 1
    assert campaigns[0]["member_count"] == 3
    assert campaigns[0]["evidence_links"]


def test_correlate_campaigns_ignores_single_isolated_attacker():
    profiles = [profiler.build_profile("203.0.113.70", _events("203.0.113.70", 5, 2), [])]
    assert profiler.correlate_campaigns(profiles) == []


def test_correlate_campaigns_separates_different_behavior():
    fast = profiler.build_profile("203.0.113.80", _events("203.0.113.80", 12, 1,
                                                           service="ssh"), [])
    slow = profiler.build_profile("203.0.113.81", _events("203.0.113.81", 4, 90,
                                                           service="mysql"), [])
    campaigns = profiler.correlate_campaigns([fast, slow])
    assert campaigns == []


# --- STIX 2.1 export --------------------------------------------------------

def test_stix_indicator_has_required_spec_fields():
    indicator = stix_export.indicator_for_ip("203.0.113.90",
                                              attack_classes=["SQL Injection"])
    for field in ("type", "spec_version", "id", "created", "modified",
                  "pattern", "pattern_type", "valid_from"):
        assert field in indicator, f"STIX zorunlu alani eksik: {field}"
    assert indicator["spec_version"] == "2.1"
    assert indicator["type"] == "indicator"


def test_stix_id_follows_spec_format():
    """Spec: <type>--<UUIDv4>"""
    indicator = stix_export.indicator_for_ip("203.0.113.91")
    assert indicator["id"].startswith("indicator--")
    uuid_part = indicator["id"].split("--", 1)[1]
    assert len(uuid_part) == 36 and uuid_part.count("-") == 4


def test_stix_timestamps_are_rfc3339_utc_with_z():
    indicator = stix_export.indicator_for_ip("203.0.113.92")
    for field in ("created", "modified", "valid_from"):
        assert indicator[field].endswith("Z"), f"{field} 'Z' ile bitmeli (UTC)"
        assert "T" in indicator[field]


def test_stix_pattern_is_valid_stix_syntax():
    indicator = stix_export.indicator_for_ip("203.0.113.93")
    assert indicator["pattern"] == "[ipv4-addr:value = '203.0.113.93']"
    assert indicator["pattern_type"] == "stix"


def test_stix_uses_official_oasis_tlp_marking_id():
    """TLP marking ID'leri spec'te SABITTIR - uydurulamaz."""
    indicator = stix_export.indicator_for_ip("203.0.113.94")
    assert indicator["object_marking_refs"] == [
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"  # TLP:GREEN
    ]


def test_stix_carries_both_kill_chain_mappings():
    """Spec her ikisini de destekler; ikisini birden vermek uyumlulugu artirir."""
    indicator = stix_export.indicator_for_ip("203.0.113.95",
                                              attack_classes=["SQL Injection"])
    names = {p["kill_chain_name"] for p in indicator["kill_chain_phases"]}
    assert names == {"lockheed-martin-cyber-kill-chain", "mitre-attack"}


def test_stix_external_references_link_attck_and_cwe():
    indicator = stix_export.indicator_for_ip("203.0.113.96",
                                              attack_classes=["SQL Injection"])
    sources = {ref["source_name"] for ref in indicator["external_references"]}
    assert "mitre-attack" in sources
    assert "cwe" in sources


def test_stix_confidence_is_clamped_to_valid_range():
    high = stix_export.indicator_for_ip("203.0.113.97", confidence=500)
    low = stix_export.indicator_for_ip("203.0.113.98", confidence=-20)
    assert high["confidence"] == 100
    assert low["confidence"] == 0


def test_stix_bundle_is_json_serializable_and_well_formed():
    profiles = [{
        "source_ip": "203.0.113.99", "event_count": 12, "alert_count": 2,
        "max_alert_score": 90, "attack_classes": ["SQL Injection"],
        "tools": [("sqlmap", 95)], "threat_class": "arac-kullanan",
        "threat_class_reason": "sqlmap tespit edildi",
        "first_seen": "2026-08-14 10:00:00", "last_seen": "2026-08-14 10:05:00",
    }]
    bundle = stix_export.build_stix_bundle(profiles)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    types = [o["type"] for o in bundle["objects"]]
    assert "identity" in types and "indicator" in types and "observed-data" in types
    # Gercekten serilestirilebilir olmali - baska sistemler bunu okuyacak
    json.dumps(bundle)


def test_stix_bundle_includes_grouping_for_campaign():
    profiles = [
        {"source_ip": "203.0.113.100", "event_count": 5, "alert_count": 1,
         "max_alert_score": 60, "attack_classes": [], "tools": [],
         "first_seen": "2026-08-14 10:00:00", "last_seen": "2026-08-14 10:01:00"},
        {"source_ip": "203.0.113.101", "event_count": 5, "alert_count": 1,
         "max_alert_score": 60, "attack_classes": [], "tools": [],
         "first_seen": "2026-08-14 10:00:00", "last_seen": "2026-08-14 10:01:00"},
    ]
    campaigns = [{
        "campaign_id": "abc123", "member_ips": ["203.0.113.100", "203.0.113.101"],
        "member_count": 2, "assessment_tr": "Test kampanyasi",
    }]
    bundle = stix_export.build_stix_bundle(profiles, campaigns)
    groupings = [o for o in bundle["objects"] if o["type"] == "grouping"]
    assert len(groupings) == 1
    assert len(groupings[0]["object_refs"]) == 2
