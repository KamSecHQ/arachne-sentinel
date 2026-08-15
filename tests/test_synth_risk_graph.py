"""Faz 16 (imza uretimi), 18 (risk), 19 (saldiri grafigi) testleri."""
from arachne.intel import attack_graph, risk_engine, signature_synth


# --- Faz 16: Imza uretimi ---------------------------------------------------

def test_synthesize_finds_discriminative_signature():
    malicious = [
        "id=1 UNION SELECT password FROM users",
        "id=2 UNION SELECT creditcard FROM users",
        "id=3 UNION SELECT email FROM users",
    ]
    benign = [
        "GET /products?category=shoes",
        "search=red running shoes",
        "page=2&sort=price",
    ]
    result = signature_synth.synthesize_signatures(malicious, benign)
    assert result["candidate_count"] > 0
    # Ayirt edici imzalar SQLi yapisiyla iliskili n-gram'lar olmali
    # (n-gram parcalari oldugu icin tam kelime yerine parca araniyor)
    sigs = " ".join(c["signature"] for c in result["candidates"])
    assert any(frag in sigs for frag in ("nion", "lect", "from", "user"))
    # Hepsi kotu yuklerde yuksek, mesru yuklerde dusuk destege sahip olmali
    for c in result["candidates"]:
        assert c["malicious_support"] >= 0.3
        assert c["benign_support"] <= 0.02


def test_synthesize_rejects_common_benign_strings():
    """Mesru trafikte de sik gorunen diziler imza OLMAMALI."""
    malicious = ["attack payload with common word test123"]
    benign = ["test123"] * 50   # 'test123' mesru trafikte cok sik
    result = signature_synth.synthesize_signatures(malicious, benign)
    sigs = [c["signature"] for c in result["candidates"]]
    assert not any("test123" in s for s in sigs)


def test_synthesize_empty_malicious():
    result = signature_synth.synthesize_signatures([], ["benign"])
    assert result["candidate_count"] == 0 if "candidate_count" in result else True
    assert result["candidates"] == []


def test_candidate_marked_as_candidate_not_active():
    """Uretilen imzalar ASLA otomatik aktif olmamali - sadece aday."""
    malicious = ["union select password from admin_users where"] * 3
    benign = ["hello world"]
    result = signature_synth.synthesize_signatures(malicious, benign)
    for cand in result["candidates"]:
        assert cand["status"] == "candidate"


def test_candidate_to_rule_conversion():
    candidate = {"signature": "union select", "malicious_support": 0.9,
                 "benign_support": 0.01}
    rule = signature_synth.candidate_to_rule(candidate)
    assert rule["strings"][0]["value"] == "union select"
    assert rule["_synthesized"] is True


# --- Faz 18: Risk motoru ----------------------------------------------------

def test_risk_higher_for_rce_than_scan():
    rce = risk_engine.compute_risk(attack_classes=["Command Injection"],
                                   kill_chain_phase="installation")
    scan = risk_engine.compute_risk(attack_classes=["Port Scan"],
                                    kill_chain_phase="reconnaissance")
    assert rce["risk_score"] > scan["risk_score"]


def test_risk_factors_are_explained():
    result = risk_engine.compute_risk(
        attack_classes=["SQL Injection"], kill_chain_phase="exploitation",
        repeat_offender=True, in_campaign=True)
    assert len(result["factors"]) > 0
    for f in result["factors"]:
        assert "factor" in f and "contribution" in f


def test_risk_repeat_offender_increases_score():
    base = risk_engine.compute_risk(attack_classes=["SQL Injection"])
    repeat = risk_engine.compute_risk(attack_classes=["SQL Injection"],
                                      repeat_offender=True)
    assert repeat["likelihood_score"] > base["likelihood_score"]


def test_risk_bands_assigned():
    critical = risk_engine.compute_risk(
        attack_classes=["Command Injection", "Reverse Shell"],
        kill_chain_phase="command-and-control", has_reverse_shell=True,
        repeat_offender=True, in_campaign=True, tool_confidence=90)
    assert critical["risk_band"] in ("kritik", "yuksek")


def test_risk_empty_is_minimal():
    result = risk_engine.compute_risk()
    assert result["risk_score"] < 40


def test_risk_from_analysis():
    analysis = {
        "attack_classes": ["SQL Injection"],
        "kill_chain": {"phase": "exploitation"},
        "automated": False,
        "iocs": {"reverse_shells": []},
        "deobfuscation": {"layers": 2},
        "tools": [{"confidence": 85}],
        "entropy": 5.0,
    }
    result = risk_engine.risk_from_analysis(analysis, repeat_offender=True)
    assert result["risk_score"] > 0
    assert "vector_tr" in result


# --- Faz 19: Saldiri grafigi ------------------------------------------------

def _payload_analysis(classes, phase, ts, service, techniques=None):
    return {
        "attack_classes": classes,
        "kill_chain": {"phase": phase, "phase_tr": phase, "progress_pct": 50,
                       "stage_index": 4, "total_stages": 7},
        "timestamp": ts, "service": service,
        "attck_techniques": [{"id": t} for t in (techniques or [])],
    }


def test_attack_graph_builds_nodes_and_edges():
    analyses = [
        _payload_analysis(["Port Scan"], "reconnaissance", "2026-08-14 10:00:00", "ssh"),
        _payload_analysis(["SQL Injection"], "exploitation", "2026-08-14 10:01:00", "http-admin"),
        _payload_analysis(["Command Injection"], "installation", "2026-08-14 10:02:00", "http-admin"),
    ]
    graph = attack_graph.build_attack_graph("203.0.113.5", analyses)
    assert graph["node_count"] == 3
    assert len(graph["edges"]) == 2
    assert graph["furthest_phase"] == "installation"


def test_attack_graph_predicts_next_phase():
    analyses = [
        _payload_analysis(["SQL Injection"], "exploitation", "2026-08-14 10:00:00", "http-admin"),
    ]
    graph = attack_graph.build_attack_graph("203.0.113.6", analyses)
    # exploitation'dan sonra installation gelmeli
    assert graph["predicted_next_phase"] == "installation"


def test_attack_graph_lateral_movement():
    events = [
        {"timestamp": "2026-08-14 10:00:00", "service": "ssh"},
        {"timestamp": "2026-08-14 10:00:05", "service": "ftp"},
        {"timestamp": "2026-08-14 10:00:10", "service": "mysql"},
    ]
    analyses = [_payload_analysis(["Port Scan"], "reconnaissance",
                                  "2026-08-14 10:00:00", "ssh")]
    graph = attack_graph.build_attack_graph("203.0.113.7", analyses, events)
    assert graph["lateral_movement"]["is_lateral"] is True
    assert graph["lateral_movement"]["service_count"] == 3


def test_attack_graph_storyline_generated():
    analyses = [
        _payload_analysis(["Port Scan"], "reconnaissance", "2026-08-14 10:00:00", "ssh"),
        _payload_analysis(["SQL Injection"], "exploitation", "2026-08-14 10:01:00", "http-admin"),
    ]
    graph = attack_graph.build_attack_graph("203.0.113.8", analyses)
    assert "Saldiri anlatisi" in graph["storyline_tr"]


def test_attack_graph_empty():
    graph = attack_graph.build_attack_graph("203.0.113.9", [])
    assert graph["node_count"] == 0
