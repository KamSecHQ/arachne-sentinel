"""Faz 24/26/28 - Topluluk motoru, adaptif durus ve kapsam haritasi testleri."""
from arachne.adaptive import ensemble, posture, coverage


# --- Faz 24: Ensemble ------------------------------------------------------

def _sig(name, score, fired):
    return ensemble.DetectorSignal(name=name, score=score, fired=fired)


def test_ensemble_no_alert_on_single_weak_signal():
    det = ensemble.EnsembleDetector()
    res = det.combine("1.2.3.4", [_sig("flood", 0.4, False)])
    assert res.alert is False
    assert res.votes == 0


def test_ensemble_alerts_when_multiple_independent_detectors_fire():
    det = ensemble.EnsembleDetector(alert_threshold=1.5, min_votes=2)
    res = det.combine("1.2.3.4", [
        _sig("signature", 0.9, True),
        _sig("flood", 0.9, True),
    ])
    assert res.alert is True
    assert res.votes == 2
    assert set(res.voters) == {"signature", "flood"}


def test_ensemble_single_deception_touch_is_enough():
    # Aldatma temasi tek basina yeter (yanlis-pozitif ~sifir) - digerleri sessiz.
    det = ensemble.EnsembleDetector(alert_threshold=99, min_votes=9)
    res = det.combine("9.9.9.9", [_sig("deception", 1.0, True)])
    assert res.alert is True
    assert res.severity == "kritik"
    assert "honeytoken" in res.reason or "aldatma" in res.reason


def test_ensemble_high_threshold_blocks_when_below():
    det = ensemble.EnsembleDetector(alert_threshold=5.0, min_votes=2)
    res = det.combine("1.2.3.4", [
        _sig("signature", 0.5, True),
        _sig("flood", 0.5, True),
    ])
    assert res.alert is False


def test_ensemble_dynamic_weight_raises_contribution():
    det = ensemble.EnsembleDetector()
    base = det.combine("1.1.1.1", [_sig("slow_burn", 1.0, True)]).threat
    det.set_dynamic_weight("slow_burn", 2.0)
    boosted = det.combine("1.1.1.1", [_sig("slow_burn", 1.0, True)]).threat
    assert boosted > base


def test_ensemble_votes_only_count_independent_detectors():
    det = ensemble.EnsembleDetector()
    # "risk" bagimsiz sayilmaz; oy vermemeli.
    res = det.combine("1.2.3.4", [_sig("risk", 1.0, True)])
    assert res.votes == 0


def test_signals_from_analysis_maps_fields():
    analysis = {
        "signature_score": 0.8,
        "flood": {"flood": True, "zscore": 4.0, "reason": "x"},
        "slow_burn": {"slow_burn": False, "regularity": 0.9, "reason": "y"},
        "sybil": {"is_sybil": True, "verdict": "z"},
        "deception": {"is_breach": False},
        "risk_score": 70,
    }
    sigs = ensemble.signals_from_analysis(analysis)
    names = {s.name for s in sigs}
    assert {"signature", "flood", "slow_burn", "fingerprint", "deception", "risk"} <= names


# --- Faz 26: Adaptif durus -------------------------------------------------

def test_posture_starts_normal():
    p = posture.AdaptivePosture()
    assert p.level == "NORMAL"


def test_posture_escalates_with_hysteresis():
    p = posture.AdaptivePosture(hysteresis_ticks=2)
    # Tek yuksek tepe aninda ziplatmamali (histerezis).
    s1 = p.update(90)
    assert s1.changed is False
    assert p.level == "NORMAL"
    # Ikinci ust uste onay bir kademe ilerletir.
    s2 = p.update(90)
    assert s2.changed is True
    assert p.level == "ELEVATED"


def test_posture_climbs_step_by_step_to_critical():
    p = posture.AdaptivePosture(hysteresis_ticks=1)
    last = None
    for _ in range(5):
        last = p.update(95)
    assert p.level == "CRITICAL"
    assert last.rank == 3


def test_posture_unlocks_actions_on_escalation():
    p = posture.AdaptivePosture(hysteresis_ticks=1)
    p.update(60)  # -> ELEVATED
    s = p.update(60)  # -> HIGH (bir sonraki kademe)
    # HIGH'a cikinca MTD gibi savunmalar acilmali
    assert any("MTD" in u for u in p.snapshot()["unlocks"]) or s.triggered_actions


def test_posture_de_escalates_when_threat_drops():
    p = posture.AdaptivePosture(hysteresis_ticks=1)
    for _ in range(4):
        p.update(95)
    assert p.level == "CRITICAL"
    # Tehdit gecince kademeli iner
    for _ in range(4):
        p.update(0)
    assert p.level == "NORMAL"


def test_score_from_signals_is_bounded_and_monotone():
    low = posture.score_from_signals(ensemble_threat=0.5)
    high = posture.score_from_signals(ensemble_threat=0.5, honeytoken_triggers=2,
                                      critical_alerts=5, blocked_ips=10)
    assert high > low
    assert 0 <= high  # birikimli, ust sinirlar terim bazinda


def test_snapshot_marks_active_levels():
    p = posture.AdaptivePosture(hysteresis_ticks=1)
    for _ in range(3):
        p.update(60)
    snap = p.snapshot()
    active = [l for l in snap["all_levels"] if l["active"]]
    assert snap["level"] in {"HIGH", "ELEVATED", "CRITICAL"}
    assert len(active) >= 2


# --- Faz 28: Kapsam haritasi ----------------------------------------------

def test_coverage_maps_all_30_phases():
    assert len(coverage.PHASE_MAP) == 30
    assert [e["faz"] for e in coverage.PHASE_MAP] == list(range(1, 31))


def test_coverage_report_has_all_d3fend_tactics_scored():
    rep = coverage.build_coverage()
    assert set(rep.d3fend_covered.keys()) == set(coverage.D3FEND_TACTICS)
    assert 0 <= rep.d3fend_tactic_pct <= 100


def test_coverage_covers_deceive_and_detect():
    rep = coverage.build_coverage()
    assert rep.d3fend_covered["Deceive"]  # honeypot/honeytoken/decoy grid
    assert rep.d3fend_covered["Detect"]


def test_coverage_csf_includes_govern():
    rep = coverage.build_coverage()
    assert "Govern" in rep.csf_covered
    assert rep.csf_covered["Govern"]


def test_coverage_matrix_four_columns():
    rows = coverage.coverage_matrix()
    assert len(rows) == 30
    r = rows[0]
    assert {"faz", "ad", "d3fend", "csf", "attack_counters"} <= set(r.keys())


def test_engage_activities_present():
    rep = coverage.build_coverage()
    assert rep.engage_activities  # honeypot/honeytoken/lures map to Engage
