"""Faz 25 - Sifir Guven politika motoru testleri."""
from arachne.adaptive import zero_trust


def test_trust_from_signals_base():
    # Bos sinyal -> taban 0.5.
    assert zero_trust.trust_from_signals({}) == 0.5


def test_trust_from_signals_known_identity_raises():
    low = zero_trust.trust_from_signals({})
    high = zero_trust.trust_from_signals({"identity_known": True})
    assert high > low


def test_trust_from_signals_threat_intel_hard_drop():
    base = zero_trust.trust_from_signals({"identity_known": True})
    hit = zero_trust.trust_from_signals({
        "identity_known": True, "threat_intel_hit": True})
    # Tehdit istihbarati sert dusurur -> deny esiginin altina iner.
    assert hit < zero_trust._DENY_THRESHOLD
    assert base - hit >= 0.4  # sert dusus (agirlik 0.45)


def test_trust_from_signals_clamped():
    hi = zero_trust.trust_from_signals({
        "identity_known": True, "device_posture": 1.0,
        "behavioral_history": 1.0})
    assert 0.0 <= hi <= 1.0
    lo = zero_trust.trust_from_signals({"prior_alerts": 100})
    assert lo == 0.0


def test_decide_allow_high_trust():
    pdp = zero_trust.PolicyEngine()
    out = pdp.decide(
        subject={"identity_known": True, "device_posture": 1.0,
                 "behavioral_history": 1.0},
        resource={"sensitivity": 0.1},
        context={})
    assert out["decision"] == "allow"
    assert out["trust_score"] >= zero_trust._ALLOW_THRESHOLD
    assert any("izin" in r for r in out["reasons"])


def test_decide_deny_on_threat_intel():
    pdp = zero_trust.PolicyEngine()
    out = pdp.decide(
        subject={"identity_known": True},
        resource={"sensitivity": 0.5},
        context={"threat_intel_hit": True})
    assert out["decision"] == "deny"
    assert any("kotu" in r for r in out["reasons"])
    assert "decoy" in out["enforcement"].lower() or "reddet" in out["enforcement"].lower()


def test_decide_challenge_middle_band():
    # KILIT SENARYO: suphe artikca guven butcesi daralir -> challenge bandi.
    pdp = zero_trust.PolicyEngine()
    out = pdp.decide(
        subject={"identity_known": True, "prior_alerts": 1},
        resource={"sensitivity": 0.3},
        context={})
    assert out["decision"] == "challenge"
    assert zero_trust._DENY_THRESHOLD <= out["trust_score"] < zero_trust._ALLOW_THRESHOLD


def test_decide_context_optional():
    pdp = zero_trust.PolicyEngine()
    out = pdp.decide(subject={"identity_known": True}, resource={})
    assert out["decision"] in {"allow", "challenge", "deny"}
    assert isinstance(out["reasons"], list)


def test_segmentation_unconnected_denied():
    seg = zero_trust.Segmentation()
    seg.add_segment("dmz", 0.2)
    seg.add_segment("crown", 0.9)
    # Baglanti yok -> yatay hareket her zaman reddedilir (yuksek guvenle bile).
    out = seg.can_traverse("dmz", "crown", trust_score=1.0)
    assert out["allowed"] is False
    assert "baglant" in out["reason"]


def test_segmentation_connected_requires_trust():
    seg = zero_trust.Segmentation()
    seg.add_segment("dmz", 0.2)
    seg.add_segment("crown", 0.9)
    seg.connect("dmz", "crown")
    # Yuksek hassasiyet yuksek guven ister: dusuk guven reddedilir...
    low = seg.can_traverse("dmz", "crown", trust_score=0.5)
    assert low["allowed"] is False
    # ...yuksek guven gecer.
    high = seg.can_traverse("dmz", "crown", trust_score=0.95)
    assert high["allowed"] is True


def test_segmentation_same_segment_and_unknown():
    seg = zero_trust.Segmentation()
    seg.add_segment("a", 0.5)
    assert seg.can_traverse("a", "a", 0.0)["allowed"] is True
    assert seg.can_traverse("a", "nope", 1.0)["allowed"] is False


def test_posture_report():
    seg = zero_trust.Segmentation()
    seg.add_segment("dmz", 0.2)
    seg.add_segment("app", 0.5)
    seg.add_segment("db", 0.9)
    seg.connect("dmz", "app")
    report = seg.posture_report()
    assert report["segment_count"] == 3
    assert report["connected_pairs"] == 1
    assert report["isolated_pairs"] == 2
