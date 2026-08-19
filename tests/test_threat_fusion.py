"""Faz 43 - Bayesci tehdit fuzyonu testleri."""
import math

from arachne.adaptive import threat_fusion as tf


def test_log_odds_sigmoid_inverse():
    # sigmoid(log_odds(p)) ~ p (yuvarlama toleransiyla).
    for p in (0.1, 0.3, 0.5, 0.8, 0.95):
        assert abs(tf.sigmoid(tf.log_odds(p)) - p) < 1e-6


def test_log_odds_clamps_extremes():
    # 0 ve 1 sonsuza gitmemeli - sikistirilir, sonlu kalir.
    assert math.isfinite(tf.log_odds(0.0))
    assert math.isfinite(tf.log_odds(1.0))
    assert tf.log_odds(0.5) == 0.0  # p=0.5 -> logit 0


def test_sigmoid_bounds():
    assert 0.0 <= tf.sigmoid(-1000) <= 1e-6
    assert 1.0 - 1e-6 <= tf.sigmoid(1000) <= 1.0
    assert abs(tf.sigmoid(0.0) - 0.5) < 1e-12


def test_fuse_no_fired_returns_prior():
    # Hicbir sinyal atesleymezse sonsal ~ onsel.
    result = tf.fuse(0.15, [{"name": "x", "fired": False, "lr": 10.0}])
    assert abs(result["posterior"] - 0.15) < 1e-3
    assert result["contributions"] == []


def test_fuse_single_signal_raises_posterior():
    prior = 0.15
    result = tf.fuse(prior, [{"name": "beacon", "fired": True, "lr": 8.0}])
    assert result["posterior"] > prior
    assert result["contributions"][0]["name"] == "beacon"
    assert result["contributions"][0]["delta_logodds"] > 0


def test_fuse_multiple_signals_stack():
    # Iki bagimsiz kanit tek kanittan daha yuksek sonsal vermeli.
    one = tf.fuse(0.15, [{"name": "a", "fired": True, "lr": 6.0}])
    two = tf.fuse(0.15, [
        {"name": "a", "fired": True, "lr": 6.0},
        {"name": "b", "fired": True, "lr": 6.0},
    ])
    assert two["posterior"] > one["posterior"]


def test_fuse_lr_below_one_lowers_posterior():
    # LR<1 'temiz' lehine kanittir - sonsali onselin altina ceker.
    prior = 0.4
    result = tf.fuse(prior, [{"name": "clean", "fired": True, "lr": 0.2}])
    assert result["posterior"] < prior


def test_fuse_top_factors_ordered_by_impact():
    result = tf.fuse(0.1, [
        {"name": "small", "fired": True, "lr": 2.0},
        {"name": "huge", "fired": True, "lr": 50.0},
        {"name": "mid", "fired": True, "lr": 6.0},
    ])
    assert result["top_factors"][0] == "huge"
    assert "small" not in result["top_factors"][:1]


def test_fuse_deterministic():
    signals = [{"name": "honeytoken", "fired": True, "lr": 40.0}]
    assert tf.fuse(0.15, signals) == tf.fuse(0.15, signals)


def test_threatfusion_assess_uses_defaults():
    engine = tf.ThreatFusion()
    result = engine.assess(["honeytoken"])
    # honeytoken devasa LR -> yuksek sonsal.
    assert result["posterior"] > 0.85
    assert result["fired"] == ["honeytoken"]
    assert "honeytoken" in result["top_factors"]


def test_threatfusion_extra_override_and_unknown():
    engine = tf.ThreatFusion(prior=0.15)
    # Bilinmeyen dedektor + extra ezmesi.
    result = engine.assess(["signature", "mystery"],
                           extra={"signature": 100.0})
    names = [c["name"] for c in result["contributions"]]
    assert "signature" in names and "mystery" in names
    # signature LR 100 ile ezildi -> en buyuk katki o olmali.
    assert result["top_factors"][0] == "signature"


def test_default_detectors_have_huge_honeytoken():
    assert tf.DEFAULT_DETECTORS["honeytoken"] > tf.DEFAULT_DETECTORS["signature"]
    assert tf.DEFAULT_DETECTORS["deception_touch"] > tf.DEFAULT_DETECTORS["novelty"]
