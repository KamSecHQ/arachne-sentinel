"""Faz 21 - Dusuk-ve-yavas tespiti testleri."""
from arachne.adaptive import slow_detector


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def test_cusum_flat_series_no_exceed():
    # Hedefte sabit seri -> birikme yok.
    res = slow_detector.cusum([2.0] * 20, target=2.0, slack=1.0)
    assert res["peak"] == 0.0
    assert res["exceeded"] is False
    assert len(res["series"]) == 20


def test_cusum_accumulates_persistent_drift():
    # Hedefin uzerinde surekli kucuk sapma -> CUSUM birikir ve h'yi asar.
    res = slow_detector.cusum([5.0] * 10, target=2.0, slack=1.0)
    assert res["peak"] > 5.0
    assert res["exceeded"] is True


def test_cusum_slack_absorbs_noise():
    # target+slack'in altinda kalan degerler birikmez.
    res = slow_detector.cusum([2.5, 2.5, 2.8, 2.9], target=2.0, slack=1.0)
    assert res["peak"] == 0.0
    assert res["exceeded"] is False


def test_interval_regularity_high_for_even_pacing():
    # Esit araliklar (makine pacing'i) -> yuksek duzenlilik.
    ts = [i * 60.0 for i in range(20)]
    assert slow_detector.interval_regularity(ts) > 0.95


def test_interval_regularity_low_for_irregular():
    # Duzensiz araliklar (insan) -> dusuk duzenlilik.
    ts = [0, 3, 50, 51, 200, 201, 202, 800, 1500]
    assert slow_detector.interval_regularity(ts) < 0.6


def test_interval_regularity_insufficient_data():
    assert slow_detector.interval_regularity([1000.0]) == 0.0
    assert slow_detector.interval_regularity([]) == 0.0


def test_evaluate_unknown_ip():
    det = slow_detector.SlowBurnDetector()
    res = det.evaluate("203.0.113.99")
    assert res["slow_burn"] is False
    assert res["long_count"] == 0
    assert res["reason"] == "veri yok"


def test_slow_burn_detected_on_even_low_rate_pacing():
    # KILIT SENARYO: saatte ~1/dk'nin altinda ama TAM ESIT araliklarla
    # 30 olay. Anlik hiz flood esigi altinda ama duzenlilik + kayma yakalar.
    clock = _FakeClock()
    det = slow_detector.SlowBurnDetector(baseline_rate_per_min=2.0,
                                         cusum_slack=1.0, decision_interval=5.0,
                                         long_window_sec=3600, clock=clock)
    for _ in range(60):
        det.record("198.51.100.7")
        clock.advance(50.0)   # her 50sn'de bir - makine gibi duzenli
    res = det.evaluate("198.51.100.7")
    assert res["slow_burn"] is True
    assert res["regularity"] >= 0.85
    assert res["long_count"] >= 10
    assert "yavas" in res["reason"].lower() or "kayma" in res["reason"].lower()


def test_slow_burn_detected_on_cumulative_drift():
    # Duzensiz ama baseline uzerinde surekli hacim -> CUSUM kaymasi yakalar.
    clock = _FakeClock()
    det = slow_detector.SlowBurnDetector(baseline_rate_per_min=2.0,
                                         cusum_slack=1.0, decision_interval=5.0,
                                         long_window_sec=3600,
                                         regularity_threshold=0.99, clock=clock)
    # Her dakikaya ~8 olay koy (baseline 2/dk'nin cok uzerinde), araliklar
    # dakika icinde degisken olsun ki duzenlilik dusuk kalsin.
    rng_gaps = [3.0, 9.0, 5.0, 12.0, 7.0, 4.0, 11.0, 9.0]
    for _minute in range(15):
        for g in rng_gaps:
            det.record("198.51.100.8")
            clock.advance(g)
    res = det.evaluate("198.51.100.8")
    assert res["slow_burn"] is True
    assert res["cusum_peak"] >= 5.0


def test_no_slow_burn_on_sparse_low_volume():
    # Az sayida, duzensiz olay -> min_events altinda, alarm yok.
    clock = _FakeClock()
    det = slow_detector.SlowBurnDetector(min_events=10, clock=clock)
    for gap in (120.0, 400.0, 90.0):
        det.record("198.51.100.9")
        clock.advance(gap)
    res = det.evaluate("198.51.100.9")
    assert res["slow_burn"] is False
    assert res["long_count"] < 10


def test_long_window_excludes_old_events():
    # Uzun pencerenin disindaki eski olaylar sayilmaz.
    clock = _FakeClock()
    det = slow_detector.SlowBurnDetector(long_window_sec=3600, clock=clock)
    det.record("198.51.100.10")
    clock.advance(10000.0)   # penceresinin cok otesi
    det.record("198.51.100.10")
    det.record("198.51.100.10")
    res = det.evaluate("198.51.100.10")
    # Sadece son 2 olay pencere icinde.
    assert res["long_count"] == 2


def test_evaluate_result_shape():
    clock = _FakeClock()
    det = slow_detector.SlowBurnDetector(clock=clock)
    for _ in range(5):
        det.record("198.51.100.11")
        clock.advance(30.0)
    res = det.evaluate("198.51.100.11")
    for key in ("source_ip", "slow_burn", "cusum_peak", "long_count",
                "mean_interval_sec", "regularity", "reason"):
        assert key in res
    assert isinstance(res["slow_burn"], bool)
