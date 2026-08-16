"""Faz 39 - Metrik ve degerlendirme motoru testleri."""
from arachne.metrics import evaluation


def _labeled(tp, fp, fn, tn):
    """Verilen sayilarda TP/FP/FN/TN uretir (kolay kurulum icin)."""
    rows = []
    rows += [{"is_malicious": True, "detected": True}] * tp
    rows += [{"is_malicious": False, "detected": True}] * fp
    rows += [{"is_malicious": True, "detected": False}] * fn
    rows += [{"is_malicious": False, "detected": False}] * tn
    return rows


def test_confusion_matrix_counts():
    cm = evaluation.confusion_matrix(_labeled(3, 1, 2, 4))
    assert cm == {"tp": 3, "fp": 1, "fn": 2, "tn": 4}


def test_classification_metrics_perfect():
    m = evaluation.classification_metrics(_labeled(5, 0, 0, 5))
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["accuracy"] == 1.0
    assert m["false_positive_rate"] == 0.0
    assert m["false_negative_rate"] == 0.0


def test_classification_metrics_known_values():
    # tp=8, fp=2, fn=2, tn=8 -> precision=recall=0.8, f1=0.8
    m = evaluation.classification_metrics(_labeled(8, 2, 2, 8))
    assert m["precision"] == 0.8
    assert m["recall"] == 0.8
    assert m["f1"] == 0.8
    assert m["accuracy"] == 0.8
    assert m["detection_rate"] == m["recall"]
    assert m["false_positive_rate"] == 0.2
    assert m["false_negative_rate"] == 0.2


def test_classification_metrics_division_guard():
    # Bos veri: hicbir sey patlamamali, her sey 0.0.
    m = evaluation.classification_metrics([])
    for key in ("precision", "recall", "f1", "accuracy",
                "false_positive_rate", "false_negative_rate"):
        assert m[key] == 0.0
    assert m["tp"] == m["fp"] == m["fn"] == m["tn"] == 0


def test_percentile_empty_is_zero():
    assert evaluation.percentile([], 95) == 0.0


def test_percentile_interpolation():
    values = [10, 20, 30, 40]
    # medyan (p50): (n-1)*0.5 = 1.5 -> 20 + 0.5*(30-20) = 25
    assert evaluation.percentile(values, 50) == 25.0
    assert evaluation.percentile(values, 0) == 10.0
    assert evaluation.percentile(values, 100) == 40.0


def test_timing_metrics():
    results = [
        {"detected": True, "detect_latency_ms": 10, "respond_latency_ms": 5},
        {"detected": True, "detect_latency_ms": 30, "respond_latency_ms": 15},
        {"detected": False, "detect_latency_ms": 999},  # tespit yok -> haric
    ]
    t = evaluation.timing_metrics(results)
    assert t["mttd_ms"] == 20.0                 # (10+30)/2
    assert t["mttr_ms"] == 10.0                 # (5+15)/2
    assert t["max_detection_latency_ms"] == 30.0
    assert t["median_detection_latency_ms"] == 20.0


def test_timing_metrics_empty_guard():
    t = evaluation.timing_metrics([])
    assert t["mttd_ms"] == 0.0
    assert t["mttr_ms"] == 0.0
    assert t["p95_detection_latency_ms"] == 0.0


def test_throughput():
    assert evaluation.throughput(1000, 2.0)["events_per_sec"] == 500.0
    # Sifira bolme korumasi
    assert evaluation.throughput(1000, 0)["events_per_sec"] == 0.0


def test_response_success_rate():
    responses = [{"applied": True}, {"applied": True}, {"applied": False}]
    r = evaluation.response_success_rate(responses)
    assert r["applied"] == 2
    assert r["total"] == 3
    assert r["rate"] == round(2 / 3, 4)
    empty = evaluation.response_success_rate([])
    assert empty["rate"] == 0.0


def test_evaluation_report_structure_and_grade():
    results = _labeled(9, 1, 1, 9)
    for row in results:
        row["detect_latency_ms"] = 12
        row["respond_latency_ms"] = 8
    report = evaluation.evaluation_report(
        results, elapsed_sec=1.0,
        responses=[{"applied": True}],
        sensor_health={"ssh": "up"},
        event_count=20,
    )
    assert set(report.keys()) == {
        "classification", "timing", "throughput", "response",
        "sensor_health", "grade", "summary_tr",
    }
    # F1 ~0.9 -> A notu
    assert report["grade"].startswith("A")
    assert report["throughput"]["events_per_sec"] == 20.0
    assert report["sensor_health"] == {"ssh": "up"}
    assert "DURUSTLUK" in report["summary_tr"]


def test_evaluation_report_low_grade():
    # Cok kotu tespit: F1 dusuk -> F notu
    results = _labeled(1, 5, 5, 1)
    report = evaluation.evaluation_report(results)
    assert report["grade"].startswith("F")
