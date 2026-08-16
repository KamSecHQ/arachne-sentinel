"""Faz 40 - Benchmark harness testleri."""
from arachne.benchmark import harness
from arachne.metrics import evaluation


class _FakeClock:
    """Deterministik, enjekte edilebilir saat (her cagrida ilerler)."""
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        self.t += 0.001
        return self.t


def _perfect_detect(payload):
    """Kotu-huylu sablonlari (kucuk harf ipuclari) yakalayan basit stub."""
    low = payload.lower()
    markers = ("or 1=1", "<script", "onerror", "/etc/passwd", "whoami",
               "union select", "drop table", "ignore all previous",
               "system:", "new instruction", "..", "%63", "cgf5",
               "\\x63", "javascript:")
    detected = any(m in low for m in markers)
    return {
        "detected": detected,
        "score": 0.9 if detected else 0.0,
        "latency_ms": 5.0,
        "technique": "T1190" if detected else "none",
        "stage": "exploitation" if detected else "benign",
    }


def test_attack_families_and_benign_present():
    fams = {f["family"] for f in harness.ATTACK_FAMILIES}
    assert {"sqli", "xss", "rce", "path_traversal",
            "obfuscated", "polyglot", "prompt_injection"} <= fams
    assert len(harness.BENIGN_TEMPLATES) >= 3


def test_make_scenarios_deterministic_and_labeled():
    a = harness.make_scenarios(10, 5, seed=42)
    b = harness.make_scenarios(10, 5, seed=42)
    assert a == b                                  # ayni seed -> ayni liste
    assert len(a) == 15
    mal = [s for s in a if s["kind"] == "malicious"]
    ben = [s for s in a if s["kind"] == "benign"]
    assert len(mal) == 10 and len(ben) == 5
    assert all(s["truth"] is True for s in mal)
    assert all(s["truth"] is False for s in ben)


def test_make_scenarios_payloads_vary():
    scen = harness.make_scenarios(20, 0, seed=7)
    payloads = [s["payload"] for s in scen]
    assert len(set(payloads)) == len(payloads)     # hepsi farkli


def test_make_scenarios_different_seeds_differ():
    a = harness.make_scenarios(10, 10, seed=1)
    b = harness.make_scenarios(10, 10, seed=2)
    assert [s["payload"] for s in a] != [s["payload"] for s in b]


def test_run_scenario_chain_shape():
    scenario = {"id": "x1", "kind": "malicious", "family": "sqli",
                "payload": "' OR 1=1 --", "truth": True}
    sr = harness.run_scenario(scenario, _perfect_detect)
    phases = [c["phase"] for c in sr["chain"]]
    assert phases == ["Attack", "Detection", "Correlation", "Response", "Result"]
    assert sr["detected"] is True
    assert sr["chain"][-1]["status"] == "TP"
    assert sr["respond_latency_ms"] is not None


def test_run_scenario_true_negative():
    scenario = {"id": "b1", "kind": "benign", "family": "benign",
                "payload": "GET /index.html", "truth": False}
    sr = harness.run_scenario(scenario, _perfect_detect)
    assert sr["detected"] is False
    assert sr["chain"][-1]["status"] == "TN"
    assert sr["respond_latency_ms"] is None


def test_run_benchmark_feeds_evaluation():
    scenarios = harness.make_scenarios(30, 30, seed=99)
    bench = harness.run_benchmark(scenarios, _perfect_detect,
                                  respond_fn=lambda sr: {"applied": True})
    assert bench["n"] == 60
    assert len(bench["results"]) == 60
    assert len(bench["chains"]) == 60
    # evaluation_report dogrudan tuketebilmeli
    report = evaluation.evaluation_report(
        bench["results"], elapsed_sec=bench["elapsed_sec"],
        responses=bench["responses"],
    )
    # stub tum kotuleri yakalar, benignleri temiz birakir -> mukemmel
    assert report["classification"]["recall"] == 1.0
    assert report["classification"]["false_positive_rate"] == 0.0
    assert report["grade"].startswith("A")


def test_run_benchmark_with_clock_elapsed():
    scenarios = harness.make_scenarios(5, 5, seed=3)
    clock = _FakeClock()
    bench = harness.run_benchmark(scenarios, _perfect_detect, clock=clock)
    assert bench["elapsed_sec"] > 0


def test_signature_adapter_uses_real_engine():
    detect_fn = harness.signature_detect_adapter()
    hit = detect_fn("' OR 1=1 -- ")
    assert hit["detected"] is True
    assert hit["score"] > 0
    assert hit["latency_ms"] > 0
    miss = detect_fn("GET /index.html HTTP/1.1")
    assert miss["detected"] is False
    assert miss["score"] == 0.0


def test_signature_adapter_end_to_end():
    # Gercek imza motoru uzerinde tam benchmark -> rapor kosar.
    scenarios = harness.make_scenarios(21, 14, seed=2024)
    detect_fn = harness.signature_detect_adapter()
    bench = harness.run_benchmark(scenarios, detect_fn,
                                  respond_fn=lambda sr: {"applied": True})
    report = evaluation.evaluation_report(
        bench["results"], elapsed_sec=bench["elapsed_sec"],
        responses=bench["responses"], event_count=bench["n"],
    )
    # imza motoru benignlerde yanlis pozitif uretmemeli
    assert report["classification"]["false_positive_rate"] == 0.0
    # obfuscated/prompt_injection ailelerini kacirdigi icin recall < 1 (dururust)
    assert report["classification"]["recall"] < 1.0
    assert "benchmark" in report["summary_tr"].lower()
