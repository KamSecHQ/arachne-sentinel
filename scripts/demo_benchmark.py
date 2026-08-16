#!/usr/bin/env python3
"""
Arachne Sentinel - BENCHMARK HARNESS (Faz 40).

Binlerce ETIKETLI kontrollu senaryoyu (kotu niyetli + mesru) gercek tespit
hattindan gecirir ve her biri icin Attack -> Detection -> Correlation ->
Response -> Result zincirini kaydeder. Ardindan sistemin basarisini GERCEK
olcumlerle kanitlar: Precision, Recall, F1, FPR/FNR, MTTD, P95 gecikme,
olay/sn.

--- Neden iki temel (baseline)? ---
Yarisma anlatisi: katmanli sistem, klasik "sadece imza" savunmasindan NE KADAR
iyi? Ayni senaryolari iki dedektorden gecirir ve kiyaslariz:
  1. Sadece-imza (WAF)      : gizlenmis/prompt-injection yuklerini KACIRIR
  2. Tam katmanli sistem    : kodlama cozme + aciklanabilir tespit ile yakalar
Fark, katmanli savunmanin olculmus getirisidir.

--- DURUSTLUK ---
Senaryolar sentetiktir ama tespit GERCEKTIR (gercek imza motoru + cozucu +
aciklayici calisir). Sonuclar etiketli veriden olculur; mutlak "kirilamaz"
iddiasi yoktur. Kacirilan aileler raporda acikca gosterilir.

Kullanim:
  source .venv/bin/activate
  python scripts/demo_benchmark.py                 # 2000 senaryo (varsayilan)
  python scripts/demo_benchmark.py --n 5000        # daha buyuk kosum
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne import config  # noqa: E402
from arachne.benchmark import harness  # noqa: E402
from arachne.metrics import evaluation  # noqa: E402
from arachne.waf import rules as waf_rules  # noqa: E402
from arachne.reverse import explainer  # noqa: E402


def signature_only_detect(payload: str) -> dict:
    """Temel 1: klasik imza tabanli WAF. Gizleme/prompt-injection'i kacirir."""
    t0 = time.perf_counter()
    hits = waf_rules.scan_text(payload or "")
    latency = (time.perf_counter() - t0) * 1000
    score = min(1.0, sum(w for _, w in hits) / 10.0) if hits else 0.0
    return {"detected": bool(hits), "score": score, "latency_ms": latency,
            "technique": hits[0][0] if hits else "-", "stage": "Initial Access"}


def full_layered_detect(payload: str) -> dict:
    """Temel 2: tam katmanli sistem - aciklanabilir tespit (imza + kodlama
    cozme + regex davranis). Gizlenmis ve prompt-injection yuklerini de yakalar."""
    t0 = time.perf_counter()
    ex = explainer.explain_detection(payload or "")
    latency = (time.perf_counter() - t0) * 1000
    detected = bool(ex.get("attack_types"))
    return {"detected": detected, "score": ex.get("confidence", 0.0),
            "latency_ms": latency,
            "technique": (ex.get("mitre_technique") or {}).get("id", "-"),
            "stage": "Initial Access"}


def _respond(scenario_result: dict) -> dict:
    """Tespit edilen kotu senaryoya SOAR mudahalesi uygulanmis say (basari orani icin)."""
    applied = bool(scenario_result.get("detected") and scenario_result.get("truth"))
    return {"applied": applied}


def run(n_total=2000):
    n_mal = n_total // 2
    n_ben = n_total - n_mal
    scenarios = harness.make_scenarios(n_mal, n_ben)

    print("\n" + "=" * 74)
    print(f"  ARACHNE SENTINEL - BENCHMARK ({n_total} etiketli senaryo)")
    print("=" * 74)
    print(f"  {n_mal} kotu niyetli + {n_ben} mesru senaryo. Gercek tespit hatti calisir.")
    print("=" * 74 + "\n")

    reports = {}
    for label, detect_fn in (("Sadece-imza (WAF)", signature_only_detect),
                             ("Tam katmanli sistem", full_layered_detect)):
        t0 = time.time()
        bench = harness.run_benchmark(scenarios, detect_fn, respond_fn=_respond)
        elapsed = time.time() - t0
        rep = evaluation.evaluation_report(
            bench["results"], elapsed_sec=elapsed,
            responses=bench.get("responses"), event_count=n_total)
        reports[label] = rep
        c = rep["classification"]
        print(f"[{label}]")
        print(f"   Precision={c['precision']:.3f}  Recall={c['recall']:.3f}  "
              f"F1={c['f1']:.3f}  FPR={c['false_positive_rate']:.3f}  "
              f"FNR={c['false_negative_rate']:.3f}")
        print(f"   Detection Rate={c['detection_rate']:.3f}  "
              f"(TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']})")
        print(f"   MTTD={rep['timing']['mttd_ms']:.2f}ms  "
              f"P95={rep['timing']['p95_detection_latency_ms']:.2f}ms  "
              f"olay/sn={rep['throughput']['events_per_sec']:.0f}")
        print(f"   Not: {rep['grade']}  |  {rep['summary_tr']}\n")

    # Kiyaslama ozeti
    base = reports["Sadece-imza (WAF)"]["classification"]["f1"]
    full = reports["Tam katmanli sistem"]["classification"]["f1"]
    gain = full - base
    print("=" * 74)
    print(f"  KATMANLI SAVUNMANIN GETIRISI: F1 {base:.3f} -> {full:.3f} "
          f"(+{gain:.3f}) — imza-otesi katmanlarin OLCULMUS katkisi.")
    print("=" * 74)

    # Raporu panele sunmak icin kaydet
    out = {
        "n_total": n_total, "n_malicious": n_mal, "n_benign": n_ben,
        "generated_epoch": int(time.time()),
        "signature_only": reports["Sadece-imza (WAF)"],
        "full_system": reports["Tam katmanli sistem"],
        "f1_gain": round(gain, 4),
    }
    path = config.DATA_DIR / "benchmark_report.json"
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  Rapor kaydedildi: {path}")
    print("  Panelde 'Genel Bakis' -> metrikler bu rapordan okunur.\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Arachne Sentinel benchmark")
    p.add_argument("--n", type=int, default=2000, help="toplam senaryo (varsayilan 2000)")
    args = p.parse_args()
    run(n_total=args.n)
