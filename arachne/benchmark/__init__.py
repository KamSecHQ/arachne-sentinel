"""
Faz 40 - Benchmark Harness paketi.

Cok sayida ETIKETLI kontrollu senaryoyu (bilinen kotu + bilinen iyi) bir
tespit fonksiyonundan gecirir ve her biri icin
Saldiri -> Tespit -> Korelasyon -> Yanit -> Sonuc zincirini kaydeder.
Ciktisi dogrudan arachne.metrics.evaluation.evaluation_report tarafindan
tuketilebilir - boylece sistemin basarisi iddiayla degil, gercek benchmark
verisiyle kanitlanir.
"""

from .harness import (
    ATTACK_FAMILIES,
    BENIGN_TEMPLATES,
    make_scenarios,
    run_scenario,
    run_benchmark,
    signature_detect_adapter,
)

__all__ = [
    "ATTACK_FAMILIES",
    "BENIGN_TEMPLATES",
    "make_scenarios",
    "run_scenario",
    "run_benchmark",
    "signature_detect_adapter",
]
