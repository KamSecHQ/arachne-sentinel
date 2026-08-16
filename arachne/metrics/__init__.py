"""
Faz 39 - Metrik ve Degerlendirme paketi.

Tespit sisteminin gercek kalitesini, etiketli (ground-truth bilinen)
benchmark verisi uzerinden olcer: karisiklik matrisi, precision/recall/F1
ve SOC metrikleri (MTTD, MTTR, P95 gecikme, olay/sn).
"""

from .evaluation import (
    confusion_matrix,
    classification_metrics,
    percentile,
    timing_metrics,
    throughput,
    response_success_rate,
    evaluation_report,
)

__all__ = [
    "confusion_matrix",
    "classification_metrics",
    "percentile",
    "timing_metrics",
    "throughput",
    "response_success_rate",
    "evaluation_report",
]
