"""
Faz 8 - Guvenli Yapay Zeka Analist Katmani.

Sisteme hakim olan, istenen raporu ureten bir analist katmani; ama
guvenlik acisindan KARANTINA altinda.

--- Mimarinin ozeti ---
    yerel analist (analyst.py)      : HER ZAMAN calisir, ag gerektirmez
    karantina LLM (llm_backend.py)  : opsiyonel, sadece zenginlestirir
    sterilizasyon (sanitizer.py)    : datamarking ile prompt enjeksiyonu savunmasi
    sema (schema.py)                : kati cikti dogrulamasi + XSS onleme

--- Tasiyici ilke ---
**Yapay zeka ZENGINLESTIRIR, KARAR VERMEZ.**
Engelleme/serbest birakma kararlari tamamen deterministik kural
motorundadir (Faz 1-2) ve SOAR (Faz 7) yalnizca o kararlara tepki verir.
Basarili bir prompt enjeksiyonunun en kotu sonucu, bir rapor alanindaki
yaniltici bir cumledir.

--- Ele alinan OWASP LLM Top 10 riskleri ---
    LLM01 Prompt Injection      -> datamarking (Spotlighting) + rol kisitlama
    LLM05 Improper Output       -> kati sema + enum + HTML kacislama
    LLM06 Excessive Agency      -> modelin arac/DB/ag yetkisi YOK
    LLM07 System Prompt Leakage -> sizdirma denemesi tespit edilip raporlanir
    LLM10 Unbounded Consumption -> onbellek + saatlik kota + uzunluk siniri
"""

from . import analyst, llm_backend, sanitizer, schema
from .report_writer import (
    analyze_attack,
    generate_ai_report,
    situation_report,
)

__all__ = [
    "analyst",
    "llm_backend",
    "sanitizer",
    "schema",
    "analyze_attack",
    "generate_ai_report",
    "situation_report",
]
