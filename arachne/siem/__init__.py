"""
Faz 32 - SIEM Normalizasyon & Zenginlestirme.

Bir honeypot ham olaylar uretir: farkli servisler (ssh, http, ftp...),
farkli yuk formatlari, tutarsiz alan adlari. Bu olaylar TEK BASINA
korelasyon kurmak icin uygun degildir - once ORTAK bir semaya
donusturulmeleri gerekir. SIEM (Security Information and Event Management)
dunyasinin ilk adimi budur: normalize et, sonra zenginlestir, sonra
korele et.

Bu paket o boru hattinin ingestion (alim) katmanidir:

    ham olay --> normalize_event --> enrich_event --> to_ecs --> SIEM
                 (yapisal kayit)    (etiket+kapsam)  (ECS semasi)

--- idea ---
Her olayi IP / alan adi / hash / kullanici / cihaz / surec / zaman
etrafinda yapisal bir kayda cevirir. Varlik (entity) cikarimi icin mevcut
IOC cikaricisini (arachne/reverse/ioc_extractor.py) yeniden kullanir -
tekerlegi yeniden icat etmez.

--- Gercek dunya eslesmesi ---
Alan adlandirmasi Elastic Common Schema (ECS) ile hizalanmistir
(source.ip, destination.port, event.category, related.*). Bu, kaydin
gercek SIEM'lere (Elastic, Splunk, Wazuh) tasinabilir olmasini saglar.

--- DURUSTLUK NOTU ---
Bu tam bir SIEM DEGILDIR (kalici depolama, dagitik arama, uzun donem
korelasyon motoru burada yoktur). Yalnizca normalizasyon ve zenginlestirme
katmanini modelliyoruz - "SIEM kurduk" degil, "SIEM-uyumlu kayit uretiyoruz".

--- Savunma amacli etik not ---
Sadece kendi honeypot'umuza dusen olaylari isler; disari sorgu/trafik
uretmez. Amac gorunurlugu artirmaktir.
"""

from .normalizer import (
    enrich_event,
    normalize_batch,
    normalize_event,
    to_ecs,
)

__all__ = [
    "normalize_event",
    "enrich_event",
    "to_ecs",
    "normalize_batch",
]
