"""
Kural tabanli tespit motoru.

Her kural fonksiyonu, bir IP'ye ait (zaten zaman penceresine gore
filtrelenmis) son olay listesini alir ve (triggered, reason, weight)
uclusu dondurur. Yeni bir tespit yontemi eklemek icin buraya yeni bir
fonksiyon eklemeniz ve ALL_RULES listesine dahil etmeniz yeterli -
scorer.py bunlari otomatik olarak toplar ve toplam skoru hesaplar.

Bu tasarimin bilincli tercihi: kurallar aciklanabilir (explainable) olsun
istedik. Kara kutu bir ML modeli yerine "neden alarm verdi" sorusuna net
cevap verebilen bir sistem, hem hata ayiklamasi hem de bir juri/mulakat
karsisinda savunulmasi cok daha kolay bir yaklasimdir. Faz 2'de buraya
etiketli veriyle egitilmis bir ML siniflandirici da eklenebilir (bkz.
docs/ROADMAP.md).
"""
from collections import Counter

from .. import config
from ..native import signature_engine

# Bilinen saldiri imzalari: kategori -> aranacak alt string'ler (kucuk harfe
# cevrilmis payload icinde aranir)
#
# GENISLETME NOTU (Faz 5 sirasinda bulundu): Ilk surumde SQL Injection icin
# yalnizca "' or '1'='1" varyanti vardi. Canli test sirasinda, klasik ve en
# yaygin kaliplardan biri olan TIRNAKSIZ `' OR 1=1--` yukunun hic
# yakalanmadigi goruldu. Bu gercek bir tespit acigiydi ve asagida
# genisletilerek kapatildi.
#
# Imza secim ilkesi: her imza, mesru trafikte pratikte GORULMEYECEK kadar
# ayirt edici olmali. "or 1=1" bu testi gecer; ornegin tek basina "select"
# gecmez (yanlis pozitif ureticek kadar yaygin) - o yuzden listede yok.
ATTACK_SIGNATURES = {
    "SQL Injection": [
        "' or '1'='1", "or 1=1", "or 1 = 1", "' or 1", '" or 1',
        "union select", "union all select", "; drop table", "xp_cmdshell",
        "sleep(", "benchmark(", "waitfor delay", "pg_sleep(",
        "information_schema", "admin'--", "' or true", "') or (",
    ],
    "XSS": [
        "<script>", "onerror=", "javascript:", "<img src=", "onload=",
        "onmouseover=", "<svg/", "<svg ", "document.cookie",
    ],
    "Command Injection": [
        "; cat /etc/passwd", "&& whoami", "| nc ", "$(", "`whoami`",
        "; ls -", "&& cat ", "| bash", "| sh ", "; wget ", "; curl ",
        "/bin/sh", "/bin/bash", "; id;", "&& id",
    ],
    "Path Traversal": [
        "../../../", "..\\..\\..\\", "/etc/passwd", "/etc/shadow",
        "..%2f", "%2e%2e%2f", "....//", "/proc/self/environ",
    ],
}


def rule_port_scan(events):
    """Ayni IP kisa surede birden fazla farkli porta baglanmayi denedi mi?"""
    connects = [e for e in events if e["event_type"] == "connect"]
    distinct_ports = {e["dest_port"] for e in connects}
    if len(distinct_ports) >= config.PORT_SCAN_DISTINCT_PORTS:
        return True, (
            f"Port tarama supesi: {len(distinct_ports)} farkli port kisa surede denendi"
        ), 30
    return False, None, 0


def rule_brute_force(events):
    """Ayni servise cok sayida tekrarli baglanti denemesi (brute-force izlenimi)."""
    connects = [e for e in events if e["event_type"] == "connect"]
    by_service = Counter(e["service"] for e in connects)
    for service, count in by_service.items():
        if count >= config.BRUTE_FORCE_ATTEMPTS:
            return True, (
                f"Olasi brute-force: '{service}' servisine {count} baglanti denemesi"
            ), 40
    return False, None, 0


def rule_known_signature(events):
    """Gonderilen veri (payload) icinde bilinen bir saldiri imzasi var mi?

    Asil eslesme mantigi `native.signature_engine` uzerinden calisir: Apple
    Silicon Mac'te elle yazilmis ARM64 assembly (bkz.
    arachne/native/arm64/fast_scan.s) ile, diger her platformda ayni sonucu
    ureten bir Python yedegiyle. Hangi yolun aktif oldugu davranisi
    DEGISTIRMEZ - sadece calisma hizini etkiler (bkz. docs/ARCHITECTURE.md,
    scripts/benchmark_native_scan.py)."""
    for e in events:
        payload = (e.get("payload") or "").lower()
        if not payload:
            continue
        for attack_name, signatures in ATTACK_SIGNATURES.items():
            matched = signature_engine.contains_any(payload, signatures)
            if matched:
                return True, (
                    f"Bilinen saldiri imzasi tespit edildi: {attack_name} (icerik: '{matched[0]}')"
                ), 50
    return False, None, 0


def rule_multi_service_probe(events):
    """Ayni IP, birden fazla farkli sahte serviste deneme yapti mi (kesif davranisi)?"""
    services = {e["service"] for e in events if e["event_type"] == "connect"}
    if len(services) >= config.MULTI_SERVICE_COUNT:
        return True, (
            f"Coklu servis kesfi: {len(services)} farkli sahte serviste deneme "
            f"yapildi ({', '.join(sorted(services))})"
        ), 25
    return False, None, 0


def rule_repeated_offender(events, has_prior_alert):
    """Bu IP daha once de alarm olusturmus muydu?"""
    if has_prior_alert:
        return True, "Bu IP daha once de alarm olusturmustu (tekrarlayan saldirgan)", 20
    return False, None, 0


def rule_ml_classifier(events):
    """Payload'lari ML tabanli siniflandiriciya sorar (Faz 2). Kural setinin
    tam olarak eslesmedigi, hafif degistirilmis/obfuske edilmis saldiri
    varyasyonlarini yakalamak icin kural motoruna EK bir sinyal saglar."""
    from .ml_classifier import classify  # tembel import: sklearn'i sadece gerektiginde yukle

    for e in events:
        payload = e.get("payload") or ""
        if not payload.strip():
            continue
        is_malicious, confidence = classify(payload)
        if is_malicious and confidence >= 0.7:
            return True, (
                f"ML siniflandirici supheli isaretledi (guven: {confidence:.2f})"
            ), 35
    return False, None, 0


# scorer.py, IP'ye ozel gecmisi bilmesi gereken rule_repeated_offender haric
# tum kurallari otomatik olarak calistirir.
ALL_RULES = [rule_port_scan, rule_brute_force, rule_known_signature,
             rule_multi_service_probe, rule_ml_classifier]
