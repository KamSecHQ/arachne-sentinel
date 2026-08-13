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

# Bilinen saldiri imzalari: kategori -> aranacak alt string'ler (kucuk harfe
# cevrilmis payload icinde aranir)
ATTACK_SIGNATURES = {
    "SQL Injection": ["' or '1'='1", "union select", "; drop table", "xp_cmdshell", "sleep("],
    "XSS": ["<script>", "onerror=", "javascript:"],
    "Command Injection": ["; cat /etc/passwd", "&& whoami", "| nc ", "$(", "`whoami`"],
    "Path Traversal": ["../../../", "..\\..\\..\\", "/etc/passwd"],
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
    """Gonderilen veri (payload) icinde bilinen bir saldiri imzasi var mi?"""
    for e in events:
        payload = (e.get("payload") or "").lower()
        if not payload:
            continue
        for attack_name, signatures in ATTACK_SIGNATURES.items():
            for sig in signatures:
                if sig in payload:
                    return True, (
                        f"Bilinen saldiri imzasi tespit edildi: {attack_name} (icerik: '{sig}')"
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


# scorer.py, IP'ye ozel gecmisi bilmesi gereken rule_repeated_offender haric
# tum kurallari otomatik olarak calistirir.
ALL_RULES = [rule_port_scan, rule_brute_force, rule_known_signature, rule_multi_service_probe]
