"""
Saldiri yuk kutuphanesi — YALNIZCA yerel lab hedefini test etmek icin.

Her yuk, kendi bilincli-zafiyetli lab uygulamamizin (arachne/waf/labtarget)
bir uc noktasini hedefler. Yukler, gercek dunyada baska bir sisteme karsi
"silah" degildir; test dizeleridir ve yalnizca kendi WAF/savunmamizin bunlari
yakalayip yakalamadigini olçmek icin uretilir. Komut enjeksiyonu tarafinda
lab hedefi gercek kabuk CALISTIRMAZ (sahte kabuk), bu yuzden zarar olusmaz.
"""
from __future__ import annotations

# Kategori -> (endpoint yolu, parametre adi, [temel yukler])
CATALOG = {
    "SQL Injection": ("/search", "name", [
        "' OR '1'='1",
        "' OR 1=1 --",
        "x' UNION SELECT id, secret FROM users --",
        "admin'; DROP TABLE users; --",
        "' OR SLEEP(3)-- -",
        "' OR 'a'='a",
    ]),
    "XSS": ("/comment", "text", [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<details open ontoggle=alert(1)>",
    ]),
    "Path Traversal": ("/file", "path", [
        "app/public/../../etc/passwd",
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "app/public/../../etc/shadow",
    ]),
    "Command Injection": ("/ping", "host", [
        "127.0.0.1; whoami",
        "127.0.0.1 && id",
        "127.0.0.1 | cat /etc/passwd",
        "$(uname)",
        "127.0.0.1`whoami`",
    ]),
    "SSTI": ("/render", "name", [
        "{{7*7}}",
        "{{config}}",
        "{{''.__class__.__mro__}}",
        "${7*7}",
    ]),
}

# Zararsiz trafik (yanlis pozitif olçumu icin) — endpoint, param, deger
BENIGN = [
    ("/search", "name", "emirhan"),
    ("/search", "name", "Ali Veli"),
    ("/comment", "text", "Merhaba, guzel proje!"),
    ("/comment", "text", "1 < 2 ve 3 > 2"),
    ("/file", "path", "app/public/welcome.txt"),
    ("/ping", "host", "127.0.0.1"),
    ("/render", "name", "dunya"),
]


def base_attacks():
    """(kategori, endpoint, param, payload) uçlulerini uretir."""
    for cat, (path, param, loads) in CATALOG.items():
        for pl in loads:
            yield cat, path, param, pl


def categories():
    return list(CATALOG.keys())
