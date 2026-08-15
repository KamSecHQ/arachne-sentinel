#!/usr/bin/env python3
"""
Faz 9 - Dagitik sensor agi demosu.

Birden fazla sensor dugumunu simule eder; her biri kendi "agindan" gozlem
raporlar ve merkezi toplayiciya HMAC ile imzali gonderir.

ONEMLI - DURUSTLUK NOTU:
Bu script SIMULE EDILMIS sensorler calistirir. Gercek bir dagitik kurulumda
her sensor ayri bir makinede/agda calisir ve gercek trafik gorur. Burada
amac, mesh protokolunun (imzalama, dogrulama, tekrar koruma, toplama)
gercekten calistigini gostermektir - uretilen olaylar senaryo verisidir ve
RFC 5737 dokumantasyon adres araliklarini kullanir (bu adresler gercek bir
cihaza ait OLAMAZ, tam da ornek/test icin ayrilmistir).

Ayrica bir de KASITLI SAHTE sensor calistirilir: paylasilan siri bilmeyen
bir "saldirgan sensor" rapor gondermeye calisir ve REDDEDILIR. Bu, kimlik
dogrulamanin gercekten calistigini kanitlar.

Sadece izole/lab ortaminda kullanin - bkz. docs/ETHICS_AND_LEGAL.md
"""
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne.mesh import crypto  # noqa: E402
from arachne.mesh.sensor import Sensor  # noqa: E402

# Senaryo sensorleri: farkli aglara yerlestirilmis gibi
SENSOR_PROFILES = [
    ("kenar-dmz-01", "DMZ / dis ag kenari", ["203.0.113.%d" % i for i in range(10, 30)]),
    ("ic-ag-02", "Ic ag / kullanici segmenti", ["198.51.100.%d" % i for i in range(5, 25)]),
    ("bulut-03", "Bulut / uygulama katmani", ["192.0.2.%d" % i for i in range(40, 60)]),
    ("sube-04", "Uzak sube ofisi", ["203.0.113.%d" % i for i in range(80, 99)]),
    ("dc-05", "Veri merkezi", ["198.51.100.%d" % i for i in range(120, 140)]),
]

SERVICES = ["ssh", "ftp", "mysql", "http-admin"]

ATTACK_PAYLOADS = [
    "id=1' OR '1'='1' --",
    "GET /admin HTTP/1.1\r\nUser-Agent: gobuster/3.6",
    "user=admin&pass=123456",
    "cmd=; cat /etc/passwd",
    "GET /?id=1 HTTP/1.1\r\nUser-Agent: sqlmap/1.7.2#stable (http://sqlmap.org)",
    "<script>alert(document.cookie)</script>",
    "../../../etc/passwd",
    None,  # yuksuz baglanti (saf port yoklamasi)
]


def run_mesh_demo(collector_url="http://127.0.0.1:5000/mesh/ingest",
                  sensor_count=3, rounds=4, delay=2.0):
    """Sensor agi simulasyonunu calistirir."""
    sensor_count = max(1, min(sensor_count, len(SENSOR_PROFILES)))
    profiles = SENSOR_PROFILES[:sensor_count]

    print("\n" + "=" * 68)
    print("  FAZ 9 - DAGITIK SENSOR AGI DEMOSU")
    print("=" * 68)
    print(f"  Toplayici : {collector_url}")
    print(f"  Sensor    : {sensor_count} dugum")
    print(f"  Imzalama  : HMAC-SHA256 + nonce + zaman damgasi")
    if crypto.using_default_secret():
        print("  ! UYARI   : varsayilan lab sirri kullaniliyor.")
        print("              Uretimde ARACHNE_MESH_SECRET ortam degiskenini ayarlayin.")
    print("=" * 68 + "\n")

    sensors = [Sensor(sid, collector_url=collector_url, location=loc)
               for sid, loc, _ in profiles]

    rng = random.Random(42)   # tekrarlanabilir demo

    for round_no in range(1, rounds + 1):
        print(f"[Tur {round_no}/{rounds}] Sensorler gozlem raporluyor...")

        for sensor, (sid, loc, ip_pool) in zip(sensors, profiles):
            count = rng.randint(3, 7)
            for _ in range(count):
                sensor.observe(
                    source_ip=rng.choice(ip_pool),
                    service=rng.choice(SERVICES),
                    event_type=rng.choice(["connect", "data", "data"]),
                    source_port=rng.randint(30000, 60000),
                    dest_port=rng.choice([2222, 2121, 3307, 8081]),
                    payload=rng.choice(ATTACK_PAYLOADS),
                )

            result = sensor.flush()
            if result["ok"]:
                print(f"   [ok]  {sid:<14} ({loc}) -> {result['sent']} olay kabul edildi")
            else:
                error = str(result.get("error", ""))
                print(f"   [HATA] {sid:<14} gonderilemedi: {error[:60]}")
                if "403" in error:
                    # macOS'ta port 5000'i AirPlay Receiver tutar; panel
                    # calismiyorsa istekler ona gider ve 403 doner. Bu,
                    # "sunucu kapali" hatasi gibi gorunmedigi icin
                    # kafa karistiricidir - o yuzden acikca soyluyoruz.
                    print("          403 Forbidden: bu portta BASKA bir servis var.")
                    print("          macOS'ta port 5000'i AirPlay Receiver kullanir.")
                    print("          Cozum: paneli baska portta baslatin ->")
                    print("            python main.py dashboard --port 5001")
                    print("            python scripts/demo_mesh.py \\")
                    print("              --collector http://127.0.0.1:5001/mesh/ingest")
                else:
                    print("          Panel calisiyor mu? (python main.py dashboard)")
                    print("          Ayri terminalde .venv aktive edilmis mi?")
                    print("            source .venv/bin/activate")

        if round_no < rounds:
            time.sleep(delay)

    # --- Kimlik dogrulama testi: sahte sensor ---
    print("\n[Guvenlik testi] Paylasilan siri BILMEYEN sahte bir sensor deneniyor...")
    rogue = Sensor("SAHTE-SENSOR", collector_url=collector_url,
                   location="saldirgan", secret="yanlis-sir-12345")
    rogue.observe("203.0.113.250", "ssh", "connect", dest_port=2222,
                  payload="sahte veri")
    rogue_result = rogue.flush()
    if not rogue_result["ok"]:
        print("   [BEKLENEN] Sahte sensor REDDEDILDI - kimlik dogrulama calisiyor.")
        print("   Dogrulanmamis raporlari kabul eden bir SOAR sistemi, saldirganin")
        print("   elinde silaha donusurdu (sahte raporlarla masum IP'leri engelletebilir).")
    else:
        print("   [!!! BEKLENMEYEN] Sahte sensor kabul edildi - guvenlik acigi!")

    print("\n" + "=" * 68)
    print("  Demo tamamlandi. Canli panelde 'Faz 9 - Dagitik Sensor Agi'")
    print("  bolumunden sensorleri ve reddedilen raporu gorebilirsiniz.")
    print("=" * 68 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Arachne Sentinel - mesh demosu")
    parser.add_argument("--collector", default="http://127.0.0.1:5000/mesh/ingest")
    parser.add_argument("--sensors", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=4)
    args = parser.parse_args()

    run_mesh_demo(collector_url=args.collector, sensor_count=args.sensors,
                  rounds=args.rounds)
