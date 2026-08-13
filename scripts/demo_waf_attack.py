#!/usr/bin/env python3
"""
WAF demo saldiri scripti: calisan waf-demo uygulamasina hem normal hem
kotu niyetli istekler gonderip WAF'in farki nasil ayirt ettigini gosterir.

Kullanim:
  1) Bir terminalde:  python main.py waf-demo
  2) Baska bir terminalde: python scripts/demo_waf_attack.py
"""
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8090"


def hit(path, label):
    url = BASE + path
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            print(f"  [{resp.status}] {label}")
    except urllib.error.HTTPError as e:
        print(f"  [{e.code}] {label}  <- WAF tarafindan engellendi" if e.code == 403 else f"  [{e.code}] {label}")
    except urllib.error.URLError as e:
        print(f"  [!!] {label} - baglanti kurulamadi: {e}")
        print("       -> Once 'python main.py waf-demo' calistirdiginizdan emin olun.")


def main():
    print("1) Normal / zararsiz istekler gonderiliyor...")
    hit("/search?name=emirhan", "normal arama")
    hit("/comment?text=merhaba+dunya", "normal yorum")

    print("2) Kotu niyetli istekler gonderiliyor...")
    hit("/search?name=" + urllib.request.quote("' OR '1'='1"), "SQL injection denemesi")
    hit("/comment?text=" + urllib.request.quote("<script>alert(1)</script>"), "XSS denemesi")
    hit("/search?name=" + urllib.request.quote("x'; DROP TABLE users;--"), "SQLi (DROP TABLE) denemesi")

    print("\n3) Rate-limit testi: kisa surede cok sayida istek gonderiliyor...")
    for i in range(25):
        hit("/", f"istek #{i + 1}")

    print("\nBitti. 'python main.py waf-demo --unprotected' ile ayni saldirilari")
    print("WAF olmadan da deneyip farki gorebilirsin (SQLi'nin gercekten calistigini,")
    print("XSS'in dogrudan sayfaya yazildigini goreceksin).")


if __name__ == "__main__":
    main()
