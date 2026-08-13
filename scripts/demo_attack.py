#!/usr/bin/env python3
"""
Demo/test scripti: Arachne Sentinel'i kendi kendine test etmek icin sahte
"saldirgan" davranisi uretir. GERCEK BIR SALDIRI ARACI DEGILDIR - sadece
localhost'taki kendi honeypot servislerinize baglanir, bunu kim gormesin
diye dahi tasarlanmamistir; amac tamamen sistemin dogru calistigini
gostermektir.

Kullanim:
  1) Bir terminalde:  python main.py run
  2) Baska bir terminalde: python scripts/demo_attack.py
  3) Sonra: python main.py report   (data/report.html dosyasini acin)
     veya:  python main.py dashboard  (http://127.0.0.1:5000)
"""
import socket
import time

HOST = "127.0.0.1"


def probe(port, payload=b"", label=""):
    try:
        with socket.create_connection((HOST, port), timeout=3) as s:
            if payload:
                s.sendall(payload)
            time.sleep(0.2)
            try:
                s.recv(1024)
            except socket.timeout:
                pass
        print(f"  [ok] {label} (port {port})")
    except OSError as e:
        print(f"  [!!] {label} (port {port}) baglanti kurulamadi: {e}")
        print("       -> Once 'python main.py run' komutunu calistirdiginizdan emin olun.")


def main():
    print("1) Port tarama davranisi simule ediliyor (ssh, ftp, mysql, http-admin)...")
    for port in (2222, 2121, 3307, 8081):
        probe(port, label="port taramasi")

    print("2) Brute-force davranisi simule ediliyor (ssh'a 6 kez baglanma)...")
    for i in range(6):
        probe(2222, label=f"brute-force denemesi #{i + 1}")

    print("3) Bilinen bir SQL Injection imzasi gonderiliyor (http-admin)...")
    payload = b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\nuser=admin' OR '1'='1&pass=x"
    probe(8081, payload=payload, label="SQLi denemesi")

    print("\nBitti. Simdi 'python main.py report' calistirip data/report.html dosyasini")
    print("acabilir ya da 'python main.py dashboard' ile canli paneli gorebilirsiniz.")


if __name__ == "__main__":
    main()
