#!/usr/bin/env python3
"""
Arachne Sentinel - CLI giris noktasi.

Kullanim:
  python main.py run          # Honeypot servislerini baslatir (Ctrl+C ile durdurun)
  python main.py dashboard    # Canli web panelini baslatir (http://127.0.0.1:5000)
  python main.py report       # Statik HTML rapor uretir (data/report.html)

Sadece izole/lab ortaminda calistirin - bkz. docs/ETHICS_AND_LEGAL.md
"""
import argparse
import asyncio
import logging

from arachne import storage
from arachne.honeypot.listeners import start_all_services
from arachne.reporting.dashboard import run_dashboard
from arachne.reporting.report_generator import generate_html_report


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Arachne Sentinel")
    parser.add_argument("command", choices=["run", "dashboard", "report"])
    args = parser.parse_args()

    storage.init_db()

    if args.command == "run":
        try:
            asyncio.run(start_all_services())
        except KeyboardInterrupt:
            print("\nDurduruldu.")
    elif args.command == "dashboard":
        run_dashboard()
    elif args.command == "report":
        path = generate_html_report()
        print(f"Rapor olusturuldu: {path}")


if __name__ == "__main__":
    main()
