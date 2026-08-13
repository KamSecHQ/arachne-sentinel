#!/usr/bin/env python3
"""
Arachne Sentinel - CLI giris noktasi.

Kullanim:
  python main.py run                # Honeypot servislerini baslatir (Faz 1)
  python main.py dashboard          # Canli honeypot panelini baslatir
  python main.py report             # Statik honeypot HTML raporu uretir

  python main.py waf-demo           # WAF-korumali demo web uygulamasini baslatir (Faz 2)
  python main.py waf-demo --unprotected  # Ayni uygulamayi WAF'siz baslatir (karsilastirma icin)

  python main.py scan --host 127.0.0.1   # Otonom port/zafiyet taramasi yapar (Faz 2)

  python main.py train-ml           # ML siniflandiricisini yeniden egitir (Faz 2)

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
    parser.add_argument(
        "command",
        choices=["run", "dashboard", "report", "waf-demo", "scan", "train-ml"],
    )
    parser.add_argument("--unprotected", action="store_true",
                         help="waf-demo icin: WAF'siz calistir (karsilastirma)")
    parser.add_argument("--host", default="127.0.0.1", help="scan icin: hedef host")
    parser.add_argument("--port", type=int, default=None,
                         help="waf-demo icin: dinlenecek port (varsayilan 8090)")
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

    elif args.command == "waf-demo":
        from arachne.waf.demo_app import run as run_waf_demo
        run_waf_demo(protected=not args.unprotected, port=args.port or 8090)

    elif args.command == "scan":
        from arachne.scanner.vuln_scanner import scan_and_report
        findings = scan_and_report(args.host)
        if not findings:
            print(f"{args.host} uzerinde acik port bulunamadi.")
        else:
            print(f"{args.host} taramasi tamamlandi, {len(findings)} acik port bulundu:\n")
            for f in findings:
                print(f"  port {f['port']} ({f['service_guess']}) - [{f['severity']}] {f['finding']}")
                if f["banner"]:
                    print(f"    banner: {f['banner'][:80]}")

    elif args.command == "train-ml":
        from arachne import config
        from arachne.detection.ml_classifier import train_and_save
        train_and_save()
        print(f"ML modeli egitildi: {config.ML_MODEL_PATH}")


if __name__ == "__main__":
    main()
