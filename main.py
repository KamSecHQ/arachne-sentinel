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

  python main.py mtd-demo           # Moving Target Defense demosu (Faz 4):
                                     #   - honeypot banner'lari periyodik rotasyon
                                     #   - gercekten port degistiren "hayalet admin" servisi
                                     #   - lab-ici sahte DNS yanitlayicisi (udp 5300)

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
        choices=["run", "dashboard", "app", "report", "waf-demo", "scan", "train-ml", "mtd-demo",
                 "soar-demo", "mesh-demo", "analyze", "ai-report", "stix-export",
                 "full-demo"],
    )
    parser.add_argument("--unprotected", action="store_true",
                         help="waf-demo icin: WAF'siz calistir (karsilastirma)")
    parser.add_argument("--no-intro", action="store_true",
                         help="dashboard icin: sinematik acilis dizisini atla")
    parser.add_argument("--no-open", action="store_true",
                         help="dashboard icin: tarayiciyi otomatik acma")
    parser.add_argument("--host", default="127.0.0.1", help="scan icin: hedef host")
    parser.add_argument("--port", type=int, default=None,
                         help="dinlenecek port. waf-demo icin varsayilan 8090, "
                              "dashboard icin 5000. macOS'ta port 5000 AirPlay "
                              "Receiver ile cakisirsa: --port 5001")
    parser.add_argument("--hop-interval", type=int, default=45,
                         help="mtd-demo icin: hayalet admin panelinin kac saniyede bir "
                              "port degistirecegi (varsayilan 45)")
    parser.add_argument("--rotate-interval", type=int, default=90,
                         help="mtd-demo icin: honeypot banner'larinin kac saniyede bir "
                              "rotasyona ugrayacagi (varsayilan 90)")
    parser.add_argument("--dns-port", type=int, default=5300,
                         help="mtd-demo icin: hayalet DNS yanitlayicisinin dinleyecegi "
                              "yerel UDP portu (varsayilan 5300, GERCEK port 53 DEGIL)")
    parser.add_argument("--payload", default=None,
                         help="analyze icin: tersine muhendislik yapilacak saldiri yuku")
    parser.add_argument("--collector", default="http://127.0.0.1:5000/mesh/ingest",
                         help="mesh-demo icin: merkezi toplayici adresi")
    parser.add_argument("--sensors", type=int, default=3,
                         help="mesh-demo icin: simule edilecek sensor sayisi")
    parser.add_argument("--output", default=None, help="cikti dosyasi yolu")
    args = parser.parse_args()

    storage.init_db()

    if args.command == "run":
        try:
            asyncio.run(start_all_services())
        except KeyboardInterrupt:
            print("\nDurduruldu.")

    elif args.command == "dashboard":
        # macOS NOTU: port 5000 varsayilan olarak AirPlay Receiver tarafindan
        # kullanilir. Panel calismadiginda o servis isteklere 403 Forbidden
        # doner - bu, "sunucu kapali" hatasi gibi gorunmedigi icin kafa
        # karistiricidir. Cakisma yasarsaniz: --port 5001
        run_dashboard(port=args.port or 5000,
                      cinematic=not args.no_intro,
                      open_browser=not args.no_open)

    elif args.command == "app":
        # Native masaustu komuta merkezi penceresi (PyWebView) - tarayici degil.
        from arachne.reporting.desktop_app import run_app
        run_app(port=args.port or 5001, cinematic_terminal=not args.no_intro)

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

    elif args.command == "mtd-demo":
        from arachne.mtd import dns_ghost
        from arachne.mtd.identity_rotator import IdentityRotator
        from arachne.mtd.port_hopper import PortHopper

        rotator = IdentityRotator(rotate_interval_seconds=args.rotate_interval)
        hopper = PortHopper(hop_interval_seconds=args.hop_interval)

        print(
            "Faz 4 - Moving Target Defense demosu baslatiliyor:\n"
            f"  - honeypot servisleri (Faz 1) banner'lari her {args.rotate_interval}sn'de rotasyona ugrayacak\n"
            f"  - hayalet admin paneli her {args.hop_interval}sn'de port degistirecek "
            f"(havuz: {PortHopper().port_pool})\n"
            f"  - hayalet DNS yanitlayicisi udp 127.0.0.1:{args.dns_port} adresinde "
            f"(GERCEK sistem DNS'i DEGIL - sadece lab testi icin)\n"
            "Canli panelde (python main.py dashboard) 'Faz 4' bolumunden takip edebilirsin.\n"
        )

        async def _run_all():
            await asyncio.gather(
                start_all_services(rotator=rotator),
                hopper.run_forever(),
                dns_ghost.run_forever(port=args.dns_port),
            )

        try:
            asyncio.run(_run_all())
        except KeyboardInterrupt:
            print("\nDurduruldu.")

    elif args.command == "soar-demo":
        # Faz 7: honeypot + otonom mudahale birlikte
        from arachne.soar.playbooks import PLAYBOOKS

        print(
            "Faz 7 - SOAR otonom savunma demosu baslatiliyor:\n"
            f"  - {len(PLAYBOOKS)} playbook yuklendi\n"
            "  - alarm uretildiginde otomatik mudahale calisacak\n"
            "  - engellenen IP'lerin baglantilari GERCEKTEN reddedilecek\n"
            "  - geri alinamaz/yikici eylemler insan onayina yukseltilecek\n"
            "\nKorunan adresler (engellenemez): loopback ve ozel ag araliklari.\n"
            "Senaryo trafigi icin RFC 5737 adreslerini kullanin (203.0.113.x).\n"
            "Canli panelde 'Faz 7 - SOAR' bolumunden takip edebilirsin.\n"
        )
        try:
            asyncio.run(start_all_services(soar_enabled=True))
        except KeyboardInterrupt:
            print("\nDurduruldu.")

    elif args.command == "mesh-demo":
        from scripts.demo_mesh import run_mesh_demo
        run_mesh_demo(collector_url=args.collector, sensor_count=args.sensors)

    elif args.command == "analyze":
        from arachne.ai.report_writer import analyze_attack

        payload = args.payload
        if not payload:
            print("Kullanim: python main.py analyze --payload \"' OR '1'='1\"")
            return

        result = analyze_attack(payload)
        tech = result["technical_analysis"]
        opinion = result["analyst_opinion"]
        deob = tech["deobfuscation"]

        print("\n" + "=" * 68)
        print("  ARACHNE SENTINEL - SALDIRI TERSINE MUHENDISLIK RAPORU")
        print("=" * 68)
        print(f"\nTehdit skoru : {tech['threat_score']}/100  ({tech['verdict'].upper()})")
        print(f"Saldiri turu : {', '.join(tech['attack_classes']) or 'imza eslesmedi'}")
        if tech["hidden_attack_classes"]:
            print(f"  ! GIZLENMIS : {', '.join(tech['hidden_attack_classes'])}")
        print(f"Kill chain   : {tech['kill_chain']['phase_tr']} "
              f"({tech['kill_chain']['stage_index']}/{tech['kill_chain']['total_stages']}, "
              f"%{tech['kill_chain']['progress_pct']})")

        if deob["was_obfuscated"]:
            print(f"\nKODLAMA COZUMU ({deob['layers']} katman): {deob['method_chain']}")
            for i, step in enumerate(deob["steps"], 1):
                print(f"  {i}. {step['method']:<16} -> {step['after'][:60]}")
            print(f"  Cozulmus: {deob['decoded'][:120]}")

        if tech["tools"]:
            print("\nARAC PARMAK IZI:")
            for tool in tech["tools"]:
                print(f"  {tool['tool']:<14} guven %{tool['confidence']:<4} "
                      f"({tool['category']})")
                for evidence in tool["evidence"]:
                    print(f"     - {evidence}")

        if tech["attck_techniques"]:
            print("\nMITRE ATT&CK ESLEMESI:")
            for t in tech["attck_techniques"]:
                print(f"  {t['id']:<12} {t['name']}  [{t['tactic']}]")

        iocs = {k: v for k, v in tech["iocs"].items() if v}
        if iocs:
            print("\nCIKARILAN IOC'LER:")
            for key, values in iocs.items():
                print(f"  {key:<18} {', '.join(str(v)[:50] for v in values[:4])}")

        if result["sanitization"]["injection_attempt"]:
            print("\n  !! PROMPT ENJEKSIYONU DENEMESI TESPIT EDILDI !!")
            print(f"  {result['sanitization']['injection_assessment_tr']}")
            for ind in result["sanitization"]["injection_indicators"]:
                print(f"     - {ind['description']}: {ind['matched_text']}")
            print("  Datamarking savunmasi sayesinde talimat olarak DEGIL, kanit "
                  "olarak islendi.")

        print(f"\nANALIST YORUMU ({opinion['_source']}):")
        print(f"  {opinion['summary']}")
        print(f"\n  Saldirganin amaci: {opinion.get('attacker_intent', '-')}")
        print(f"  Onerilen odak    : {opinion.get('recommended_focus', '-')}")
        print("\n" + "=" * 68 + "\n")

    elif args.command == "ai-report":
        from arachne.ai.report_writer import generate_ai_report
        path = generate_ai_report(output_path=args.output or "data/ai_report.md")
        print(f"AI analist raporu olusturuldu: {path}")

    elif args.command == "stix-export":
        import json
        from arachne.ai.report_writer import situation_report
        from arachne.intel import stix_export

        data = situation_report()
        bundle = stix_export.build_stix_bundle(data["profiles"], data["campaigns"])
        stats = stix_export.bundle_stats(bundle)
        out_path = args.output or "data/stix_bundle.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)
        print(f"STIX 2.1 bundle olusturuldu: {out_path}")
        print(f"  {stats['total_objects']} nesne "
              f"({stats['indicators']} indicator, {stats['groupings']} grouping)")
        print("  Bu dosya MISP/OpenCTI gibi tehdit istihbarati platformlarina "
              "dogrudan aktarilabilir.")

    elif args.command == "full-demo":
        # Tum katmanlari tek komutta ayaga kaldirir - juri sunumu icin
        from arachne.mtd import dns_ghost
        from arachne.mtd.identity_rotator import IdentityRotator
        from arachne.mtd.port_hopper import PortHopper

        rotator = IdentityRotator(rotate_interval_seconds=args.rotate_interval)
        hopper = PortHopper(hop_interval_seconds=args.hop_interval)

        # Faz 12: honeytoken tuzaklari yerlestir (honeypot yollarinda izlenir)
        from arachne.active_defense.honeytokens import HoneytokenVault
        planted = HoneytokenVault().mint_set(context="full-demo")

        print(
            "\n" + "=" * 68 + "\n"
            "  ARACHNE SENTINEL - TAM SISTEM DEMOSU (Faz 1-20)\n"
            + "=" * 68 + "\n"
            "  Faz 1-3  Honeypot + WAF + ML + Native ARM64 imza cekirdegi\n"
            f"  Faz 4    MTD: banner {args.rotate_interval}sn, port {args.hop_interval}sn, DNS udp:{args.dns_port}\n"
            "  Faz 5    Tersine muhendislik: kodlama cozumu + entropi + polyglot\n"
            "  Faz 6    Istihbarat: profilleme + kampanya + STIX 2.1\n"
            "  Faz 7    SOAR: otonom mudahale AKTIF (gercek engelleme)\n"
            "  Faz 8    AI analist: yerel analist + prompt enjeksiyonu savunmasi\n"
            "  Faz 9    Sensor agi: /mesh/ingest uc noktasi panelde acik\n"
            "  Faz 10   Celik Kubbe komuta merkezi\n"
            "  Faz 11   Aktif savunma: tarpit + aldatma (kendi yuzeyimizde)\n"
            f"  Faz 12   Honeytoken: {len(planted)} tuzak yerlestirildi\n"
            "  Faz 13   Gelismis kodlama cozucu (ROT13/CHAR/gzip/entropi)\n"
            "  Faz 14   Imza kural motoru (YARA-benzeri)\n"
            "  Faz 15   Istatistiksel anomali/flood tespiti\n"
            "  Faz 16   Otomatik imza uretimi\n"
            "  Faz 17   Kurcalama-kaniti denetim zinciri\n"
            "  Faz 18   Cok faktorlu risk skorlama\n"
            "  Faz 19   Saldiri grafigi + kill chain modelleme\n"
            "  Faz 20   Yeniden tasarlanan komuta merkezi (SPA)\n"
            + "=" * 68 + "\n"
            "  Panel  : python main.py dashboard --port 5001\n"
            "           -> http://127.0.0.1:5001  (macOS'ta 5000 AirPlay ile cakisir)\n"
            "  Senaryo: python scripts/demo_global_attack.py\n"
            "  Sensor : python scripts/demo_mesh.py --collector http://127.0.0.1:5001/mesh/ingest\n"
            + "=" * 68 + "\n"
        )

        async def _run_full():
            await asyncio.gather(
                start_all_services(rotator=rotator, soar_enabled=True),
                hopper.run_forever(),
                dns_ghost.run_forever(port=args.dns_port),
            )

        try:
            asyncio.run(_run_full())
        except KeyboardInterrupt:
            print("\nDurduruldu.")


if __name__ == "__main__":
    main()
