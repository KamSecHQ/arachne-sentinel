#!/usr/bin/env python3
"""
Arachne Sentinel — Faz 115: CEKIRDEK YEMI SENARYOSU (Son Hat gercek sinyalle).

Ihlal Tatbikati (Shift+B) Son Hat'i ELLE devreye alir. Bu senaryo ise Son
Hat'in GERCEK bir sinyalle, kendi karar mantigiyla (`should_engage`) devreye
girdigini uctan uca gosterir - hicbir savunma mantigi atlanmaz ya da taklit
edilmez:

  1. Kesif       : saldirgan 4 sahte servise baglanir (port tarama + coklu servis)
  2. Brute-force : SSH'a tekrarli kimlik denemesi (gercek honeypot gibi
                   connect + data olaylari; Faz 1 kurali yakalar)
  3. Skorlama    : gercek kural motoru -> alarm; saldiri zinciri -> "Brute Force"
  4. SOAR        : gercek playbook secimi
  5. Aldatma     : yuksek skorlu saf brute-force -> "fake-success" (sahte
                   'giris basarili'). Saldirgan kubbeyi astigini sanar = CEKIRDEK YEMI
  6. Son Hat     : context_from_live() yem kaydini okur -> should_engage = True.
                   Panel aciksa /api/fortress bunu gorur ve Son Hat'i KENDILIGINDEN
                   devreye alir ("GERCEK SINYAL" etiketiyle, tatbikat degil).

--- DURUSTLUK / ETIK ---
* Tamamen savunma ve lab-ici. Hicbir dis sisteme paket gitmez; olaylar diger
  demo scriptleri gibi dogrudan yerel veritabanina yazilir.
* Kaynak adres RFC 5737 dokumantasyon araligindandir (203.0.113.0/24).
* Kalkan gercekte DELINMEZ: saldirgan sahte bir basari yanitini gercek sanar,
  gercek varliga ulasilmaz. Son Hat'i tetikleyen tam olarak bu aldanmadir.
  Yem kaydi 5 dakika gecerlidir; o sure boyunca Son Hat devrede kalir.

Kullanim:
  source .venv/bin/activate
  python main.py dashboard --port 5001      # 1. terminal: komuta merkezi
  python scripts/demo_core_breach.py        # 2. terminal: senaryo
  # Panel birkac saniye icinde Son Hat gorunumune kendiliginden gecer.
"""
import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne import config, storage  # noqa: E402
from arachne.active_defense.deception import DeceptionEngine  # noqa: E402
from arachne.detection.scorer import evaluate_ip  # noqa: E402
from arachne.lastline import LastLineFortress, context_from_live  # noqa: E402
from arachne.reverse.attack_analyzer import analyze_ip  # noqa: E402

ATTACKER_IP = "203.0.113.200"
PORTS = {"ssh": 2222, "ftp": 2121, "mysql": 3307, "http-admin": 8081}
# Sozluk saldirisi (yaygin varsayilan kimlikler). Bilerek SQLi / path
# traversal icermez: aldatma motoru o siniflara 'fake-data' ile yanit verir,
# cekirdek yemi yalnizca saf brute-force'ta ('fake-success') acilir.
CREDENTIALS = ["root:toor", "root:123456", "admin:admin", "root:password",
               "ubuntu:ubuntu", "admin:letmein", "pi:raspberry", "root:root"]


class _TerminalFortress(LastLineFortress):
    """Terminal onizlemesi icin ayri kale ornegi. Musteri webhook'unu ve Faz 116
    yaptirimlarini panel surecindeki kale uygular; burada ikinci kez UYGULANMAZ."""

    def _notify_engagement(self, ctx):
        pass


def run_core_breach(db_path=None, soar_enabled=True, speed=1.0, verbose=True):
    """Senaryoyu calistirir ve her asamanin GERCEK sonucunu dondurur."""
    say = print if verbose else (lambda *a, **k: None)
    rng = random.Random(115)
    storage.init_db(db_path=db_path)

    def pause(seconds):
        if speed > 0:
            time.sleep(seconds / speed)

    def emit(service, event_type, payload=None):
        storage.log_event(ATTACKER_IP, service, event_type,
                          source_port=rng.randint(30000, 60000),
                          dest_port=PORTS[service], payload=payload,
                          db_path=db_path)

    say("=" * 66)
    say("  FAZ 115 — CEKIRDEK YEMI SENARYOSU (Son Hat gercek sinyalle)")
    say("=" * 66)
    say(f"  Saldirgan: {ATTACKER_IP} (RFC 5737 test adresi, lab-ici)")

    say("\n[1/6] Kesif: 4 sahte servise baglanti")
    for service, port in PORTS.items():
        emit(service, "connect")
        say(f"      {service:<10} :{port}")
        pause(0.15)

    say(f"\n[2/6] SSH brute-force: {len(CREDENTIALS)} kimlik denemesi")
    for cred in CREDENTIALS:
        emit("ssh", "connect")
        emit("ssh", "data", cred)
        say(f"      ssh  {cred}")
        pause(0.12)

    result = evaluate_ip(ATTACKER_IP, db_path=db_path)
    events = storage.get_recent_events(source_ip=ATTACKER_IP,
                                       since_seconds=config.DEFAULT_LOOKBACK_SECONDS,
                                       db_path=db_path)
    classes = analyze_ip(ATTACKER_IP, events)["attack_classes"]
    say(f"\n[3/6] Skor: {result['score']} ({result['severity']}) "
        f"alarm={'EVET' if result['triggered_alert'] else 'hayir'}")
    for reason in result["reasons"]:
        say(f"      - {reason}")
    say(f"      saldiri siniflari: {', '.join(classes) or 'yok'}")

    soar_summary = None
    if soar_enabled and result["triggered_alert"]:
        from arachne.soar.engine import respond_to_alert
        response = respond_to_alert(ATTACKER_IP, result["score"], result["severity"],
                                    attack_classes=classes, db_path=db_path)
        soar_summary = response.get("summary_tr")
    say(f"\n[4/6] SOAR: {soar_summary or ('kapali' if not soar_enabled else 'eslesen playbook yok')}")

    deception = DeceptionEngine(db_path=db_path).apply(ATTACKER_IP, result["score"], classes)
    decision = deception["decision"]
    say(f"\n[5/6] Aldatma karari: {decision['action']} - {decision['reason']}")
    if deception["core_vault_touched"]:
        say("      Saldirgan sahte 'giris basarili' yanitini aldi -> CEKIRDEK YEMI yutuldu")

    ctx = context_from_live(db_path=db_path)
    engage, reason = LastLineFortress.should_engage(ctx)
    say(f"\n[6/6] Son Hat karari: {'DEVREYE GIR' if engage else 'beklemede'} ({reason})")

    fortress_status = None
    if engage:
        fortress_status = _TerminalFortress().engage(ctx)
        if verbose:
            _print_fortress(fortress_status)
        say("\n  Panel aciksa (python main.py dashboard --port 5001) birkac saniye")
        say("  icinde Son Hat gorunumune KENDILIGINDEN gecer - 'GERCEK SINYAL'.")
        say("  Faz 116 yaptirimlarini (SOAR engeli + aldatma karantinasi + hizli")
        say("  port sicramasi) panel sureci uygular; bu onizleme uygulamaz.")
    else:
        say("  Esik asilmadi; Son Hat beklemede kaldi (bu da gercek bir sonuctur).")

    return {
        "attacker_ip": ATTACKER_IP,
        "score": result["score"],
        "triggered_alert": result["triggered_alert"],
        "attack_classes": classes,
        "soar_summary": soar_summary,
        "deception_action": decision["action"],
        "core_vault_touched": deception["core_vault_touched"],
        "should_engage": engage,
        "engage_reason": reason,
        "fortress": fortress_status,
    }


def _print_fortress(st):
    summary = st["summary"]
    print("\n" + "-" * 66)
    print("  SON HAT — 50 katman (terminal onizlemesi, gercek motor)")
    print("-" * 66)
    for layer in st["layers"]:
        mark = "MUHURLU" if layer["engaged"] else "hazir  "
        print(f"  {layer['id']} {layer['name']:<30} [{layer['tier']:<9}] {mark} "
              f"{layer['action'][:44]}")
    print("-" * 66)
    print(f"  Muhurlu katman : {summary['sealed_layers']} / {summary['total_layers']}")
    print(f"  Tepki suresi   : {st['reaction_ms']:.1f} ms (hedef < 100 ms)")
    print(f"  Butunluk koku  : 0x{st['integrity_root']}")
    print(f"  Kilitleme olas.: {summary['attacker_lock_probability']} (model, garanti degil)")
    print(f"  Gercek varliga ulasildi mi: {'EVET' if summary['reached_real_asset'] else 'HAYIR'}")


def main():
    parser = argparse.ArgumentParser(description="Faz 115 cekirdek yemi senaryosu")
    parser.add_argument("--no-soar", action="store_true", help="SOAR mudahalesini atla")
    parser.add_argument("--fast", action="store_true", help="beklemesiz calistir")
    args = parser.parse_args()
    run_core_breach(soar_enabled=not args.no_soar, speed=0 if args.fast else 1.0)


if __name__ == "__main__":
    main()
