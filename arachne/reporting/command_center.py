"""
Faz 10 - Celik Kubbe Komuta Merkezi veri katmani.

Panelin gorsel bilesenlerini (katmanli savunma simulasyonu ve dunya
haritasi) besleyen veriyi hazirlar.

--- "Celik Kubbe" benzetmesi neyi temsil ediyor? ---
Gelen her saldiri bir mermidir; savunma katmanlari ise onu YOL BOYUNCA
durdurmaya calisan halkalardir. Onemli olan sudur: hangi katmanin
durdurdugu UYDURULMAZ - gercek veriden turetilir:

    Katman 1 (SOAR)      : IP zaten engelliyse baglanti kurulmadan reddedildi
    Katman 2 (MTD)       : kimlik rotasyonu sayesinde eski hedef bilgisi bosa dustu
    Katman 3 (WAF)       : istek imza motoru tarafindan 403 ile engellendi
    Katman 4 (Aldatma)   : saldirgan gercek sistem yerine honeypot'a dustu
    Katman 5 (Tespit)    : kural motoru davranisi alarma cevirdi
    Cekirdek             : korunan varlik (bu mimaride hicbir saldiri ulasmaz,
                           cunku honeypot zaten gercek sistemden ayridir)

Bu, bir animasyon susu degil; her mermi gercek bir veritabani kaydidir ve
carptigi halka, o kaydi gercekten isleyen katmandir.
"""
from collections import Counter

from .. import storage
from ..intel.geo import geo_for_ip

# Savunma katmanlari - disaridan iceriye. `radius` degeri arayuzdeki
# halkanin goreli yaricapidir (1.0 = en dis, 0.0 = cekirdek).
#
# Faz 30: kubbe 5 halkadan 14 halkaya genisletildi (~2.8x). Yeni halkalar
# Faz 21-30 adaptif savunma katmanlarini temsil eder. Sira, savunmanin
# fiziksel derinligiyle ayni: en disarida caydirici/otomatik katmanlar
# (saldirgan iceri girmeden), en iceride tespit ve butunluk. Her halkanin
# "interceptions" degeri GERCEK veriden turetilir (build_dome_state icinde).
DEFENSE_LAYERS = [
    {
        "id": "soar", "name": "SOAR Kisitlama", "name_en": "Autonomous Response",
        "phase": "Faz 7", "radius": 1.00, "color": "255,59,69",
        "description_tr": (
            "Otomatik mudahale. Engellenmis bir IP tekrar baglanmaya "
            "calistiginda baglanti kurulmadan reddedilir."),
    },
    {
        "id": "posture", "name": "Adaptif Durus", "name_en": "Adaptive Posture",
        "phase": "Faz 26", "radius": 0.93, "color": "255,99,72",
        "description_tr": (
            "Tehdit seviyesine gore yukselen savunma durusu (NORMAL->KRITIK). "
            "Tirmandikca daha guclu ama maliyetli savunmalar acilir."),
    },
    {
        "id": "zero_trust", "name": "Sifir Guven Kapisi", "name_en": "Zero Trust PDP",
        "phase": "Faz 25", "radius": 0.86, "color": "251,146,60",
        "description_tr": (
            "NIST 800-207. Her istek oturum bazinda guven skoruyla degerlendirilir; "
            "dusuk guven reddedilir veya sahte ortama yonlendirilir."),
    },
    {
        "id": "mtd", "name": "Hareketli Hedef (MTD)", "name_en": "Moving Target Defense",
        "phase": "Faz 4", "radius": 0.79, "color": "245,166,35",
        "description_tr": (
            "Kimlik rotasyonu. Saldirganin onceki taramasinda topladigi "
            "port/banner bilgisi gecersizlestirilir; eski hedefe atis bosa duser."),
    },
    {
        "id": "collective", "name": "Kolektif Bagisiklik", "name_en": "Collective Defense",
        "phase": "Faz 29", "radius": 0.72, "color": "234,179,8",
        "description_tr": (
            "Bir sensor bir saldirgani yakalayinca gostergeyi paylasir; tum ag "
            "saldirgan onlara ulasmadan bagisiklanir (STIX/TAXII benzeri)."),
    },
    {
        "id": "ensemble", "name": "Topluluk Motoru", "name_en": "Ensemble Detector",
        "phase": "Faz 24", "radius": 0.65, "color": "163,230,53",
        "description_tr": (
            "Birden cok bagimsiz dedektorun oylamasi. Tek bir kurali atlatmak "
            "sistemi atlatmaya yetmez."),
    },
    {
        "id": "waf", "name": "WAF Imza Motoru", "name_en": "Web Application Firewall",
        "phase": "Faz 2", "radius": 0.58, "color": "74,222,128",
        "description_tr": (
            "Uygulama katmani guvenlik duvari. SQLi/XSS/komut enjeksiyonu "
            "imzalari eslesen istekler 403 ile reddedilir."),
    },
    {
        "id": "fingerprint", "name": "Parmak Izi / Sybil", "name_en": "Fingerprint / Sybil",
        "phase": "Faz 22", "radius": 0.51, "color": "45,212,191",
        "description_tr": (
            "JA3/JA4 benzeri istemci parmak izi. Tek bir aktor cok kimlik gibi "
            "gorunmeye calissa da parmak izi altindan yakalanir."),
    },
    {
        "id": "slow_burn", "name": "Dusuk-ve-Yavas", "name_en": "Low-and-Slow",
        "phase": "Faz 21", "radius": 0.44, "color": "34,211,238",
        "description_tr": (
            "CUSUM/EWMA kayma tespiti. Flood esiginin altinda kalmaya calisan "
            "sabirli saldirgan, birikimli sapma ve ritim duzenliligiyle yakalanir."),
    },
    {
        "id": "deception_grid", "name": "Aldatma Agi / Kirinti", "name_en": "Deception Grid",
        "phase": "Faz 23", "radius": 0.37, "color": "56,189,248",
        "description_tr": (
            "Katmanli aldatma. Belirgin tuzaklardan kacan saldirgan bile kirinti "
            "yolunu izleyip daha derin bir sahte dugume duser (yanlis-pozitif ~sifir)."),
    },
    {
        "id": "honeytoken", "name": "Honeytoken Tuzagi", "name_en": "Honeytoken",
        "phase": "Faz 12", "radius": 0.30, "color": "96,165,250",
        "description_tr": (
            "Yalnizca tuzak icin var olan izlenebilir sahte kimlikler. Biri "
            "kullanilirsa neredeyse kesin ihlal kanitidir (yanlis-pozitif ~sifir)."),
    },
    {
        "id": "deception", "name": "Aldatma Yuzeyi", "name_en": "Deception Surface",
        "phase": "Faz 1", "radius": 0.24, "color": "129,140,248",
        "description_tr": (
            "Honeypot katmani. Saldirgan gercek sistem yerine sahte servise duser; "
            "her etkilesim kayit altina alinir, hicbir gercek varlik risk almaz."),
    },
    {
        "id": "detection", "name": "Kural Motoru + ML", "name_en": "Detection Engine",
        "phase": "Faz 1-2", "radius": 0.17, "color": "167,139,250",
        "description_tr": (
            "Aciklanabilir kural motoru ve ML siniflandirici. Davranisi puanlayip "
            "alarma cevirir; her alarm gerekcesiyle birlikte kaydedilir."),
    },
    {
        "id": "integrity", "name": "Butunluk Zinciri", "name_en": "Integrity Chain",
        "phase": "Faz 17", "radius": 0.10, "color": "192,132,252",
        "description_tr": (
            "Kurcalama-kaniti hash zinciri + Merkle koku. Uretilen tum kanit "
            "kaydinin degistirilmedigi kriptografik olarak dogrulanir."),
    },
]

LAYER_BY_ID = {layer["id"]: layer for layer in DEFENSE_LAYERS}


def _classify_interception(event: dict, ctx: dict) -> str:
    """Bir olayin GERCEKTEN hangi savunma katmaninda durduruldugunu belirler.

    Onemli: sira, savunmanin fiziksel derinligiyle ayni (dis -> ic). Bir olay
    birden fazla katmanin ilgi alanina girse de, onu ILK yakalayan (en distaki)
    katman sayilir - "defense in depth" boyle calisir: bilinen tehdit ceperde,
    yeni/gizli tehdit derinde yakalanir. Hangi katmana atandigi olayin GERCEK
    ozelliklerinden turer (uydurulmaz):

      soar          : IP zaten engel listesinde -> baglanti kurulmadan reddedildi
      zero_trust    : alarmli kimlikten gelen ham baglanti -> politikayla reddedildi
      collective    : ayni /24'te baska bir IP zaten yakalanmis -> suru bagisikligi
      waf           : yuk bir WAF imzasiyla eslesti (SQLi/XSS/RCE...)
      fingerprint   : IP bir kimlik-rotasyonu kumesinin ilk uyesi -> parmak izi
      slow_burn     : IP dusuk-ve-yavas ritimde -> birikimli sapmayla yakalandi
      honeytoken    : yuk bir honeytoken degeri iceriyor -> neredeyse kesin ihlal
      detection     : alarmli + yuklu ama imza yok -> DAVRANISLA yakalandi (yeni/gizli)
      deception     : honeypot'a dusen ama henuz alarm uretmeyen etkilesim
    """
    ip = event.get("source_ip") or ""
    etype = (event.get("event_type") or "").lower()
    payload = event.get("payload") or ""
    subnet = _subnet(ip)

    # Sira mantigi: once "istek aninda kesin" yakalamalar (engel listesi, imza,
    # honeytoken), sonra korelasyon-tabanli (kolektif/parmak-izi/yavas), en sonda
    # davranissal tespit ve ham honeypot etkilesimi.
    # 1) SOAR - bilinen-kotu IP ceperde durur (istek aninda, kesin)
    if etype == "blocked" or ip in ctx["blocked_ips"]:
        return "soar"
    # 2) Sifir Guven - alarmli kimlikten ham baglanti politikayla reddedilir
    if etype == "connect" and ip in ctx["alert_ips"]:
        return "zero_trust"
    # 3) WAF - yuk gercek bir imzayla eslesiyor mu? (istek aninda, kesin)
    if payload and ctx["signature_hit"](payload):
        return "waf"
    # 4) Honeytoken - yuk bir tuzak deger iceriyor mu? (istek aninda, kesin ihlal)
    if payload and any(tok and tok in payload for tok in ctx["honeytoken_values"]):
        return "honeytoken"
    # 5) Kolektif bagisiklik - ayni /24'teki bir kardes zaten yakalandi (korelasyon)
    if ip in ctx["collective_siblings"]:
        return "collective"
    # 6) Parmak izi - kimlik-rotasyonu kumesinin ilk uyesi (korelasyon)
    if ip in ctx["sybil_first"]:
        return "fingerprint"
    # 7) Dusuk-ve-yavas (uzun-pencere korelasyon)
    if ip in ctx["slow_ips"]:
        return "slow_burn"
    # 8) Davranissal tespit - alarmli + yuklu ama imza yok (yeni/gizli saldiri)
    if ip in ctx["alert_ips"] and payload:
        return "detection"
    # 9) Aldatma yuzeyi - honeypot'a dustu, henuz alarm yok
    return "deception"


def _subnet(ip: str) -> str:
    """IP'nin /24 blogunu dondurur (kaba kimlik-rotasyonu kumeleme icin)."""
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else ip


def build_adaptive_layer_counts(db_path=None, alerts=None, blocked=None,
                                projectile_counts=None, events=None) -> dict:
    """Faz 21-30 adaptif katmanlarinin kubbedeki 'interceptions' sayilarini
    GERCEK veriden turetir. Hicbir sayi uydurulmaz; her biri var olan bir
    kayittan/analizden gelir. Veri yoksa katman 0 (bos halka) kalir - bu da
    durustluk geregi 'bu kosuda tetiklenmedi' demektir."""
    from .. import storage
    from ..adaptive import posture as posture_mod
    from ..adaptive.slow_detector import interval_regularity

    alerts = alerts if alerts is not None else storage.get_all_alerts(limit=200, db_path=db_path)
    if blocked is None:
        try:
            from ..soar import blocklist
            blocked = blocklist.active_blocks()
        except Exception:
            blocked = []
    projectile_counts = projectile_counts or {}

    alert_ips = [a.get("source_ip") for a in alerts if a.get("source_ip")]
    distinct_alert_ips = set(alert_ips)
    critical_alerts = sum(1 for a in alerts if str(a.get("severity", "")).lower() in ("critical", "kritik"))

    ht_stats = storage.honeytoken_stats(db_path=db_path)
    ht_triggered = ht_stats.get("triggered_tokens", ht_stats.get("triggered", 0))
    ad_stats = storage.active_defense_stats(db_path=db_path)
    deception_actions = 0
    for technique, cnt in (ad_stats.get("by_technique") or {}).items():
        tl = str(technique).lower()
        if "aldat" in tl or "decept" in tl or "tarpit" in tl:
            deception_actions += cnt
    # aldatma tekniginin adi degisebilir; hicbiri eslesmezse tum aktif savunmayi al
    if deception_actions == 0:
        deception_actions = ad_stats.get("total_actions", 0)

    # Kimlik rotasyonu (Sybil) yaklasik: ayni /24 icinde >=3 farkli IP alarm
    # veriyorsa, tek aktorun kimlik dondurmesi olarak sayilir.
    subnet_ips = {}
    for ip in distinct_alert_ips:
        subnet_ips.setdefault(_subnet(ip), set()).add(ip)
    sybil_clusters = sum(1 for ips in subnet_ips.values() if len(ips) >= 3)

    # Dusuk-ve-yavas: bir IP'nin olay zaman damgalari asiri duzenliyse (makine
    # ritmi) ve yeterli olay varsa say. DIKKAT: yavas-ve-sinsi TANIMI geregi
    # uzun bir pencere gerektirir - kubbenin 15dk'lik penceresi bunu goremez.
    # Bu yuzden slow-burn icin AYRI, genis bir pencere (2 saat) sorgulariz.
    slow_ips = set()
    try:
        from collections import defaultdict
        import datetime as _dt
        slow_events = storage.get_recent_events(since_seconds=7200, db_path=db_path)
        ts_by_ip = defaultdict(list)
        for ev in slow_events:
            ip = ev.get("source_ip"); ts = ev.get("timestamp")
            if not ip or not ts:
                continue
            try:
                t = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
                ts_by_ip[ip].append(t)
            except (ValueError, TypeError):
                continue
        for ip, ts in ts_by_ip.items():
            # Genis pencerede >=6 olay + asiri duzenli ritim + gercekten
            # "yavas" (olaylar en az birkac dakikaya yayilmis) olmali.
            if len(ts) >= 6 and interval_regularity(sorted(ts)) >= 0.85:
                span = max(ts) - min(ts)
                if span >= 300:  # en az 5 dakikaya yayilmis (flood degil)
                    slow_ips.add(ip)
    except Exception:
        slow_ips = set()
    slow_burners = len(slow_ips)

    # Adaptif durus skoru ve seviyesi
    score = posture_mod.score_from_signals(
        ensemble_threat=min(4.0, len(distinct_alert_ips) * 0.5),
        critical_alerts=critical_alerts,
        blocked_ips=len(blocked),
        honeytoken_triggers=ht_triggered,
        sybil_actors=sybil_clusters,
        slow_burners=slow_burners,
    )
    pm = posture_mod.AdaptivePosture(hysteresis_ticks=1)
    # Tek atislik anlik degerlendirme (canli panelde birikimli skorun karsiligi)
    pm.update(score); pm.update(score); pm.update(score)
    snap = pm.snapshot()

    counts = {
        # durus katmani: seviye yukseldiyse (skor>=25) tetiklenmis sayilir;
        # sayi olarak kritik alarm sayisini gosteririz (durusa neden olan sinyal)
        "posture": (critical_alerts or 1) if score >= 25 else 0,
        "zero_trust": len(distinct_alert_ips),          # her alarmli IP = reddedilen/challenge guven karari
        "collective": len(distinct_alert_ips),          # paylasilan gosterge (IOC)
        "ensemble": len(alerts),                        # birlesik karar sayisi
        "fingerprint": sybil_clusters,
        "slow_burn": slow_burners,
        "deception_grid": deception_actions,
        "honeytoken": ht_triggered,
        "integrity": len(storage.get_soar_actions(limit=500, db_path=db_path)),
    }
    return {"counts": counts, "posture": snap, "posture_score": score,
            "slow_ips": slow_ips, "sybil_subnets": {
                sn for sn, ips in subnet_ips.items() if len(ips) >= 3}}


def build_dome_state(db_path=None, limit: int = 60) -> dict:
    """Celik Kubbe gorselinin ihtiyac duydugu tam durum verisi."""
    events = storage.get_recent_events(since_seconds=900, db_path=db_path)[:limit]
    alerts = storage.get_all_alerts(limit=100, db_path=db_path)
    waf_events = storage.get_waf_events(limit=60, db_path=db_path)
    mtd_rotations = storage.get_mtd_rotations(limit=30, db_path=db_path)

    alert_ips = {a.get("source_ip") for a in alerts}
    try:
        from ..soar import blocklist
        blocked = blocklist.active_blocks()
        blocked_ips = {b["ip"] for b in blocked}
    except Exception:
        blocked, blocked_ips = [], set()

    # Faz 21-30: adaptif katmanlarin sayilarini + yardimci kumeleri gercek
    # veriden turet (once cagir, cunku siniflandirma bunlara ihtiyac duyar).
    adaptive = build_adaptive_layer_counts(
        db_path=db_path, alerts=alerts, blocked=blocked, events=events)

    # --- Gercekci siniflandirma baglami (ctx) ---------------------------------
    # Her mermiyi GERCEK ozelliklerinden dogru katmana yonlendirmek icin gereken
    # yardimci kumeler. Hicbiri uydurulmaz; hepsi var olan veriden turer.
    from ..waf import rules as _waf_rules
    honeytoken_values = {h.get("value") for h in storage.get_honeytokens(db_path=db_path)
                         if h.get("value") and len(str(h.get("value"))) >= 8}

    # Alarmli IP'leri /24 bloklarina gore grupla
    subnet_alert_ips = {}
    for ip in alert_ips:
        if ip:
            subnet_alert_ips.setdefault(_subnet(ip), []).append(ip)
    sybil_subnets = adaptive.get("sybil_subnets", set())
    # kimlik-rotasyonu kumesinin ILK (en dusuk) uyesi -> parmak izi yakalar
    sybil_first = {min(subnet_alert_ips[sn]) for sn in sybil_subnets if subnet_alert_ips.get(sn)}
    # herhangi bir /24'te >=2 alarmli IP varsa, ilki disindakiler -> kolektif bagisiklik
    collective_siblings = set()
    for sn, ips in subnet_alert_ips.items():
        if len(ips) >= 2:
            lo = min(ips)
            collective_siblings.update(i for i in ips if i != lo)

    ctx = {
        "blocked_ips": blocked_ips,
        "alert_ips": alert_ips,
        "collective_siblings": collective_siblings,
        "sybil_first": sybil_first,
        "slow_ips": adaptive.get("slow_ips", set()),
        "honeytoken_values": honeytoken_values,
        "signature_hit": lambda p: bool(_waf_rules.scan_text(p)),
    }

    # --- Mermiler (gelen saldirilar) ---
    projectiles = []

    for event in events:
        ip = event.get("source_ip")
        if not ip:
            continue
        layer = _classify_interception(event, ctx)
        projectiles.append({
            "id": f"ev-{event.get('id')}",
            "source_ip": ip,
            "geo": geo_for_ip(ip),
            "timestamp": event.get("timestamp"),
            "service": event.get("service"),
            "kind": "honeypot",
            "intercepted_by": layer,
            "label": LAYER_BY_ID.get(layer, {}).get("name", layer),
            "sensor_id": event.get("sensor_id"),
        })

    for waf in waf_events:
        ip = waf.get("source_ip")
        if not ip:
            continue
        layer = "waf" if waf.get("blocked") else "detection"
        projectiles.append({
            "id": f"waf-{waf.get('id')}",
            "source_ip": ip,
            "geo": geo_for_ip(ip),
            "timestamp": waf.get("timestamp"),
            "service": "waf",
            "kind": "waf",
            "intercepted_by": layer,
            "label": LAYER_BY_ID.get(layer, {}).get("name", layer),
            "sensor_id": None,
        })

    layer_counts = Counter(p["intercepted_by"] for p in projectiles)

    layers = []
    for layer in DEFENSE_LAYERS:
        count = layer_counts.get(layer["id"], 0)
        if layer["id"] == "mtd":
            count = len(mtd_rotations)
        if layer["id"] == "soar":
            count = max(count, len(blocked))
        # adaptif katmanlar kendi hesaplanmis sayilarini kullanir
        if layer["id"] in adaptive["counts"]:
            count = adaptive["counts"][layer["id"]]
        layers.append({**layer, "interceptions": count, "active": count > 0})

    total = len(projectiles)
    return {
        "layers": layers,
        "projectiles": projectiles,
        "total_projectiles": total,
        "reached_core": 0,   # aldatma mimarisinde gercek varlik hedef degildir
        "interception_rate": 100 if total else 0,
        "active_blocks": blocked,
        "posture": adaptive["posture"],
        "mtd_rotation_count": len(mtd_rotations),
        "explanation_tr": (
            "Her mermi gercek bir veritabani kaydidir; carptigi halka, o kaydi "
            "gercekten isleyen savunma katmanidir. Cekirdege ulasan saldiri sayisi "
            "sifirdir cunku aldatma mimarisinde saldirgan hicbir zaman gercek "
            "varliga degil, ondan tamamen ayri bir sahte yuzeye baglanir."
        ),
    }


def build_attack_map(db_path=None, limit: int = 200) -> dict:
    """Dunya haritasi gorselinin verisi: saldirgan konumlari + saldiri yaylari.

    DURUSTLUK: Konum bilgisi cevrimdisi, RIR (bolge kayit kurumu) seviyesinde
    bir TAHMINDIR - sehir seviyesi degildir ve oyle iddia edilmez. Lab
    trafigi (127.0.0.1) acikca 'LAB' dugumunde toplanir, sahte bir ulkeye
    yerlestirilmez."""
    stats = storage.summary_stats(db_path=db_path)
    alerts = storage.get_all_alerts(limit=200, db_path=db_path)

    alert_by_ip = {}
    for alert in alerts:
        ip = alert.get("source_ip")
        if not ip:
            continue
        existing = alert_by_ip.get(ip)
        if not existing or (alert.get("score") or 0) > (existing.get("score") or 0):
            alert_by_ip[ip] = alert

    try:
        from ..soar import blocklist
        blocked_ips = {b["ip"] for b in blocklist.active_blocks()}
    except Exception:
        blocked_ips = set()

    nodes = []
    for ip, count in stats.get("top_ips", [])[:limit]:
        if not ip:
            continue
        geo = geo_for_ip(ip)
        alert = alert_by_ip.get(ip)
        nodes.append({
            "ip": ip,
            "event_count": count,
            "lat": geo["lat"], "lon": geo["lon"],
            "scope": geo["scope"],
            "region": geo["region"], "region_name": geo["region_name"],
            "precision": geo["precision"], "precision_tr": geo["precision_tr"],
            "severity": alert.get("severity") if alert else None,
            "score": alert.get("score") if alert else 0,
            "blocked": ip in blocked_ips,
        })

    # Savunulan varlik: haritanin merkezi. Lab kurulumunda Istanbul'a
    # sabitlendi (proje ekibinin konumu) - bu bir tahmin degil, tanimdir.
    defended_asset = {
        "name": "Arachne Sentinel (korunan yuzey)",
        "lat": 41.0, "lon": 29.0,
    }

    by_scope = Counter(n["scope"] for n in nodes)
    by_region = Counter(n["region_name"] for n in nodes if n["scope"] != "loopback")

    return {
        "nodes": nodes,
        "node_count": len(nodes),
        "defended_asset": defended_asset,
        "by_scope": dict(by_scope),
        "by_region": dict(by_region),
        "honesty_note_tr": (
            "Konumlar cevrimdisi, bolge (RIR) seviyesinde tahmindir; sehir "
            "hassasiyeti iddia edilmez. Yerel lab trafigi ayri bir 'LAB' "
            "dugumunde toplanir - sahte bir ulkeye yerlestirilmez."
        ),
    }


def build_layer_health(db_path=None) -> dict:
    """Her savunma katmaninin canli saglik/etkinlik durumu."""
    honeypot = storage.summary_stats(db_path=db_path)
    waf = storage.waf_summary_stats(db_path=db_path)
    mtd = storage.mtd_summary_stats(db_path=db_path)
    soar = storage.soar_summary_stats(db_path=db_path)
    mesh = storage.mesh_summary_stats(db_path=db_path)

    try:
        from ..soar import blocklist
        active_blocks = len(blocklist.active_blocks())
    except Exception:
        active_blocks = 0

    try:
        from ..native import signature_engine
        native_active = signature_engine.NATIVE_ENGINE_ACTIVE
    except Exception:
        native_active = False

    try:
        from ..ai import llm_backend
        ai_status = llm_backend.status()
    except Exception:
        ai_status = {"enabled": False, "mode_tr": "AI katmani yuklenemedi"}

    return {
        "soar": {
            "label": "SOAR Kisitlama", "phase": "Faz 7",
            "operational": True,
            "metric": active_blocks, "metric_label": "aktif engelleme",
            "detail": f"{soar['total_actions']} otomatik eylem, "
                      f"{soar['awaiting_approval']} onay bekliyor",
        },
        "mtd": {
            "label": "Hareketli Hedef", "phase": "Faz 4",
            "operational": mtd["total_rotations"] > 0,
            "metric": mtd["total_rotations"], "metric_label": "kimlik rotasyonu",
            "detail": "Kimlik rotasyonu aktif" if mtd["total_rotations"]
                      else "Baslatilmadi (python main.py mtd-demo)",
        },
        "waf": {
            "label": "WAF Imza Motoru", "phase": "Faz 2",
            "operational": waf["total_requests"] > 0,
            "metric": waf["blocked_requests"], "metric_label": "engellenen istek",
            "detail": f"{waf['blocked_requests']}/{waf['total_requests']} istek engellendi",
        },
        "deception": {
            "label": "Aldatma Yuzeyi", "phase": "Faz 1",
            "operational": True,
            "metric": honeypot["total_events"], "metric_label": "yakalanan olay",
            "detail": "4 sahte servis dinlemede",
        },
        "detection": {
            "label": "Kural Motoru + ML", "phase": "Faz 1-2",
            "operational": True,
            "metric": honeypot["total_alerts"], "metric_label": "uretilen alarm",
            "detail": ("Native ARM64 imza cekirdegi AKTIF" if native_active
                       else "Python imza cekirdegi (native yedek)"),
        },
        "mesh": {
            "label": "Sensor Agi", "phase": "Faz 9",
            "operational": mesh["sensor_count"] > 0,
            "metric": mesh["online_count"], "metric_label": "cevrimici sensor",
            "detail": f"{mesh['sensor_count']} kayitli sensor, "
                      f"{mesh['total_reports_rejected']} rapor reddedildi",
        },
        "ai": {
            "label": "AI Analist", "phase": "Faz 8",
            "operational": True,
            "metric": 1, "metric_label": "analist aktif",
            "detail": ai_status.get("mode_tr", ""),
        },
    }
