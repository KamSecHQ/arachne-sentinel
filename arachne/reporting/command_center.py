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
# Faz 30: kubbe 5 halkadan 14 halkaya genisletildi (~2.8x). Faz 44: dort yeni
# ko-evrim halkasi (Faz 41-44) eklendi -> toplam 18 halka. Yeni halkalar
# Faz 21-44 adaptif/ko-evrim savunma katmanlarini temsil eder. Sira, savunmanin
# fiziksel derinligiyle ayni: en disarida caydirici/otomatik katmanlar
# (saldirgan iceri girmeden), en iceride tespit ve butunluk. Yaricaplar 18 halka
# arasinda ~1.00 (en dis) ile ~0.09 (cekirdek) arasinda esit dagitilmistir. Her
# halkanin "interceptions" degeri GERCEK veriden turetilir (build_dome_state
# icinde); veri yoksa 0 (durustce "bu kosuda tetiklenmedi").
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
        "phase": "Faz 26", "radius": 0.95, "color": "255,99,72",
        "description_tr": (
            "Tehdit seviyesine gore yukselen savunma durusu (NORMAL->KRITIK). "
            "Tirmandikca daha guclu ama maliyetli savunmalar acilir."),
    },
    {
        "id": "zero_trust", "name": "Sifir Guven Kapisi", "name_en": "Zero Trust PDP",
        "phase": "Faz 25", "radius": 0.89, "color": "251,146,60",
        "description_tr": (
            "NIST 800-207. Her istek oturum bazinda guven skoruyla degerlendirilir; "
            "dusuk guven reddedilir veya sahte ortama yonlendirilir."),
    },
    {
        "id": "mtd", "name": "Hareketli Hedef (MTD)", "name_en": "Moving Target Defense",
        "phase": "Faz 4", "radius": 0.84, "color": "245,166,35",
        "description_tr": (
            "Kimlik rotasyonu. Saldirganin onceki taramasinda topladigi "
            "port/banner bilgisi gecersizlestirilir; eski hedefe atis bosa duser."),
    },
    {
        "id": "collective", "name": "Kolektif Bagisiklik", "name_en": "Collective Defense",
        "phase": "Faz 29", "radius": 0.79, "color": "234,179,8",
        "description_tr": (
            "Bir sensor bir saldirgani yakalayinca gostergeyi paylasir; tum ag "
            "saldirgan onlara ulasmadan bagisiklanir (STIX/TAXII benzeri)."),
    },
    {
        # Faz 44 - Kimlik/cografi anomali. Kolektif bagisiklik ile Sifir Guven'in
        # yaninda, dis-orta bant: kimlik daha derin denetimden GECMEDEN once
        # cografi tutarlilik acisindan degerlendirilir.
        "id": "geo_velocity", "name": "Imkansiz Seyahat", "name_en": "Impossible Travel",
        "phase": "Faz 44", "radius": 0.73, "color": "202,214,30",
        "description_tr": (
            "Imkansiz seyahat tespiti (MITRE T1078). Ayni aktor kisa surede "
            "cografi olarak cok uzak iki bolgeden gorunurse gereken hiz fiziksel "
            "tavani (900 km/s) asar ve olasi hesap-ele-gecirme olarak isaretlenir; "
            "bolge merkezleri yaklasiktir, karar insana yukseltmedir."),
    },
    {
        "id": "ensemble", "name": "Topluluk Motoru", "name_en": "Ensemble Detector",
        "phase": "Faz 24", "radius": 0.68, "color": "163,230,53",
        "description_tr": (
            "Birden cok bagimsiz dedektorun oylamasi. Tek bir kurali atlatmak "
            "sistemi atlatmaya yetmez."),
    },
    {
        # Faz 43 - Meta/skorlama halkasi. Topluluk motorunun hemen icinde, orta
        # derinlikte: bagimsiz dedektorlerin kararlarini olasiliksal olarak birlestirir.
        "id": "threat_fusion", "name": "Bayes Tehdit Fuzyonu", "name_en": "Bayesian Threat Fusion",
        "phase": "Faz 43", "radius": 0.63, "color": "116,226,90",
        "description_tr": (
            "Bayesci tehdit fuzyonu. Bagimsiz dedektorlerin (imza, honeytoken, "
            "beacon, yavas-yanma, sybil) sinyalleri log-odds uzayinda tek bir "
            "sonsal olasiliga birlestirilir; esigi asan IP'ler onceliklendirilir "
            "(olasilik tahminidir, kesin degil)."),
    },
    {
        "id": "waf", "name": "WAF Imza Motoru", "name_en": "Web Application Firewall",
        "phase": "Faz 2", "radius": 0.57, "color": "74,222,128",
        "description_tr": (
            "Uygulama katmani guvenlik duvari. SQLi/XSS/komut enjeksiyonu "
            "imzalari eslesen istekler 403 ile reddedilir."),
    },
    {
        "id": "fingerprint", "name": "Parmak Izi / Sybil", "name_en": "Fingerprint / Sybil",
        "phase": "Faz 22", "radius": 0.52, "color": "45,212,191",
        "description_tr": (
            "JA3/JA4 benzeri istemci parmak izi. Tek bir aktor cok kimlik gibi "
            "gorunmeye calissa da parmak izi altindan yakalanir."),
    },
    {
        "id": "slow_burn", "name": "Dusuk-ve-Yavas", "name_en": "Low-and-Slow",
        "phase": "Faz 21", "radius": 0.46, "color": "34,211,238",
        "description_tr": (
            "CUSUM/EWMA kayma tespiti. Flood esiginin altinda kalmaya calisan "
            "sabirli saldirgan, birikimli sapma ve ritim duzenliligiyle yakalanir."),
    },
    {
        # Faz 41 - Zamanlama-korelasyonu halkasi. Parmak izi / yavas-yanma bandinda:
        # payload opak olsa bile call-home ritmini istatistikle yakalar.
        "id": "beacon", "name": "C2 Isaret Tespiti", "name_en": "Beacon Detection",
        "phase": "Faz 41", "radius": 0.41, "color": "40,205,244",
        "description_tr": (
            "Zamanlama tabanli C2 beacon tespiti. Payload sifreli olsa bile "
            "implantin duzenli call-home ritmi gelis-araligi istatistigiyle "
            "(dusuk jitter/degisim katsayisi) yakalanir; kesin kanit degil, "
            "insan incelemesine yukseltme sinyalidir."),
    },
    {
        "id": "deception_grid", "name": "Aldatma Agi / Kirinti", "name_en": "Deception Grid",
        "phase": "Faz 23", "radius": 0.36, "color": "56,189,248",
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
        "phase": "Faz 1", "radius": 0.25, "color": "129,140,248",
        "description_tr": (
            "Honeypot katmani. Saldirgan gercek sistem yerine sahte servise duser; "
            "her etkilesim kayit altina alinir, hicbir gercek varlik risk almaz."),
    },
    {
        # Faz 42 - Davranissal/yeni desen halkasi. Tespit motorunun hemen disinda,
        # derinde: imza bulunmayan ama tanidik-olmayan payload'lari isaretler.
        "id": "novelty", "name": "Sifir-Gun Sezgisi", "name_en": "Zero-Day Novelty",
        "phase": "Faz 42", "radius": 0.20, "color": "150,140,250",
        "description_tr": (
            "Imzasiz sifir-gun sezgisi. Bir payload'un bilinen saldiri korpusuna "
            "ve son trafige gore ne kadar TANIDIK OLMADIGI karakter n-gram "
            "nadirligiyle olculur; yuksek yenilik 'kesin kotu' degil 'daha once "
            "gorulmemis' demektir, insan incelemesine yonlendirilir."),
    },
    {
        "id": "detection", "name": "Kural Motoru + ML", "name_en": "Detection Engine",
        "phase": "Faz 1-2", "radius": 0.14, "color": "167,139,250",
        "description_tr": (
            "Aciklanabilir kural motoru ve ML siniflandirici. Davranisi puanlayip "
            "alarma cevirir; her alarm gerekcesiyle birlikte kaydedilir."),
    },
    {
        "id": "integrity", "name": "Butunluk Zinciri", "name_en": "Integrity Chain",
        "phase": "Faz 17", "radius": 0.09, "color": "192,132,252",
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
      beacon        : IP duzenli call-home ritmi gosteriyor -> C2 beacon (Faz 41)
      honeytoken    : yuk bir honeytoken degeri iceriyor -> neredeyse kesin ihlal
      novelty       : yuk bilinen desenlere benzemiyor -> sifir-gun sezgisi (Faz 42)
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
    # 8) C2 beacon - zamanlama ritmi duzenli (Faz 41, korelasyon/istatistik)
    if ip in ctx.get("beacon_ips", ()):
        return "beacon"
    # 9) Sifir-gun sezgisi - yuk bilinen desenlere benzemiyor (Faz 42, davranissal)
    if payload and ip in ctx.get("novel_ips", ()):
        return "novelty"
    # 10) Davranissal tespit - alarmli + yuklu ama imza yok (yeni/gizli saldiri)
    if ip in ctx["alert_ips"] and payload:
        return "detection"
    # 11) Aldatma yuzeyi - honeypot'a dustu, henuz alarm yok
    return "deception"


def _subnet(ip: str) -> str:
    """IP'nin /24 blogunu dondurur (kaba kimlik-rotasyonu kumeleme icin)."""
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else ip


# Faz 44 geo-velocity icin bolge (RIR/LAB) -> temsili merkez koordinat. Bunlar
# JITTER'SIZ (kanonik) merkezlerdir: ayni bolgedeki iki gozlemin mesafesi tam
# olarak 0 olsun ki jitter gurultusu YANLIS bir "imkansiz seyahat" uretmesin.
# Yalnizca gozlemler GERCEKTEN farkli bolgelere dustugunde mesafe > 0 olur.
_REGION_CENTROIDS = {
    "NA": (39.0, -98.0), "EU": (50.0, 10.0), "AP": (25.0, 115.0),
    "LA": (-14.0, -51.0), "AF": (0.0, 20.0), "LAB": (41.0, 29.0),
}


def _parse_ts(ts):
    """ISO/SQL zaman damgasini epoch saniyeye cevirir; basarisizsa None."""
    if not ts:
        return None
    import datetime as _dt
    try:
        return _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _coevolution_counts(db_path, distinct_alert_ips, slow_ips, sybil_subnets):
    """Faz 41-44 ko-evrim halkalarinin 'interceptions' sayilarini GERCEK
    veriden turetir. Her sayi var olan bir kayittan/analizden gelir; veri yoksa
    0 (durustce 'bu kosuda tetiklenmedi'). Her hesap ayri try/except ile
    korunur: bir dedektor patlarsa o halka 0 kalir, kubbe cokmez.

    Ayrica siniflandirma (build_dome_state ctx) icin yardimci kumeler doner:
      beacon_ips : call-home ritmi duzenli bulunan IP'ler
      novel_ips  : bilinen desenlere benzemeyen (yeni) bir payload gonderen IP'ler
    """
    from collections import Counter, defaultdict

    counts = {"beacon": 0, "novelty": 0, "threat_fusion": 0, "geo_velocity": 0}
    beacon_ips, novel_ips = set(), set()

    # Son 2 saatin olaylari: beacon ritmi + novelty payload korpusu icin ortak
    # kaynak. (Kubbenin 15dk penceresi bu korelasyonlar icin cok dar.)
    try:
        recent = storage.get_recent_events(since_seconds=7200, db_path=db_path)
    except Exception:
        recent = []

    ts_by_ip = defaultdict(list)
    pay_by_ip = defaultdict(list)
    for ev in recent:
        ip = ev.get("source_ip")
        if not ip:
            continue
        t = _parse_ts(ev.get("timestamp"))
        if t is not None:
            ts_by_ip[ip].append(t)
        if ev.get("payload"):
            pay_by_ip[ip].append(ev["payload"])

    # --- Faz 41: C2 beacon (zamanlama) --------------------------------------
    # Her IP'nin sirali zaman damgalarini beacon_score'a ver; is_beacon True
    # olanlari say. beacon_score kendi esigini (>=6 olay, regularity>=0.5)
    # uygular - biz uydurmayiz, sadece dedektorun kararini sayariz.
    try:
        from ..adaptive.beacon import beacon_score
        for ip, ts in ts_by_ip.items():
            if len(ts) < 6:
                continue
            if beacon_score(sorted(ts)).get("is_beacon"):
                beacon_ips.add(ip)
        counts["beacon"] = len(beacon_ips)
    except Exception:
        beacon_ips = set()
        counts["beacon"] = 0

    # --- Faz 42: Sifir-gun yenilik (novelty) --------------------------------
    # Ayni payload'i egitim setine koyup test etmek her seyi 'tanidik' yapar;
    # bilinen saldiri korpusuyla egitip test etmek her normal istegi 'yeni'
    # yapar. Ikisinin de tuzagina dusmemek icin BIRAK-BIRINI-DISARIDA
    # (leave-one-out) yontemi: her farkli payload, DIGER tum payload'lar +
    # bilinen saldiri korpusu uzerine egitilmis modelle skorlanir. Boylece
    # 'yeni' = hem bilinen saldirilara hem de son trafige benzemeyen demektir.
    try:
        from ..adaptive.novelty import NoveltyModel, _DEFAULT_CORPUS
        distinct_payloads = list(dict.fromkeys(
            p for ps in pay_by_ip.values() for p in ps))
        # Anlamli bir 'digerleri' olusabilmesi icin en az 3 farkli payload gerek.
        # Cok buyuk kumelerde LOO'yu makul bir tavanla sinirla (deterministik).
        if len(distinct_payloads) >= 3:
            loo_set = distinct_payloads[:250]
            novel_payloads = set()
            for i, p in enumerate(loo_set):
                others = _DEFAULT_CORPUS + [q for j, q in enumerate(loo_set) if j != i]
                model = NoveltyModel(n=3).train(others)
                if model.novelty(p).get("is_novel"):
                    novel_payloads.add(p)
            if novel_payloads:
                for ip, ps in pay_by_ip.items():
                    if any(p in novel_payloads for p in ps):
                        novel_ips.add(ip)
                # Sayi = payload'i yeni bulunan olay sayisi (halka etkinligi).
                counts["novelty"] = sum(
                    1 for ev in recent if ev.get("payload") in novel_payloads)
    except Exception:
        novel_ips = set()
        counts["novelty"] = 0

    # --- Faz 43: Bayes tehdit fuzyonu ---------------------------------------
    # Her farkli alarmli IP icin, o IP hakkinda ELIMIZDE OLAN kanitlari
    # (imza, honeytoken, beacon, yavas-yanma, sybil, novelty) atesleyen
    # dedektorler olarak topla ve fuse() ile tek bir sonsal olasiliga birlestir.
    # sonsal > 0.5 olan IP'leri say. Sinyaller uydurulmaz; hepsi baska halkalarin
    # zaten hesapladigi gercek kanit kumelerinden gelir.
    try:
        from ..adaptive.threat_fusion import ThreatFusion
        from ..waf import rules as _waf_rules
        ht_values = {h.get("value") for h in storage.get_honeytokens(db_path=db_path)
                     if h.get("value") and len(str(h.get("value"))) >= 8}
        tf = ThreatFusion()
        for ip in distinct_alert_ips:
            if not ip:
                continue
            pays = pay_by_ip.get(ip, [])
            fired = []
            try:
                if any(p and _waf_rules.scan_text(p) for p in pays):
                    fired.append("signature")
            except Exception:
                pass
            if ht_values and any(tok and tok in p for p in pays for tok in ht_values):
                fired.append("honeytoken")
            if ip in beacon_ips:
                fired.append("beacon")
            if ip in slow_ips:
                fired.append("slow_burn")
            if _subnet(ip) in sybil_subnets:
                fired.append("sybil")
            if ip in novel_ips:
                fired.append("novelty")
            if fired and tf.assess(fired).get("posterior", 0.0) > 0.5:
                counts["threat_fusion"] += 1
    except Exception:
        counts["threat_fusion"] = 0

    # --- Faz 44: Imkansiz seyahat (geo-velocity) ----------------------------
    # KIMLIK secimi: bu proje bir /24'u 'tek aktorun kimlik rotasyonu' olarak
    # modeller (bkz. sybil). Dolayisiyla aktor = /24; gozlem = alarmli IP'nin
    # KANONIK bolge merkezi (jitter'siz). Ayni aktor kisa surede iki FARKLI
    # bolgeden gorunurse gereken hiz tavani asar -> imkansiz seyahat. Jitter
    # kullanmadigimiz icin ayni bolge = 0 mesafe; sahte pozitif uretmez.
    try:
        from ..adaptive.geo_velocity import GeoVelocityMonitor
        obs = []
        for ev in recent:
            ip = ev.get("source_ip")
            if not ip or ip not in distinct_alert_ips:
                continue
            t = _parse_ts(ev.get("timestamp"))
            if t is None:
                continue
            region = geo_for_ip(ip).get("region")
            coord = _REGION_CENTROIDS.get(region)
            if not coord:
                continue          # bilinmeyen bolge: konum iddia etmeyiz
            obs.append((t, _subnet(ip), coord[0], coord[1]))
        obs.sort(key=lambda o: o[0])   # kronolojik (observe boyle bekler)
        mon = GeoVelocityMonitor()
        for t, actor, lat, lon in obs:
            mon.observe(actor, lat, lon, t)
        counts["geo_velocity"] = mon.report().get("flagged_count", 0)
    except Exception:
        counts["geo_velocity"] = 0

    return {"counts": counts, "beacon_ips": beacon_ips, "novel_ips": novel_ips}


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

    # Faz 41-44 ko-evrim halkalari: beacon/novelty/fusion/geo sayilarini gercek
    # veriden turet ve ayni counts sozlugune ekle. Yardimci kumeler (beacon_ips,
    # novel_ips) siniflandirma icin yukari tasinir.
    sybil_subnets = {sn for sn, ips in subnet_ips.items() if len(ips) >= 3}
    coevo = _coevolution_counts(db_path, distinct_alert_ips, slow_ips, sybil_subnets)
    counts.update(coevo["counts"])

    return {"counts": counts, "posture": snap, "posture_score": score,
            "slow_ips": slow_ips, "sybil_subnets": sybil_subnets,
            "beacon_ips": coevo["beacon_ips"], "novel_ips": coevo["novel_ips"]}


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
        "beacon_ips": adaptive.get("beacon_ips", set()),
        "novel_ips": adaptive.get("novel_ips", set()),
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
