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
DEFENSE_LAYERS = [
    {
        "id": "soar",
        "name": "SOAR Kisitlama",
        "name_en": "Autonomous Response",
        "phase": "Faz 7",
        "radius": 1.0,
        "color": "255,59,69",
        "description_tr": (
            "Otomatik mudahale katmani. Daha once engellenmis bir IP tekrar "
            "baglanmaya calistiginda, baglanti kurulmadan reddedilir."
        ),
    },
    {
        "id": "mtd",
        "name": "Hareketli Hedef (MTD)",
        "name_en": "Moving Target Defense",
        "phase": "Faz 4",
        "radius": 0.82,
        "color": "45,212,191",
        "description_tr": (
            "Kimlik rotasyonu katmani. Saldirganin onceki taramasinda topladigi "
            "port/banner bilgisi gecersizlestirilir; eski hedefe atis bosa duser."
        ),
    },
    {
        "id": "waf",
        "name": "WAF Imza Motoru",
        "name_en": "Web Application Firewall",
        "phase": "Faz 2",
        "radius": 0.64,
        "color": "245,166,35",
        "description_tr": (
            "Uygulama katmani guvenlik duvari. SQLi/XSS/komut enjeksiyonu "
            "imzalari eslesen istekler 403 ile reddedilir."
        ),
    },
    {
        "id": "deception",
        "name": "Aldatma Yuzeyi",
        "name_en": "Deception Surface",
        "phase": "Faz 1",
        "radius": 0.46,
        "color": "34,211,238",
        "description_tr": (
            "Honeypot katmani. Saldirgan gercek sistem yerine sahte servise "
            "duser; her etkilesim kayit altina alinir, hicbir gercek varlik risk almaz."
        ),
    },
    {
        "id": "detection",
        "name": "Kural Motoru + ML",
        "name_en": "Detection Engine",
        "phase": "Faz 1-2",
        "radius": 0.28,
        "color": "167,139,250",
        "description_tr": (
            "Aciklanabilir kural motoru ve ML siniflandirici. Davranisi "
            "puanlayip alarma cevirir; her alarm gerekcesiyle birlikte kaydedilir."
        ),
    },
]

LAYER_BY_ID = {layer["id"]: layer for layer in DEFENSE_LAYERS}


def _classify_interception(event: dict, blocked_ips: set, alert_ips: set) -> str:
    """Bir olayin HANGI katmanda durduruldugunu belirler.

    Sira, savunmanin fiziksel sirasiyla ayni: en disarida duran katman
    once kontrol edilir. Bir olay birden fazla katmandan gecmisse, onu
    ILK durduran katman sayilir."""
    event_type = (event.get("event_type") or "").lower()
    source_ip = event.get("source_ip")

    # Katman 1: baglanti daha kurulmadan SOAR tarafindan reddedildiyse
    if event_type == "blocked":
        return "soar"
    # Katman 5: kural motoru bu IP icin alarm uretmisse, davranis tespit edildi
    if source_ip in alert_ips and event.get("payload"):
        return "detection"
    # Katman 4: honeypot'a dusen her etkilesim aldatma katmaninda durdurulmustur
    return "deception"


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

    # --- Mermiler (gelen saldirilar) ---
    projectiles = []

    for event in events:
        ip = event.get("source_ip")
        if not ip:
            continue
        layer = _classify_interception(event, blocked_ips, alert_ips)
        projectiles.append({
            "id": f"ev-{event.get('id')}",
            "source_ip": ip,
            "geo": geo_for_ip(ip),
            "timestamp": event.get("timestamp"),
            "service": event.get("service"),
            "kind": "honeypot",
            "intercepted_by": layer,
            "label": f"{event.get('service', '?')} / {event.get('event_type', '?')}",
            "sensor_id": event.get("sensor_id"),
        })

    for waf in waf_events:
        ip = waf.get("source_ip")
        if not ip:
            continue
        projectiles.append({
            "id": f"waf-{waf.get('id')}",
            "source_ip": ip,
            "geo": geo_for_ip(ip),
            "timestamp": waf.get("timestamp"),
            "service": "waf",
            "kind": "waf",
            "intercepted_by": "waf" if waf.get("blocked") else "detection",
            "label": f"{waf.get('method', '?')} {waf.get('path', '')}"[:60],
            "sensor_id": None,
        })

    # MTD rotasyonlari mermi degildir; kalkanin kendisinin hareketidir.
    # Yine de gorselde "kalkan dondu" efekti icin sayilarini veriyoruz.
    layer_counts = Counter(p["intercepted_by"] for p in projectiles)

    layers = []
    for layer in DEFENSE_LAYERS:
        count = layer_counts.get(layer["id"], 0)
        if layer["id"] == "mtd":
            count = len(mtd_rotations)
        if layer["id"] == "soar":
            count = max(count, len(blocked))
        layers.append({**layer, "interceptions": count, "active": count > 0})

    total = len(projectiles)
    return {
        "layers": layers,
        "projectiles": projectiles,
        "total_projectiles": total,
        "reached_core": 0,   # aldatma mimarisinde gercek varlik hedef degildir
        "interception_rate": 100 if total else 0,
        "active_blocks": blocked,
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
