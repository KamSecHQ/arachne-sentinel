"""
Faz 102 - Opsiyonel dis tehdit istihbarati zenginlestirmesi (KARANTINA).

--- Mimari: ayni karantina ilkesi, bu sefer bir LLM icin degil dis bir
    tehdit istihbarati API'si icin (AbuseIPDB / AlienVault OTX) ---

    Deterministik tespit motoru (Faz 1-2)  <- KARARI BU VERIR
        |
        +--> SOAR mudahale  ..... dis API'ye HIC BAKMADAN calisir
        |
        v
    [KARANTINA tehdit istihbarati sorgusu]  <- sadece PUBLIC IP'ler icin
        |                                       (lab/private/loopback ASLA
        |                                        disariya gonderilmez)
        v
    [Risk motorunda kucuk, aciklanabilir bir EK faktor]

Tasiyici cumle: **Dis istihbarat ZENGINLESTIRIR, KARAR VERMEZ.** AbuseIPDB/OTX
erisilemez olsa, kota dolsa ya da yanlis veri donse bile, engelleme kararlari
tamamen deterministik kural motorunda kalir - bu modul opsiyoneldir ve
KAPALIYKEN sistem hicbir sey kaybetmez (ayni `llm_backend.py` felsefesi).

--- Anahtar yonetimi ---
Anahtarlar SADECE ortam degiskeninden okunur (ARACHNE_ABUSEIPDB_API_KEY,
ARACHNE_OTX_API_KEY). Kod/veritabaninda ASLA saklanmaz. Anahtar yoksa o
kaynak sessizce atlanir - digeri varsa o calismaya devam eder.

--- Lab guvenligi ---
Loopback/ozel/RFC 5737 dokumantasyon adresleri ASLA dis bir API'ye
gonderilmez (bkz. `arachne.intel.geo.classify_ip_scope`) - hem gereksiz
hem de yanlis yorumlanabilir sinyal uretir (ornegin 127.0.0.1 hicbir
tehdit istihbarati kaynaginda kayitli olamaz)."""
import json
import logging
import os
import time

from . import geo
from .. import storage

logger = logging.getLogger(__name__)

ENV_ENABLED = "ARACHNE_THREAT_INTEL_ENABLED"
ENV_ABUSEIPDB_KEY = "ARACHNE_ABUSEIPDB_API_KEY"
ENV_OTX_KEY = "ARACHNE_OTX_API_KEY"

MAX_CALLS_PER_HOUR = 60
REQUEST_TIMEOUT_SECONDS = 10
CACHE_MAX_AGE_SECONDS = 3600  # 1 saat - ucretsiz API kotalarina saygi

_call_times = []


def is_enabled() -> bool:
    """Dis tehdit istihbarati sorgusu kullanilabilir mi?

    Acikca etkinlestirilmis olmali VE en az bir anahtar bulunmali. Varsayilan
    KAPALIdir - guvenli varsayilan ilkesi (bkz. llm_backend.is_enabled)."""
    if os.environ.get(ENV_ENABLED, "").lower() not in ("1", "true", "yes", "evet"):
        return False
    return bool(os.environ.get(ENV_ABUSEIPDB_KEY) or os.environ.get(ENV_OTX_KEY))


def status() -> dict:
    """Panelde gosterilecek durum (anahtarlari ASLA sizdirmaz)."""
    return {
        "enabled": is_enabled(),
        "abuseipdb_key_present": bool(os.environ.get(ENV_ABUSEIPDB_KEY)),
        "otx_key_present": bool(os.environ.get(ENV_OTX_KEY)),
        "calls_last_hour": len(_recent_calls()),
        "rate_limit": MAX_CALLS_PER_HOUR,
        "mode_tr": (
            "Karantina tehdit istihbarati aktif (zenginlestirme modu)" if is_enabled()
            else "Kapali - sistem sadece kendi deterministik motoruyla calisir"
        ),
    }


def _recent_calls():
    cutoff = time.time() - 3600
    return [t for t in _call_times if t > cutoff]


def _rate_limited() -> bool:
    global _call_times
    _call_times = _recent_calls()
    return len(_call_times) >= MAX_CALLS_PER_HOUR


def lookup_ip(ip: str, db_path=None) -> dict:
    """Bir public IP icin dis tehdit istihbaratini sorgular.

    Basarisizlik/kapali/lab-IP/kota durumunda None doner - cagiran taraf
    HER ZAMAN None kontrolu yapip sessizce devam etmelidir. ASLA istisna
    firlatmaz."""
    if not is_enabled():
        return None

    scope = geo.classify_ip_scope(ip)
    if scope != "public":
        # Lab/private/dokumantasyon trafigini gercek bir dis API'ye
        # gondermek hem gereksiz hem yanlis yorumlanabilir sinyal uretir.
        return None

    result = {"ip": ip, "sources": {}}
    found_any = False

    if os.environ.get(ENV_ABUSEIPDB_KEY):
        abuse = _lookup_abuseipdb(ip, db_path=db_path)
        if abuse is not None:
            result["sources"]["abuseipdb"] = abuse
            found_any = True

    if os.environ.get(ENV_OTX_KEY):
        otx = _lookup_otx(ip, db_path=db_path)
        if otx is not None:
            result["sources"]["otx"] = otx
            found_any = True

    if not found_any:
        return None

    result["abuse_confidence_score"] = result["sources"].get(
        "abuseipdb", {}).get("abuse_confidence_score", 0)
    result["otx_pulse_count"] = result["sources"].get(
        "otx", {}).get("pulse_count", 0)
    return result


def _lookup_abuseipdb(ip: str, db_path=None) -> dict:
    cached = storage.get_cached_threat_intel(ip, "abuseipdb", CACHE_MAX_AGE_SECONDS,
                                              db_path=db_path)
    if cached is not None:
        cached = dict(cached)
        cached["_cached"] = True
        return cached

    if _rate_limited():
        logger.warning("Tehdit istihbarati kota siniri asildi (%s/saat)",
                       MAX_CALLS_PER_HOUR)
        return None

    try:
        raw = _call_abuseipdb(ip)
    except Exception as exc:
        logger.warning("AbuseIPDB cagrisi basarisiz (%s)", exc)
        return None

    if raw is None:
        return None

    parsed = {
        "abuse_confidence_score": raw.get("abuseConfidenceScore", 0),
        "total_reports": raw.get("totalReports", 0),
        "is_public": raw.get("isPublic", True),
        "usage_type": raw.get("usageType"),
        "_cached": False,
    }
    _call_times.append(time.time())
    storage.cache_threat_intel(ip, "abuseipdb", parsed, db_path=db_path)
    return parsed


def _lookup_otx(ip: str, db_path=None) -> dict:
    cached = storage.get_cached_threat_intel(ip, "otx", CACHE_MAX_AGE_SECONDS,
                                              db_path=db_path)
    if cached is not None:
        cached = dict(cached)
        cached["_cached"] = True
        return cached

    if _rate_limited():
        logger.warning("Tehdit istihbarati kota siniri asildi (%s/saat)",
                       MAX_CALLS_PER_HOUR)
        return None

    try:
        raw = _call_otx(ip)
    except Exception as exc:
        logger.warning("OTX cagrisi basarisiz (%s)", exc)
        return None

    if raw is None:
        return None

    pulse_info = raw.get("pulse_info", {}) or {}
    parsed = {
        "pulse_count": pulse_info.get("count", 0),
        "reputation": raw.get("reputation", 0),
        "_cached": False,
    }
    _call_times.append(time.time())
    storage.cache_threat_intel(ip, "otx", parsed, db_path=db_path)
    return parsed


def _call_abuseipdb(ip: str):
    """AbuseIPDB'nin /api/v2/check uc noktasini cagirir.

    Bilincli olarak SADECE stdlib (urllib) kullanir - bkz. llm_backend.py'nin
    ayni gerekcesi: kurulum kucuk kalir, hangi verinin nereye gittigi tek
    bakista gorulur."""
    import urllib.parse
    import urllib.request

    api_key = os.environ.get(ENV_ABUSEIPDB_KEY, "")
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({
        "ipAddress": ip, "maxAgeInDays": 90,
    })
    request = urllib.request.Request(url, headers={
        "Key": api_key, "Accept": "application/json",
    })
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        data = json.loads(response.read().decode("utf-8"))
    return data.get("data")


def _call_otx(ip: str):
    """AlienVault OTX'in /indicators/IPv4/{ip}/general uc noktasini cagirir."""
    import urllib.request

    api_key = os.environ.get(ENV_OTX_KEY, "")
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    request = urllib.request.Request(url, headers={"X-OTX-API-KEY": api_key})
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def analyze_recent(db_path=None, since_seconds=3600) -> dict:
    """Panel/aggregator icin 0-guvenli ozet - son donemdeki saldirgan IP'lerden
    (public olanlardan) onbellekte zenginlestirme verisi var mi gosterir.

    ONEMLI: bu fonksiyon YENI dis API cagrisi YAPMAZ (sadece onbellegi okur) -
    boylece panel her poll dongusunde kotayi tuketmez. Gercek sorgu sadece
    `lookup_ip()` acikca cagirildiginda (CLI/SOAR entegrasyonu) yapilir."""
    safe_default = {
        "enabled": is_enabled(),
        "enriched_ip_count": 0,
        "high_risk_ips": [],
        "by_source": {},
    }
    try:
        events = storage.get_recent_events(since_seconds=since_seconds, db_path=db_path)
        ips = {e["source_ip"] for e in events if e.get("source_ip")}
        high_risk = []
        for ip in ips:
            cached = storage.get_cached_threat_intel(
                ip, "abuseipdb", CACHE_MAX_AGE_SECONDS, db_path=db_path)
            if cached and cached.get("abuse_confidence_score", 0) >= 50:
                high_risk.append({"ip": ip, "abuse_confidence_score":
                                  cached["abuse_confidence_score"]})
        stats = storage.threat_intel_cache_stats(db_path=db_path)
        safe_default["enriched_ip_count"] = stats.get("total_cached", 0)
        safe_default["by_source"] = stats.get("by_source", {})
        safe_default["high_risk_ips"] = sorted(
            high_risk, key=lambda x: -x["abuse_confidence_score"])[:10]
        return safe_default
    except Exception:
        logger.debug("threat_intel.analyze_recent basarisiz", exc_info=True)
        return safe_default
