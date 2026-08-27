"""
Faz 107 - Opsiyonel NVD (National Vulnerability Database) CVE zenginlestirmesi.

`known_vulnerabilities.py` (Faz 2) kendi docstring'inde zaten durustce
soyluyor: "Gercek bir urunde NVD API gibi guncel bir kaynakla
degistirilmesi gerekir." Bu modul o statik listeyi DEGISTIRMEZ - onun
YANINA, ayni karantina/opsiyonel mimariyi (bkz. `ai/llm_backend.py`,
`intel/threat_intel.py`) izleyen bir EK katman ekler.

--- Guvenli varsayilan ---
Varsayilan olarak KAPALIDIR (ARACHNE_NVD_ENABLED). Kapaliyken/basarisiz
oldugunda `vuln_scanner.py` sessizce SADECE statik listeyle calismaya
devam eder - REGRESYON YOK. API anahtari (ARACHNE_NVD_API_KEY) opsiyoneldir,
sadece NVD'nin kota sinirini yukseltir (anahtarsiz 5 istek/30sn, anahtarli
50 istek/30sn - bkz. NVD API dokumantasyonu); istemci tarafinda bu kotaya
saygi duyan basit bir kayan-pencere hiz sinirlayici uygulanir ("iyi
internet vatandasi" ilkesi).

--- Onbellekleme ---
Sonuclar SQLite'a (`storage.nvd_cache`) 24 saat TTL ile onbelleklenir - hem
kotaya saygi hem de ayni demo kosusunun tekrar tekrar ayni sorguyu
yapmamasi icin."""
import json
import logging
import os
import time

from .. import storage

logger = logging.getLogger(__name__)

ENV_ENABLED = "ARACHNE_NVD_ENABLED"
ENV_API_KEY = "ARACHNE_NVD_API_KEY"

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECONDS = 15
CACHE_MAX_AGE_SECONDS = 86400  # 24 saat

_RATE_WINDOW_SECONDS = 30
_call_times = []


def is_enabled() -> bool:
    """Varsayilan KAPALI - guvenli varsayilan ilkesi (bkz. llm_backend.is_enabled)."""
    return os.environ.get(ENV_ENABLED, "").lower() in ("1", "true", "yes", "evet")


def status() -> dict:
    """Panelde gosterilecek durum (anahtari ASLA sizdirmaz)."""
    has_key = bool(os.environ.get(ENV_API_KEY))
    return {
        "enabled": is_enabled(),
        "api_key_present": has_key,
        "rate_limit_per_30s": 50 if has_key else 5,
        "mode_tr": (
            "NVD zenginlestirmesi aktif" if is_enabled()
            else "Kapali - tarayici sadece statik known_vulnerabilities "
                 "listesiyle calisir (bkz. ARACHNE_NVD_ENABLED)"
        ),
    }


def _rate_limited() -> bool:
    global _call_times
    limit = 50 if os.environ.get(ENV_API_KEY) else 5
    cutoff = time.time() - _RATE_WINDOW_SECONDS
    _call_times = [t for t in _call_times if t > cutoff]
    return len(_call_times) >= limit


def lookup_by_keyword(keyword: str, db_path=None) -> list:
    """Bir urun/banner anahtar kelimesiyle NVD'de CVE arar.

    Basarisizlik/kapali/kota durumunda BOS LISTE doner - istisna ASLA
    firlatilmaz; cagiran taraf (vuln_scanner) bunu "NVD'den ek bulgu yok"
    olarak yorumlar ve statik listeyle calismaya devam eder."""
    if not is_enabled() or not keyword or not keyword.strip():
        return []

    cache_key = keyword.strip().lower()
    cached = storage.get_cached_nvd_query(cache_key, CACHE_MAX_AGE_SECONDS, db_path=db_path)
    if cached is not None:
        return cached

    if _rate_limited():
        logger.warning("NVD kota siniri asildi (%ssn penceresi) - bu sorgu atlaniyor",
                       _RATE_WINDOW_SECONDS)
        return []

    try:
        raw = _call_nvd(keyword)
    except Exception as exc:
        logger.warning("NVD cagrisi basarisiz (%s)", exc)
        return []

    if raw is None:
        return []

    _call_times.append(time.time())
    results = _parse_nvd_response(raw)
    storage.cache_nvd_query(cache_key, results, db_path=db_path)
    return results


def _call_nvd(keyword: str):
    """NVD CVE 2.0 REST API'sini cagirir. Sadece stdlib (urllib) kullanir -
    bkz. llm_backend.py/threat_intel.py'nin ayni gerekcesi."""
    import urllib.parse
    import urllib.request

    url = NVD_BASE_URL + "?" + urllib.parse.urlencode({
        "keywordSearch": keyword, "resultsPerPage": 5,
    })
    headers = {"Accept": "application/json"}
    api_key = os.environ.get(ENV_API_KEY)
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def _parse_nvd_response(raw: dict) -> list:
    """NVD CVE 2.0 JSON semasini kucuk, sabit bir dict listesine indirger."""
    results = []
    for item in (raw.get("vulnerabilities") or [])[:5]:
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue

        descriptions = cve.get("descriptions", []) or []
        description = next((d.get("value", "") for d in descriptions
                            if d.get("lang") == "en"),
                           descriptions[0].get("value", "") if descriptions else "")

        severity = "unknown"
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {}) or {}
                severity = cvss_data.get("baseSeverity") or entries[0].get(
                    "baseSeverity", "unknown")
                break

        results.append({
            "cve": cve_id,
            "description": description[:300],
            "severity": str(severity).lower(),
            "source": "nvd",
        })
    return results
