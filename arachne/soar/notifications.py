"""
Faz 110 - Musteriye giden kritik olay bildirimi (webhook).

--- Neden gerekli? ---
Faz 1-109'a kadar tum "haber verme" mekanizmasi canli komuta merkeziydi -
birinin panele bakiyor olmasi gerekiyordu. Bunu gercek bir musteriye
satilabilir hale getirmek icin, kritik bir olay oldugunda (Son Hat devreye
girdi, kritik siddette alarm) müşteriye DISARI, aktif olarak haber
verilmesi gerekir - panel sadece pasif bir goruntu olmamali.

--- Guvenli varsayilan (ayni karantina ilkesi) ---
Musteri profili (`arachne.customer.profile`) bir webhook URL'si
icermiyorsa HICBIR AG CAGRISI YAPILMAZ - `llm_backend.py`/`threat_intel.py`
ile birebir ayni "acikca yapilandirilmadan disariya hicbir sey gitmez"
ilkesi. Bildirim basarisiz olsa/zaman asimina ugrasa bile ASLA istisna
firlatmaz - bir bildirim sorunu cekirdek savunma kararlarini ETKILEYEMEZ.

--- Veri minimizasyonu ---
Webhook'a SADECE tehdit metadatasi gider: kaynak IP, skor, siddet, olay
turu, kisa bir aciklama. Honeypot'a gelen ham payload, musteri profilinin
iletisim bilgileri (e-posta/webhook URL'sinin kendisi) ya da veritabani
icerigi ASLA gonderilmez. Format duz JSON - Slack/Discord/Teams/generic
webhook alicilarinin hepsi (bir "Incoming Webhook" ayarlamasiyla) bunu
okuyabilir.
"""
import json
import logging
import time

from ..customer import profile as customer_profile

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 8
MAX_NOTIFICATIONS_PER_HOUR = 30  # musterinin webhook'unu spam'lememe kotasi

_send_times = []


def _recent_sends():
    cutoff = time.time() - 3600
    return [t for t in _send_times if t > cutoff]


def _rate_limited() -> bool:
    global _send_times
    _send_times = _recent_sends()
    return len(_send_times) >= MAX_NOTIFICATIONS_PER_HOUR


def status() -> dict:
    prof = customer_profile.load_profile()
    return {
        "webhook_configured": bool(prof.get("alert_webhook_url")),
        "notifications_last_hour": len(_recent_sends()),
        "rate_limit": MAX_NOTIFICATIONS_PER_HOUR,
    }


def notify_critical_event(event_type: str, source_ip: str, severity: str,
                          score: int = None, detail: str = "") -> bool:
    """Kritik bir olayi musteri webhook'una gonderir.

    Donen deger sadece TESHIS/test amaclidir (gonderildi mi?) - cagiran
    taraf bunu ASLA bir hata olarak ele almamali; bildirim basarisiz olsa
    bile savunma/SOAR/Son Hat akisi aynen devam eder."""
    try:
        prof = customer_profile.load_profile()
        webhook_url = prof.get("alert_webhook_url")
        if not webhook_url:
            return False

        if _rate_limited():
            logger.warning("Musteri webhook kota siniri asildi (%s/saat) - "
                           "bildirim atlaniyor", MAX_NOTIFICATIONS_PER_HOUR)
            return False

        payload = {
            "product": "Arachne Sentinel",
            "asset_name": prof.get("asset_name"),
            "event_type": event_type,
            "source_ip": source_ip,
            "severity": severity,
            "score": score,
            "detail": (detail or "")[:300],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        _send(webhook_url, payload)
        _send_times.append(time.time())
        return True
    except Exception as exc:
        logger.warning("Musteri webhook gonderimi basarisiz (%s)", exc)
        return False


def _send(url: str, payload: dict):
    """Sadece stdlib (urllib) - bkz. llm_backend.py/threat_intel.py'nin
    ayni gerekcesi: kurulum kucuk kalir, hangi verinin nereye gittigi tek
    bakista gorulur."""
    import urllib.request

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        response.read()


def clear_rate_limit():
    """Bellekteki gonderim sayacini temizler (testler icin)."""
    global _send_times
    _send_times = []
