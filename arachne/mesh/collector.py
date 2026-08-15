"""
Merkezi sensor toplayicisi - "orumcek aginin" merkezi.

Dagitik sensorlerden gelen imzali raporlari dogrular, kaydeder ve tespit
hattina besler. Panelde tum agin durumu tek ekranda gorulur.

--- Guvenlik akisi (sirasi onemli) ---
    1. Zarf yapisi kontrolu       (ucuz)
    2. Zaman damgasi / tekrar      (ucuz)
    3. HMAC imza dogrulamasi       (pahali - en sona)
    4. Payload sema dogrulamasi    (guvenilmeyen veri temizligi)
    5. Kaydet + tespit motoruna ver

3. adim gecilmeden HICBIR veri veritabanina yazilmaz. Dogrulanmamis
sensor raporlarini kabul etmek, SOAR katmanini saldirganin eline
verirdi (bkz. crypto.py aciklamasi).

--- Neden Flask Blueprint? ---
Toplayici, mevcut panel uygulamasina takilabilen bagimsiz bir bilesen
olarak tasarlandi. Boylece tek bir surecte hem panel hem toplayici
calisabilir (kucuk lab kurulumu) ya da ayri ayri calistirilabilir
(gercek dagitik senaryo) - kod degistirmeden.
"""
import ipaddress
import logging

from flask import Blueprint, jsonify, request

from .. import storage
from . import crypto

logger = logging.getLogger(__name__)

mesh_bp = Blueprint("mesh", __name__)

# Sensor raporundaki bir olayin gecerli olmasi icin gereken alanlar
REQUIRED_EVENT_FIELDS = {"source_ip", "service", "event_type"}
# Tek bir raporda kabul edilen maksimum olay sayisi (kaynak tuketimi siniri)
MAX_EVENTS_PER_REPORT = 200
MAX_PAYLOAD_LEN = 4096


def _validate_event(event: dict) -> tuple:
    """Sensorden gelen tek bir olayi dogrular ve temizler.

    Sensor DOGRULANMIS olsa bile icerigi kor kabul etmiyoruz: bir sensor
    ele gecirilmis olabilir. Derinlemesine savunma (defense in depth)
    ilkesi geregi her katman kendi girdisini dogrular."""
    if not isinstance(event, dict):
        return None, "olay bir nesne degil"

    missing = REQUIRED_EVENT_FIELDS - set(event)
    if missing:
        return None, f"eksik alanlar: {', '.join(sorted(missing))}"

    source_ip = str(event["source_ip"])[:45]
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return None, f"gecersiz IP: {source_ip}"

    payload = event.get("payload")
    if payload is not None:
        payload = str(payload)[:MAX_PAYLOAD_LEN]

    def _int_or_none(value):
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    return {
        "source_ip": source_ip,
        "service": str(event["service"])[:64],
        "event_type": str(event["event_type"])[:64],
        "source_port": _int_or_none(event.get("source_port")),
        "dest_port": _int_or_none(event.get("dest_port")),
        "payload": payload,
    }, None


@mesh_bp.route("/mesh/ingest", methods=["POST"])
def ingest():
    """Sensor raporu alma uc noktasi.

    Basarisiz dogrulamalar 401 doner ve KAYDEDILIR - basarisiz kimlik
    dogrulama denemelerinin kendisi bir guvenlik sinyalidir."""
    envelope = request.get_json(silent=True)
    if envelope is None:
        return jsonify({"ok": False, "error": "Gecersiz JSON"}), 400

    valid, reason = crypto.verify_message(envelope)
    if not valid:
        remote = request.remote_addr or "bilinmiyor"
        logger.warning("Sensor dogrulamasi basarisiz (%s): %s", remote, reason)
        try:
            storage.log_mesh_event(
                sensor_id=str(envelope.get("payload", {}).get("sensor_id", "bilinmiyor"))[:64]
                if isinstance(envelope.get("payload"), dict) else "bilinmiyor",
                status="reddedildi", detail=reason, event_count=0,
                remote_addr=remote,
            )
        except Exception:
            pass
        return jsonify({"ok": False, "error": "Dogrulama basarisiz", "reason": reason}), 401

    payload = envelope["payload"]
    sensor_id = str(payload.get("sensor_id", "isimsiz-sensor"))[:64]
    events = payload.get("events", [])

    if not isinstance(events, list):
        return jsonify({"ok": False, "error": "events bir dizi olmali"}), 400
    if len(events) > MAX_EVENTS_PER_REPORT:
        return jsonify({
            "ok": False,
            "error": f"Cok fazla olay (max {MAX_EVENTS_PER_REPORT})",
        }), 413

    accepted, rejected = 0, []
    for raw_event in events:
        clean, error = _validate_event(raw_event)
        if error:
            rejected.append(error)
            continue
        try:
            storage.log_event(
                source_ip=clean["source_ip"],
                service=clean["service"],
                event_type=clean["event_type"],
                source_port=clean["source_port"],
                dest_port=clean["dest_port"],
                payload=clean["payload"],
                sensor_id=sensor_id,
            )
            accepted += 1
        except Exception:
            logger.exception("Olay kaydedilemedi")
            rejected.append("veritabani hatasi")

    try:
        storage.register_sensor(
            sensor_id=sensor_id,
            location=str(payload.get("location", ""))[:120],
            version=str(payload.get("version", ""))[:32],
            event_count=accepted,
        )
        storage.log_mesh_event(
            sensor_id=sensor_id, status="kabul", detail=f"{accepted} olay islendi",
            event_count=accepted, remote_addr=request.remote_addr or "",
        )
    except Exception:
        logger.exception("Sensor kaydi guncellenemedi")

    # Tespit hattini tetikle: mesh'ten gelen olaylar da skorlamaya girer.
    # Bu, aglar arasi korelasyonun calistigi noktadir - bir sensordeki
    # davranis, digerindeki gecmisle birlikte degerlendirilir.
    scored = []
    try:
        from ..detection.scorer import evaluate_ip
        for ip in {e.get("source_ip") for e in events if isinstance(e, dict)}:
            if not ip:
                continue
            result = evaluate_ip(str(ip))
            if result.get("triggered_alert"):
                scored.append({"ip": ip, "score": result["score"],
                               "severity": result["severity"]})
    except Exception:
        logger.exception("Mesh olaylari skorlanamadi")

    return jsonify({
        "ok": True,
        "sensor_id": sensor_id,
        "accepted": accepted,
        "rejected": len(rejected),
        "rejection_reasons": rejected[:5],
        "alerts_triggered": scored,
    })


@mesh_bp.route("/mesh/status", methods=["GET"])
def mesh_status():
    """Ag durumu - kayitli sensorler ve saglik bilgileri."""
    try:
        sensors = storage.get_sensors()
        recent = storage.get_mesh_events(limit=50)
    except Exception:
        sensors, recent = [], []

    return jsonify({
        "sensors": sensors,
        "sensor_count": len(sensors),
        "online_count": sum(1 for s in sensors if s.get("online")),
        "recent_activity": recent,
        "using_default_secret": crypto.using_default_secret(),
        "replay_window_seconds": crypto.REPLAY_WINDOW_SECONDS,
        "nonce_cache_size": crypto.nonce_cache_size(),
    })
