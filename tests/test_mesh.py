"""Faz 9 - Dagitik sensor agi testleri.

Bu testlerin en kritik bolumu kriptografik dogrulamadir: dogrulanmamis
sensor raporlarini kabul eden bir SOAR sistemi, saldirganin elinde
silaha donusur (sahte raporlarla masum IP'leri engelletebilir).
"""
import json
import tempfile
import time
from pathlib import Path

import pytest

from arachne import storage
from arachne.mesh import crypto
from arachne.mesh.sensor import Sensor


def _tmp_db():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=tmp)
    return tmp


@pytest.fixture(autouse=True)
def _clean_nonces():
    crypto.clear_nonce_cache()
    yield
    crypto.clear_nonce_cache()


# --- Kriptografik imzalama --------------------------------------------------

def test_signed_message_verifies():
    envelope = crypto.sign_message({"sensor_id": "s1", "events": []}, secret="gizli")
    valid, reason = crypto.verify_message(envelope, secret="gizli")
    assert valid is True, reason


def test_wrong_secret_is_rejected():
    envelope = crypto.sign_message({"sensor_id": "s1"}, secret="dogru-sir")
    valid, reason = crypto.verify_message(envelope, secret="yanlis-sir")
    assert valid is False
    assert "imza" in reason.lower()


def test_tampered_payload_is_rejected():
    """Mesaj icerigi degistirilirse imza tutmaz - butunluk garantisi."""
    envelope = crypto.sign_message({"sensor_id": "s1", "events": ["a"]}, secret="s")
    envelope["payload"]["events"] = ["kotu-niyetli-veri"]
    valid, _ = crypto.verify_message(envelope, secret="s")
    assert valid is False


def test_tampered_signature_is_rejected():
    envelope = crypto.sign_message({"sensor_id": "s1"}, secret="s")
    envelope["signature"] = "0" * 64
    assert crypto.verify_message(envelope, secret="s")[0] is False


def test_replay_of_same_nonce_is_rejected():
    """Tekrar oynatma korumasi: ayni mesaj iki kez kabul edilemez."""
    envelope = crypto.sign_message({"sensor_id": "s1"}, secret="s")
    assert crypto.verify_message(envelope, secret="s")[0] is True
    valid, reason = crypto.verify_message(envelope, secret="s")
    assert valid is False
    assert "nonce" in reason.lower()


def test_old_message_is_rejected():
    envelope = crypto.sign_message({"sensor_id": "s1"}, secret="s")
    envelope["timestamp"] = int(time.time()) - (crypto.REPLAY_WINDOW_SECONDS + 60)
    envelope["signature"] = crypto._compute_signature(envelope, "s")
    valid, reason = crypto.verify_message(envelope, secret="s")
    assert valid is False
    assert "eski" in reason.lower()


def test_future_message_is_rejected():
    envelope = crypto.sign_message({"sensor_id": "s1"}, secret="s")
    envelope["timestamp"] = int(time.time()) + (crypto.REPLAY_WINDOW_SECONDS + 60)
    envelope["signature"] = crypto._compute_signature(envelope, "s")
    assert crypto.verify_message(envelope, secret="s")[0] is False


def test_missing_fields_are_rejected():
    for field in ("payload", "timestamp", "nonce", "signature"):
        envelope = crypto.sign_message({"sensor_id": "s1"}, secret="s")
        del envelope[field]
        valid, reason = crypto.verify_message(envelope, secret="s")
        assert valid is False
        assert field in reason


def test_non_dict_envelope_is_rejected():
    assert crypto.verify_message("bu bir zarf degil", secret="s")[0] is False
    assert crypto.verify_message(None, secret="s")[0] is False


def test_nonces_are_unique():
    nonces = {crypto.generate_nonce() for _ in range(500)}
    assert len(nonces) == 500


def test_canonical_json_is_key_order_independent():
    """Ayni sozluk, farkli sirayla -> AYNI imza. Aksi halde dogrulama
    rastgele basarisiz olur (hata ayiklamasi cok zor bir hata sinifi)."""
    a = crypto.canonical_json({"b": 2, "a": 1})
    b = crypto.canonical_json({"a": 1, "b": 2})
    assert a == b


def test_signatures_differ_for_different_payloads():
    e1 = crypto.sign_message({"x": 1}, secret="s")
    e2 = crypto.sign_message({"x": 2}, secret="s")
    assert e1["signature"] != e2["signature"]


def test_default_lab_secret_is_detectable():
    """Varsayilan sir kullaniliyorsa panelde uyari gosterilebilmeli."""
    assert isinstance(crypto.using_default_secret(), bool)


# --- Sensor istemcisi -------------------------------------------------------

def test_sensor_queues_observations():
    sensor = Sensor("test-01", location="lab")
    sensor.observe("203.0.113.5", "ssh", "connect", dest_port=22)
    sensor.observe("203.0.113.5", "ssh", "data", payload="test")
    assert sensor.pending_count() == 2
    assert sensor.stats["observed"] == 2


def test_sensor_queue_drops_oldest_when_full():
    """Kuyruk dolunca EN ESKI dusurulur - saldiri sirasinda yeni veri
    daha degerlidir."""
    sensor = Sensor("test-02", queue_size=3)
    for i in range(5):
        sensor.observe(f"203.0.113.{i}", "ssh", "connect")
    assert sensor.pending_count() == 3
    assert sensor.stats["dropped"] == 2


def test_sensor_builds_valid_signed_report():
    sensor = Sensor("test-03", location="DMZ", secret="paylasilan-sir")
    envelope = sensor.build_report([{"source_ip": "203.0.113.9", "service": "ssh",
                                      "event_type": "connect"}])
    valid, reason = crypto.verify_message(envelope, secret="paylasilan-sir")
    assert valid is True, reason
    assert envelope["payload"]["sensor_id"] == "test-03"
    assert envelope["payload"]["location"] == "DMZ"


def test_sensor_report_is_json_serializable():
    sensor = Sensor("test-04")
    envelope = sensor.build_report([{"source_ip": "203.0.113.10", "service": "ftp",
                                      "event_type": "connect"}])
    json.dumps(envelope)


def test_sensor_flush_with_empty_queue_is_noop():
    sensor = Sensor("test-05")
    result = sensor.flush()
    assert result["ok"] is True
    assert result["sent"] == 0


def test_sensor_requeues_events_on_network_failure():
    """Gecici ag kesintisinde veri kaybolmamali (at-least-once teslimat)."""
    sensor = Sensor("test-06", collector_url="http://127.0.0.1:1/mesh/ingest")
    sensor.observe("203.0.113.11", "ssh", "connect")
    result = sensor.flush()
    assert result["ok"] is False
    assert sensor.pending_count() == 1     # olay geri konuldu
    assert sensor.stats["failed"] == 1


def test_sensor_status_reports_health():
    sensor = Sensor("test-07", location="bulut")
    sensor.observe("203.0.113.12", "mysql", "connect")
    status = sensor.status()
    assert status["sensor_id"] == "test-07"
    assert status["location"] == "bulut"
    assert status["pending"] == 1


# --- Sensor kaydi ve depolama -----------------------------------------------

def test_register_sensor_creates_and_updates():
    db = _tmp_db()
    storage.register_sensor("s-01", location="DMZ", version="1.0",
                            event_count=5, db_path=db)
    sensors = storage.get_sensors(db_path=db)
    assert len(sensors) == 1
    assert sensors[0]["total_events"] == 5

    storage.register_sensor("s-01", event_count=3, db_path=db)
    sensors = storage.get_sensors(db_path=db)
    assert len(sensors) == 1                     # yeni kayit acmadi
    assert sensors[0]["total_events"] == 8       # toplam guncellendi


def test_sensor_online_status_is_computed():
    db = _tmp_db()
    storage.register_sensor("s-02", db_path=db)
    sensors = storage.get_sensors(db_path=db)
    assert sensors[0]["online"] is True


def test_mesh_log_records_rejected_reports():
    """Basarisiz kimlik dogrulama denemeleri KAYDEDILMELI - bunlar birer
    guvenlik sinyalidir."""
    db = _tmp_db()
    storage.log_mesh_event("sahte-sensor", "reddedildi",
                           detail="imza dogrulanamadi", db_path=db)
    events = storage.get_mesh_events(db_path=db)
    assert len(events) == 1
    assert events[0]["status"] == "reddedildi"


def test_mesh_summary_stats():
    db = _tmp_db()
    storage.register_sensor("s-03", event_count=10, db_path=db)
    storage.log_mesh_event("s-03", "kabul", event_count=10, db_path=db)
    storage.log_mesh_event("kotu", "reddedildi", db_path=db)
    stats = storage.mesh_summary_stats(db_path=db)
    assert stats["sensor_count"] == 1
    assert stats["total_reports_accepted"] == 1
    assert stats["total_reports_rejected"] == 1


def test_events_store_sensor_id():
    """Mesh'ten gelen olaylar hangi sensorden geldigini tasimali."""
    db = _tmp_db()
    storage.log_event("203.0.113.20", "ssh", "connect",
                      sensor_id="kenar-01", db_path=db)
    events = storage.get_recent_events(source_ip="203.0.113.20", db_path=db)
    assert events[0]["sensor_id"] == "kenar-01"


# --- Toplayici (uctan uca, gercek Flask test istemcisi) --------------------

def _collector_app(db_path):
    """Test icin izole bir toplayici uygulamasi olusturur."""
    from flask import Flask
    from arachne.mesh.collector import mesh_bp

    app = Flask(__name__)
    app.register_blueprint(mesh_bp)
    app.config["TESTING"] = True
    return app


def test_collector_accepts_valid_signed_report(monkeypatch):
    db = _tmp_db()
    monkeypatch.setattr("arachne.config.DB_PATH", db)
    app = _collector_app(db)

    sensor = Sensor("kenar-01", location="DMZ")
    envelope = sensor.build_report([
        {"source_ip": "203.0.113.30", "service": "ssh", "event_type": "connect",
         "dest_port": 22},
    ])

    with app.test_client() as client:
        response = client.post("/mesh/ingest", json=envelope)
        assert response.status_code == 200
        data = response.get_json()
        assert data["ok"] is True
        assert data["accepted"] == 1


def test_collector_rejects_unsigned_report(monkeypatch):
    """Imzasiz rapor 401 almali ve HICBIR veri kaydedilmemeli."""
    db = _tmp_db()
    monkeypatch.setattr("arachne.config.DB_PATH", db)
    app = _collector_app(db)

    with app.test_client() as client:
        response = client.post("/mesh/ingest", json={
            "payload": {"sensor_id": "sahte", "events": [
                {"source_ip": "1.2.3.4", "service": "ssh", "event_type": "connect"}]},
            "timestamp": int(time.time()), "nonce": "abc", "signature": "sahte",
        })
        assert response.status_code == 401
        assert response.get_json()["ok"] is False

    assert storage.get_recent_events(source_ip="1.2.3.4", db_path=db) == []


def test_collector_rejects_malformed_events_but_keeps_valid_ones(monkeypatch):
    """Derinlemesine savunma: sensor dogrulanmis olsa bile icerik dogrulanir."""
    db = _tmp_db()
    monkeypatch.setattr("arachne.config.DB_PATH", db)
    app = _collector_app(db)

    sensor = Sensor("kenar-02")
    envelope = sensor.build_report([
        {"source_ip": "203.0.113.40", "service": "ssh", "event_type": "connect"},
        {"source_ip": "gecersiz-ip", "service": "ssh", "event_type": "connect"},
        {"service": "eksik-alanlar"},
    ])

    with app.test_client() as client:
        data = client.post("/mesh/ingest", json=envelope).get_json()
        assert data["accepted"] == 1
        assert data["rejected"] == 2


def test_collector_rejects_oversized_report(monkeypatch):
    db = _tmp_db()
    monkeypatch.setattr("arachne.config.DB_PATH", db)
    app = _collector_app(db)

    sensor = Sensor("kenar-03")
    events = [{"source_ip": "203.0.113.50", "service": "ssh", "event_type": "connect"}
              for _ in range(500)]
    envelope = sensor.build_report(events)

    with app.test_client() as client:
        assert client.post("/mesh/ingest", json=envelope).status_code == 413


def test_collector_status_endpoint(monkeypatch):
    db = _tmp_db()
    monkeypatch.setattr("arachne.config.DB_PATH", db)
    storage.register_sensor("s-99", location="test", db_path=db)
    app = _collector_app(db)

    with app.test_client() as client:
        data = client.get("/mesh/status").get_json()
        assert "sensors" in data
        assert data["replay_window_seconds"] == crypto.REPLAY_WINDOW_SECONDS
