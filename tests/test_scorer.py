import tempfile
from pathlib import Path

from arachne import storage
from arachne.detection import scorer


def _tmp_db():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=tmp)
    return tmp


def test_evaluate_ip_no_events_returns_low_severity():
    db = _tmp_db()
    result = scorer.evaluate_ip("1.1.1.1", db_path=db)
    assert result["score"] == 0
    assert result["severity"] == "low"
    assert result["triggered_alert"] is False


def test_evaluate_ip_triggers_alert_and_persists_it():
    db = _tmp_db()
    ip = "2.2.2.2"
    # Brute-force + coklu servis + bilinen imza uretecek sekilde olay ekleyelim
    for _ in range(5):
        storage.log_event(ip, "ssh", "connect", dest_port=2222, db_path=db)
    storage.log_event(ip, "ftp", "connect", dest_port=2121, db_path=db)
    storage.log_event(ip, "http-admin", "data", dest_port=8081,
                       payload="user=admin' OR '1'='1", db_path=db)

    result = scorer.evaluate_ip(ip, db_path=db)

    assert result["triggered_alert"] is True
    assert result["score"] >= 30
    assert result["severity"] in ("medium", "high", "critical")
    assert len(result["reasons"]) >= 2

    stored_alerts = storage.get_all_alerts(db_path=db)
    assert len(stored_alerts) == 1
    assert stored_alerts[0]["source_ip"] == ip


def test_evaluate_ip_marks_repeated_offender_on_second_pass():
    db = _tmp_db()
    ip = "3.3.3.3"
    for _ in range(5):
        storage.log_event(ip, "ssh", "connect", dest_port=2222, db_path=db)
    first = scorer.evaluate_ip(ip, db_path=db)
    assert first["triggered_alert"] is True

    storage.log_event(ip, "ssh", "connect", dest_port=2222, db_path=db)
    second = scorer.evaluate_ip(ip, db_path=db)
    assert any("tekrarlayan saldirgan" in r for r in second["reasons"])
