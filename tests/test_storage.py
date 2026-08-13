import tempfile
from pathlib import Path

from arachne import storage


def _tmp_db():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=tmp)
    return tmp


def test_log_and_read_event():
    db = _tmp_db()
    storage.log_event("1.2.3.4", "ssh", "connect", source_port=1111, dest_port=2222,
                       db_path=db)
    events = storage.get_recent_events(source_ip="1.2.3.4", db_path=db)
    assert len(events) == 1
    assert events[0]["service"] == "ssh"
    assert events[0]["event_type"] == "connect"


def test_log_alert_and_prior_alert_flag():
    db = _tmp_db()
    assert storage.has_prior_alert("9.9.9.9", db_path=db) is False
    storage.log_alert("9.9.9.9", 55, "medium", ["test sebebi"], db_path=db)
    assert storage.has_prior_alert("9.9.9.9", db_path=db) is True
    alerts = storage.get_all_alerts(db_path=db)
    assert alerts[0]["source_ip"] == "9.9.9.9"
    assert alerts[0]["severity"] == "medium"


def test_summary_stats_counts_events_and_top_ips():
    db = _tmp_db()
    for i in range(3):
        storage.log_event("5.5.5.5", "ftp", "connect", db_path=db)
    storage.log_event("6.6.6.6", "ftp", "connect", db_path=db)
    stats = storage.summary_stats(db_path=db)
    assert stats["total_events"] == 4
    assert stats["top_ips"][0] == ("5.5.5.5", 3)
