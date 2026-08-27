"""Faz 104 - CEF/syslog disa aktarim testleri.

Gercek internet cagrisi YOK - SyslogSender testleri sadece 127.0.0.1'deki
gecici (ephemeral) bir yerel UDP soketine gonderim yapar."""
import socket

from arachne import storage
from arachne.siem import exporter, normalizer


# --- CEF kacis kurallari -----------------------------------------------------

def test_cef_header_escapes_pipe_and_backslash():
    assert exporter._cef_escape_header("a|b\\c") == "a\\|b\\\\c"


def test_cef_extension_escapes_equals_and_backslash():
    assert exporter._cef_escape_extension("key=value\\x") == "key\\=value\\\\x"


def test_cef_extension_escapes_newlines():
    assert exporter._cef_escape_extension("line1\nline2\r\nline3") == \
        "line1\\nline2\\nline3"


def test_to_cef_payload_with_pipe_and_equals_does_not_break_header():
    normalized = normalizer.normalize_event({
        "source_ip": "203.0.113.5", "service": "http-admin", "event_type": "data",
        "payload": "user=admin|pass=1234\nSECOND=INJECTED", "timestamp": "2026-01-01 00:00:00",
        "dest_port": 8081, "source_port": 55000,
    })
    cef = exporter.to_cef(normalized)
    header = cef.split("|", 7)
    # Baslikta tam olarak 7 pipe-ayrilmis alan olmali (CEF:0|Vendor|Product|
    # Version|SigID|Name|Severity|Extension) - yuk icindeki '|' hicbirini
    # kirmamis olmali.
    assert header[0] == "CEF:0"
    assert header[1] == "ArachneSentinel"
    # Extension icindeki '=' kacirilmis olmali - sahte bir CEF alani
    # enjekte edilmemis olmali.
    assert "SECOND=INJECTED" not in cef
    assert "\\=" in cef  # kacirilmis '=' iceriyor


def test_to_cef_includes_source_ip_and_port():
    normalized = normalizer.normalize_event({
        "source_ip": "203.0.113.5", "service": "ssh", "event_type": "connect",
        "payload": "", "timestamp": "2026-01-01 00:00:00",
        "dest_port": 2222, "source_port": 44000,
    })
    cef = exporter.to_cef(normalized)
    assert "src=203.0.113.5" in cef
    assert "spt=44000" in cef
    assert "dpt=2222" in cef


# --- RFC 3164 syslog satiri ---------------------------------------------------

def test_syslog_pri_computation():
    line = exporter.to_syslog_line("test", facility=1, severity=5)
    # PRI = facility*8 + severity = 1*8+5 = 13
    assert line.startswith(b"<13>")


def test_syslog_line_contains_hostname_and_tag():
    line = exporter.to_syslog_line("merhaba", hostname="myhost", tag="MyTag")
    text = line.decode()
    assert "myhost" in text
    assert "MyTag: merhaba" in text


# --- SyslogSender: yapilandirilmamis -> ag cagrisi yok ----------------------

def test_sender_unconfigured_by_default(monkeypatch):
    monkeypatch.delenv("ARACHNE_SIEM_HOST", raising=False)
    sender = exporter.SyslogSender()
    assert sender.is_configured() is False
    assert sender.send(b"test") is False


def test_sender_send_failure_does_not_raise():
    """Ulasilamayan bir hedefe (kullanilmayan lokal port) gonderim UDP'de
    genelde sessizce basarili donebilir (baglanti-suz protokol); yine de
    fonksiyon ASLA istisna firlatmamali."""
    sender = exporter.SyslogSender(host="127.0.0.1", port=1, protocol="tcp", timeout=0.5)
    assert sender.send(b"test") is False  # port 1 TCP'de kimse dinlemiyor olmali


# --- Gercek ama YEREL UDP round-trip (gercek internet cagrisi yok) ----------

def test_sender_delivers_to_local_udp_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(2)
        port = listener.getsockname()[1]

        sender = exporter.SyslogSender(host="127.0.0.1", port=port, protocol="udp")
        line = exporter.to_syslog_line("test-mesaji")
        assert sender.send(line) is True

        received, _ = listener.recvfrom(4096)
        assert received == line
        assert b"test-mesaji" in received


# --- export_recent: varsayilan olarak ag cagrisi yok ------------------------

def test_export_recent_without_sink_makes_no_network_call(tmp_path):
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    storage.log_event("203.0.113.5", "ssh", "connect", db_path=db)
    storage.log_event("203.0.113.5", "ssh", "data", payload="' OR 1=1--", db_path=db)

    result = exporter.export_recent(db_path=db, sink=None)
    assert result["count"] == 2
    assert result["sent"] == 0
    assert len(result["sample"]) <= 3
    for line in result["lines"]:
        assert line.startswith("<")  # syslog PRI onceki


def test_export_recent_empty_db_returns_zero_safe(tmp_path):
    db = str(tmp_path / "empty.db")
    storage.init_db(db_path=db)
    result = exporter.export_recent(db_path=db)
    assert result["count"] == 0
    assert result["lines"] == []


def test_export_recent_with_sink_sends_each_line(tmp_path):
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    storage.log_event("203.0.113.5", "ftp", "connect", db_path=db)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(2)
        port = listener.getsockname()[1]

        sender = exporter.SyslogSender(host="127.0.0.1", port=port)
        result = exporter.export_recent(db_path=db, sink=sender)
        assert result["sent"] == result["count"] == 1

        received, _ = listener.recvfrom(4096)
        assert b"ftp" in received or b"connect" in received
