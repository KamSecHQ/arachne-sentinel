import socket
import threading
import time

from arachne.scanner import known_vulnerabilities, port_scanner


def test_known_vulnerabilities_lookup_matches():
    result = known_vulnerabilities.lookup("220 (vsFTPd 2.3.4)")
    assert result is not None
    assert result["cve"] == "CVE-2011-2523"


def test_known_vulnerabilities_lookup_no_match():
    assert known_vulnerabilities.lookup("220 ProFTPD 1.3.8 Server ready") is None


def test_known_vulnerabilities_lookup_empty():
    assert known_vulnerabilities.lookup("") is None
    assert known_vulnerabilities.lookup(None) is None


def _start_dummy_server(port, banner=b"TEST-BANNER\r\n"):
    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        s.settimeout(3)
        try:
            conn, _ = s.accept()
            conn.sendall(banner)
            conn.close()
        except socket.timeout:
            pass
        finally:
            s.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.2)
    return t


def test_scan_port_detects_open_port_and_banner():
    port = 34567
    _start_dummy_server(port)
    is_open, banner = port_scanner.scan_port("127.0.0.1", port, timeout=2.0)
    assert is_open is True
    assert "TEST-BANNER" in banner


def test_scan_port_reports_closed_port():
    # 1 numarali port genelde kapali/erisilemezdir test ortaminda
    is_open, banner = port_scanner.scan_port("127.0.0.1", 1, timeout=0.5)
    assert is_open is False
