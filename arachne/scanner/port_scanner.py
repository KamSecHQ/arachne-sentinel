"""Basit, bagimliliksiz (nmap gerektirmeyen) port tarayici ve banner grabber."""
import socket

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
    2222: "ssh-alt", 2121: "ftp-alt", 3307: "mysql-alt", 8081: "http-alt2",
}


def _grab_banner(sock) -> str:
    try:
        sock.settimeout(1.5)
        data = sock.recv(256)
        return data.decode(errors="replace").strip()
    except (socket.timeout, OSError):
        return ""


def scan_port(host: str, port: int, timeout: float = 1.0):
    """Tek bir portu tarar. Aciksa (is_open=True, banner) doner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = _grab_banner(sock)
            return True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, ""


def scan_target(host: str, ports=None, timeout: float = 1.0):
    """Verilen hedefteki portlari tarar.

    Donen: list[dict] - her acik port icin {"port", "service_guess", "banner"}
    """
    ports = ports or COMMON_PORTS
    results = []
    for port in ports:
        is_open, banner = scan_port(host, port, timeout=timeout)
        if is_open:
            results.append({
                "port": port,
                "service_guess": COMMON_PORTS.get(port, "bilinmiyor"),
                "banner": banner,
            })
    return results
