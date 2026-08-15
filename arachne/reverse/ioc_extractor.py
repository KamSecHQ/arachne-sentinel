"""
IOC (Indicator of Compromise / Uzlasma Belirteci) cikarici.

Cozulmus bir saldiri yukunden makine-okunabilir gostergeler cikarir:
IP adresleri, alan adlari, URL'ler, dosya yollari, kabuk komutlari,
kripto para cuzdanlari, hash'ler.

Bu, tehdit istihbaratinin temel birimidir: bir saldiriyi "ilginc bir olay"
olmaktan cikarip, baska sistemlerle PAYLASILABILIR bir veriye donusturur
(bkz. arachne/intel/stix_export.py - STIX 2.1 formatinda disari aktarim).
"""
import ipaddress
import re

# --- Duzenli ifadeler -------------------------------------------------------
# Not: Bu regex'ler bilincli olarak biraz genis tutuldu; amac "hicbir sey
# kacmasin" (recall onceligi). Yanlis pozitifler _validate_* fonksiyonlariyla
# ikinci asamada eleniyor - iki asamali yaklasim, tek dev regex'ten hem daha
# okunabilir hem de hata ayiklamasi cok daha kolay.

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_URL_RE = re.compile(r"\b(?:https?|ftp|file|gopher|dict)://[^\s\"'<>\\)]{4,}", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|tk|onion|co|dev|sh|me|pw)\b", re.I
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_UNIX_PATH_RE = re.compile(r"(?:/(?:etc|bin|usr|var|tmp|root|home|proc|dev|opt)[\w./-]*)")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\\\?(?:[\w\s.-]+\\\\?)+")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")

# Kabuk/sistem komutlari - saldirganin "ne yapmak istedigini" gosterir.
# Bunlar MITRE ATT&CK T1059.004 (Unix Shell) ile eslesir.
_SHELL_COMMANDS = [
    "wget", "curl", "nc ", "netcat", "ncat", "bash -i", "sh -i", "/bin/sh",
    "/bin/bash", "python -c", "python3 -c", "perl -e", "ruby -e", "php -r",
    "chmod +x", "chmod 777", "rm -rf", "cat /etc/passwd", "cat /etc/shadow",
    "whoami", "id;", "uname -a", "ifconfig", "ip addr", "ps aux", "crontab",
    "systemctl", "service ", "kill -9", "nohup", "base64 -d", "xxd",
    "powershell", "cmd.exe", "certutil", "bitsadmin", "regsvr32", "rundll32",
    "net user", "net localgroup", "schtasks", "wmic", "mshta", "msiexec",
]

# Ters kabuk (reverse shell) kaliplari - en kritik bulgu tipi
_REVERSE_SHELL_PATTERNS = [
    re.compile(r"bash\s+-i\s*>\s*&\s*/dev/tcp/", re.I),
    re.compile(r"nc\s+(?:-[a-z]+\s+)*[\d.]+\s+\d+\s*-e\s*/bin/(?:ba)?sh", re.I),
    re.compile(r"python3?\s+-c\s+.{0,40}socket.{0,80}connect", re.I | re.S),
    re.compile(r"socket\.socket\(.{0,60}connect\(", re.I | re.S),
    re.compile(r"/dev/tcp/[\d.]+/\d+", re.I),
    re.compile(r"mkfifo\s+/tmp/", re.I),
]

_PRIVATE_HINT = ("LAB/ozel ag adresi")


def _valid_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


def _valid_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text)
        return True
    except ValueError:
        return False


def _dedupe(items):
    """Sirayi koruyarak tekrarlari siler (rapor okunakliligi icin onemli)."""
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def extract_iocs(text: str) -> dict:
    """Metinden tum IOC turlerini cikarir.

    Donen sozluk anahtarlari sabittir (bos olsa bile anahtar vardir) - bu,
    tuketici kodun `.get()` ile ugrasmasini engeller ve JSON semasini
    ongorulebilir kilar."""
    if not text:
        text = ""

    ipv4 = [ip for ip in _IPV4_RE.findall(text) if _valid_ipv4(ip)]
    ipv6 = [ip for ip in _IPV6_RE.findall(text) if _valid_ipv6(ip)]
    urls = _URL_RE.findall(text)

    # Alan adlarini bulurken URL icindekileri de yakalariz; bu istenen bir
    # davranis (URL'siz de olsa alan adi bir IOC'dir).
    domains = [d for d in _DOMAIN_RE.findall(text) if not _valid_ipv4(d)]

    lower = text.lower()
    commands = [cmd.strip() for cmd in _SHELL_COMMANDS if cmd in lower]

    reverse_shells = []
    for pattern in _REVERSE_SHELL_PATTERNS:
        match = pattern.search(text)
        if match:
            reverse_shells.append(match.group(0)[:120])

    return {
        "ipv4": _dedupe(ipv4),
        "ipv6": _dedupe(ipv6),
        "urls": _dedupe(urls),
        "domains": _dedupe(domains),
        "emails": _dedupe(_EMAIL_RE.findall(text)),
        "unix_paths": _dedupe(_UNIX_PATH_RE.findall(text)),
        "windows_paths": _dedupe(_WIN_PATH_RE.findall(text)),
        "md5": _dedupe(_MD5_RE.findall(text)),
        "sha1": _dedupe(_SHA1_RE.findall(text)),
        "sha256": _dedupe(_SHA256_RE.findall(text)),
        "bitcoin_addresses": _dedupe(_BTC_RE.findall(text)),
        "shell_commands": _dedupe(commands),
        "reverse_shells": _dedupe(reverse_shells),
    }


def ioc_count(iocs: dict) -> int:
    """Toplam IOC sayisi (bos kategoriler dahil edilmez)."""
    return sum(len(v) for v in iocs.values() if isinstance(v, list))


def classify_ip(ip: str) -> str:
    """Bir IP'yi kategorize eder.

    Donen degerler: loopback / private / documentation / reserved /
    public / invalid

    Lab ortaminda her sey 127.0.0.1'dir; bunu durustce isaretlemek,
    'sahte kuresel harita' gostermekten cok daha savunulabilir bir tercihtir
    (bkz. docs/ETHICS_AND_LEGAL.md).

    Tek dogruluk kaynagi intel.geo modulu - siniflandirma mantigi orada
    tanimli, burada sadece yeniden kullaniliyor."""
    from ..intel.geo import classify_ip_scope
    return classify_ip_scope(ip)


def summarize_iocs(iocs: dict) -> str:
    """Insan-okunabilir tek satirlik ozet (panel/rapor icin)."""
    parts = []
    labels = {
        "ipv4": "IPv4", "ipv6": "IPv6", "urls": "URL", "domains": "alan adi",
        "emails": "e-posta", "unix_paths": "Unix yolu", "windows_paths": "Windows yolu",
        "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256",
        "bitcoin_addresses": "BTC adresi", "shell_commands": "kabuk komutu",
        "reverse_shells": "TERS KABUK",
    }
    for key, label in labels.items():
        n = len(iocs.get(key, []))
        if n:
            parts.append(f"{n} {label}")
    return ", ".join(parts) if parts else "IOC bulunamadi"
