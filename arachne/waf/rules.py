"""
WAF icin regex tabanli imza kurallari.

honeypot tarafinda (arachne/detection/rules.py) basit alt-string eslesmesi
yeterliydi çünkü orada gercek bir uygulama korunmuyordu, sadece davranis
gozlemleniyordu. Burada gercek istekleri filtreledigimiz icin daha az
yanlis pozitif ureten, regex tabanli imzalar kullaniyoruz.
"""
import re

# Her kural: (kategori adi, derlenmis regex, agirlik)
_PATTERNS = [
    ("SQL Injection", re.compile(
        r"(\bunion\b[\s\S]{1,80}\bselect\b)|('\s*or\s*'?\d+'?\s*=\s*'?\d+)|"
        r"(;\s*drop\s+table)|(\bxp_cmdshell\b)|(\bsleep\s*\(\s*\d+\s*\))|"
        r"(\bor\s+1\s*=\s*1\b)", re.IGNORECASE), 60),
    ("XSS", re.compile(
        r"(<script[\s>])|(javascript\s*:)|(on(error|load|click)\s*=)|"
        r"(<img[^>]+onerror)", re.IGNORECASE), 55),
    ("Command Injection", re.compile(
        r"(;\s*cat\s+/etc/passwd)|(&&\s*whoami)|(\|\s*nc\s+)|(\$\()|(`[^`]+`)",
        re.IGNORECASE), 60),
    ("Path Traversal", re.compile(
        r"(\.\./){2,}|(\.\.\\){2,}|(/etc/passwd\b)", re.IGNORECASE), 50),
]

# Cok kisa surede ayni IP'den gelen istek sayisi bu esigi asarsa
# "olasi DDoS/asiri istek" olarak isaretlenir (bkz. middleware.py).
RATE_LIMIT_WINDOW_SECONDS = 10
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WEIGHT = 60


def scan_text(text: str):
    """Verilen metni tum imzalara karsi tarar, (kategori, agirlik) listesi doner."""
    hits = []
    if not text:
        return hits
    for category, pattern, weight in _PATTERNS:
        if pattern.search(text):
            hits.append((category, weight))
    return hits
