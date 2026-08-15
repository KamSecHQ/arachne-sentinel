"""
Faz 5 - Saldiri Tersine Muhendisligi (Attack Reverse Engineering).

Bu modul, yakalanan bir saldiri yukunu (payload) "acar": katman katman
kodlamayi cozer, icinden IOC (Indicator of Compromise) cikarir, saldirganin
hangi araci kullandigini parmak izinden tespit eder ve sonucu MITRE ATT&CK
teknik ID'lerine esler.

ONEMLI ETIK NOT: Buradaki "tersine muhendislik" ifadesi, BASKASININ YAZILIMINI
kirmak/kopyalamak anlaminda DEGILDIR. Bize gelen saldirinin kendisini
analiz etmeyi kasteder - yani savunma amacli adli bilisim (defensive
forensics). Hicbir harici sisteme dokunmaz, sadece kendi honeypot/WAF
kayitlarimizi isler.
"""

from .deobfuscator import deobfuscate, DecodeStep
from .ioc_extractor import extract_iocs
from .tool_fingerprint import fingerprint_tool
from .attack_analyzer import analyze_payload, analyze_ip

__all__ = [
    "deobfuscate",
    "DecodeStep",
    "extract_iocs",
    "fingerprint_tool",
    "analyze_payload",
    "analyze_ip",
]
