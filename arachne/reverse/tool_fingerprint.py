"""
Saldiri araci parmak izi tespiti (attack tooling fingerprinting).

"Bu saldiriyi bir insan mi yazdi, yoksa hazir bir arac mi uretti?" sorusunu
cevaplar. Cevap savunma acisindan kritiktir:

  - Otomatik arac (sqlmap, nikto, gobuster...) -> genellikle firsatci,
    genis capli tarama. Yuksek hacim, dusuk hedefleme.
  - Elle yazilmis, araca benzemeyen yuk -> hedefli saldiri olasiligi. Daha
    az olay ama cok daha yuksek risk.

Bu ayrim, SOAR katmanindaki (Faz 7) mudahale kararini dogrudan degistirir.

Parmak izleri; araclarin varsayilan User-Agent'lari, karakteristik yuk
sozdizimi ve istek kaliplari uzerinden cikarildi. Her imza icin "neden"
alani var - hicbir tespit aciklamasiz degildir (projenin temel ilkesi).
"""
import re
from dataclasses import dataclass

# Guven skorlari: bir imza ne kadar "sadece o araca ozgu" ise o kadar yuksek.
# User-Agent taklit edilebilir (dusuk-orta guven), yuk sozdizimi cok daha zor
# taklit edilir (yuksek guven).

TOOL_SIGNATURES = {
    "sqlmap": {
        "category": "SQL Injection otomasyonu",
        "patterns": [
            (re.compile(r"sqlmap/[\d.]+", re.I), 95, "sqlmap User-Agent imzasi"),
            (re.compile(r"\bAND\s+\d+=\d+\s*(?:--|#|/\*)", re.I), 60,
             "sqlmap tarzi boolean-based test yuku"),
            (re.compile(r"\(SELECT\s+\(CASE\s+WHEN", re.I), 75,
             "sqlmap CASE-WHEN kor enjeksiyon kalibi"),
            (re.compile(r"SLEEP\(\d+\)|WAITFOR\s+DELAY|pg_sleep\(", re.I), 70,
             "zaman tabanli kor SQLi (time-based blind)"),
            (re.compile(r"\bUNION\s+ALL\s+SELECT\s+NULL", re.I), 65,
             "sqlmap UNION sutun sayisi kesfi"),
            (re.compile(r"[qQ][a-z]{4}[qQ]", ), 40,
             "sqlmap rastgele sinir isaretcisi (boundary marker)"),
        ],
        "attck": ["T1190"],
    },
    "nikto": {
        "category": "Web sunucu zafiyet tarayicisi",
        "patterns": [
            (re.compile(r"Nikto/[\d.]+", re.I), 95, "Nikto User-Agent imzasi"),
            (re.compile(r"/(?:cgi-bin|nikto-test)/", re.I), 45,
             "Nikto'nun klasik cgi-bin yoklamasi"),
        ],
        "attck": ["T1595.002"],
    },
    "nmap": {
        "category": "Ag/port tarayicisi",
        "patterns": [
            (re.compile(r"Nmap\s+Scripting\s+Engine", re.I), 95, "Nmap NSE User-Agent"),
            (re.compile(r"^GET\s+/\s+HTTP/1\.0\r?\n\r?\n$"), 55,
             "Nmap'in minimal HTTP yoklama istegi"),
            (re.compile(r"\\x00\\x00\\x00|\x00{4,}"), 35,
             "Nmap servis surumu tespiti icin NULL yoklama"),
        ],
        "attck": ["T1046", "T1595.001"],
    },
    "hydra": {
        "category": "Kimlik bilgisi brute-force araci",
        "patterns": [
            (re.compile(r"\bhydra\b", re.I), 80, "Hydra imzasi"),
            (re.compile(r"Mozilla/4\.0\s+\(Hydra\)", re.I), 95, "Hydra User-Agent"),
        ],
        "attck": ["T1110.001"],
    },
    "gobuster": {
        "category": "Dizin/icerik brute-force araci",
        "patterns": [
            (re.compile(r"gobuster/[\d.]+", re.I), 95, "gobuster User-Agent"),
        ],
        # DIKKAT: dizin brute-force T1110 DEGIL, T1595.003'tur (Wordlist
        # Scanning). MITRE'nin kendi tanimi: "amac gecerli kimlik bilgisi
        # kesfi degil, icerik/altyapi kesfidir". Bu ayrim bilincli yapildi.
        "attck": ["T1595.003"],
    },
    "dirb": {
        "category": "Dizin/icerik brute-force araci",
        "patterns": [
            (re.compile(r"\(?compatible;?\s*DIRB", re.I), 95, "DIRB User-Agent"),
        ],
        "attck": ["T1595.003"],
    },
    "ffuf": {
        "category": "Dizin/parametre fuzzer",
        "patterns": [
            (re.compile(r"Fuzz\s*Faster\s*U\s*Fool|ffuf/[\d.]+", re.I), 95, "ffuf User-Agent"),
            (re.compile(r"FUZZ", ), 30, "ffuf yer tutucu (placeholder) sizintisi"),
        ],
        "attck": ["T1595.003"],
    },
    "metasploit": {
        "category": "Sizma test cercevesi",
        "patterns": [
            (re.compile(r"meterpreter|msfconsole|metasploit", re.I), 90, "Metasploit imzasi"),
            (re.compile(r"/[A-Za-z0-9]{4}/[A-Za-z0-9]{16}\b"), 30,
             "Metasploit varsayilan payload URI kalibi"),
        ],
        "attck": ["T1190", "T1059"],
    },
    "wpscan": {
        "category": "WordPress zafiyet tarayicisi",
        "patterns": [
            (re.compile(r"WPScan\s+v?[\d.]+", re.I), 95, "WPScan User-Agent"),
            (re.compile(r"/wp-(?:login|admin|content|json)/", re.I), 35,
             "WordPress'e ozgu yol yoklamasi"),
        ],
        "attck": ["T1595.002"],
    },
    "curl": {
        "category": "Komut satiri HTTP istemcisi",
        "patterns": [
            (re.compile(r"curl/[\d.]+", re.I), 85, "curl User-Agent"),
        ],
        "attck": [],
    },
    "wget": {
        "category": "Komut satiri indirici",
        "patterns": [
            (re.compile(r"Wget/[\d.]+", re.I), 85, "Wget User-Agent"),
        ],
        "attck": [],
    },
    "python-script": {
        "category": "Ozel yazilmis script",
        "patterns": [
            (re.compile(r"python-requests/[\d.]+", re.I), 80, "python-requests User-Agent"),
            (re.compile(r"python-urllib|aiohttp/[\d.]+", re.I), 75, "Python HTTP kutuphanesi"),
        ],
        "attck": [],
    },
}


@dataclass
class ToolMatch:
    tool: str
    category: str
    confidence: int
    evidence: list          # eslesmeye yol acan aciklamalar
    attck_techniques: list

    def to_dict(self):
        return {
            "tool": self.tool,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "attck_techniques": self.attck_techniques,
        }


def fingerprint_tool(payload: str) -> list:
    """Yuk icinde bilinen saldiri araclarinin izlerini arar.

    Birden fazla arac eslesebilir (ornek: sqlmap yuku curl ile gonderilmis
    olabilir). Sonuc guven skoruna gore azalan sirada dondurulur.

    Guven birlestirme mantigi: ayni arac icin birden fazla imza eslesirse,
    en yuksek guveni alir ve her ek kanit icin +5 (tavan 99). Bunun sebebi
    bagimsiz kanitlarin birbirini guclendirmesi ama hicbir zaman %100
    kesinlik iddia etmememiz - taklit her zaman mumkundur."""
    if not payload:
        return []

    matches = []
    for tool_name, spec in TOOL_SIGNATURES.items():
        hits = []
        best = 0
        for pattern, confidence, why in spec["patterns"]:
            if pattern.search(payload):
                hits.append(why)
                best = max(best, confidence)
        if hits:
            final = min(99, best + (len(hits) - 1) * 5)
            matches.append(ToolMatch(
                tool=tool_name,
                category=spec["category"],
                confidence=final,
                evidence=hits,
                attck_techniques=list(spec.get("attck", [])),
            ))

    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


def is_automated(payload: str, min_confidence: int = 60) -> bool:
    """Yuk otomatik bir arac tarafindan mi uretilmis?

    SOAR katmani bunu kullanir: otomatik arac -> hizli, geri alinabilir
    kisitlama yeterli. Elle yazilmis hedefli yuk -> insan onayina yukselt."""
    return any(m.confidence >= min_confidence for m in fingerprint_tool(payload))
