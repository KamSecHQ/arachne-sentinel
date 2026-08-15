"""
Faz 28 - D3FEND & NIST CSF 2.0 Kapsam Haritasi.

--- Amac ---
Bir savunma sistemi "cok sey yapiyorum" diyebilir; ama JURI/denetci sunu sorar:
"Hangi STANDART savunma tekniklerini, adiyla, kapsiyorsun?" Bu modul her fazi
gercek, adiyla anilan cerceve tekniklerine esler ve bir KAPSAM KARNESI cikarir.
Bu, projeyi "ad-hoc script yigini" olmaktan cikarip "tehdit-bilgili savunma"
(threat-informed defense) seviyesine tasir.

--- Eslenen cerceveler (gercek) ---
* MITRE D3FEND - savunma teknikleri taksonomisi. 7 ust taktik:
  Model, Harden, Detect, Isolate, Deceive, Evict, Restore.
* NIST CSF 2.0 - 6 fonksiyon: Govern, Identify, Protect, Detect, Respond, Recover.
* (Ilgili yerlerde) MITRE Engage aldatma aktiviteleri.

--- DURUSTLUK ---
Bu bir OZ-DEGERLENDIRME haritasidir; bir teknigi "kapsiyoruz" demek, o teknigin
CEKIRDEK MANTIGINI kucuk olcekte uyguladigimiz anlamina gelir - kurumsal bir
urunun tam olgunlugunu iddia etmez. Kapsam yuzdeleri "kac D3FEND ust-taktiginde
en az bir teknik uyguladik" gibi ACIK tanimlara dayanir; sisirilmez.

--- ETIK ---
Salt raporlama/haritalama. Hicbir eylem, hicbir dis sistem.
"""
from dataclasses import dataclass
from typing import Dict, List

# D3FEND ust taktikleri (guncel: 7 taktik).
D3FEND_TACTICS = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]

# NIST CSF 2.0 fonksiyonlari (Govern, 2.0 ile eklendi).
CSF_FUNCTIONS = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]

# Faz -> cerceve eslemesi. Her giris: fazin adi, D3FEND teknikleri (taktik:teknik),
# CSF fonksiyonlari, varsa Engage aktivitesi, ve ATT&CK karsi-teknigi.
# Bu tablo, jto jury gosterilecek "dort sutunlu" kanittir.
PHASE_MAP: List[dict] = [
    {"faz": 1, "ad": "Honeypot Aldatma Yuzeyi", "d3fend": [("Deceive", "Decoy Environment")],
     "csf": ["Detect"], "engage": "Decoy System", "attack_counters": "T1595 Active Scanning"},
    {"faz": 2, "ad": "WAF Imza Motoru", "d3fend": [("Detect", "Network Traffic Analysis"), ("Harden", "Message Hardening")],
     "csf": ["Protect", "Detect"], "engage": None, "attack_counters": "T1190 Exploit Public-Facing App"},
    {"faz": 3, "ad": "Zafiyet Tarayici", "d3fend": [("Model", "Asset Inventory")],
     "csf": ["Identify"], "engage": None, "attack_counters": "T1046 Network Service Scanning"},
    {"faz": 4, "ad": "Hareketli Hedef (MTD)", "d3fend": [("Harden", "Platform Hardening"), ("Isolate", "Network Isolation")],
     "csf": ["Protect"], "engage": "Network Manipulation", "attack_counters": "T1590 Gather Victim Network Info"},
    {"faz": 5, "ad": "Tersine Muhendislik / Cozucu", "d3fend": [("Detect", "File Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1027 Obfuscated Files"},
    {"faz": 6, "ad": "Profilleme & Kampanya", "d3fend": [("Detect", "User Behavior Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1071 Application Layer Protocol"},
    {"faz": 7, "ad": "SOAR Otomatik Mudahale", "d3fend": [("Isolate", "Network Isolation"), ("Evict", "Process Eviction")],
     "csf": ["Respond"], "engage": None, "attack_counters": "T1078 Valid Accounts"},
    {"faz": 8, "ad": "AI Analist", "d3fend": [("Detect", "Process Analysis")],
     "csf": ["Detect", "Respond"], "engage": None, "attack_counters": "-"},
    {"faz": 9, "ad": "Sensor Agi", "d3fend": [("Detect", "Network Traffic Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "-"},
    {"faz": 10, "ad": "Komuta Merkezi", "d3fend": [("Model", "Operational Dependency Mapping")],
     "csf": ["Govern", "Identify"], "engage": None, "attack_counters": "-"},
    {"faz": 11, "ad": "Aktif Savunma / Tarpit", "d3fend": [("Isolate", "Execution Isolation"), ("Deceive", "Decoy Environment")],
     "csf": ["Respond"], "engage": "Software Manipulation", "attack_counters": "T1071 C2"},
    {"faz": 12, "ad": "Honeytoken / Canary", "d3fend": [("Deceive", "Decoy Object")],
     "csf": ["Detect"], "engage": "Decoy Credentials", "attack_counters": "T1552 Unsecured Credentials"},
    {"faz": 13, "ad": "Gelismis Kodlama Cozucu / Entropi", "d3fend": [("Detect", "File Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1140 Deobfuscate/Decode"},
    {"faz": 14, "ad": "Imza Kural Motoru", "d3fend": [("Detect", "Network Traffic Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1059 Command Execution"},
    {"faz": 15, "ad": "Anomali & Flood Tespiti", "d3fend": [("Detect", "Network Traffic Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1498 Network DoS"},
    {"faz": 16, "ad": "Otomatik Imza Uretimi", "d3fend": [("Detect", "Network Traffic Analysis"), ("Model", "Attack Modeling")],
     "csf": ["Identify", "Detect"], "engage": None, "attack_counters": "-"},
    {"faz": 17, "ad": "Butunluk Zinciri (Hash/Merkle)", "d3fend": [("Detect", "File Integrity Monitoring"), ("Restore", "Restore Object")],
     "csf": ["Protect", "Recover"], "engage": None, "attack_counters": "T1565 Data Manipulation"},
    {"faz": 18, "ad": "Cok-Faktorlu Risk Skorlama", "d3fend": [("Model", "Attack Modeling")],
     "csf": ["Identify"], "engage": None, "attack_counters": "-"},
    {"faz": 19, "ad": "Saldiri Grafigi / Kill Chain", "d3fend": [("Model", "Attack Modeling")],
     "csf": ["Identify", "Detect"], "engage": None, "attack_counters": "-"},
    {"faz": 20, "ad": "Yeniden Tasarlanan Komuta Merkezi", "d3fend": [("Model", "Operational Dependency Mapping")],
     "csf": ["Govern"], "engage": None, "attack_counters": "-"},
    # --- Faz 21-30: adaptif savunma ---
    {"faz": 21, "ad": "Dusuk-ve-Yavas Tespiti (CUSUM/EWMA)", "d3fend": [("Detect", "User Behavior Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1595.001 Slow Scanning"},
    {"faz": 22, "ad": "Parmak Izi & Kimlik Rotasyonu (JA3/JA4)", "d3fend": [("Detect", "Identifier Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1090 Proxy / Identity Rotation"},
    {"faz": 23, "ad": "Aldatma Agi & Kirinti Yolu", "d3fend": [("Deceive", "Decoy Object"), ("Deceive", "Decoy Environment")],
     "csf": ["Detect"], "engage": "Lures / Decoy Content", "attack_counters": "TA0008 Lateral Movement"},
    {"faz": 24, "ad": "Topluluk Tespit Motoru (Ensemble)", "d3fend": [("Detect", "Network Traffic Analysis")],
     "csf": ["Detect"], "engage": None, "attack_counters": "T1027 Evasion"},
    {"faz": 25, "ad": "Sifir Guven Politika Motoru (800-207)", "d3fend": [("Harden", "Credential Hardening"), ("Isolate", "Network Isolation")],
     "csf": ["Protect", "Govern"], "engage": None, "attack_counters": "T1078 Valid Accounts / T1210 Lateral"},
    {"faz": 26, "ad": "Adaptif Savunma Durusu", "d3fend": [("Model", "Attack Modeling"), ("Isolate", "Network Isolation")],
     "csf": ["Respond", "Govern"], "engage": None, "attack_counters": "-"},
    {"faz": 27, "ad": "Oyun-Teorik Savunma (Stackelberg)", "d3fend": [("Model", "Attack Modeling"), ("Harden", "Platform Hardening")],
     "csf": ["Govern", "Protect"], "engage": None, "attack_counters": "-"},
    {"faz": 28, "ad": "D3FEND & CSF Kapsam Haritasi", "d3fend": [("Model", "Operational Dependency Mapping")],
     "csf": ["Govern", "Identify"], "engage": None, "attack_counters": "-"},
    {"faz": 29, "ad": "Kolektif Savunma & Paylasim (STIX)", "d3fend": [("Detect", "Network Traffic Analysis"), ("Model", "Attack Modeling")],
     "csf": ["Detect", "Govern"], "engage": None, "attack_counters": "-"},
    {"faz": 30, "ad": "Genisletilmis Cok-Katmanli Kubbe", "d3fend": [("Model", "Operational Dependency Mapping")],
     "csf": ["Govern"], "engage": None, "attack_counters": "-"},
]


@dataclass
class CoverageReport:
    d3fend_covered: Dict[str, List[str]]
    d3fend_tactic_pct: float
    csf_covered: Dict[str, List[str]]
    csf_function_pct: float
    engage_activities: List[str]
    total_phases: int
    summary_tr: str


def build_coverage() -> CoverageReport:
    """Tum fazlari tarayip D3FEND ve CSF 2.0 kapsam karnesini uretir."""
    d3fend_covered: Dict[str, List[str]] = {t: [] for t in D3FEND_TACTICS}
    csf_covered: Dict[str, List[str]] = {f: [] for f in CSF_FUNCTIONS}
    engage: List[str] = []

    for entry in PHASE_MAP:
        for tactic, technique in entry["d3fend"]:
            if tactic in d3fend_covered and technique not in d3fend_covered[tactic]:
                d3fend_covered[tactic].append(technique)
        for func in entry["csf"]:
            if func in csf_covered:
                label = f"Faz {entry['faz']}"
                csf_covered[func].append(label)
        if entry.get("engage"):
            engage.append(entry["engage"])

    covered_tactics = sum(1 for t in D3FEND_TACTICS if d3fend_covered[t])
    covered_funcs = sum(1 for f in CSF_FUNCTIONS if csf_covered[f])
    d3fend_pct = round(100.0 * covered_tactics / len(D3FEND_TACTICS), 1)
    csf_pct = round(100.0 * covered_funcs / len(CSF_FUNCTIONS), 1)

    missing_tactics = [t for t in D3FEND_TACTICS if not d3fend_covered[t]]
    summary = (
        f"{len(PHASE_MAP)} faz, {covered_tactics}/{len(D3FEND_TACTICS)} D3FEND "
        f"ust-taktigi (%{d3fend_pct:.0f}) ve {covered_funcs}/{len(CSF_FUNCTIONS)} "
        f"NIST CSF 2.0 fonksiyonu (%{csf_pct:.0f}) kapsiyor."
    )
    if missing_tactics:
        summary += f" Henuz zayif: {', '.join(missing_tactics)} (durustluk notu)."

    return CoverageReport(
        d3fend_covered=d3fend_covered,
        d3fend_tactic_pct=d3fend_pct,
        csf_covered={k: sorted(set(v)) for k, v in csf_covered.items()},
        csf_function_pct=csf_pct,
        engage_activities=sorted(set(engage)),
        total_phases=len(PHASE_MAP),
        summary_tr=summary,
    )


def coverage_matrix() -> List[dict]:
    """Panel/rapor icin duz, dort-sutunlu esleme tablosu."""
    rows = []
    for entry in PHASE_MAP:
        rows.append({
            "faz": entry["faz"],
            "ad": entry["ad"],
            "d3fend": [f"{t}: {n}" for t, n in entry["d3fend"]],
            "csf": entry["csf"],
            "engage": entry.get("engage"),
            "attack_counters": entry.get("attack_counters", "-"),
        })
    return rows
