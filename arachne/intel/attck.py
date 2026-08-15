"""
MITRE ATT&CK / CWE / CAPEC eslemesi ve Lockheed Martin Cyber Kill Chain.

Bu modul bilincli olarak SAF VERIdir - hicbir sey import etmez, hicbir yan
etkisi yoktur. Boylece hem `reverse` hem `intel` hem `soar` katmanlari
dairesel bagimlilik olmadan kullanabilir.

--- Neden bu kadar detayli ID esliyoruz? ---
"SQL Injection tespit edildi" demek bir seydir; "T1190 Exploit Public-Facing
Application, CWE-89, CAPEC-66, Kill Chain: Exploitation" demek bambaska bir
seydir. Ikincisi, bulgumuzu dunyanin geri kalaniyla ayni dili konusan bir
veriye donusturur - SIEM'e, tehdit istihbarati platformuna, bir baska
kuruma aktarilabilir hale getirir.

--- ONEMLI GUNCELLIK NOTU (ATT&CK v19, Nisan 2026) ---
MITRE, "Defense Evasion" taktigini yeniden adlandirdi:
  * TA0005 artik "Stealth" (eski adi: Defense Evasion)
  * TA0112 "Defense Impairment" yeni bir taktik olarak eklendi
Bu dosya GUNCEL isimleri kullanir. Internetteki cogu ogretici hala eski
ismi kullaniyor; biz birincil kaynagi (MITRE CTI STIX paketi) esas aldik.

Kaynaklar:
  https://attack.mitre.org/
  https://cwe.mitre.org/
  https://capec.mitre.org/
  https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
"""

# --- ATT&CK Enterprise taktikleri (guncel, matris sirasinda) ----------------
TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",              # v19'da "Defense Evasion" iken degisti
    "TA0112": "Defense Impairment",   # v19'da eklendi
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

TACTIC_TR = {
    "Reconnaissance": "Kesif",
    "Resource Development": "Kaynak Gelistirme",
    "Initial Access": "Ilk Erisim",
    "Execution": "Calistirma",
    "Persistence": "Kalicilik",
    "Privilege Escalation": "Yetki Yukseltme",
    "Stealth": "Gizlenme",
    "Defense Impairment": "Savunmayi Etkisizlestirme",
    "Credential Access": "Kimlik Bilgisi Erisimi",
    "Discovery": "Kesfetme",
    "Lateral Movement": "Yanal Hareket",
    "Collection": "Toplama",
    "Command and Control": "Komuta ve Kontrol",
    "Exfiltration": "Veri Sizdirma",
    "Impact": "Etki",
}

# --- Teknik katalogu --------------------------------------------------------
# Her kayit: teknik ID -> (isim, taktik, kill chain asamasi)
TECHNIQUES = {
    "T1595":     ("Active Scanning", "Reconnaissance", "reconnaissance"),
    "T1595.001": ("Scanning IP Blocks", "Reconnaissance", "reconnaissance"),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance", "reconnaissance"),
    "T1595.003": ("Wordlist Scanning", "Reconnaissance", "reconnaissance"),
    "T1046":     ("Network Service Discovery", "Discovery", "reconnaissance"),
    "T1592":     ("Gather Victim Host Information", "Reconnaissance", "reconnaissance"),
    "T1590":     ("Gather Victim Network Information", "Reconnaissance", "reconnaissance"),
    "T1110":     ("Brute Force", "Credential Access", "exploitation"),
    "T1110.001": ("Password Guessing", "Credential Access", "exploitation"),
    "T1110.003": ("Password Spraying", "Credential Access", "exploitation"),
    "T1110.004": ("Credential Stuffing", "Credential Access", "exploitation"),
    "T1190":     ("Exploit Public-Facing Application", "Initial Access", "exploitation"),
    "T1059":     ("Command and Scripting Interpreter", "Execution", "installation"),
    "T1059.004": ("Unix Shell", "Execution", "installation"),
    "T1059.003": ("Windows Command Shell", "Execution", "installation"),
    "T1059.006": ("Python", "Execution", "installation"),
    "T1059.007": ("JavaScript", "Execution", "installation"),
    "T1083":     ("File and Directory Discovery", "Discovery", "reconnaissance"),
    "T1027":     ("Obfuscated Files or Information", "Stealth", "weaponization"),
    "T1027.010": ("Command Obfuscation", "Stealth", "weaponization"),
    "T1027.013": ("Encrypted/Encoded File", "Stealth", "weaponization"),
    "T1140":     ("Deobfuscate/Decode Files or Information", "Stealth", "weaponization"),
    "T1505.003": ("Web Shell", "Persistence", "installation"),
    "T1078":     ("Valid Accounts", "Initial Access", "exploitation"),
    "T1071":     ("Application Layer Protocol", "Command and Control", "command-and-control"),
    "T1499":     ("Endpoint Denial of Service", "Impact", "actions-on-objectives"),
    "T1082":     ("System Information Discovery", "Discovery", "reconnaissance"),
}

# --- Lockheed Martin Cyber Kill Chain (kanonik 7 asama) --------------------
KILL_CHAIN = [
    ("reconnaissance", "Kesif", "Hedef hakkinda bilgi toplama"),
    ("weaponization", "Silahlandirma", "Exploit + payload birlestirme"),
    ("delivery", "Teslimat", "Silahin hedefe iletilmesi"),
    ("exploitation", "Sömürü", "Zafiyetin tetiklenmesi"),
    ("installation", "Kurulum", "Kalici arka kapi yerlestirme"),
    ("command-and-control", "Komuta-Kontrol", "Uzaktan yonetim kanali"),
    ("actions-on-objectives", "Hedefe Ulasma", "Asil amacin gerceklestirilmesi"),
]
KILL_CHAIN_ORDER = {name: i for i, (name, _, _) in enumerate(KILL_CHAIN)}
KILL_CHAIN_TR = {name: tr for name, tr, _ in KILL_CHAIN}

# --- Saldiri sinifi -> cerceve eslemesi ------------------------------------
# ATT&CK teknik seviyesinde bilincli olarak soyuttur: SQLi icin ayri bir
# teknik YOKTUR. Profesyonel yaklasim, ATT&CK'i CWE/CAPEC ile birlikte
# tasimaktir - biz de oyle yapiyoruz.
ATTACK_CLASS_MAP = {
    "SQL Injection": {
        "attck": ["T1190"],
        "cwe": ["CWE-89"],
        "capec": ["CAPEC-66"],
        "description_tr": "Veritabani sorgusuna kotu niyetli girdi enjekte etme",
    },
    "XSS": {
        "attck": ["T1059.007"],
        "cwe": ["CWE-79"],
        "capec": ["CAPEC-63"],
        "description_tr": "Kurbanin tarayicisinda script calistirma",
    },
    "Command Injection": {
        "attck": ["T1190", "T1059.004"],
        "cwe": ["CWE-77", "CWE-78"],
        "capec": ["CAPEC-248"],
        "description_tr": "Isletim sistemi kabuk komutu calistirma",
    },
    "Path Traversal": {
        "attck": ["T1190", "T1083"],
        # CAPEC-213 KULLANMIYORUZ - o ID artik gecersiz (deprecated).
        "cwe": ["CWE-22", "CWE-23"],
        "capec": ["CAPEC-126", "CAPEC-139"],
        "description_tr": "Izin verilen dizinin disina cikarak dosya okuma",
    },
    "Port Scan": {
        "attck": ["T1046", "T1595.001"],
        "cwe": [],
        "capec": ["CAPEC-300"],
        "description_tr": "Acik servisleri kesfetmek icin port tarama",
    },
    "Brute Force": {
        "attck": ["T1110.001"],
        "cwe": ["CWE-307"],
        "capec": ["CAPEC-49"],
        "description_tr": "Tekrarli kimlik dogrulama denemesi",
    },
    "Directory Brute Force": {
        "attck": ["T1595.003"],
        "cwe": [],
        "capec": ["CAPEC-127"],
        "description_tr": "Kelime listesiyle gizli dizin/dosya arama",
    },
    "Obfuscation": {
        "attck": ["T1027.010"],
        "cwe": [],
        "capec": ["CAPEC-267"],
        "description_tr": "Imza tabanli savunmayi atlatmak icin yuku gizleme",
    },
    "Web Shell": {
        "attck": ["T1505.003"],
        "cwe": ["CWE-434"],
        "capec": ["CAPEC-650"],
        "description_tr": "Sunucuya kalici uzaktan erisim arayuzu yerlestirme",
    },
    "Reverse Shell": {
        "attck": ["T1059.004", "T1071"],
        "cwe": ["CWE-78"],
        "capec": ["CAPEC-248"],
        "description_tr": "Kurbandan saldirgana geri baglanan kabuk",
    },
    "Service Discovery": {
        "attck": ["T1046"],
        "cwe": [],
        "capec": ["CAPEC-300"],
        "description_tr": "Calisan servisleri ve surumlerini belirleme",
    },
}


def technique_info(technique_id: str) -> dict:
    """Bir teknik ID'si icin tam bilgi dondurur (bilinmiyorsa guvenli varsayilan)."""
    name, tactic, kc = TECHNIQUES.get(
        technique_id, ("Bilinmeyen Teknik", "Discovery", "reconnaissance")
    )
    return {
        "id": technique_id,
        "name": name,
        "tactic": tactic,
        "tactic_tr": TACTIC_TR.get(tactic, tactic),
        "kill_chain_phase": kc,
        "kill_chain_phase_tr": KILL_CHAIN_TR.get(kc, kc),
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }


def map_attack_class(attack_class: str) -> dict:
    """Bir saldiri sinifini (ornek: 'SQL Injection') tum cerceve ID'lerine esler."""
    spec = ATTACK_CLASS_MAP.get(attack_class)
    if not spec:
        return {
            "attack_class": attack_class,
            "attck": [], "cwe": [], "capec": [],
            "techniques": [], "description_tr": "",
            "kill_chain_phase": "reconnaissance",
        }
    techniques = [technique_info(tid) for tid in spec["attck"]]
    # Kill chain asamasi olarak en ILERI asamayi aliriz: bir saldiri hem
    # kesif hem somuru iceriyorsa, tehdit seviyesi somuruye gore belirlenir.
    phase = "reconnaissance"
    for t in techniques:
        if KILL_CHAIN_ORDER.get(t["kill_chain_phase"], 0) > KILL_CHAIN_ORDER.get(phase, 0):
            phase = t["kill_chain_phase"]
    return {
        "attack_class": attack_class,
        "attck": list(spec["attck"]),
        "cwe": list(spec["cwe"]),
        "capec": list(spec["capec"]),
        "techniques": techniques,
        "description_tr": spec["description_tr"],
        "kill_chain_phase": phase,
        "kill_chain_phase_tr": KILL_CHAIN_TR.get(phase, phase),
    }


def furthest_kill_chain_phase(phases) -> str:
    """Verilen asamalar arasindaki en ileri (en tehlikeli) olani dondurur."""
    best = None
    best_rank = -1
    for p in phases:
        rank = KILL_CHAIN_ORDER.get(p, -1)
        if rank > best_rank:
            best, best_rank = p, rank
    return best or "reconnaissance"


def kill_chain_progress(phases) -> dict:
    """Saldirganin kill chain'de ne kadar ilerledigini yuzde olarak verir.

    Bir juri/yonetici sunumunda 'saldirgan zincirin %57'sine ulasti' ifadesi,
    teknik ID listesinden cok daha anlasilirdir."""
    reached = furthest_kill_chain_phase(phases)
    rank = KILL_CHAIN_ORDER.get(reached, 0)
    return {
        "phase": reached,
        "phase_tr": KILL_CHAIN_TR.get(reached, reached),
        "stage_index": rank + 1,
        "total_stages": len(KILL_CHAIN),
        "progress_pct": round(((rank + 1) / len(KILL_CHAIN)) * 100),
    }
