"""
Faz 35 - 9-Asamali Saldiri Zinciri Siniflandiricisi (Attack Chain Stager).

--- Fikir ---
Tek bir olayin "SQLi" ya da "port tarama" olmasi bir seydir; ama bir
saldirganin ZINCIRIN NERESINDE oldugunu bilmek bambaska bir seydir. Bu modul,
her olayi/saldirgani 9 kanonik asamaya yerlestirir ve her asamada Gok Kubbe
(dome) savunma katmanlarindan HANGISININ devreye girdigini soyler. Boylece
"Attack Replay" gorsellestirmesi Kesif -> ... -> Sizdirma yolunu oynatabilir
ve her adimda hangi kalkanin kalktigini gosterebilir.

--- Gercek cerceve eslemesi ---
9 asama, iki yerlesik modelin birlesimidir:
  * Lockheed Martin Cyber Kill Chain (kesif -> hedefe ulasma)
  * MITRE ATT&CK Enterprise taktikleri (TA00xx)
Her asama, `STAGE_MITRE` icinde birincil ATT&CK taktigine eslenir. ATT&CK'te
"Scanning" ayri bir taktik DEGILDIR (aktif tarama T1595/T1046 teknikleridir);
bu yuzden onu en yakin taktik olan Discovery'ye (TA0007) esliyoruz - bu
bilincli bir modelleme karari, uydurma bir ID degil.

--- DURUSTLUK NOTU ---
Bu bir asama TAHMINIDIR, kesin bir yargi degildir. Tek bir HTTP istegi cogu
zaman birden fazla asamaya uyabilir (ornek: bir komut enjeksiyonu hem
"Execution" hem "Initial Access" sinyali tasir). Siniflandirici en guclu
sinyali secer ve `confidence` (0..1) ile ne kadar emin oldugunu durustce
bildirir. Asama, bir engelleme karari TEK BASINA vermez - karar deterministik
kural motorunda (Faz 1) kalir; bu katman yalnizca zenginlestirir ve
gorsellestirir.

--- Savunma-amacli etik not ---
Buradaki hicbir kalip bir saldiriyi URETMEZ ya da YURUTMEZ; yalnizca kendi
honeypot/WAF kayitlarimizda GOZLEMLENEN saldirilari siniflandirir. Ag yok,
dosya yok, yan etki yok - saf, deterministik siniflandirma.
"""
import re
from dataclasses import dataclass, field

from ..waf import rules as waf_rules

# --- 9 kanonik asama (zincir sirasinda) ------------------------------------
STAGES = [
    "Reconnaissance",
    "Scanning",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Lateral Movement",
    "Exfiltration",
]
STAGE_INDEX = {stage: i for i, stage in enumerate(STAGES)}

# Asama -> Turkce ad (panel/rapor icin)
STAGE_TR = {
    "Reconnaissance": "Kesif",
    "Scanning": "Tarama",
    "Initial Access": "Ilk Erisim",
    "Execution": "Calistirma",
    "Persistence": "Kalicilik",
    "Privilege Escalation": "Yetki Yukseltme",
    "Credential Access": "Kimlik Bilgisi Erisimi",
    "Lateral Movement": "Yanal Hareket",
    "Exfiltration": "Veri Sizdirma",
}

# --- Asama -> birincil MITRE ATT&CK taktigi (id + isim) ---------------------
# "Scanning" -> Discovery (TA0007): aktif tarama ATT&CK'te ayri taktik degil,
# en yakin taktik Discovery'dir. Digerleri birebir taktik karsiligina eslesir.
STAGE_MITRE = {
    "Reconnaissance":       {"id": "TA0043", "name": "Reconnaissance"},
    "Scanning":             {"id": "TA0007", "name": "Discovery"},
    "Initial Access":       {"id": "TA0001", "name": "Initial Access"},
    "Execution":            {"id": "TA0002", "name": "Execution"},
    "Persistence":          {"id": "TA0003", "name": "Persistence"},
    "Privilege Escalation": {"id": "TA0004", "name": "Privilege Escalation"},
    "Credential Access":    {"id": "TA0006", "name": "Credential Access"},
    "Lateral Movement":     {"id": "TA0008", "name": "Lateral Movement"},
    "Exfiltration":         {"id": "TA0010", "name": "Exfiltration"},
}

# --- Asama -> devreye giren Gok Kubbe (dome) savunma katmani ----------------
# Gerekce (her esleme bir savunma mantigina dayanir):
#   Reconnaissance       -> deception     : kesif yapani sahte varliklarla oyala
#   Scanning             -> detection      : tarama imza/anomali motoruyla goze carpar
#   Initial Access       -> waf            : somuru yukunu WAF gecirmez/filtreler
#   Execution            -> detection      : komut calistirma davranissal tespitle yakalanir
#   Persistence          -> honeytoken     : cron/webshell/anahtar bIrakinca honeytoken tetiklenir
#   Privilege Escalation -> zero_trust     : yetki yukseltme zero-trust dogrulamayla durur
#   Credential Access    -> honeytoken     : sahte kimlik/token'a dokunmak alarm uretir
#   Lateral Movement     -> deception_grid : yanal hareket sahte ag IzgarasIna dusurulur
#   Exfiltration         -> soar           : sizdirma girisimi SOAR otomasyonuyla mudahale gorur
STAGE_DEFENSE_LAYER = {
    "Reconnaissance":       "deception",
    "Scanning":             "detection",
    "Initial Access":       "waf",
    "Execution":            "detection",
    "Persistence":          "honeytoken",
    "Privilege Escalation": "zero_trust",
    "Credential Access":    "honeytoken",
    "Lateral Movement":     "deception_grid",
    "Exfiltration":         "soar",
}

# --- Asama basina imza kaliplari --------------------------------------------
# Her kalip: (derlenmis regex, insan-okunabilir gosterge etiketi). Kaliplar
# uzerinde eslesen etiketler `indicators` alaninda dondurulur - hicbir tespit
# aciklamasiz degildir (projenin temel ilkesi).
_STAGE_PATTERNS = {
    "Reconnaissance": [
        (re.compile(r"robots\.txt", re.I), "robots.txt yoklamasi"),
        (re.compile(r"sitemap\.xml", re.I), "sitemap.xml yoklamasi"),
        (re.compile(r"/\.well-known", re.I), ".well-known kesfi"),
        (re.compile(r"\b(nikto|nmap|masscan|zgrab|shodan|censys|whatweb|wpscan)\b",
                    re.I), "tarayici User-Agent imzasi"),
        (re.compile(r"favicon\.ico", re.I), "favicon parmak izi yoklamasi"),
    ],
    "Scanning": [
        (re.compile(r"\b(gobuster|dirbuster|dirb|ffuf|feroxbuster|nuclei)\b",
                    re.I), "dizin/path fuzzing araci"),
        (re.compile(r"/(admin|phpmyadmin|wp-admin|wp-login|manager|console)\b",
                    re.I), "yaygin yonetici path taramasi"),
        (re.compile(r"/(\.env|\.git|\.svn|backup|config\.php|\.bak)\b", re.I),
         "hassas dosya/dizin taramasi"),
        (re.compile(r"\bFUZZ\b"), "fuzzing yer tutucusu (FUZZ)"),
    ],
    "Initial Access": [
        (re.compile(r"\$\{jndi:", re.I), "Log4Shell (JNDI) somuru yuku"),
        (re.compile(r"\(\s*\)\s*\{\s*:;\s*\}\s*;", re.I),
         "Shellshock somuru yuku"),
        (re.compile(r"(\.\./){2,}|(\.\.\\){2,}", re.I), "path traversal somurusu"),
        (re.compile(r"\bunion\b[\s\S]{1,80}\bselect\b", re.I),
         "SQLi UNION somuru yuku"),
    ],
    "Execution": [
        (re.compile(r";\s*(cat|ls|id|whoami|uname|pwd)\b", re.I),
         "zincirlenmis kabuk komutu"),
        (re.compile(r"/bin/(ba)?sh\b|cmd\.exe|powershell", re.I),
         "kabuk yorumlayici cagrisi"),
        (re.compile(r"\b(system|exec|passthru|shell_exec|popen|eval)\s*\(",
                    re.I), "kod calistirma fonksiyonu"),
        (re.compile(r"\$\(|`[^`]+`"), "komut ikamesi (command substitution)"),
    ],
    "Persistence": [
        (re.compile(r"(crontab|/etc/cron|/var/spool/cron)", re.I),
         "cron ile kalicilik"),
        (re.compile(r"authorized_keys|\.ssh/id_", re.I),
         "SSH authorized_keys manipulasyonu"),
        (re.compile(r"<\?php[\s\S]{0,40}(eval|system|assert)\s*\(", re.I),
         "webshell yerlestirme"),
        (re.compile(r"(rc\.local|/etc/init\.d|systemctl\s+enable|schtasks\s+/create)",
                    re.I), "servis/baslangic kalicilIgI"),
    ],
    "Privilege Escalation": [
        (re.compile(r"\bsudo\b", re.I), "sudo ile yetki yukseltme"),
        (re.compile(r"(chmod\s+(\+s|4755|u\+s)|setuid|setgid)", re.I),
         "SUID/SGID bit manipulasyonu"),
        (re.compile(r"/etc/sudoers", re.I), "sudoers dosyasi erisimi"),
        (re.compile(r"(pkexec|dirtycow|dirty[_ ]?pipe|polkit)", re.I),
         "bilinen privesc somuru araci"),
    ],
    "Credential Access": [
        (re.compile(r"/etc/shadow", re.I), "/etc/shadow parola hash erisimi"),
        (re.compile(r"(password|passwd|pwd)\s*=", re.I), "duz-metin parola alani"),
        (re.compile(r"\b(api[_-]?key|secret[_-]?key|access[_-]?token|bearer)\b",
                    re.I), "token/anahtar sizintisi"),
        (re.compile(r"(\.aws/credentials|id_rsa\b|\.pgpass|mimikatz|lsass)", re.I),
         "kimlik deposu/aracI erisimi"),
    ],
    "Lateral Movement": [
        (re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
                    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
         "ic ag (internal IP) hedefi"),
        (re.compile(r"\b(psexec|wmic|winrm|smbclient|smbexec|crackmapexec)\b",
                    re.I), "SMB/Windows pivot araci"),
        (re.compile(r"\bssh\s+[\w.-]+@[\w.-]+", re.I), "SSH pivot baglantisi"),
        (re.compile(r"net\s+use\s+\\\\", re.I), "SMB paylasim baglama"),
    ],
    "Exfiltration": [
        (re.compile(r"\b(curl|wget)\b[^\n]*\b(https?|ftp)://", re.I),
         "harici sunucuya veri aktarimi"),
        (re.compile(r"base64\s+(-w\s*0|--wrap|-d)?", re.I),
         "base64 ile veri paketleme"),
        (re.compile(r"(tar\s+[^\n]*\||zip\s+-r|scp\s+[\w./-]+@)", re.I),
         "arsivleme/kopyalama ile sizdirma"),
        (re.compile(r"(dnscat|dns\s*tunnel|exfil)", re.I), "gizli sizdirma kanali"),
    ],
}

# WAF imza kategorisi -> hangi asamaya sinyal katkisi verir. scan_text (Faz 14)
# ciktisini yeniden kullanip somuru/komut sinyallerini asamaya bagliyoruz.
_WAF_CATEGORY_STAGE = {
    "SQL Injection": "Initial Access",
    "XSS": "Initial Access",
    "Path Traversal": "Initial Access",
    "Command Injection": "Execution",
}

# "Buyuk GET" esigi (byte) - uzun bir GET yuku olasi veri sizdirmadir.
_LARGE_GET_BYTES = 512
# Uzun base64 blogu (exfil "base64 dump" gostergesi)
_BASE64_DUMP_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


@dataclass
class _StageHit:
    """Bir asama icin biriken eslesme kaniti."""
    stage: str
    indicators: list = field(default_factory=list)


def _scan_stages(payload: str, service: str = None,
                 event_type: str = None) -> dict:
    """Tum asamalara karsi tarar, asama -> gosterge etiketleri sozlugu doner."""
    text = payload or ""
    hits = {}

    def _add(stage, label):
        hits.setdefault(stage, [])
        if label not in hits[stage]:
            hits[stage].append(label)

    # 1) Asama imza kaliplari
    for stage, patterns in _STAGE_PATTERNS.items():
        for pattern, label in patterns:
            if pattern.search(text):
                _add(stage, label)

    # 2) WAF imza motoru ciktisini yeniden kullan (Faz 14)
    for category, _weight in waf_rules.scan_text(text):
        stage = _WAF_CATEGORY_STAGE.get(category)
        if stage:
            _add(stage, f"WAF imzasi: {category}")

    # 3) Buyuk GET / base64 dump -> exfiltration baglami
    et = (event_type or "").upper()
    if et in ("GET", "HTTP", "REQUEST") and len(text) >= _LARGE_GET_BYTES:
        _add("Exfiltration", f"buyuk GET yuku ({len(text)} byte)")
    if _BASE64_DUMP_RE.search(text):
        _add("Exfiltration", "uzun base64 veri blogu")

    # 4) event_type ipuclari
    if et in ("PORT_SCAN", "SCAN"):
        _add("Scanning", f"olay turu: {event_type}")
    if et in ("LOGIN_FAILED", "AUTH_FAIL", "BRUTE_FORCE"):
        _add("Credential Access", f"olay turu: {event_type}")

    return hits


def _confidence(num_indicators: int, num_stages: int) -> float:
    """Gosterge sayisi + asama cesitliligine gore guven (0..1).

    Tek gosterge orta guven verir; birden fazla ve farkli asama sinyali
    guveni artirir ama tek bir asamada yigilma daha nettir (dusuk belirsizlik).
    """
    if num_indicators <= 0:
        return 0.0
    base = 0.45 + 0.18 * (num_indicators - 1)
    # Cok farkli asama ayni anda eslesirse belirsizlik artar -> guven duser.
    ambiguity_penalty = 0.08 * max(0, num_stages - 1)
    return round(max(0.1, min(1.0, base - ambiguity_penalty)), 2)


def classify_stage(payload: str, service: str = None,
                   event_type: str = None) -> dict:
    """Tek bir olayi 9 asamadan birine yerlestirir.

    Donen sozluk: {stage, confidence (0..1), indicators [eslesen etiketler],
    mitre_tactic {id,name}, defense_layer}. Hicbir asama eslesmezse stage None
    doner - "bilmiyorum"u durustce ifade eder, asla uydurmaz.

    Secim kurali: en cok gosterge eslesen asama; esitlik durumunda zincirde
    daha ILERI (daha yuksek riskli) asama secilir.
    """
    hits = _scan_stages(payload, service, event_type)
    if not hits:
        return {
            "stage": None,
            "confidence": 0.0,
            "indicators": [],
            "mitre_tactic": None,
            "defense_layer": None,
        }

    # En cok gosterge; esitlikte en ileri asama (en buyuk STAGE_INDEX).
    best_stage = max(
        hits, key=lambda s: (len(hits[s]), STAGE_INDEX[s])
    )
    indicators = hits[best_stage]
    return {
        "stage": best_stage,
        "stage_tr": STAGE_TR[best_stage],
        "confidence": _confidence(len(indicators), len(hits)),
        "indicators": list(indicators),
        "mitre_tactic": dict(STAGE_MITRE[best_stage]),
        "defense_layer": STAGE_DEFENSE_LAYER[best_stage],
    }


def stage_progression(events: list) -> dict:
    """Bir saldirganin sirali olaylari uzerinde zincir ilerlemesini olcer.

    Donen sozluk:
      stages_reached : ulasilan benzersiz asamalar (zincir sirasinda)
      current_stage  : son (en guncel) olayin asamasi
      furthest_stage : ulasilan en ileri asama
      progress_pct   : en ileri asamanin zincirdeki yuzdesi
      timeline       : [{stage, timestamp, evidence, defense_layer}]
      mitre_tactics  : ulasilan asamalarin benzersiz ATT&CK taktikleri
    """
    timeline = []
    reached_idx = set()
    current_stage = None

    for ev in events or []:
        payload = ev.get("payload") or ev.get("text") or ""
        result = classify_stage(payload, ev.get("service"),
                                ev.get("event_type"))
        stage = result["stage"]
        if stage is None:
            continue
        current_stage = stage
        reached_idx.add(STAGE_INDEX[stage])
        timeline.append({
            "stage": stage,
            "stage_tr": STAGE_TR[stage],
            "timestamp": ev.get("timestamp"),
            "evidence": result["indicators"],
            "defense_layer": result["defense_layer"],
        })

    if not reached_idx:
        return {
            "stages_reached": [],
            "current_stage": None,
            "furthest_stage": None,
            "progress_pct": 0,
            "timeline": [],
            "mitre_tactics": [],
        }

    ordered_idx = sorted(reached_idx)
    stages_reached = [STAGES[i] for i in ordered_idx]
    furthest_idx = ordered_idx[-1]
    furthest_stage = STAGES[furthest_idx]
    mitre_tactics = [dict(STAGE_MITRE[s]) for s in stages_reached]

    return {
        "stages_reached": stages_reached,
        "current_stage": current_stage,
        "furthest_stage": furthest_stage,
        "progress_pct": round(((furthest_idx + 1) / len(STAGES)) * 100),
        "timeline": timeline,
        "mitre_tactics": mitre_tactics,
    }


def replay_timeline(events: list) -> list:
    """Attack Replay gorsellestirmesi icin sirali adim listesi uretir.

    Her adim: {step, stage, timestamp, payload_excerpt, defense_layer,
    mitre_tactic}. UI bu listeyi Kesif -> ... -> Sizdirma seklinde oynatir ve
    her adimda hangi Gok Kubbe katmaninin devreye girdigini gosterir.
    """
    steps = []
    step_no = 0
    for ev in events or []:
        payload = ev.get("payload") or ev.get("text") or ""
        result = classify_stage(payload, ev.get("service"),
                                ev.get("event_type"))
        stage = result["stage"]
        if stage is None:
            continue
        step_no += 1
        excerpt = payload[:80]
        steps.append({
            "step": step_no,
            "stage": stage,
            "stage_tr": STAGE_TR[stage],
            "timestamp": ev.get("timestamp"),
            "payload_excerpt": excerpt,
            "defense_layer": result["defense_layer"],
            "mitre_tactic": dict(STAGE_MITRE[stage]),
        })
    return steps
