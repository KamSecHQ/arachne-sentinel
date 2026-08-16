"""
Faz 36 - Aciklanabilir Tersine Muhendislik (Explainable Reverse Engineering).

--- Fikir ---
Bir saldiriyi SINIFLANDIRMAK yeterli degildir; NEDEN oyle siniflandirdigimizi
da soyleyebilmeliyiz. Bu modul her tespiti "acar": HANGI kaliplarin eslestigi,
eslesen GERCEK alt-dizgiler, gerekcesiyle birlikte bir guven degeri ve ilgili
MITRE ATT&CK teknigi. Kapsam: SQLi, Komut Enjeksiyonu, XSS, kodlama/gizleme,
polyglot ve prompt enjeksiyonu.

--- Gercek cerceve eslemesi ---
  * Aciklanabilir tespit (explainable detection): her karar iz surulebilir.
  * MITRE ATT&CK Enterprise: SQLi->T1190, Komut->T1059.004, XSS->T1059.007,
    Gizleme->T1027.
  * MITRE ATLAS: prompt enjeksiyonu icin AML.T0051 (LLM Prompt Injection).
    Prompt enjeksiyonu klasik ATT&CK Enterprise'da YOKTUR - dogru cerceve
    ATLAS'tir; uydurma bir Enterprise ID kullanmiyoruz.
  * OWASP: SQLi/XSS/Command Injection OWASP Top 10 A03 (Injection) altindadir.

--- DURUSTLUK NOTU ---
Imza tabanli aciklama, yalnizca "gordugu" kaliplari raporlar. Eslesme yoksa
"kanit yok" der, guveni 0 dondurur - hicbir zaman kanit uydurmaz. Guven degeri,
eslesme SAYISI ve CESITLILIGINDEN turetilen sezgisel bir olcudur, olasiliksal
bir kesinlik iddiasi degildir. Bu katman zenginlestirir; engelleme karari
deterministik kural motorunda (Faz 1) kalir.

--- Savunma-amacli etik not ---
Analiz edilen "tersine muhendislik", baskasinin yazilimini kirmak degil,
BIZE GELEN saldiri yukunu adli bilisim amaciyla incelemektir. Ag yok, dosya
yok, yan etki yok - saf, deterministik metin analizi.
"""
import re
from dataclasses import dataclass, field

from ..reverse.advanced_decoder import is_polyglot
from ..waf import rules as waf_rules

# --- Saldiri kategorisi -> MITRE teknigi (id, isim, url) --------------------
# ATT&CK'te SQLi/XSS icin ayri teknik yoktur; profesyonel yaklasim en yakin
# teknige eslemektir (bkz. intel/attck.py). Prompt enjeksiyonu ATLAS'a aittir.
MITRE_TECHNIQUES = {
    "SQL Injection": {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "Command Injection": {
        "id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "XSS": {
        "id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
    },
    "Encoding/Obfuscation": {
        "id": "T1027", "name": "Obfuscated Files or Information",
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
    "Polyglot": {
        "id": "T1027", "name": "Obfuscated Files or Information",
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
    "Prompt Injection": {
        "id": "AML.T0051", "name": "LLM Prompt Injection",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
}

# En tehlikeliden en az tehlikeliye onem sirasi. "En iyi eslesme" MITRE teknigi
# secilirken bu sira kullanilir (komut calistirma > SQLi > XSS > ...).
_SEVERITY_ORDER = [
    "Command Injection",
    "SQL Injection",
    "XSS",
    "Prompt Injection",
    "Polyglot",
    "Encoding/Obfuscation",
]

# --- Kategori basina alt-dizgi cikaran regex'ler ----------------------------
# Her kalip: (derlenmis regex, insan-okunabilir aciklama). regex.search().group()
# ile GERCEK eslesen metin cikarilir - "neyin eslestigini" tam olarak gosteririz.
_EXTRACTORS = {
    "SQL Injection": [
        (re.compile(r"\bunion\b[\s\S]{1,80}\bselect\b", re.I),
         "UNION-based SQLi (union ... select)"),
        (re.compile(r"('\s*or\s*'?\d+'?\s*=\s*'?\d+)|(\bor\s+1\s*=\s*1\b)", re.I),
         "tautoloji / OR 1=1"),
        (re.compile(r"\bsleep\s*\(\s*\d+\s*\)|waitfor\s+delay|pg_sleep\s*\(", re.I),
         "zaman tabanli kor SQLi (SLEEP)"),
        (re.compile(r";\s*drop\s+table\b", re.I), "yigilmis sorgu (DROP TABLE)"),
    ],
    "Command Injection": [
        (re.compile(r"(;|&&|\|\||`|\$\()"), "kabuk komut ayirici (; && | ` $() )"),
        (re.compile(r"/bin/(ba)?sh\b|\bnc\s|\bwget\s|\bcurl\s", re.I),
         "kabuk ikilisi / arac cagrisi"),
        (re.compile(r"cat\s+/etc/(passwd|shadow)|whoami|uname\s+-a", re.I),
         "hassas komut/dosya erisimi"),
    ],
    "XSS": [
        (re.compile(r"<script[\s>]", re.I), "<script> etiketi"),
        (re.compile(r"on(error|load|click|mouseover)\s*=", re.I),
         "inline olay isleyici (onerror= vb.)"),
        (re.compile(r"javascript\s*:", re.I), "javascript: URI"),
        (re.compile(r"<(img|svg)[^>]+on\w+\s*=", re.I),
         "olay isleyicili img/svg etiketi"),
    ],
    "Encoding/Obfuscation": [
        (re.compile(r"(%[0-9a-fA-F]{2}){3,}"), "URL-encode (%XX) dizisi"),
        (re.compile(r"(\\x[0-9a-fA-F]{2}){3,}"), "hex escape (\\xNN) dizisi"),
        (re.compile(r"[A-Za-z0-9+/]{24,}={0,2}"), "base64 blogu"),
    ],
    "Prompt Injection": [
        (re.compile(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+"
                    r"(instructions|prompts?)", re.I),
         "'ignore previous instructions'"),
        (re.compile(r"(^|[\s\"'>])system\s*:", re.I), "'system:' rol enjeksiyonu"),
        (re.compile(r"disregard\s+(all|the|your)\b|you\s+are\s+now\b", re.I),
         "talimat gecersiz kilma / rol degistirme"),
        (re.compile(r"(reveal|print|show|repeat)\b[\s\S]{0,30}"
                    r"(system\s+prompt|your\s+instructions)", re.I),
         "sistem talimatini sizdirma girisimi"),
    ],
}

# WAF imza kategorisi (Faz 14 scan_text) -> bu modulun kategori adi.
_WAF_CATEGORY_MAP = {
    "SQL Injection": "SQL Injection",
    "XSS": "XSS",
    "Command Injection": "Command Injection",
    "Path Traversal": "Encoding/Obfuscation",  # traversal cogu zaman kodlama ile birlikte
}

# Kategori -> "neden kotu niyetli" Turkce gerekcesi (why_tr icin).
_WHY_TR = {
    "SQL Injection": "veritabani sorgusunu manipule eden SQL enjeksiyon kaliplari iceriyor",
    "Command Injection": "isletim sistemi kabuk komutu calistirmaya calisan enjeksiyon iceriyor",
    "XSS": "kurban tarayicisinda script calistiran XSS kaliplari iceriyor",
    "Encoding/Obfuscation": "imza savunmasini atlatmak icin kodlanmis/gizlenmis icerik iceriyor",
    "Polyglot": "birden fazla ayristiriciyi ayni anda atlatan polyglot yapi iceriyor",
    "Prompt Injection": "LLM sisteminin talimatlarini ele gecirmeye calisan prompt enjeksiyonu iceriyor",
}


@dataclass
class _Match:
    """Tek bir eslesen kalip."""
    category: str
    pattern_desc: str
    matched_text: str

    def to_dict(self):
        return {"category": self.category, "pattern_desc": self.pattern_desc,
                "matched_text": self.matched_text}


def _extract_matches(text: str) -> list:
    """Metni tum cikaricilara karsi tarar, eslesen alt-dizgileri toplar."""
    matches = []
    for category, extractors in _EXTRACTORS.items():
        for pattern, desc in extractors:
            m = pattern.search(text)
            if m:
                matches.append(_Match(category, desc, m.group(0)[:120]))
    return matches


def _confidence(n_patterns: int, n_types: int, polyglot: bool) -> float:
    """Guven: eslesme sayisi + kategori cesitliligi + polyglot bonusu.

    Tek imza orta guven; birden fazla imza ve farkli kategori guveni artirir.
    Polyglot, ileri seviye bir saldiri gostergesi oldugundan ek katki verir.
    """
    if n_patterns <= 0:
        return 0.0
    score = 0.35 + 0.12 * (n_patterns - 1) + 0.12 * max(0, n_types - 1)
    if polyglot:
        score += 0.10
    return round(min(1.0, score), 2)


def _best_technique(attack_types) -> dict:
    """Tespit edilen kategoriler arasindan en tehlikeli olanin MITRE teknigi."""
    for category in _SEVERITY_ORDER:
        if category in attack_types:
            return dict(MITRE_TECHNIQUES[category])
    return None


def explain_detection(payload: str) -> dict:
    """Tek bir yuk icin tam, aciklanabilir tespit raporu uretir.

    Donen sozluk: {attack_types, matched_patterns [{category, pattern_desc,
    matched_text}], confidence (0..1), confidence_reason_tr, mitre_technique
    {id,name,url} veya None, is_polyglot (bool), evasion_notes_tr, why_tr}.
    """
    text = payload or ""

    # 1) Kendi regex cikaricilarimizla eslesen alt-dizgileri topla.
    matches = _extract_matches(text)
    attack_types = []
    for m in matches:
        if m.category not in attack_types:
            attack_types.append(m.category)

    # 2) WAF imza motorunu (Faz 14) yeniden kullan - kacirdigimiz imzalari ekle.
    for category, _weight in waf_rules.scan_text(text):
        mapped = _WAF_CATEGORY_MAP.get(category, category)
        if mapped not in attack_types:
            attack_types.append(mapped)
            matches.append(_Match(mapped, f"WAF imza motoru eslesmesi ({category})",
                                  ""))

    # 3) Polyglot analizi (Faz 13 is_polyglot'u yeniden kullan).
    poly = is_polyglot(text)
    polyglot = bool(poly["is_polyglot"])
    if polyglot and "Polyglot" not in attack_types:
        attack_types.append("Polyglot")
        matches.append(_Match(
            "Polyglot",
            f"polyglot: {', '.join(poly['contexts'])} baglamlari",
            ", ".join(poly["contexts"])))

    matched_patterns = [m.to_dict() for m in matches]
    confidence = _confidence(len(matched_patterns), len(attack_types), polyglot)

    # Guven gerekcesi (Turkce)
    if not attack_types:
        confidence_reason_tr = ("Hicbir saldiri imzasi eslesmedi; kanit yok, "
                                "guven 0.")
    else:
        confidence_reason_tr = (
            f"{len(matched_patterns)} imza, {len(attack_types)} farkli "
            f"kategoride ({', '.join(attack_types)}) eslesti"
            + ("; polyglot yapi tespit edildi -> guven artirildi."
               if polyglot else ".")
        )

    # Kacinma/gizleme notlari
    evasion_flags = []
    if "Encoding/Obfuscation" in attack_types:
        evasion_flags.append("kodlama/gizleme (URL/hex/base64)")
    if polyglot:
        evasion_flags.append("polyglot (coklu baglam)")
    evasion_notes_tr = (
        "Kacinma teknigi tespit edildi: " + ", ".join(evasion_flags)
        + " - imza tabanli savunmayi atlatma girisimi."
        if evasion_flags else
        "Belirgin bir kodlama/kacinma teknigi tespit edilmedi."
    )

    # Neden kotu niyetli (dogal dil Turkce aciklama)
    if attack_types:
        reasons = [_WHY_TR.get(c, c) for c in attack_types]
        why_tr = "Bu yuk kotu niyetli gorunuyor cunku " + "; ".join(reasons) + "."
    else:
        why_tr = ("Bu yukte bilinen bir saldiri imzasi tespit edilmedi; "
                  "zararsiz gorunuyor (ancak kesin degildir).")

    return {
        "attack_types": attack_types,
        "matched_patterns": matched_patterns,
        "confidence": confidence,
        "confidence_reason_tr": confidence_reason_tr,
        "mitre_technique": _best_technique(attack_types),
        "is_polyglot": polyglot,
        "evasion_notes_tr": evasion_notes_tr,
        "why_tr": why_tr,
    }


def explain_many(payloads: list) -> list:
    """Bir yuk listesi icin toplu aciklama uretir (deterministik, sirali)."""
    return [explain_detection(p) for p in (payloads or [])]
