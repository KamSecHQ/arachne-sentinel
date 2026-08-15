"""
Faz 14 - Bildirimsel imza kural motoru (YARA-benzeri).

Faz 1'in imza sozlugu basit alt-string listeleriydi. Bu modul, gercek
guvenlik urunlerindeki (YARA, Suricata, Sigma) kural motorlarinin kucuk
ama gercek bir karsiligini kurar: kurallar VERI olarak tanimlanir,
DERLENIR ve bir yuke karsi calistirilir.

--- Kural yapisi (saf sozluk, kod degil) ---
    {
        "id": "sqli-union-based",
        "name": "UNION tabanli SQL Injection",
        "severity": "high",
        "attck": ["T1190"],
        "condition": "all",         # all | any | <sayi> of
        "strings": [
            {"id": "s1", "type": "contains", "value": "union", "nocase": True},
            {"id": "s2", "type": "regex", "value": r"select.{0,40}from"},
            {"id": "s3", "type": "entropy_above", "value": 5.5},
        ],
    }

--- Kosul turleri ---
    contains        : alt-string arama (nocase destekli)
    regex           : duzenli ifade
    icontains       : her zaman buyuk/kucuk harf duyarsiz alt-string
    length_above    : yuk uzunlugu esigi
    entropy_above   : Shannon entropi esigi
    count_above     : bir alt-string'in tekrar sayisi esigi

--- Neden 'derle'? ---
Kurallar bir kez derlenir (regex'ler onceden compile edilir, kosullar
dogrulanir) ve cok kez calistirilir. Bu, gercek motorlarin yaptigi gibi
sicak yolu hizlandirir ve bozuk kurallari CALISTIRMADAN once yakalar.

--- Aciklanabilirlik ---
Bir kural eslestginde, HANGI string'lerin eslestigini de dondururuz -
"kural X tetiklendi cunku s1, s3 eslesti". Hicbir tespit kara kutu degil.
"""
import re
from dataclasses import dataclass, field

from ..reverse.advanced_decoder import shannon_entropy

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
STRING_TYPES = {"contains", "icontains", "regex", "length_above",
                "entropy_above", "count_above"}


class RuleCompileError(ValueError):
    """Kural derlenemedi - bozuk kural CALISTIRILMADAN once yakalanir."""


@dataclass
class CompiledString:
    id: str
    type: str
    value: object
    nocase: bool = False
    _regex: object = None

    def evaluate(self, payload: str, lower: str, entropy: float) -> bool:
        if self.type == "contains":
            return (self.value.lower() in lower) if self.nocase else (self.value in payload)
        if self.type == "icontains":
            return self.value.lower() in lower
        if self.type == "regex":
            return bool(self._regex.search(payload))
        if self.type == "length_above":
            return len(payload) > self.value
        if self.type == "entropy_above":
            return entropy > self.value
        if self.type == "count_above":
            needle, threshold = self.value
            return lower.count(needle.lower()) > threshold
        return False


@dataclass
class CompiledRule:
    id: str
    name: str
    severity: str
    attck: list
    condition: str            # "all" | "any" | int (N of)
    strings: list             # CompiledString listesi
    description: str = ""
    cwe: list = field(default_factory=list)

    def evaluate(self, payload: str) -> dict:
        """Kurali yuke karsi calistirir. Eslesme + hangi string'lerin
        eslestigini dondurur (aciklanabilirlik)."""
        lower = payload.lower()
        entropy = shannon_entropy(payload)
        matched = [s.id for s in self.strings if s.evaluate(payload, lower, entropy)]
        count = len(matched)

        if self.condition == "all":
            fired = count == len(self.strings)
        elif self.condition == "any":
            fired = count >= 1
        elif isinstance(self.condition, int):
            fired = count >= self.condition
        else:
            fired = False

        return {
            "rule_id": self.id,
            "name": self.name,
            "severity": self.severity,
            "fired": fired,
            "matched_strings": matched,
            "match_count": count,
            "total_strings": len(self.strings),
            "attck": self.attck,
            "cwe": self.cwe,
            "description": self.description,
        }


def compile_rule(rule: dict) -> CompiledRule:
    """Bir kural sozlugunu derler; bozuksa RuleCompileError firlatir."""
    if not isinstance(rule, dict):
        raise RuleCompileError("Kural bir sozluk olmali")
    for req in ("id", "name", "strings"):
        if req not in rule:
            raise RuleCompileError(f"Eksik alan: {req}")

    severity = rule.get("severity", "medium")
    if severity not in VALID_SEVERITIES:
        raise RuleCompileError(f"Gecersiz siddet: {severity}")

    condition = rule.get("condition", "all")
    if condition not in ("all", "any") and not isinstance(condition, int):
        raise RuleCompileError(f"Gecersiz kosul: {condition}")

    compiled_strings = []
    for s in rule["strings"]:
        stype = s.get("type")
        if stype not in STRING_TYPES:
            raise RuleCompileError(f"Gecersiz string turu: {stype}")
        value = s.get("value")
        regex = None
        if stype == "regex":
            try:
                flags = re.I if s.get("nocase") else 0
                regex = re.compile(value, flags)
            except re.error as exc:
                raise RuleCompileError(f"Bozuk regex ({s.get('id')}): {exc}")
        elif stype in ("length_above", "entropy_above"):
            if not isinstance(value, (int, float)):
                raise RuleCompileError(f"{stype} sayisal deger bekler")
        elif stype == "count_above":
            if not (isinstance(value, (list, tuple)) and len(value) == 2):
                raise RuleCompileError("count_above [alt-string, esik] bekler")
        compiled_strings.append(CompiledString(
            id=s.get("id", f"s{len(compiled_strings)}"),
            type=stype, value=value, nocase=s.get("nocase", False), _regex=regex,
        ))

    if isinstance(condition, int) and condition > len(compiled_strings):
        raise RuleCompileError(
            f"Kosul {condition} of ama sadece {len(compiled_strings)} string var")

    return CompiledRule(
        id=rule["id"], name=rule["name"], severity=severity,
        attck=list(rule.get("attck", [])), cwe=list(rule.get("cwe", [])),
        condition=condition, strings=compiled_strings,
        description=rule.get("description", ""),
    )


# --- Yerlesik kural seti ----------------------------------------------------
# Gercek imza kurallarinin nasil gorundugunu gosteren, calisan bir set.
BUILTIN_RULES = [
    {
        "id": "sqli-union-based", "name": "UNION tabanli SQL Injection",
        "severity": "high", "attck": ["T1190"], "cwe": ["CWE-89"],
        "condition": "any",
        "strings": [
            {"id": "union_select", "type": "regex",
             "value": r"union\s+(all\s+)?select", "nocase": True},
            {"id": "info_schema", "type": "icontains", "value": "information_schema"},
        ],
        "description": "Veritabani sutunlarini birlestirerek veri sizdirma",
    },
    {
        "id": "sqli-blind-time", "name": "Zaman tabanli kor SQL Injection",
        "severity": "high", "attck": ["T1190"], "cwe": ["CWE-89"],
        "condition": "any",
        "strings": [
            {"id": "sleep", "type": "regex", "value": r"sleep\s*\(\s*\d", "nocase": True},
            {"id": "benchmark", "type": "regex", "value": r"benchmark\s*\(", "nocase": True},
            {"id": "waitfor", "type": "icontains", "value": "waitfor delay"},
            {"id": "pg_sleep", "type": "regex", "value": r"pg_sleep\s*\(", "nocase": True},
        ],
        "description": "Sunucu cevap suresinden veri cikaran kor enjeksiyon",
    },
    {
        "id": "rce-shell-chain", "name": "Kabuk komut zinciri (RCE)",
        "severity": "critical", "attck": ["T1059.004"], "cwe": ["CWE-78"],
        "condition": 2,
        "strings": [
            {"id": "separator", "type": "regex", "value": r"[;|&`]|\$\("},
            {"id": "shell_cmd", "type": "regex",
             "value": r"(cat|wget|curl|nc|bash|sh|whoami|id|uname)\b", "nocase": True},
            {"id": "sensitive_path", "type": "icontains", "value": "/etc/passwd"},
        ],
        "description": "Ayirici + kabuk komutu birlikte = komut enjeksiyonu",
    },
    {
        "id": "xss-script-injection", "name": "Script enjeksiyonu (XSS)",
        "severity": "high", "attck": ["T1059.007"], "cwe": ["CWE-79"],
        "condition": "any",
        "strings": [
            {"id": "script_tag", "type": "regex", "value": r"<\s*script", "nocase": True},
            {"id": "event_handler", "type": "regex",
             "value": r"on(error|load|mouseover|click)\s*=", "nocase": True},
            {"id": "js_uri", "type": "icontains", "value": "javascript:"},
            {"id": "svg_onload", "type": "regex", "value": r"<svg[^>]*onload", "nocase": True},
        ],
        "description": "Kurbanin tarayicisinda script calistirma",
    },
    {
        "id": "path-traversal", "name": "Dizin gecisi (Path Traversal)",
        "severity": "high", "attck": ["T1083"], "cwe": ["CWE-22"],
        "condition": "any",
        "strings": [
            {"id": "dotdot", "type": "regex", "value": r"(\.\./|\.\.\\){2,}"},
            {"id": "encoded_dotdot", "type": "icontains", "value": "%2e%2e%2f"},
            {"id": "sensitive", "type": "regex",
             "value": r"/(etc/passwd|etc/shadow|proc/self)", "nocase": True},
        ],
        "description": "Web kokunun disina cikarak dosya okuma",
    },
    {
        "id": "obfuscation-high-entropy",
        "name": "Yuksek entropili gizlenmis yuk",
        "severity": "medium", "attck": ["T1027"], "cwe": [],
        "condition": "all",
        "strings": [
            {"id": "long", "type": "length_above", "value": 40},
            {"id": "high_entropy", "type": "entropy_above", "value": 5.5},
        ],
        "description": "Uzun ve yuksek entropili yuk - kodlanmis/sifrelenmis",
    },
    {
        "id": "webshell-upload", "name": "Web shell yukleme girisimi",
        "severity": "critical", "attck": ["T1505.003"], "cwe": ["CWE-434"],
        "condition": "any",
        "strings": [
            {"id": "php_eval", "type": "regex",
             "value": r"(eval|assert|system|passthru|shell_exec)\s*\(\s*\$", "nocase": True},
            {"id": "preg_e", "type": "icontains", "value": "preg_replace"},
        ],
        "description": "Sunucuya kalici uzaktan erisim arayuzu birakma",
    },
]


class RuleSet:
    """Derlenmis kural koleksiyonu; bir yuke karsi hepsini calistirir."""

    def __init__(self, rules=None):
        self.rules = []
        self.errors = []
        for rule in (rules if rules is not None else BUILTIN_RULES):
            try:
                self.rules.append(compile_rule(rule))
            except RuleCompileError as exc:
                self.errors.append({"rule": rule.get("id", "?"), "error": str(exc)})

    def scan(self, payload: str) -> list:
        """Yuku tum kurallara karsi tarar; tetiklenen kurallari dondurur."""
        if not payload:
            return []
        results = []
        for rule in self.rules:
            outcome = rule.evaluate(payload)
            if outcome["fired"]:
                results.append(outcome)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda r: severity_order.get(r["severity"], 9))
        return results

    def scan_summary(self, payload: str) -> dict:
        matches = self.scan(payload)
        return {
            "matched_rules": matches,
            "match_count": len(matches),
            "highest_severity": matches[0]["severity"] if matches else None,
            "attck_techniques": sorted({t for m in matches for t in m["attck"]}),
            "rules_loaded": len(self.rules),
            "rules_failed": len(self.errors),
        }


# Modul seviyesinde tek bir varsayilan set (yerlesik kurallarla)
_default_ruleset = None


def default_ruleset() -> RuleSet:
    global _default_ruleset
    if _default_ruleset is None:
        _default_ruleset = RuleSet()
    return _default_ruleset


def scan_payload(payload: str) -> dict:
    """Kolaylik fonksiyonu: varsayilan kural setiyle tara."""
    return default_ruleset().scan_summary(payload)
