"""
Faz 13 - Gelismis kodlama cozucu ve entropi analizi.

Faz 5'teki temel cozucu (deobfuscator.py) yaygin kodlamalari acar; bu modul
onu daha egzotik ve saldirganlarin gercekten kullandigi ileri tekniklerle
guclendirir:

  * ROT13 / Caesar kaymalari
  * Ondalik ve hex karakter kodlari (JS String.fromCharCode, HTML &#NN;)
  * SQL CHAR()/CHR() zincirleri  (ornek: CHAR(39)+CHAR(79)+CHAR(82))
  * PHP chr() birlestirmeleri
  * gzip/zlib + base64 (sıkıstirilmis yuk)
  * ters cevrilmis (reversed) diziler
  * bosluk/yorum enjeksiyonu temizligi (SQL /**/ , cift bosluk)

Ayrica **entropi analizi** ekler: yuksek Shannon entropisi, sikistirilmis
ya da sifrelenmis - yani kasitli olarak gizlenmis - bir yuke isaret eder.
Mesru HTTP trafigi dusuk-orta entropilidir; ~5.0 bit/karakter ustu bir
deger tek basina bir supheli-lik sinyalidir.

--- Neden ayri bir modul? ---
Temel cozucu (Faz 5) "her zaman guvenli, yanlis pozitif uretmeyen"
katmanlara odaklandi. Buradaki teknikler daha agresiftir ve bazen mesru
veriyi de donusturebilir; bu yuzden ayri tutuldu ve analiz baglaminda
(karar degil) kullanilir.
"""
import base64
import binascii
import gzip
import math
import re
import zlib
from dataclasses import dataclass, field

MAX_DEPTH = 6
MIN_PRINTABLE_RATIO = 0.85

_SQL_CHAR_RE = re.compile(r"(?:CHR|CHAR)\s*\(\s*(\d{1,3})\s*\)", re.I)
_PHP_CHR_RE = re.compile(r"chr\s*\(\s*(\d{1,3})\s*\)", re.I)
_JS_FROMCHARCODE_RE = re.compile(
    r"String\.fromCharCode\s*\(([\d,\s]+)\)", re.I)
_DECIMAL_ENTITY_RE = re.compile(r"&#(\d{1,7});")
_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


@dataclass
class AdvancedStep:
    method: str
    before: str
    after: str

    def to_dict(self):
        return {"method": self.method, "before": self.before[:160],
                "after": self.after[:160]}


@dataclass
class AdvancedResult:
    original: str
    decoded: str
    steps: list = field(default_factory=list)
    entropy: float = 0.0
    entropy_verdict: str = ""

    @property
    def layers(self) -> int:
        return len(self.steps)

    @property
    def was_transformed(self) -> bool:
        return bool(self.steps)

    def method_chain(self) -> str:
        return " -> ".join(s.method for s in self.steps) if self.steps else "yok"

    def to_dict(self):
        return {
            "original": self.original[:400],
            "decoded": self.decoded[:400],
            "layers": self.layers,
            "was_transformed": self.was_transformed,
            "method_chain": self.method_chain(),
            "steps": [s.to_dict() for s in self.steps],
            "entropy": round(self.entropy, 3),
            "entropy_verdict": self.entropy_verdict,
        }


def shannon_entropy(text: str) -> float:
    """Bir metnin Shannon entropisini (bit/karakter) hesaplar.

    Yuksek entropi = az ongorulebilir = sikistirilmis/sifrelenmis/rastgele.
    Ingilizce dogal metin ~4.0-4.5, base64 ~6.0, sifreli/sikistirilmis ~7.5+.
    """
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def entropy_assessment(entropy: float) -> str:
    if entropy >= 6.5:
        return ("Cok yuksek entropi - sikistirilmis ya da sifrelenmis veri; "
                "mesru HTTP trafigi bu kadar rastgele degildir")
    if entropy >= 5.0:
        return ("Yuksek entropi - kodlanmis (base64/hex) ya da gizlenmis yuk "
                "olasi")
    if entropy >= 3.5:
        return "Normal metin entropisi"
    return "Dusuk entropi - tekrarlayan ya da basit yapili veri"


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isprintable() or c in "\r\n\t") / len(text)


def _try_rot13(text: str):
    if not re.search(r"[A-Za-z]", text):
        return None
    out = text.translate(_ROT13_TABLE)
    # Sadece anlamli bir donusum varsa kabul et: cozulmus metin bilinen
    # saldiri anahtar kelimeleri iceriyorsa guclu sinyal.
    markers = ("select", "union", "script", "etc/passwd", "http", "or ", "and ")
    if out != text and any(m in out.lower() for m in markers):
        return out
    return None


def _try_sql_char(text: str):
    """CHAR(39)+CHAR(79)... zincirlerini cozer."""
    matches = _SQL_CHAR_RE.findall(text)
    if len(matches) < 2:
        return None
    try:
        decoded = "".join(chr(int(m)) for m in matches if 0 <= int(m) < 1114112)
    except (ValueError, OverflowError):
        return None
    return decoded if decoded and _printable_ratio(decoded) >= MIN_PRINTABLE_RATIO else None


def _try_php_chr(text: str):
    matches = _PHP_CHR_RE.findall(text)
    if len(matches) < 2:
        return None
    try:
        decoded = "".join(chr(int(m)) for m in matches if 0 <= int(m) < 256)
    except (ValueError, OverflowError):
        return None
    return decoded if decoded and _printable_ratio(decoded) >= MIN_PRINTABLE_RATIO else None


def _try_js_fromcharcode(text: str):
    match = _JS_FROMCHARCODE_RE.search(text)
    if not match:
        return None
    nums = [n.strip() for n in match.group(1).split(",") if n.strip()]
    if len(nums) < 2:
        return None
    try:
        decoded = "".join(chr(int(n)) for n in nums if 0 <= int(n) < 1114112)
    except (ValueError, OverflowError):
        return None
    return decoded if decoded and _printable_ratio(decoded) >= MIN_PRINTABLE_RATIO else None


def _try_decimal_entities(text: str):
    if not _DECIMAL_ENTITY_RE.search(text):
        return None
    def repl(m):
        try:
            return chr(int(m.group(1)))
        except (ValueError, OverflowError):
            return m.group(0)
    out = _DECIMAL_ENTITY_RE.sub(repl, text)
    return out if out != text else None


def _try_gzip_base64(text: str):
    """base64(gzip(payload)) ya da base64(zlib(payload)) cozer."""
    stripped = "".join(text.split())
    if len(stripped) < 16 or not re.match(r"^[A-Za-z0-9+/=]+$", stripped):
        return None
    try:
        raw = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    for name, decompress in (("gzip", gzip.decompress),
                             ("zlib", zlib.decompress)):
        try:
            out = decompress(raw).decode("utf-8", errors="strict")
            if out and _printable_ratio(out) >= MIN_PRINTABLE_RATIO:
                return out
        except (OSError, zlib.error, UnicodeDecodeError, ValueError):
            continue
    return None


def _try_reversed(text: str):
    """Ters cevrilmis yuk (ornek: 'txet' -> 'text'). Sadece bilinen anahtar
    kelimeler ters halde gorunuyorsa uygulanir."""
    rev = text[::-1]
    markers = ("tceles", "noinu", "tpircs", "dwssap")  # select/union/script/passwd ters
    if any(m in text.lower() for m in markers):
        return rev
    return None


def _clean_sql_comments(text: str):
    """SQL /**/ yorum enjeksiyonlarini ve fazla boslugu temizler."""
    if "/*" not in text:
        return None
    cleaned = _SQL_COMMENT_RE.sub(" ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned if cleaned != text else None


_DECODERS = [
    ("sql-comment-strip", _clean_sql_comments),
    ("decimal-entity", _try_decimal_entities),
    ("js-fromcharcode", _try_js_fromcharcode),
    ("sql-char", _try_sql_char),
    ("php-chr", _try_php_chr),
    ("gzip-base64", _try_gzip_base64),
    ("rot13", _try_rot13),
    ("reversed", _try_reversed),
]


def advanced_decode(payload: str, max_depth: int = MAX_DEPTH) -> AdvancedResult:
    """Ileri kodlama katmanlarini sabit noktaya kadar acar + entropi olcer."""
    payload = payload or ""
    current = payload
    steps = []

    for _ in range(max_depth):
        progressed = False
        for name, decoder in _DECODERS:
            try:
                out = decoder(current)
            except Exception:
                out = None
            if out is not None and out != current:
                steps.append(AdvancedStep(method=name, before=current, after=out))
                current = out
                progressed = True
                break
        if not progressed:
            break

    entropy = shannon_entropy(payload)
    return AdvancedResult(
        original=payload, decoded=current, steps=steps,
        entropy=entropy, entropy_verdict=entropy_assessment(entropy),
    )


def is_polyglot(payload: str) -> dict:
    """Yuk birden fazla dil/formatta gecerli mi (polyglot)?

    Polyglot yukler (ornek: hem gecerli JS hem gecerli resim, ya da hem SQL
    hem XSS) birden fazla ayristiriciyi atlatmak icin kullanilir - ileri
    seviye bir saldiri gostergesidir."""
    lower = (payload or "").lower()
    contexts = []
    if re.search(r"(union\s+select|or\s+1=1|'\s*or\s*')", lower):
        contexts.append("SQL")
    if re.search(r"(<script|onerror=|javascript:|<svg)", lower):
        contexts.append("HTML/JS")
    if re.search(r"(;|\||&&|\$\(|`)", payload or "") and \
            re.search(r"(cat |whoami|/bin/|nc )", lower):
        contexts.append("Shell")
    if re.search(r"(\{\{|\$\{|<%|#\{)", payload or ""):
        contexts.append("Template")
    return {
        "is_polyglot": len(contexts) >= 2,
        "contexts": contexts,
        "assessment_tr": (
            f"Polyglot yuk: ayni girdi {len(contexts)} farkli baglamda "
            f"({', '.join(contexts)}) saldiri iceriyor - birden fazla "
            f"ayristiriciyi atlatma girisimi"
            if len(contexts) >= 2 else "Tek baglamli yuk"
        ),
    }
