"""
Cok katmanli kodlama cozucu (deobfuscator).

Saldirganlar imza tabanli savunmalari atlatmak icin yuklerini kodlar:
URL-encode, cift URL-encode, base64, hex, HTML entity, unicode escape...
Bu modul, yuku "sabit noktaya" (fixed point) ulasana kadar tekrar tekrar
cozer ve HANGI adimlardan gectigini de kaydeder.

Neden adimlari da kaydediyoruz? Cunku bir yukun 3 kat base64 + URL-encode
ile sarilmis olmasi, tek basina bir tehdit sinyalidir: mesru trafik boyle
gorunmez. Bu, MITRE ATT&CK T1027.010 (Command Obfuscation) ile eslesir.

Tasarim ilkesi: cozme islemi HER ZAMAN sonlanmali. Sonsuz donguye karsi
iki koruma var - maksimum derinlik (MAX_DEPTH) ve "cikti girdiyle ayni ise
dur" kurali.
"""
import base64
import binascii
import html
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

# Bir yuku en fazla kac kez acmaya calisiriz. Gercek dunyada 2-3 katman
# tipiktir; 8 fazlasiyla guvenli bir ust sinir ve sonsuz donguyu engeller.
MAX_DEPTH = 8

# Cozulmus metnin "anlamli" sayilmasi icin gereken minimum yazdirilabilir
# karakter orani. Base64 cozumu rastgele binary uretirse bunu eleriz.
MIN_PRINTABLE_RATIO = 0.85

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F\s]{16,}$")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_HTML_ENTITY_RE = re.compile(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z]+);")
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")


@dataclass
class DecodeStep:
    """Cozme zincirindeki tek bir adim."""
    method: str          # "url", "base64", "hex", "html-entity", "unicode-escape"
    before: str
    after: str

    def to_dict(self):
        return {"method": self.method, "before": self.before[:200], "after": self.after[:200]}


@dataclass
class DeobfuscationResult:
    original: str
    decoded: str
    steps: list = field(default_factory=list)

    @property
    def layers(self) -> int:
        return len(self.steps)

    @property
    def was_obfuscated(self) -> bool:
        return self.layers > 0

    def method_chain(self) -> str:
        """Ornek: 'url -> base64 -> url' (raporlarda okunakli gosterim)."""
        return " -> ".join(s.method for s in self.steps) if self.steps else "duz metin"

    def to_dict(self):
        return {
            "original": self.original[:500],
            "decoded": self.decoded[:500],
            "layers": self.layers,
            "was_obfuscated": self.was_obfuscated,
            "method_chain": self.method_chain(),
            "steps": [s.to_dict() for s in self.steps],
        }


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text)


def _try_url(text: str):
    """Yuzde-kodlamasini cozer. Sadece gercekten %XX iceriyorsa dener."""
    if not _PERCENT_RE.search(text) and "+" not in text:
        return None
    try:
        out = unquote_plus(text, errors="strict")
    except (UnicodeDecodeError, ValueError):
        try:
            out = unquote(text, errors="replace")
        except Exception:
            return None
    return out if out != text else None


def _try_base64(text: str):
    """Base64 cozer - ama sadece sonuc okunabilir metinse kabul eder.

    Bu 'okunabilirlik' kontrolu kritik: base64 alfabesindeki her metin
    teknik olarak cozulebilir ama cogu zaman anlamsiz binary cikar. Yanlis
    pozitif uretmemek icin sadece anlamli sonuclari kabul ediyoruz."""
    stripped = "".join(text.split())
    if not _BASE64_RE.match(stripped) or len(stripped) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(stripped, validate=True)
        out = raw.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if _printable_ratio(out) < MIN_PRINTABLE_RATIO or out == text:
        return None
    return out


def _try_hex(text: str):
    """Duz hex bloklarini (ornek: '2f6574632f706173737764') cozer."""
    stripped = "".join(text.split())
    if stripped.lower().startswith("0x"):
        stripped = stripped[2:]
    if not _HEX_RE.match(stripped) or len(stripped) % 2 != 0:
        return None
    try:
        out = bytes.fromhex(stripped).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if _printable_ratio(out) < MIN_PRINTABLE_RATIO or out == text:
        return None
    return out


def _try_escapes(text: str):
    r"""\xNN ve \uNNNN kacis dizilerini cozer (JS/Python tarzi obfuskasyon)."""
    if "\\x" not in text and "\\u" not in text:
        return None
    out = _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    out = _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), out)
    return out if out != text else None


def _try_html_entity(text: str):
    """&lt; &#x3c; &#60; gibi HTML varliklarini cozer (XSS filtreleri atlatmak
    icin cok kullanilir)."""
    if not _HTML_ENTITY_RE.search(text):
        return None
    out = html.unescape(text)
    return out if out != text else None


# Sira onemli: once en spesifik/ucuz olanlar. Base64'u sona koyduk cunku
# en cok yanlis pozitif uretme potansiyeli onda.
_DECODERS = [
    ("url", _try_url),
    ("html-entity", _try_html_entity),
    ("unicode-escape", _try_escapes),
    ("hex", _try_hex),
    ("base64", _try_base64),
]


def deobfuscate(payload: str, max_depth: int = MAX_DEPTH) -> DeobfuscationResult:
    """Yuku sabit noktaya ulasana kadar katman katman cozer.

    Donen nesne hem son cozulmus metni hem de gecilen adimlarin listesini
    icerir - yani "bu yuk 3 kat sarilmisti" bilgisi kaybolmaz."""
    if payload is None:
        payload = ""
    original = payload
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
                steps.append(DecodeStep(method=name, before=current, after=out))
                current = out
                progressed = True
                break  # her turda tek bir katman ac, sonra bastan dene
        if not progressed:
            break

    return DeobfuscationResult(original=original, decoded=current, steps=steps)


def obfuscation_score(result: DeobfuscationResult) -> int:
    """Obfuskasyon yogunluguna gore 0-100 arasi bir supheli-lik skoru.

    Gerekce: mesru bir istemci yukunu 3 kat kodlamaz. Katman sayisi arttikca
    kotu niyet olasiligi ustel olarak artar. Cift kodlama (ayni yontem iki
    kez) ozellikle guclu bir sinyaldir - WAF atlatma denemesinin klasik
    imzasidir."""
    if not result.was_obfuscated:
        return 0
    score = min(40, result.layers * 20)
    methods = [s.method for s in result.steps]
    # ayni yontem birden fazla kez -> cift kodlama, klasik WAF atlatma
    if len(methods) != len(set(methods)):
        score += 30
    # base64 + baska bir katman -> ciddi gizleme cabasi
    if "base64" in methods and len(methods) > 1:
        score += 20
    return min(100, score)
