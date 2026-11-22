"""
Mutasyon (evasion) motoru — bir saldiri yukunu, imza tabanli savunmayi
ATLATMAYI denemek uzere deterministik olarak donusturur.

Bunlar, guvenlik testinde bilinen standart WAF-atlatma teknikleridir (buyuk/
kucuk harf oynama, yorum ekleme, kodlama, bosluk hilesi...). Amac, kendi
WAF'imizin hangi varyantlari kacirdigini bulup savunmayi guclendirmektir.
Deterministiktir: ayni girdi -> ayni cikti (tekrarlanabilir, test edilebilir).
Yalnizca kendi lab hedefimize karsi kullanilir.
"""
from __future__ import annotations

from urllib.parse import quote

_SQL_KW = ["UNION", "SELECT", "DROP", "SLEEP", "OR", "AND", "FROM", "TABLE"]


def _case_alt(s: str) -> str:
    out, up = [], True
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if up else ch.lower()); up = not up
        else:
            out.append(ch)
    return "".join(out)


def _inline_comment_sql(s: str) -> str:
    import re
    out = s
    for kw in _SQL_KW:
        if len(kw) >= 4:
            rep = kw[:2] + "/**/" + kw[2:]
        else:
            rep = kw[0] + "/**/" + kw[1:]
        out = re.sub(kw, rep, out, flags=re.IGNORECASE)
    return out


def _ws_comment(s: str) -> str:
    return s.replace(" ", "/**/")


def _url_encode(s: str) -> str:
    return quote(s, safe="")


def _double_url_encode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


def _nested_tag(s: str) -> str:
    # <script> -> <scr<script>ipt> ; <svg -> <sv<svg>g gibi filtre-kirma
    for tag in ("script", "svg", "img", "details"):
        if tag in s.lower():
            i = s.lower().index(tag)
            return s[:i] + tag[:2] + "<" + tag + ">" + tag[2:] + s[i + len(tag):]
    return s + "<x>"


def _newline_inject(s: str) -> str:
    # metachar tabanli imzalari atlatmak icin ayirici -> yeni satir (%0a)
    for sep in ("; ", ";", " && ", "&&", " | ", "|"):
        if sep in s:
            return s.replace(sep, "\n", 1)
    return s


def _dot_pct(s: str) -> str:
    return s.replace("../", "..%2f").replace("..\\", "..%5c")


def _double_dot_pct(s: str) -> str:
    # tek çözmeyi atlatmak icin cift kodlama
    return s.replace("../", "%252e%252e%252f")


def _space_pad(s: str) -> str:
    return s.replace("{{", "{{ ").replace("}}", " }}").replace("*", " * ")


# kategori -> uygulanacak mutatorler (ad, fonksiyon)
_BY_CATEGORY = {
    "SQL Injection": [("case", _case_alt), ("inline_comment", _inline_comment_sql),
                      ("ws_comment", _ws_comment), ("url", _url_encode)],
    "XSS": [("case", _case_alt), ("nested_tag", _nested_tag), ("url", _url_encode)],
    "Command Injection": [("newline", _newline_inject), ("case", _case_alt)],
    "Path Traversal": [("dot_pct", _dot_pct), ("double_pct", _double_dot_pct),
                       ("url", _url_encode)],
    "SSTI": [("space_pad", _space_pad), ("case", _case_alt)],
}


def mutate(category: str, payload: str):
    """(mutasyon_adi, mutasyonlu_payload) listesi doner. 'base' orijinaldir."""
    out = [("base", payload)]
    for name, fn in _BY_CATEGORY.get(category, []):
        try:
            mutated = fn(payload)
        except Exception:
            continue
        if mutated and mutated != payload:
            out.append((name, mutated))
    # iki katmanli kombinasyon (or. case + inline_comment) — daha zorlu varyant
    muts = _BY_CATEGORY.get(category, [])
    if len(muts) >= 2:
        (n1, f1), (n2, f2) = muts[0], muts[1]
        try:
            combo = f2(f1(payload))
            if combo not in (p for _, p in out):
                out.append((f"{n1}+{n2}", combo))
        except Exception:
            pass
    return out


def mutator_names(category: str):
    return ["base"] + [n for n, _ in _BY_CATEGORY.get(category, [])]
