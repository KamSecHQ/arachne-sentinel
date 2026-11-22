"""
ADAPTIF SAVUNMA (mavi takim) — ko-evrim icin.

Sabit WAF imzalari, saldirganin atlatma (evasion) varyantlarini kaçirabilir.
Bu adaptif katman, imza taramasindan ONCE bir dizi NORMALLESTIRME uygular
(yorumlari sil, boslugu daralt, URL çöz...). Ko-evrim döngusu, saldirganin
buldugu her atlatmaya karsi uygun normallestiriciyi devreye alarak savunmayi
ogretir. Boylece savunma, saldirgan gelistikçe yukari çekilir.

Imza motoru olarak kendi WAF kurallarimizi (arachne.waf.rules) yeniden kullanir.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus


def _strip_sql_comments(s: str) -> str:
    # yorumu SIL: UN/**/ION -> UNION (keyword'u yeniden birlestirir)
    return re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)


def _collapse_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace("/**/", " ")).strip()


def _url_decode(s: str) -> str:
    return unquote_plus(s)


def _recursive_url_decode(s: str) -> str:
    prev, cur, n = None, s, 0
    while cur != prev and n < 5:
        prev, cur = cur, unquote_plus(cur); n += 1
    return cur


def _normalize_separators(s: str) -> str:
    # yeni satir / sekme ile gizlenmis komut ayiricilarini geri getir
    return s.replace("\n", ";").replace("\r", ";").replace("\t", " ")


NORMALIZERS = {
    "strip_comments": _strip_sql_comments,
    "collapse_ws": _collapse_ws,
    "url_decode": _url_decode,
    "recursive_url_decode": _recursive_url_decode,
    "normalize_separators": _normalize_separators,
}

# hangi mutasyon, hangi normallestirici ile etkisiz kalir (mavi takim ogrenir)
COUNTER = {
    "inline_comment": ["strip_comments"],
    "ws_comment": ["strip_comments", "collapse_ws"],
    "case": [],                       # imzalar zaten IGNORECASE
    "nested_tag": [],                 # ic içe etiket — normalize zor (açik bosluk)
    "url": ["url_decode"],
    "double_pct": ["recursive_url_decode"],
    "dot_pct": ["url_decode"],
    "newline": ["normalize_separators"],
    "space_pad": ["collapse_ws"],
}


class AdaptiveWAF:
    """Ogrenebilen savunma. `enabled` normallestirici kumesi büyüdükçe güçlenir."""

    def __init__(self, enabled=None, block_threshold: int = 50):
        self.enabled = set(enabled or [])
        self.block_threshold = block_threshold

    _ORDER = ("recursive_url_decode", "url_decode", "strip_comments",
              "collapse_ws", "normalize_separators")

    def _candidates(self, text: str):
        """Taranacak aday dizeler: ham + her normallestirici TEK TEK + tam zincir.
        Farkli mutasyonlar farkli normallestirmeyle çözuldugu icin (inline_comment
        -> yorum-sil, ws_comment -> bosluga-daralt) adaylarin HEPSI taranir; biri
        bile imzayi tetiklerse istek engellenir."""
        cands = {text}
        for name in self.enabled:
            try:
                cands.add(NORMALIZERS[name](text))
            except Exception:
                pass
        chained = text
        for name in self._ORDER:
            if name in self.enabled:
                try:
                    chained = NORMALIZERS[name](chained)
                except Exception:
                    pass
        cands.add(chained)
        return cands

    def would_block(self, category, path, param, payload) -> bool:
        from arachne.waf import rules
        best = 0
        for text in self._candidates(payload):
            score = sum(weight for _cat, weight in rules.scan_text(text))
            best = max(best, score)
        return best >= self.block_threshold

    def as_callable(self):
        return lambda cat, path, param, payload: self.would_block(cat, path, param, payload)

    def learn_from(self, bypassed_mutations) -> set:
        """Atlatan mutasyonlara karsi gereken normallestiricileri devreye alir.
        Yeni eklenenlerin kumesini doner."""
        added = set()
        for mut in bypassed_mutations:
            for base in mut.split("+"):          # 'case+inline_comment' -> ikisi de
                for norm in COUNTER.get(base, []):
                    if norm not in self.enabled:
                        self.enabled.add(norm); added.add(norm)
        return added
