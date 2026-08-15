"""
Faz 16 - Otomatik imza uretimi (signature synthesis / feedback loop).

Gercek tehdit istihbarati sistemlerinin en degerli ozelliklerinden biri
KENDINI GELISTIRMESIDIR: yakaladigi saldirilardan yeni imzalar turetir ve
bir sonraki benzer saldiriyi imza tabanli olarak, cok daha hizli yakalar.

--- Nasil calisir? ---
  1. Kotu niyetli yukleri (alarm uretmis olaylar) topla.
  2. Ortak n-gram'lari (ardisik karakter dizileri) cikar.
  3. Her aday n-gram icin YANLIS POZITIF kontrolu yap: bu dizi mesru
     trafikte de gorunuyor mu? Goruyorsa REDDET.
  4. Hayatta kalan, ayirt edici n-gram'lari aday imza olarak oner.

--- Neden yanlis pozitif kontrolu kritik? ---
"select" alt-dizisi tum SQLi yuklerinde var ama mesru "select box" gibi
metinlerde de var. Iyi bir imza, kotu yuklerde SIK ama iyi yuklerde NADIR
gorunmelidir. Bu, klasik bir bilgi-getirisi (information gain) problemidir
ve biz basit ama gercek bir versiyonunu uyguluyoruz.

--- Insan onayi ---
Uretilen imzalar OTOMATIK OLARAK aktif edilmez - "aday" olarak isaretlenir.
Bir imzayi canli tespit hattina almak insan onayi gerektirir. Sebep: kotu
bir otomatik imza, mesru trafigi engelleyerek kendi kendine bir DoS
yaratabilir. Otomasyon oneri getirir; karari insan verir.
"""
import re
from collections import Counter

# Aday n-gram uzunluk araligi (karakter)
MIN_NGRAM = 5
MAX_NGRAM = 20
# Bir aday imzanin kotu yuklerde gorunmesi gereken minimum oran
MIN_MALICIOUS_SUPPORT = 0.3
# Bir aday imzanin mesru yuklerde gorunebilecegi maksimum oran
MAX_BENIGN_SUPPORT = 0.02

# Anlamsiz/cok yaygin diziler (stop-gram) - bunlar imza olamaz
_STOPGRAMS = {
    "http/1.1", "content-", "user-agent", "mozilla", "accept", "get /",
    "post /", "host:", " http", "html", "text/", "charset",
}


def _normalize(payload: str) -> str:
    return " ".join((payload or "").lower().split())


def _extract_ngrams(text: str, n: int) -> set:
    """Metinden n uzunlugunda benzersiz alt-dizileri cikarir."""
    if len(text) < n:
        return set()
    return {text[i:i + n] for i in range(len(text) - n + 1)}


def _is_meaningful(ngram: str) -> bool:
    """Bir n-gram imza adayi olabilecek kadar anlamli mi?"""
    if any(stop in ngram for stop in _STOPGRAMS):
        return False
    # Cogunlukla bosluk ya da tek karakter tekrari ise reddet
    if ngram.count(" ") > len(ngram) * 0.5:
        return False
    if len(set(ngram)) <= 2:
        return False
    return True


def synthesize_signatures(malicious_payloads: list, benign_payloads: list,
                          max_candidates=15) -> dict:
    """Kotu ve mesru yuklerden ayirt edici imza adaylari uretir."""
    mal = [_normalize(p) for p in malicious_payloads if p and p.strip()]
    ben = [_normalize(p) for p in benign_payloads if p and p.strip()]

    if not mal:
        return {"candidates": [], "reason": "kotu niyetli yuk yok",
                "malicious_count": 0, "benign_count": len(ben)}

    # Kotu yuklerde her n-gram'in kac yukte gorundugunu say
    mal_support = Counter()
    for payload in mal:
        seen = set()
        for n in range(MIN_NGRAM, MAX_NGRAM + 1):
            for ng in _extract_ngrams(payload, n):
                if _is_meaningful(ng):
                    seen.add(ng)
        for ng in seen:
            mal_support[ng] += 1

    # Mesru yuklerde her n-gram'in gorunumu
    ben_support = Counter()
    for payload in ben:
        seen = set()
        for n in range(MIN_NGRAM, MAX_NGRAM + 1):
            for ng in _extract_ngrams(payload, n):
                seen.add(ng)
        for ng in seen:
            ben_support[ng] += 1

    n_mal = len(mal)
    n_ben = max(1, len(ben))

    candidates = []
    for ngram, mcount in mal_support.items():
        mal_ratio = mcount / n_mal
        ben_ratio = ben_support.get(ngram, 0) / n_ben
        # Kotu yuklerde SIK, mesru yuklerde NADIR olmali
        if mal_ratio >= MIN_MALICIOUS_SUPPORT and ben_ratio <= MAX_BENIGN_SUPPORT:
            # Bilgi getirisi benzeri skor: kotu destek yuksek, iyi destek dusuk
            discrimination = mal_ratio - ben_ratio * 5
            candidates.append({
                "signature": ngram,
                "malicious_support": round(mal_ratio, 3),
                "benign_support": round(ben_ratio, 3),
                "discrimination_score": round(discrimination, 3),
                "matched_malicious": mcount,
                "status": "candidate",   # ASLA otomatik "active" degil
            })

    # En ayirt edici olanlar once; ust-dizileri (superstring) ele
    candidates.sort(key=lambda c: -c["discrimination_score"])
    candidates = _remove_redundant(candidates)[:max_candidates]

    return {
        "candidates": candidates,
        "candidate_count": len(candidates),
        "malicious_count": n_mal,
        "benign_count": len(ben),
        "note_tr": (
            "Bu imzalar ADAYDIR - otomatik aktif edilmez. Canli tespit "
            "hattina alinmadan once insan onayi gerekir (kotu bir imza "
            "mesru trafigi engelleyip DoS yaratabilir)."
        ),
    }


def _remove_redundant(candidates: list) -> list:
    """Bir aday baska bir adayin alt-dizisiyse ve benzer destege sahipse,
    daha kisa/genel olani tut (gereksiz ozel imzalari ele)."""
    kept = []
    signatures = [c["signature"] for c in candidates]
    for i, cand in enumerate(candidates):
        sig = cand["signature"]
        # Bu imza, listedeki daha kisa bir imzanin ust-dizisi mi?
        redundant = any(
            other != sig and other in sig and
            abs(candidates[j]["malicious_support"] - cand["malicious_support"]) < 0.1
            for j, other in enumerate(signatures) if len(other) < len(sig)
        )
        if not redundant:
            kept.append(cand)
    return kept


def candidate_to_rule(candidate: dict, rule_id: str = None) -> dict:
    """Bir aday imzayi, Faz 14 kural motorunun anlayacagi kural sozlugune
    cevirir. Boylece onaylanan bir aday dogrudan kural setine eklenebilir."""
    sig = candidate["signature"]
    return {
        "id": rule_id or f"synth-{abs(hash(sig)) % 100000}",
        "name": f"Otomatik uretilen imza: {sig[:30]}",
        "severity": "medium",
        "attck": [],
        "condition": "any",
        "strings": [{"id": "synth", "type": "icontains", "value": sig}],
        "description": (
            f"Yakalanan saldirilardan otomatik turetildi "
            f"(kotu destek %{candidate['malicious_support']*100:.0f}, "
            f"mesru destek %{candidate['benign_support']*100:.0f})"
        ),
        "_synthesized": True,
    }
