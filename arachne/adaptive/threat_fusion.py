"""
Faz 43 - Bayesci Tehdit Fuzyonu (Bayesian Threat Fusion).

--- Ko-evrim fikri ---
Onceki fazlarda cok sayida bagimsiz dedektor uretildi: imza (Faz 1),
flood/anomali (Faz 15), beacon (Faz 41), yenilik/sifir-gun (Faz 42),
yavas-yanma (slow burn), honeytoken, sybil, aldatma-dokunusu... Her biri
tek basina "supheli mi?" sorusuna KISMI bir cevap verir. Naif yaklasim
bunlari agirlikli toplamla birlestirir; ama agirlikli toplamin olasiliksal
bir anlami yoktur ve kalibre etmesi zordur.

Bu modul daha ilkeli bir yol izler: her dedektor bir OLABILIRLIK ORANI
(likelihood ratio, LR) sunar ve biz bir ONSEL (prior) inanci Bayes kuraliyla
guncelleriz. Sonuc tek bir SONSAL (posterior) tehdit olasiligidir (0..1).

--- Matematik (belgeli) ---
Bayes kurali oran (odds) formunda cok sade calisir. Bir dedektor D "atesledi"
(fired) ise, onun olabilirlik orani:
    LR = P(D atesler | tehdit) / P(D atesler | temiz)
Bayes kurali oran formunda:
    posterior_odds = prior_odds * LR
Cok sayida BAGIMSIZ dedektor icin (naive-Bayes varsayimi) LR'ler carpilir:
    posterior_odds = prior_odds * LR_1 * LR_2 * ... * LR_k
Carpimlar sayisal olarak tasabilir; bu yuzden logaritma (log-odds / logit)
uzayinda calisiriz, carpim toplama doner:
    log_odds(posterior) = log_odds(prior) + sum( ln(LR_i) )   [sadece atesleyenler]
Son adimda logit'i geri olasiliga ceviririz (sigmoid):
    posterior = sigmoid( log_odds(posterior) )
Bu, spam filtrelerindeki (Robinson/Graham) log-olabilirlik birlestirmesiyle
ve cok-sensorlu fuzyondaki (sensor fusion) log-likelihood toplamiyla AYNI
matematiktir.

--- DURUSTLUK NOTU ---
Naive-Bayes "kosullu bagimsizlik" varsayimini kullanir: dedektorlerin
tehdit verildiginde birbirinden bagimsiz atesledigini kabul eder. Gercekte
dedektorler korele olabilir (ornek: flood ve beacon ayni botnet'ten). Bu
durumda ortak kanit CIFT sayilabilir ve sonsal olasilik SISIRILIR. Bu yuzden
cikti bir OLASILIK TAHMINIDIR, kesin gercek degil; LR degerleri de kaba,
elle-kalibre tahminlerdir. Uretimde LR'ler etiketli veriden ogrenilmeli ve
korelasyon icin duzeltilmelidir. Bu modul cekirdek mantigi aciklanabilir
sekilde gosterir; kalibre edilmis bir risk motorunun tam kopyasi degildir.

--- Gercek cerceve eslemesi ---
Bayes cikarimi, olasiliksal sensor fuzyonu, log-odds (logit) birlestirme,
naive-Bayes siniflandirma, olabilirlik orani testi (likelihood-ratio test).
Kavramsal olarak SIEM risk-skorlama motorlarinin ve Bayes tehdit-fuzyon
arastirmalarinin cekirdegiyle ayni ailedendir.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca kendi dedektorlerimizin urettigi sinyalleri
yerel olarak birlestirir; hicbir baska sisteme dokunmaz, hack-back yoktur,
disari veri gondermez. Deterministiktir (rastgelelik yok). Yuksek sonsal
olasilik bir onceliklendirme/yukseltme girdisidir, otomatik saldiri gerekcesi
degildir.

Harici bagimlilik yok - sadece stdlib math.
"""
import math
from dataclasses import dataclass, field

# Olasiligi (0,1) araligina sikistirmak icin epsilon - log_odds'ta 0 ya da 1
# sonsuza (inf) goturur; bunu engelleriz.
_EPS = 1e-9


def log_odds(p: float) -> float:
    """Bir olasiligi log-odds (logit) uzayina cevirir: ln(p / (1-p)).

    `p` 0 ya da 1'e cok yakinsa logit sonsuza gider; bu yuzden p'yi
    [_EPS, 1-_EPS] araligina sikistiririz (clamp). Boylece fonksiyon her
    zaman sonlu bir sayi doner - deterministik ve sayisal olarak guvenli.
    """
    p = min(1.0 - _EPS, max(_EPS, p))
    return math.log(p / (1.0 - p))


def sigmoid(x: float) -> float:
    """Log-odds'u (logit) geri olasiliga cevirir: 1 / (1 + e^-x).

    log_odds'un tersidir. Cok buyuk negatif x'te overflow olmasin diye
    iki kollu (numerically-stable) hesaplanir. Donus daima [0,1] araliginda.
    """
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


@dataclass
class Signal:
    """Tek bir dedektorun sundugu kanit birimi.

    name : dedektor adi (ornek 'honeytoken').
    fired: dedektor atesledi mi? Sadece atesleyenler sonsala katkida bulunur.
    lr   : atesledignde olabilirlik orani (>1 supheyi artirir, =1 notr,
           <1 aslinda supheyi azaltir - 'temiz' lehine kanit).
    """
    name: str
    fired: bool
    lr: float = 1.0


def _coerce_signal(s) -> Signal:
    """Dict ya da Signal girdisini Signal'e cevirir (esnek API icin)."""
    if isinstance(s, Signal):
        return s
    return Signal(
        name=str(s.get("name", "?")),
        fired=bool(s.get("fired", False)),
        lr=float(s.get("lr", 1.0)),
    )


def fuse(prior: float, signals: list) -> dict:
    """Bagimsiz dedektor sinyallerini Bayes ile tek bir sonsal olasiliga birlestirir.

    `prior`  : onsel tehdit olasiligi (0..1) - kanit gelmeden onceki inanc.
    `signals`: {"name": str, "fired": bool, "lr": float} sozluklerinin (ya da
               Signal nesnelerinin) listesi.

    Matematik (bkz. modul basligi):
        L = log_odds(prior) + sum( ln(lr_i) )   [sadece fired=True olanlar]
        posterior = sigmoid(L)

    Donus dict:
      posterior     : float 0..1, birlesik sonsal tehdit olasiligi.
      prior         : float, kullanilan onsel (sikistirilmis).
      contributions : atesleyen her sinyal icin {name, lr, delta_logodds}.
      top_factors   : en cok katki yapan (mutlak delta) sinyal adlari.
      verdict_tr    : Turkce degerlendirme.
    Deterministik: ayni girdi -> ayni cikti, rastgelelik yok.
    """
    prior = min(1.0 - _EPS, max(_EPS, float(prior)))
    base = log_odds(prior)
    total = base
    contributions = []
    for raw in signals:
        sig = _coerce_signal(raw)
        if not sig.fired:
            continue
        lr = max(_EPS, float(sig.lr))   # lr<=0 anlamsiz; guvenli tabana cek
        delta = math.log(lr)
        total += delta
        contributions.append({
            "name": sig.name,
            "lr": lr,
            "delta_logodds": round(delta, 4),
        })

    posterior = sigmoid(total)

    # En cok agirlik tasiyan faktorler (mutlak katkiya gore).
    ranked = sorted(contributions, key=lambda c: -abs(c["delta_logodds"]))
    top_factors = [c["name"] for c in ranked[:3]]

    if posterior >= 0.85:
        verdict = (
            f"YUKSEK TEHDIT (sonsal %{posterior * 100:.0f}): birden fazla "
            f"bagimsiz kanit ayni yonu gosteriyor ({', '.join(top_factors) or '-'}) "
            f"- yukseltmeye deger. DURUSTLUK: olasilik tahminidir, kesin degil."
        )
    elif posterior >= 0.5:
        verdict = (
            f"ORTA TEHDIT (sonsal %{posterior * 100:.0f}): kanitlar supheyi "
            f"onsel uzerine cikardi ({', '.join(top_factors) or '-'}) - izle/dogrula."
        )
    elif posterior >= prior:
        verdict = (
            f"DUSUK-ARTAN (sonsal %{posterior * 100:.0f}): kanit onsel inanci "
            f"biraz artirdi ama esik alti - tekil izleme yeterli."
        )
    else:
        verdict = (
            f"TEMIZ EGILIM (sonsal %{posterior * 100:.0f}): atesleyen kanit yok "
            f"ya da 'temiz' lehine - sonsal onselin altinda/esdeger."
        )

    return {
        "posterior": round(posterior, 4),
        "prior": round(prior, 4),
        "contributions": contributions,
        "top_factors": top_factors,
        "verdict_tr": verdict,
    }


# Varsayilan dedektor olabilirlik oranlari (LR). Elle-kalibre, kaba tahminler.
# honeytoken ve deception_touch DEVASA LR tasir cunku bunlarin yanlis-pozitif
# orani neredeyse sifirdir: mesru bir kullanici bir bal-jetonuna (honeytoken)
# ya da aldatma-tuzagina (deception) dokunmaz - dokunan neredeyse kesin dusman.
DEFAULT_DETECTORS = {
    "signature": 6.0,        # bilinen imza eslesmesi
    "flood": 4.0,            # hacim anomalisi / DDoS gostergesi
    "beacon": 8.0,           # duzenli C2 beacon periyodikligi
    "honeytoken": 40.0,      # bal-jetonu erisimi - neredeyse sifir yanlis-pozitif
    "novelty": 3.0,          # sifir-gun / tanidik olmayan payload
    "slow_burn": 5.0,        # yavas-ve-alcak (low-and-slow) kampanya
    "sybil": 6.0,            # sahte coklu kimlik / Sybil davranisi
    "deception_touch": 50.0,  # aldatma tuzagina dokunus - neredeyse kesin dusman
}


class ThreatFusion:
    """Isimli dedektorlerden gelen atesleme sinyallerini Bayes ile birlestiren motor.

    `prior`     : temel onsel tehdit olasiligi.
    `detectors` : name -> varsayilan LR eslemesi (None ise DEFAULT_DETECTORS).
    `assess`    : atesleyen dedektor adlarindan sinyaller kurar ve fuse() cagirir;
                  LR'ler `extra` ile ornek-bazinda ezilebilir.
    Deterministik: rastgelelik yoktur.
    """

    def __init__(self, prior: float = 0.15, detectors: dict = None):
        self.prior = prior
        self.detectors = dict(detectors) if detectors is not None else dict(DEFAULT_DETECTORS)

    def assess(self, fired_names: list, extra: dict = None) -> dict:
        """Atesleyen dedektor adlarindan bir tehdit degerlendirmesi uretir.

        `fired_names`: atesleyen dedektorlerin adlari (liste).
        `extra`      : opsiyonel name -> LR ezmesi. Bilinmeyen bir ad `extra`
                       ile veya varsayilan (2.0) LR ile yine de sinyal olur;
                       boylece yeni dedektorler kayit gerektirmeden katilabilir.

        fuse()'un ciktisina ek olarak degerlendirilen 'fired' listesini de ekler.
        """
        extra = extra or {}
        signals = []
        for name in fired_names:
            if name in extra:
                lr = float(extra[name])
            elif name in self.detectors:
                lr = float(self.detectors[name])
            else:
                # Kayitsiz dedektor: notr-uzeri makul bir varsayilan.
                lr = 2.0
            signals.append(Signal(name=name, fired=True, lr=lr))

        result = fuse(self.prior, signals)
        result["fired"] = list(fired_names)
        return result
