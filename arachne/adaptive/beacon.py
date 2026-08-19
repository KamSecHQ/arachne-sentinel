"""
Faz 41 - Sifreli C2 Beacon Tespiti (ZAMANLAMA tabanli).

--- Ko-evrim fikri ---
Saldirgan, imza/payload tabanli tespitin yakalandigini OGRENIR ve C2
(Command-and-Control) trafigini TLS ile sifreler. Artik payload'a bakarak
"kotu"yu goremeyiz - icerik opak. Ama implant/beacon'un bir zayifligi kalir:
kurbandaki implant, operatore DUZENLI araliklarla "eve telefon eder"
(call-home). Bu ritim, icerik sifreli olsa bile ZAMANLAMA duzleminde
gorunur. Bu modul, olaylarin gelis-araligi (inter-arrival) dizisini
istatistiksel olarak inceleyerek bu ritmi tespit eder.

--- Iki sinyal ---
  1. DUZENLILIK (regularity): Gelis araliklarinin ortalamasi (mean) ve
     degisim katsayisi (CV = std / mean). Dusuk CV = cok duzenli araliklar
     = makine ureten periyodik davranis. Insan trafigi dagilimca duzensizdir
     (yuksek CV), beacon ise duzenlidir.
  2. JITTER'LI BEACON: Gercek implantlar (Cobalt Strike vb.) tespiti
     zorlastirmak icin araliga +/- rastgele jitter ekler (ornek 60sn +/- %20).
     Bu durumda CV sifir degildir ama araliklar hala bir TABAN periyodun
     etrafinda KUMELENIR. Jitter yuzdesini tahmin edip, makul jitter (<%50)
     ile hala tutarli olan trafigi "jitterli beacon" olarak isaretleriz.

--- Esikler (belgeli, deterministik) ---
  * min_events: en az 6 olay olmadan istatistik anlamsiz (varsayilan 6).
  * regularity = max(0, 1 - CV) olarak 0..1'e sikistirilir.
  * is_beacon = yeterli olay VE regularity >= 0.5 (yani CV <= 0.5,
    jitter <= ~%50). Cok temiz beacon (CV<=0.15) yuksek guven alir.
  * jitter_pct = CV * 100 (araligin ortalamaya gore goreli sapmasi).

--- DURUSTLUK NOTU ---
Bu bir *tespit gostergesidir*, kesin kanit DEGILDIR. Ne yapar: sifreli olsa
bile periyodik call-home ritmini istatistikle isaretler. Ne IDDIA ETMEZ:
trafigin kesin kotu oldugunu, hangi C2 ailesi oldugunu, ya da payload'i
cozdugunu. Mesru periyodik trafik de vardir (NTP, yazilim guncelleme yoklama,
saglik-kontrol/heartbeat, RSS cekme) ve bunlar da beacon gibi gorunur - bu
yuzden cikti bir human-review sinyalidir, otomatik blok gerekcesi degil.
Kucuk/deterministik bir otokorelasyon yaklasimidir; NetFlow/Zeek olcekli bir
motorun tam kopyasi degildir.

--- Gercek cerceve eslemesi ---
MITRE ATT&CK T1071 (Application Layer Protocol / C2), beacon+jitter analizi
(Cobalt Strike tespiti), gelis-araligi otokorelasyonu (RITA / Zeek / Corelight
beaconing analytics), frekans/periyodiklik tespiti.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca kendi izleme yuzeyimize gelen olaylarin zaman
damgalarini analiz eder; hicbir baska sisteme dokunmaz, hack-back yoktur,
disari paket gondermez. Tum analiz yerel zaman damgalari uzerinde kalir.

Harici bagimlilik yok - sadece stdlib statistics/time/collections.
"""
import statistics
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field


def _intervals(timestamps: list) -> list:
    """Sirali zaman damgalarindan ardil gelis-araliklarini (delta) uretir."""
    ts = sorted(timestamps)
    return [b - a for a, b in zip(ts, ts[1:]) if (b - a) > 0]


def detect_period(intervals: list) -> float:
    """Baskin periyodu (saniye) tahmin eder - deterministik.

    Basit otokorelasyon/mod yaklasimi: araliklari makul bir kovaya
    (bucket) yuvarlar ve en cok tekrar eden kova merkezini baskin periyot
    kabul eder. Boylece jitter'la dagilmis araliklar ayni kovada toplanip
    taban periyodu ele verir. Aday yoksa medyana duser.

    `intervals`: pozitif gelis-araliklari listesi (saniye).
    Donus: baskin periyot (saniye), bos girdide 0.0.
    """
    intervals = [i for i in intervals if i > 0]
    if not intervals:
        return 0.0
    if len(intervals) == 1:
        return round(float(intervals[0]), 3)

    # Kova boyutu: medyanin ~ %10'u (en az 1sn), araliklari periyodun
    # etrafinda toplamak icin. Deterministik: sadece verinin kendisine bagli.
    med = statistics.median(intervals)
    bucket = max(1.0, med * 0.10)
    counts = Counter(round(i / bucket) for i in intervals)
    best_bucket, best_n = counts.most_common(1)[0]

    # Baskin kovaya dusen araliklarin ortalamasi = daha hassas periyot tahmini.
    members = [i for i in intervals if round(i / bucket) == best_bucket]
    if members:
        return round(statistics.fmean(members), 3)
    return round(med, 3)


def beacon_score(timestamps: list) -> dict:
    """Bir kaynagin olay zaman damgalarindan C2-beacon skorunu hesaplar.

    Yaklasim: gelis-araliklarinin degisim katsayisi (CV = std/mean).
    Dusuk CV = duzenli ritim = beacon suphesi. Jitter'li beacon icin de
    makul jitter'a (CV <= 0.5) izin verilir.

    `timestamps`: bir kaynaga ait olay zaman damgalari (saniye, sirali olmasa
    da olur - fonksiyon siralar).

    Donus dict:
      is_beacon  : bool  - beacon suphesi var mi
      period_sec : float|None - tahmini periyot (saniye)
      jitter_pct : float - araligin ortalamaya gore goreli sapmasi (%)
      regularity : float - 0..1, 1 = mukemmel duzenli
      confidence : float - 0..1, tespit guveni (olay sayisi + duzenlilik)
      reason     : str   - Turkce aciklama
    """
    intervals = _intervals(timestamps)
    n_events = len(timestamps)

    # Yeterli veri yok: istatistik anlamsiz.
    if len(intervals) < 2:
        return {
            "is_beacon": False,
            "period_sec": None,
            "jitter_pct": 0.0,
            "regularity": 0.0,
            "confidence": 0.0,
            "reason": (
                f"Yetersiz veri: beacon istatistigi icin en az 3 olay gerekli "
                f"({n_events} olay var)"
            ),
        }

    mean_iv = statistics.fmean(intervals)
    std_iv = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    cv = (std_iv / mean_iv) if mean_iv > 0 else 1.0

    # Duzenlilik: CV'yi 0..1'e ters cevir. CV=0 -> 1.0 (mukemmel), CV>=1 -> 0.
    regularity = max(0.0, 1.0 - cv)
    jitter_pct = round(cv * 100, 2)
    period = detect_period(intervals)

    # Esik: yeterli olay VE regularity >= 0.5 (CV <= 0.5, jitter <= ~%50).
    enough = n_events >= 6
    is_beacon = enough and regularity >= 0.5

    # Guven: olay bollugu ve duzenlilikle artar. 12+ olayda olay-terimi doyar.
    event_factor = min(1.0, len(intervals) / 11.0)
    confidence = round(regularity * event_factor, 3) if is_beacon else round(
        regularity * event_factor * 0.5, 3)

    if is_beacon:
        if cv <= 0.15:
            kind = "cok temiz periyodik beacon (dusuk jitter)"
        else:
            kind = "jitterli beacon (taban periyot + rastgele sapma)"
        reason = (
            f"C2 beacon suphesi: {n_events} olay, ~{period:.1f}sn periyot, "
            f"jitter %{jitter_pct:.0f}, duzenlilik {regularity:.2f} - {kind}. "
            f"Sifreli olsa bile zamanlama ritmi duzenli."
        )
    elif not enough:
        reason = (
            f"Beacon degerlendirmesi icin yetersiz olay: {n_events} "
            f"(en az 6 gerekli) - egilim: duzenlilik {regularity:.2f}"
        )
    else:
        reason = (
            f"Beacon degil: {n_events} olay ama duzensiz araliklar "
            f"(jitter %{jitter_pct:.0f}, duzenlilik {regularity:.2f}) - "
            f"insan/rastgele trafik profiline benziyor"
        )

    return {
        "is_beacon": is_beacon,
        "period_sec": round(period, 3) if period else None,
        "jitter_pct": jitter_pct,
        "regularity": round(regularity, 3),
        "confidence": confidence,
        "reason": reason,
    }


@dataclass
class _Track:
    """Bir kaynagin olay zaman damgalarini tutan kayan pencere."""
    timestamps: deque = field(default_factory=lambda: deque(maxlen=2000))


class BeaconMonitor:
    """Kaynak-basi call-home ritmi izleyici.

    Her kaynak icin olay zaman damgalarini kaydeder ve talep uzerine
    `beacon_score` ile degerlendirir. Saat enjekte edilebilir (test icin
    deterministik).
    """

    def __init__(self, min_events=6, clock=time.monotonic):
        self.min_events = min_events
        self._clock = clock
        self._tracks = defaultdict(_Track)

    def record(self, source_ip: str) -> None:
        """Bir kaynaktan gelen olayi (call-home adayi) zaman damgasiyla ekler."""
        now = self._clock()
        self._tracks[source_ip].timestamps.append(now)

    def evaluate(self, source_ip: str) -> dict:
        """Bir kaynagin beacon durumunu degerlendirir.

        Kayitli zaman damgalarini `beacon_score`'a verir. Olay sayisi
        `min_events`'in altindaysa erken bir "veri yok/az" yaniti doner
        (ama beacon_score kendi esigini de uygular)."""
        track = self._tracks.get(source_ip)
        if not track or len(track.timestamps) < 2:
            return {
                "source_ip": source_ip,
                "is_beacon": False,
                "period_sec": None,
                "jitter_pct": 0.0,
                "regularity": 0.0,
                "confidence": 0.0,
                "reason": "veri yok veya yetersiz olay",
            }
        result = beacon_score(list(track.timestamps))
        # min_events monitor politikasi: score is_beacon dese bile monitor
        # esiginin altindaysa henuz beacon ilan etme (deterministik kapi).
        if len(track.timestamps) < self.min_events:
            result["is_beacon"] = False
        result["source_ip"] = source_ip
        return result
