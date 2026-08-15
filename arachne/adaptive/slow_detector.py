"""
Faz 21 - Dusuk-ve-Yavas (low-and-slow) tespiti.

--- Ko-evrim fikri ---
Faz 15'te bir flood/DDoS tespiti kurduk: kisa pencerede hiz esigi asilirsa
alarm. Akilli saldirgan bunu OGRENIR ve taktik degistirir: eylemlerini uzun
bir zamana yayar - saatte 1 parola denemesi (password spraying), gunlere
yayilmis yavas port taramasi, damla damla veri sizdirma (drip exfil). Anlik
hiz hicbir zaman flood esigini tetiklemez, bu yuzden hacim tabanli tespit
kordur. Bu modul o kor noktayi kapatir: anlik hiz yerine UZUN penceredeki
KUMULATIF kaymayi ve inter-arrival (varislar arasi) DUZENLILIGINI olcer.

--- Uc sinyal ---
  1. CUSUM (kumulatif toplam kontrol karti): her gozlemin hedeften sapmasini
     bir "slack" (k) payi dusulerek kumulatif toplar. Kucuk ama SUREKLI bir
     sapma, tek basina alarm vermese de CUSUM'da birikip karar araligini
     (h) asar. Klasik SPC (statistical process control) araci.
  2. Inter-arrival duzenliligi: bir insan duzensiz araliklarla is yapar;
     bir betik/otomat cogu zaman ESIT araliklarla (dusuk varyasyon katsayisi)
     pacing yapar. Anormal DUZENLILIK, dusuk-ve-yavas otomasyonun izidir.
  3. Uzun pencere sayimi: flood esiginin altinda kalsa da uzun pencerede
     (ornek 1 saat) toplam eylem sayisi.

--- DURUSTLUK NOTU ---
Bu bir *tespit gostergesidir*, kanit degil. CUSUM ve duzenlilik sezgisel
esikler kullanir; me sru ama duzenli otomasyon (saglik kontrolu, cron)
false-positive uretebilir - bu yuzden cikti aciklanabilir bir `reason` ile
gelir, nihai karar degil skor sunar. Darktrace'in "low and slow" tespiti ya
da tam bir UEBA urunu DEGILDIR; onlarin cekirdek istatistiksel mantigini
(CUSUM/EWMA drift + inter-arrival regularity) kucuk ve deterministik olarak
gosterir.

--- Gercek cerceve eslemesi ---
CUSUM/EWMA kontrol kartlari (SPC), Darktrace "low and slow" anomali tespiti,
MITRE D3FEND "User Behavior Analysis" (D3-UBA), password spraying (MITRE
ATT&CK T1110.003), yavas tarama.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca kendi izleme yuzeyimizdeki (honeypot/monitor)
zaman damgalarini analiz eder; hicbir baska sisteme dokunmaz, hack-back
yoktur. "Tespit" isaretler, "durdurma" SOAR katmaninin isidir.

Harici bagimlilik yok - sadece stdlib.
"""
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


def cusum(values: list, target: float, slack: float) -> dict:
    """Tek-tarafli (yukari yonlu) CUSUM kontrol karti.

    Her gozlem icin kumulatif toplam:
        S_i = max(0, S_{i-1} + (x_i - target - slack))
    `slack` (k) kucuk gurultuyu emer; sadece target+slack'i asan kalici
    sapmalar birikir. Donen `peak`, serinin ulastigi en yuksek kumulatif
    degerdir. `exceeded`, peak >= karar araligi (h = 5 * slack, slack=0 ise
    h=5.0) oldugunda True olur. h=5k, SPC literaturunde yaygin bir varsayilan
    karar araligidir (~ort. 3 sigma kaymaya duyarli).

    Doner: {"peak": float, "series": list[float], "exceeded": bool}
    """
    s = 0.0
    peak = 0.0
    series = []
    for x in values:
        s = max(0.0, s + (x - target - slack))
        series.append(round(s, 4))
        if s > peak:
            peak = s
    decision_interval = 5.0 * slack if slack > 0 else 5.0
    return {
        "peak": round(peak, 4),
        "series": series,
        "exceeded": peak >= decision_interval,
    }


def interval_regularity(timestamps: list) -> float:
    """Varislar arasi (inter-arrival) surelerin DUZENLILIGINI 0..1 olcer.

    Metrik: 1 - CV, burada CV = std / mean, inter-arrival surelerinin
    varyasyon katsayisidir (coefficient of variation). Bir insan duzensiz
    calisir (yuksek CV -> dusuk skor); bir otomat sabit araliklarla pacing
    yapar (CV ~ 0 -> skor ~ 1). Sonuc [0,1] araligina kirpilir.

    Yorumlama: YUKSEK deger = anormal derecede duzenli = makine pacing'i.
    En az 3 zaman damgasi (yani 2 aralik) gerekir; yetersiz veride 0.0.
    """
    if len(timestamps) < 3:
        return 0.0
    ts = sorted(timestamps)
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    mean = statistics.fmean(intervals)
    if mean <= 0:
        # Tum damgalar ayni ani -> ayirt edilemez, duzenlilik iddia etme.
        return 0.0
    std = statistics.pstdev(intervals)
    cv = std / mean
    return round(max(0.0, min(1.0, 1.0 - cv)), 4)


@dataclass
class _SlowWindow:
    """Bir kaynagin uzun pencere zaman damgalarini tutar."""
    timestamps: deque = field(default_factory=lambda: deque(maxlen=5000))


class SlowBurnDetector:
    """Dusuk-ve-yavas (sub-threshold) davranis tespiti.

    Her kaynak icin uzun pencere (ornek 1 saat) zaman damgalarini tutar.
    Dakikalik hizlari bir CUSUM kontrol kartina besler: anlik hiz taban
    cizgisini (baseline_rate_per_min) az ama SUREKLI asiyorsa CUSUM birikir.
    Ayrica inter-arrival duzenliligini olcer. slow_burn, CUSUM karar
    araligini asarsa VEYA duzenlilik yuksekse True olur - anlik hiz hicbir
    zaman flood alarmi vermese bile.
    """

    def __init__(self, baseline_rate_per_min=2.0, cusum_slack=1.0,
                 decision_interval=5.0, long_window_sec=3600,
                 regularity_threshold=0.85, min_events=10,
                 clock=time.monotonic):
        self.baseline_rate_per_min = baseline_rate_per_min
        self.cusum_slack = cusum_slack
        self.decision_interval = decision_interval
        self.long_window_sec = long_window_sec
        self.regularity_threshold = regularity_threshold
        self.min_events = min_events          # gurultu icin alt esik
        self._clock = clock
        self._sources = defaultdict(_SlowWindow)

    def record(self, source_ip: str) -> None:
        now = self._clock()
        win = self._sources[source_ip]
        win.timestamps.append(now)

    def _recent(self, timestamps, now) -> list:
        cutoff = now - self.long_window_sec
        return [t for t in timestamps if t >= cutoff]

    def _per_minute_rates(self, timestamps, now) -> list:
        """Uzun penceredeki olaylari dakikalik kovalara toplar (olay/dk)."""
        cutoff = now - self.long_window_sec
        buckets = defaultdict(int)
        for t in timestamps:
            if t >= cutoff:
                buckets[int((t - cutoff) // 60)] += 1
        if not buckets:
            return []
        span = max(buckets) + 1
        return [float(buckets.get(i, 0)) for i in range(span)]

    def evaluate(self, source_ip: str) -> dict:
        """Bir kaynagin dusuk-ve-yavas durumunu degerlendirir."""
        now = self._clock()
        win = self._sources.get(source_ip)
        empty = {
            "source_ip": source_ip, "slow_burn": False, "cusum_peak": 0.0,
            "long_count": 0, "mean_interval_sec": 0.0, "regularity": 0.0,
            "reason": "veri yok",
        }
        if not win or not win.timestamps:
            return empty

        recent = self._recent(win.timestamps, now)
        long_count = len(recent)
        if long_count < 2:
            e = dict(empty)
            e["long_count"] = long_count
            e["reason"] = "yetersiz veri (uzun pencerede <2 olay)"
            return e

        intervals = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
        mean_interval = statistics.fmean(intervals) if intervals else 0.0

        rates = self._per_minute_rates(recent, now)
        cu = cusum(rates, target=self.baseline_rate_per_min,
                   slack=self.cusum_slack)
        cusum_peak = cu["peak"]

        regularity = interval_regularity(recent)

        # Karar: yeterli hacim varken, kumulatif kayma karar araligini asiyor
        # ya da inter-arrival anormal duzenli. Anlik hiz flood esigi altinda
        # olsa bile bu, kasitli sub-threshold pacing'in izidir.
        drift_hit = cusum_peak >= self.decision_interval
        regular_hit = regularity >= self.regularity_threshold
        slow_burn = long_count >= self.min_events and (drift_hit or regular_hit)

        if slow_burn:
            parts = []
            if drift_hit:
                parts.append(
                    f"kumulatif kayma (CUSUM peak {cusum_peak:.1f} >= "
                    f"karar araligi {self.decision_interval})")
            if regular_hit:
                parts.append(
                    f"anormal duzenli aralik (duzenlilik {regularity:.2f} >= "
                    f"{self.regularity_threshold}, ~otomat pacing'i)")
            reason = (
                f"Dusuk-ve-yavas: {long_count} olay {self.long_window_sec}sn'e "
                f"yayilmis, ort. aralik {mean_interval:.0f}sn - anlik hiz flood "
                f"esigini tetiklemiyor ama " + " ve ".join(parts))
        elif long_count < self.min_events:
            reason = (
                f"Yetersiz hacim: {long_count} olay (min {self.min_events}) - "
                f"dusuk-ve-yavas iddiasi icin cok az")
        else:
            reason = (
                f"Normal tempo: {long_count} olay, ort. aralik "
                f"{mean_interval:.0f}sn, CUSUM peak {cusum_peak:.1f} "
                f"(esik {self.decision_interval}), duzenlilik {regularity:.2f}")

        return {
            "source_ip": source_ip,
            "slow_burn": slow_burn,
            "cusum_peak": round(cusum_peak, 3),
            "long_count": long_count,
            "mean_interval_sec": round(mean_interval, 2),
            "regularity": regularity,
            "reason": reason,
        }
