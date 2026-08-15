"""
Faz 15 - Istatistiksel anomali ve flood/DDoS tespiti.

Imza tabanli tespit (Faz 1, 14) "bilinen kotu"yu yakalar. Anomali tespiti
ise "normalden sapan"i yakalar - imzasi olmayan, yeni ya da hacim tabanli
saldirilari.

--- Iki yaklasim ---
  1. HACIM ANOMALISI (flood/DDoS): Kayan bir pencerede istek hizini olcer;
     ogrenilen bir taban cizgisinin (baseline) uzerine cikan ani artislari
     yakalar. z-score (kac standart sapma uzakta) ile ifade edilir.

  2. DAGILIM ANOMALISI: Bir kaynagin davranis dagilimi (servis/port/olay
     turu) genel populasyondan ne kadar sapiyor? Nadir kombinasyonlar
     supheli.

--- DURUSTLUK NOTU ---
Bu, izole lab ortami icin bir DDoS *tespit* gostergesidir, gercek internet
olcekli bir DDoS *azaltma* (mitigation) sistemi DEGILDIR. Gercek DDoS
korumasi (Cloudflare, Akamai) ISS seviyesinde, anycast agi ve terabit
kapasiteyle calisir - bu bambaska bir muhendislik alanidir. Biz "anormal
hacim artisini tespit edip isaretleme" yetenegini kuruyoruz, "durdurma"
degil (durdurma SOAR katmaninin isi, Faz 7).

Harici bagimlilik yok - sadece stdlib statistics ve collections.
"""
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class _Window:
    """Bir kaynagin zaman damgalarini tutan kayan pencere."""
    timestamps: deque = field(default_factory=lambda: deque(maxlen=2000))


class FloodDetector:
    """Kayan pencere tabanli hacim anomalisi tespiti.

    Her kaynak icin istek zaman damgalarini tutar ve kisa pencere hizini
    (ornek: son 10sn) uzun pencere ortalamasiyla (ornek: son 5dk)
    karsilastirir. Kisa pencere hizi, uzun ortalamanin cok ustundeyse
    (yuksek z-score) flood alarmi verir.
    """

    def __init__(self, short_window=10, long_window=300,
                 flood_threshold=20, zscore_threshold=3.0,
                 clock=time.monotonic):
        self.short_window = short_window
        self.long_window = long_window
        self.flood_threshold = flood_threshold      # kisa pencerede min olay
        self.zscore_threshold = zscore_threshold
        self._clock = clock
        self._sources = defaultdict(_Window)
        # Dakika-kova bazli gecmis hiz (baseline icin)
        self._rate_history = defaultdict(lambda: deque(maxlen=60))

    def record(self, source_ip: str) -> None:
        now = self._clock()
        self._sources[source_ip].timestamps.append(now)

    def _count_in_window(self, timestamps, window, now) -> int:
        cutoff = now - window
        return sum(1 for t in timestamps if t >= cutoff)

    def evaluate(self, source_ip: str) -> dict:
        """Bir kaynagin flood durumunu degerlendirir."""
        now = self._clock()
        window = self._sources.get(source_ip)
        if not window or not window.timestamps:
            return {"source_ip": source_ip, "flood": False,
                    "short_rate": 0, "reason": "veri yok"}

        ts = window.timestamps
        short_count = self._count_in_window(ts, self.short_window, now)
        long_count = self._count_in_window(ts, self.long_window, now)

        short_rate = short_count / self.short_window          # olay/sn
        long_rate = long_count / self.long_window

        # Baseline: uzun pencere hizinin gecmisi
        history = self._rate_history[source_ip]
        history.append(long_rate)
        baseline_mean = statistics.fmean(history) if history else 0.0
        baseline_std = statistics.pstdev(history) if len(history) > 1 else 0.0

        zscore = 0.0
        if baseline_std > 0:
            zscore = (short_rate - baseline_mean) / baseline_std
        elif short_count >= self.flood_threshold:
            zscore = float(self.zscore_threshold + 1)  # baseline yok ama hacim yuksek

        is_flood = (short_count >= self.flood_threshold and
                    zscore >= self.zscore_threshold)

        return {
            "source_ip": source_ip,
            "flood": is_flood,
            "short_count": short_count,
            "short_rate": round(short_rate, 2),
            "long_count": long_count,
            "zscore": round(zscore, 2),
            "baseline_mean_rate": round(baseline_mean, 3),
            "reason": (
                f"Flood: son {self.short_window}sn'de {short_count} olay "
                f"(z-score {zscore:.1f}, esik {self.zscore_threshold}) - "
                f"taban cizgisinin cok ustunde"
                if is_flood else
                f"Normal hacim: {short_count} olay/{self.short_window}sn"
            ),
        }

    def top_talkers(self, limit=10) -> list:
        """En cok istek yapan kaynaklar (kisa pencere)."""
        now = self._clock()
        rows = []
        for ip, window in self._sources.items():
            count = self._count_in_window(window.timestamps, self.short_window, now)
            if count:
                rows.append({"source_ip": ip, "recent_count": count})
        rows.sort(key=lambda r: -r["recent_count"])
        return rows[:limit]


def distribution_anomaly(source_profile: dict, population: dict) -> dict:
    """Bir kaynagin davranis dagiliminin populasyondan sapmasini olcer.

    `source_profile`: {"services": {"ssh": 5, ...}, ...}
    `population`     : tum kaynaklarin toplam servis dagilimi

    Bir kaynak, populasyonda nadir olan servisleri yogun kullaniyorsa
    (ornek: herkes web'e giderken bu IP sadece MySQL'i doverken) bu bir
    anomalidir. Basit bir 'nadir kombinasyon' skoru dondurur.
    """
    src_services = source_profile.get("services", {})
    if not src_services:
        return {"anomaly_score": 0.0, "rare_services": [], "assessment_tr": "veri yok"}

    total_pop = sum(population.values()) or 1
    rare = []
    anomaly = 0.0
    for service, count in src_services.items():
        pop_share = population.get(service, 0) / total_pop
        # Populasyonda nadir (<%5) ama bu kaynakta yogun -> anomali
        if pop_share < 0.05 and count >= 3:
            rare.append(service)
            anomaly += (0.05 - pop_share) * count
    anomaly = min(1.0, anomaly)

    return {
        "anomaly_score": round(anomaly, 3),
        "rare_services": rare,
        "assessment_tr": (
            f"Anomali: bu kaynak populasyonda nadir olan servisleri "
            f"({', '.join(rare)}) yogun kullaniyor - hedefli/atipik davranis"
            if rare else "Davranis dagilimi populasyonla uyumlu"
        ),
    }


def build_baseline(events: list) -> dict:
    """Olay listesinden bir davranis taban cizgisi (baseline) ogrenir.

    Bu, 'normal'in ne oldugunu ogrenmenin basit halidir: servis, port ve
    olay turu dagilimlari. Anomali tespiti bu tabana gore sapmayi olcer."""
    services = defaultdict(int)
    event_types = defaultdict(int)
    ports = defaultdict(int)
    for e in events:
        if e.get("service"):
            services[e["service"]] += 1
        if e.get("event_type"):
            event_types[e["event_type"]] += 1
        if e.get("dest_port"):
            ports[e["dest_port"]] += 1
    return {
        "services": dict(services),
        "event_types": dict(event_types),
        "ports": dict(ports),
        "total_events": len(events),
    }
