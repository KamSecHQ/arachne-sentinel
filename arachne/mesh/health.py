"""
Faz 31 - Sensor Sagligi & Telemetri (Observability / SRE katmani).

Dagitik sensor agi (Faz 9) mesajlari HMAC-SHA256 + nonce + zaman damgasi +
tekrar oynatma korumasiyla GUVENLI bir sekilde tasir. Ama "mesaj guvenli"
ile "sensor SAGLIKLI" ayni sey degildir: guvenli imzalanmis bir sensor da
sessizce olebilir, paket kaybedebilir ya da bozuk veri gonderebilir.

Bu modul o boslugu doldurur - kriptografiyi DEGIL, OPERASYONEL SAGLIGI olcer:

  1. HEARTBEAT (kalp atisi): Her sensor duzenli "yasiyorum" sinyali gonderir.
     Belirlenen sure icinde sinyal gelmezse sensor 'offline' sayilir. Bu,
     SRE/observability dunyasinin en temel primitifidir (Prometheus 'up',
     Consul health check, Kubernetes liveness probe ile ayni fikir).

  2. PAKET KAYBI (packet loss): Sensor her olaya artan bir sira numarasi
     (sequence) verir. Toplayicida gorulen sira numaralarindaki BOSLUKLAR
     kayip paketleri gosterir - klasik ag izleme teknigi (RTP/TCP sira
     analizi ile ayni mantik). Yuksek kayip = aginda sorun ya da olay dusme.

  3. VERI BUTUNLUGU (data integrity): Toplayici bozuk/dogrulanamayan olaylari
     isaretler; bunlarin sayisi bir saglik gostergesidir.

--- Esik degerleri nasil sectik (DURUSTLUK NOTU) ---
  * heartbeat_timeout=30sn: Tipik sensor 10sn'de bir atis gonderir; 30sn
    ~3 kacirilan atisa denk gelir. Tek bir gecikmede yanlis alarm vermemek
    icin bilincli olarak 1 atislik degil, 3 atislik tolerans birakildi.
  * packet_loss > %5 -> 'degraded': %5, telekom/VoIP kalite esikleriyle
    uyumlu kaba bir "kullanici hisseder" siniridir. Altindaki kayip
    tipik ag gurultusudur, ustu gercek bir sorun sinyalidir.
  * herhangi bir butunluk hatasi -> 'degraded': butunluk ihlali asla
    "gurultu" sayilmaz; bir tane bile supheli oldugu icin sifir tolerans.
Bu esikler mutlak gercek degil, savunulabilir muhendislik secimleridir ve
`__init__` uzerinden ayarlanabilir.

--- Savunma amacli etik not ---
Bu modul yalnizca KENDI sensor filomuzun sagligini izler; hedef sistemlere
dokunmaz, disari ag trafigi uretmez. Amac, savunma altyapisinin kor
noktalarini (sessizce olen sensor = gormedigimiz saldiri) ortaya cikarmaktir.

Harici bagimlilik yok - sadece stdlib. Saf ve test edilebilir: enjekte
edilebilir `clock`, dosya/ag I/O yok, storage.py'ye dokunulmaz.
"""
import time
from dataclasses import dataclass, field


def packet_loss(received_seqs: list) -> dict:
    """Alinan sira numaralarindan paket kaybini hesaplar.

    Sensor her olaya artan bir sira numarasi verir. Toplayicida gorulen
    numaralarin min..max araligi 'beklenen' penceredir; bu pencerede
    EKSIK olan numaralar kayip pakettir. Tekrarlar (dupe) benzersiz kabul
    edilir - ayni numara iki kez gorulse de tek bir paket sayilir.

    Donen: {expected, received, lost, loss_pct}. Bos liste -> hepsi sifir.
    (Numaralar araliktan bagimsiz oldugu icin >2 boyutlu bir sey degil,
    tek bir akisin sira butunlugunu olcer.)
    """
    seqs = [s for s in received_seqs if isinstance(s, int) and not isinstance(s, bool)]
    if not seqs:
        return {"expected": 0, "received": 0, "lost": 0, "loss_pct": 0.0}

    lo, hi = min(seqs), max(seqs)
    expected = hi - lo + 1
    received = len(set(seqs))          # benzersiz -> gercekten gelen paket sayisi
    lost = max(0, expected - received)
    loss_pct = round(100.0 * lost / expected, 2) if expected else 0.0
    return {
        "expected": expected,
        "received": received,
        "lost": lost,
        "loss_pct": loss_pct,
    }


@dataclass
class _SensorState:
    """Tek bir sensorun ham telemetri sayaclari (dahili kullanim)."""
    heartbeat_times: list = field(default_factory=list)
    seqs: list = field(default_factory=list)
    events_seen: int = 0
    integrity_failures: int = 0


class SensorHealth:
    """Sensor filosunun operasyonel sagligini izleyen telemetri toplayici.

    Kriptografik dogrulama (HMAC/nonce/replay) ayri bir katmanin isidir ve
    burada TEKRARLANMAZ; bu sinif yalnizca "sensor yasiyor mu, veri kayipsiz
    ve butun mu geliyor mu" sorularina yanit verir.

    Zaman kaynagi enjekte edilebilir (`clock=time.monotonic`) - bu sayede
    testler sahte bir saat vererek heartbeat yaslanmasini determinist olarak
    dogrulayabilir.
    """

    def __init__(self, heartbeat_timeout_sec=30, clock=time.monotonic):
        self.heartbeat_timeout_sec = heartbeat_timeout_sec
        self._clock = clock
        self._sensors = {}

    def _state(self, sensor_id) -> _SensorState:
        state = self._sensors.get(sensor_id)
        if state is None:
            state = _SensorState()
            self._sensors[sensor_id] = state
        return state

    def record_heartbeat(self, sensor_id, seq: int = None) -> None:
        """Bir sensorun 'yasiyorum' sinyalini simdiki zamana kaydeder.

        Istege bagli `seq` verilirse paket kaybi hesabina da katilir."""
        state = self._state(sensor_id)
        state.heartbeat_times.append(self._clock())
        if seq is not None:
            state.seqs.append(seq)

    def record_event(self, sensor_id, seq: int = None,
                     integrity_ok: bool = True) -> None:
        """Bir sensordan gelen olayi sayar; butunluk ve sira takibi yapar."""
        state = self._state(sensor_id)
        state.events_seen += 1
        if seq is not None:
            state.seqs.append(seq)
        if not integrity_ok:
            state.integrity_failures += 1

    def _uptime_pct(self, state: _SensorState, now: float) -> float:
        """Heartbeat kadansindan uptime yuzdesi hesaplar.

        Ardisik atislar arasindaki her aralik + son atistan bu ana kadar
        gecen sure bir 'aralik' sayilir; timeout icinde kalan araliklar
        'ayakta' kabul edilir. Boylece uzun suredir sessiz (offline) bir
        sensorun uptime'i dogal olarak duser."""
        if not state.heartbeat_times:
            return 0.0
        times = state.heartbeat_times
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        intervals.append(now - times[-1])   # son atistan simdiye kadarki bosluk
        good = sum(1 for gap in intervals if gap <= self.heartbeat_timeout_sec)
        return round(100.0 * good / len(intervals), 2)

    def sensor_report(self, sensor_id) -> dict:
        """Tek bir sensorun saglik ozeti.

        status:
          * offline  - timeout icinde hic heartbeat yok
          * degraded - paket kaybi > %5 VEYA butunluk hatasi > 0
          * online   - digeri
        """
        now = self._clock()
        state = self._sensors.get(sensor_id)
        if state is None:
            return {
                "sensor_id": sensor_id,
                "status": "offline",
                "last_heartbeat_age_sec": None,
                "packet_loss_pct": 0.0,
                "integrity_failures": 0,
                "integrity_ok": True,
                "events_seen": 0,
                "uptime_pct": 0.0,
            }

        loss = packet_loss(state.seqs)
        if state.heartbeat_times:
            age = round(now - state.heartbeat_times[-1], 3)
        else:
            age = None

        offline = age is None or age > self.heartbeat_timeout_sec
        if offline:
            status = "offline"
        elif loss["loss_pct"] > 5.0 or state.integrity_failures > 0:
            status = "degraded"
        else:
            status = "online"

        return {
            "sensor_id": sensor_id,
            "status": status,
            "last_heartbeat_age_sec": age,
            "packet_loss_pct": loss["loss_pct"],
            "integrity_failures": state.integrity_failures,
            "integrity_ok": state.integrity_failures == 0,
            "events_seen": state.events_seen,
            "uptime_pct": self._uptime_pct(state, now),
        }

    def fleet_report(self) -> dict:
        """Tum filonun toplu saglik goruntusu (panel/komuta merkezi icin)."""
        reports = [self.sensor_report(sid) for sid in self._sensors]
        online = sum(1 for r in reports if r["status"] == "online")
        degraded = sum(1 for r in reports if r["status"] == "degraded")
        offline = sum(1 for r in reports if r["status"] == "offline")
        total = len(reports)
        fleet_health = round(100.0 * online / total, 2) if total else 0.0

        summary_tr = (
            f"Filo saglik: {fleet_health}% "
            f"({online} cevrimici, {degraded} bozulmus, {offline} cevrimdisi / "
            f"toplam {total} sensor)"
            if total else "Filo bos: kayitli sensor yok"
        )
        return {
            "sensors": reports,
            "online": online,
            "degraded": degraded,
            "offline": offline,
            "fleet_health_pct": fleet_health,
            "summary_tr": summary_tr,
        }
