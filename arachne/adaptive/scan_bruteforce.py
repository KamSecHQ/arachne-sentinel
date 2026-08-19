"""
Faz 61 - Tarama & Kaba-Kuvvet Hiz Dedektoru (davranissal, zamanlama tabanli).

--- Ko-evrim fikri ---
Saldirgan, tek tek payload'larin imzayla yakalandigini OGRENIR ve daha
"sessiz" bir kesif/erisim taktigine geceR. Ama iki temel davranis hala
ISTATISTIKSEL olarak gorunur kalir - cunku bunlar saldirinin DOGASINDAN gelir:

  1. YATAY TARAMA (horizontal scan): tek bir kaynak IP, KISA bir pencerede
     COK sayida FARKLI servise/porta dokunur (yuzey haritasi cikarma). Mesru
     bir istemci genelde bir-iki servisle konusur; onlarca farkli servise
     saniyeler icinde dokunmak kesif taramasidir (MITRE T1046 / T1595).

  2. KABA-KUVVET / KIMLIK-DOLDURMA (brute-force / credential stuffing): tek
     bir kaynak IP, AYNI servise karsi COK sayida HIZLI ve tekrarli deneme
     yapar (MITRE T1110). Insan trafigi bu tempoda tekrar etmez; makine ritmi
     eder.

--- Iki eksen, iki farkli imza ---
  * Tarama  = COK FARKLI hedef (yuksek 'distinct_services'), kisa pencere.
  * Kaba-kuvvet = COK TEKRAR ayni hedefte (yuksek 'attempts' + yuksek 'hiz').
Ayni olay akisi her iki skoru da alabilir; skorlar bagimsizdir.

--- Esikler (belgeli, deterministik) ---
  * Tarama: distinct_services >= min_distinct (varsayilan 5) VE olaylar kisa
    bir pencereye (varsayilan <= 180 sn) sigmali. Uzun sureye yayilmis cok
    servisli trafik 'tarama' sayilmaz (normal kullanim olabilir).
  * Kaba-kuvvet: en cok dokunulan servise attempts >= min_attempts
    (varsayilan 8) VE hiz >= min_rate_per_min (varsayilan 20/dk). Yuksek
    tekrar + yuksek tempo birlikte gerekir.
  * Ayni saniyeye dusen (window_sec == 0) olaylar icin hiz hesabinda pencere
    en az 1 sn kabul edilir (sonsuz hizdan kacinmak icin); gercek window_sec
    yine de durustce raporlanir.

--- DURUSTLUK NOTU ---
Bu bir *tespit gostergesidir*, kesin kanit DEGILDIR. Mesru tarayicilar
(saglik-kontrol, servis kesfi, monitoring, yedekleme ajanlari) ve otomatik
istemciler de benzer gorunebilir - bu yuzden cikti bir INSAN-INCELEME
sinyalidir, otomatik blok gerekcesi degil. Her sayi gercek olay kaydindan
turer; veri yoksa 0 doner (uydurma yok).

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca kendi izleme yuzeyimize gelen olaylarin
meta-verisini (kaynak, servis, zaman) analiz eder; hicbir baska sisteme
dokunmaz, disari paket gondermez, hack-back yoktur.

Harici bagimlilik yok - sadece stdlib.
"""
import datetime as _dt
from collections import Counter, defaultdict


# --- Varsayilan esikler (deterministik, belgeli) -------------------------
SCAN_MIN_DISTINCT = 5        # tarama icin gereken en az farkli servis sayisi
SCAN_MAX_WINDOW_SEC = 180.0  # taramanin sigmasi gereken en genis pencere
BF_MIN_ATTEMPTS = 8          # kaba-kuvvet icin ayni serviste en az deneme
BF_MIN_RATE_PER_MIN = 20.0   # kaba-kuvvet icin gereken en az tempo (dk basi)


def _to_epoch(ts):
    """ISO str veya epoch (sayi/sayisal str) zaman damgasini epoch saniyeye cevirir.

    Cozulemezse None doner (cagiran atlar). Deterministik; saat kullanmaz.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip()
    if not s:
        return None
    # Once dogrudan epoch (ornek "1000" ya da "1000.5"). ISO dizeleri '-'/':'
    # icerdiginden float() basarisiz olur ve asagidaki ISO ayristirmaya duser.
    try:
        return float(s)
    except ValueError:
        pass
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _service_key(ev) -> str:
    """Bir olaydan servis/uc-nokta anahtari uretir.

    Servis adini (varsa) kullanir; bir hedef port varsa 'servis:port' olarak
    birlestirir (boylece ayni servisin farkli portlari ayri hedef sayilir -
    port taramasini da yakalar). Ne servis ne port varsa None.
    """
    svc = ev.get("service")
    port = ev.get("dest_port")
    if port in (None, ""):
        port = ev.get("port")
    if svc not in (None, ""):
        if port not in (None, ""):
            return f"{svc}:{port}"
        return str(svc)
    if port not in (None, ""):
        return f"port:{port}"
    return None


def _extract(events):
    """Olay listesinden (servis_anahtari, epoch_ts) ciftlerini toplar.

    Zaman damgasi cozulemeyen olaylar hiz/pencere hesabina katilmaz ama
    servis dagilimina yine katilir (hedef sayimi zamandan bagimsizdir).
    """
    services = []
    stamps = []
    for ev in events or []:
        key = _service_key(ev)
        if key is not None:
            services.append(key)
        t = _to_epoch(ev.get("timestamp") or ev.get("ts"))
        if t is not None:
            stamps.append(t)
    return services, sorted(stamps)


def _window(stamps) -> float:
    """Sirali zaman damgalarindan pencere genisligini (sn) hesaplar."""
    if len(stamps) < 2:
        return 0.0
    return round(stamps[-1] - stamps[0], 3)


def _rate_per_min(count, window_sec) -> float:
    """Dakika basi olay temposu. window==0 icin taban 1 sn (sonsuzdan kacinir)."""
    denom = window_sec if window_sec and window_sec > 0 else 1.0
    return round(count * 60.0 / denom, 2)


def scan_score(events, min_distinct: int = SCAN_MIN_DISTINCT,
               max_window_sec: float = SCAN_MAX_WINDOW_SEC) -> dict:
    """TEK bir IP'nin olaylarindan yatay-tarama skorunu hesaplar.

    `events`: her biri en az `service` (ve tercihen `timestamp`, `dest_port`)
    iceren sozluk listesi. Ayni kaynaga ait oldugu varsayilir.

    Donus dict:
      is_scan           : bool  - yatay tarama suphesi var mi
      distinct_services : int   - dokunulan farkli servis/uc-nokta sayisi
      window_sec        : float - ilk-son olay arasi sure (sn)
      rate_per_min      : float - dakika basi olay temposu
      verdict_tr        : str   - kisa Turkce hukum
      reason            : str   - ayrintili Turkce aciklama
    """
    services, stamps = _extract(events)
    distinct = len(set(services))
    n = len(services)
    window = _window(stamps)
    rate = _rate_per_min(len(stamps), window)

    if n == 0:
        return {
            "is_scan": False, "distinct_services": 0, "window_sec": 0.0,
            "rate_per_min": 0.0,
            "verdict_tr": "veri yok",
            "reason": "Olay yok - tarama degerlendirilemez.",
        }

    enough_distinct = distinct >= min_distinct
    # Pencere kisitlamasi: cok servisli ama SAATLERE yayilmis trafik tarama
    # degildir. Tek/es-zamanli olaylarda (window==0) kisit dogal saglanir.
    short_window = window <= max_window_sec
    is_scan = enough_distinct and short_window

    if is_scan:
        verdict = f"YATAY TARAMA suphesi ({distinct} farkli servis)"
        reason = (
            f"Tek kaynak {distinct} farkli servise/uc-noktaya {window:.0f} sn "
            f"icinde dokundu (tempo ~{rate:.0f}/dk). Yuzey haritasi cikarma / "
            f"kesif taramasi profili (MITRE T1046/T1595). INSAN INCELEMESINE "
            f"yukselt - otomatik blok DEGIL."
        )
    elif enough_distinct and not short_window:
        verdict = "cok servisli ama yayilmis (tarama degil)"
        reason = (
            f"{distinct} farkli servis var ama {window:.0f} sn'ye yayilmis "
            f"(pencere > {max_window_sec:.0f} sn) - hizli tarama profili degil, "
            f"normal cok-servisli kullanim olabilir."
        )
    else:
        verdict = "tarama degil"
        reason = (
            f"Yalnizca {distinct} farkli servis (esik {min_distinct}) - yatay "
            f"tarama esigi altinda, dar hedefli trafik."
        )

    return {
        "is_scan": is_scan,
        "distinct_services": distinct,
        "window_sec": window,
        "rate_per_min": rate,
        "verdict_tr": verdict,
        "reason": reason,
    }


def bruteforce_score(events, min_attempts: int = BF_MIN_ATTEMPTS,
                     min_rate_per_min: float = BF_MIN_RATE_PER_MIN) -> dict:
    """TEK bir IP'nin olaylarindan kaba-kuvvet/kimlik-doldurma skorunu hesaplar.

    En cok dokunulan servisi bulur ve o servise yapilan denemelerin sayisini
    + temposunu degerlendirir.

    Donus dict:
      is_bruteforce : bool  - kaba-kuvvet suphesi var mi
      attempts      : int   - en cok dokunulan servise yapilan deneme sayisi
      top_service   : str   - en cok dokunulan servis (yoksa "")
      rate_per_min  : float - o servise dakika basi deneme temposu
      window_sec    : float - o servisteki ilk-son deneme arasi sure (sn)
      verdict_tr    : str   - kisa Turkce hukum
      reason        : str   - ayrintili Turkce aciklama
    """
    # Servis basina zaman damgalarini grupla (hiz o servise ozgu hesaplanmali).
    by_service = defaultdict(list)
    counts = Counter()
    for ev in events or []:
        key = _service_key(ev)
        if key is None:
            continue
        counts[key] += 1
        t = _to_epoch(ev.get("timestamp") or ev.get("ts"))
        if t is not None:
            by_service[key].append(t)

    if not counts:
        return {
            "is_bruteforce": False, "attempts": 0, "top_service": "",
            "rate_per_min": 0.0, "window_sec": 0.0,
            "verdict_tr": "veri yok",
            "reason": "Olay yok - kaba-kuvvet degerlendirilemez.",
        }

    top_service, attempts = counts.most_common(1)[0]
    stamps = sorted(by_service.get(top_service, []))
    window = _window(stamps)
    rate = _rate_per_min(len(stamps) if stamps else attempts, window)

    enough = attempts >= min_attempts
    rapid = rate >= min_rate_per_min
    is_bruteforce = enough and rapid

    if is_bruteforce:
        verdict = f"KABA-KUVVET suphesi ({top_service})"
        reason = (
            f"'{top_service}' servisine {attempts} tekrarli deneme, tempo "
            f"~{rate:.0f}/dk ({window:.0f} sn pencere). Ayni hedefe hizli "
            f"tekrar = kaba-kuvvet/kimlik-doldurma profili (MITRE T1110). "
            f"INSAN INCELEMESINE yukselt - otomatik blok DEGIL."
        )
    elif enough and not rapid:
        verdict = "cok deneme ama yavas (kaba-kuvvet degil)"
        reason = (
            f"'{top_service}' servisine {attempts} deneme var ama tempo dusuk "
            f"(~{rate:.0f}/dk < {min_rate_per_min:.0f}/dk) - hizli kaba-kuvvet "
            f"profili degil, yavas/normal tekrar olabilir."
        )
    else:
        verdict = "kaba-kuvvet degil"
        reason = (
            f"En yogun servis '{top_service}' yalnizca {attempts} deneme "
            f"(esik {min_attempts}) - kaba-kuvvet esigi altinda."
        )

    return {
        "is_bruteforce": is_bruteforce,
        "attempts": attempts,
        "top_service": top_service,
        "rate_per_min": rate,
        "window_sec": window,
        "verdict_tr": verdict,
        "reason": reason,
    }


class SweepMonitor:
    """Cok sayida IP'yi izleyip tarama/kaba-kuvvet davranisini toplayan monitor.

    Her IP icin (servis, zaman) gozlemlerini biriktirir ve `report()` ile
    hepsini birden skorlar. Deterministik: rastgelelik/enjekte saat yok -
    zaman damgalari cagiran tarafindan verilir.
    """

    def __init__(self, min_distinct: int = SCAN_MIN_DISTINCT,
                 min_attempts: int = BF_MIN_ATTEMPTS,
                 min_rate_per_min: float = BF_MIN_RATE_PER_MIN):
        self.min_distinct = min_distinct
        self.min_attempts = min_attempts
        self.min_rate_per_min = min_rate_per_min
        self._events = defaultdict(list)   # ip -> [event dict, ...]

    def observe(self, ip, service, ts) -> None:
        """Bir IP'den gelen tek bir olayi (servis + zaman) kaydeder."""
        if ip is None:
            return
        self._events[ip].append({"service": service, "timestamp": ts})

    def report(self) -> dict:
        """Tum izlenen IP'leri skorlar; tarayici ve kaba-kuvvetcileri listeler.

        Donus dict:
          scanners     : is_scan olan IP'lerin ozet listesi (skor alanlariyla)
          bruteforcers : is_bruteforce olan IP'lerin ozet listesi
          counts       : {ips, scanners, bruteforcers, events}
        """
        scanners, bruteforcers = [], []
        total_events = 0
        for ip, evs in self._events.items():
            total_events += len(evs)
            s = scan_score(evs, min_distinct=self.min_distinct)
            if s["is_scan"]:
                scanners.append({"ip": ip, **s})
            b = bruteforce_score(evs, min_attempts=self.min_attempts,
                                 min_rate_per_min=self.min_rate_per_min)
            if b["is_bruteforce"]:
                bruteforcers.append({"ip": ip, **b})

        # En agir once: tarayicilar farkli-servise, kaba-kuvvetciler deneme sayisina gore.
        scanners.sort(key=lambda x: -x["distinct_services"])
        bruteforcers.sort(key=lambda x: -x["attempts"])

        return {
            "scanners": scanners,
            "bruteforcers": bruteforcers,
            "counts": {
                "ips": len(self._events),
                "scanners": len(scanners),
                "bruteforcers": len(bruteforcers),
                "events": total_events,
            },
        }


def analyze_recent(db_path=None, since_seconds: int = 7200) -> dict:
    """Son olaylari veritabanindan cekip IP basi tarama/kaba-kuvvet analizi yapar.

    GERCEK veriden calisir; veri yoksa ya da bir hata olursa 0/bos doner
    (asla catlamaz, asla uydurmaz).

    Donus dict:
      scanner_ips     : yatay tarama isaretlenen IP'ler (str listesi)
      bruteforce_ips  : kaba-kuvvet isaretlenen IP'ler (str listesi)
      scanner_count   : int
      bruteforce_count: int
      top_scanner     : {ip, distinct_services} | None - en cok servise dokunan
      top_bruteforcer : {ip, attempts, top_service} | None - en cok deneme yapan
    """
    empty = {
        "scanner_ips": [], "bruteforce_ips": [],
        "scanner_count": 0, "bruteforce_count": 0,
        "top_scanner": None, "top_bruteforcer": None,
    }
    try:
        from .. import storage
        events = storage.get_recent_events(since_seconds=since_seconds, db_path=db_path)
        if not events:
            return dict(empty)

        by_ip = defaultdict(list)
        for ev in events:
            ip = ev.get("source_ip")
            if ip:
                by_ip[ip].append(ev)

        scanners, bruteforcers = [], []
        for ip, evs in by_ip.items():
            s = scan_score(evs)
            if s["is_scan"]:
                scanners.append({"ip": ip,
                                 "distinct_services": s["distinct_services"]})
            b = bruteforce_score(evs)
            if b["is_bruteforce"]:
                bruteforcers.append({"ip": ip, "attempts": b["attempts"],
                                     "top_service": b["top_service"]})

        scanners.sort(key=lambda x: -x["distinct_services"])
        bruteforcers.sort(key=lambda x: -x["attempts"])

        return {
            "scanner_ips": [x["ip"] for x in scanners],
            "bruteforce_ips": [x["ip"] for x in bruteforcers],
            "scanner_count": len(scanners),
            "bruteforce_count": len(bruteforcers),
            "top_scanner": scanners[0] if scanners else None,
            "top_bruteforcer": bruteforcers[0] if bruteforcers else None,
        }
    except Exception:
        # Salt-savunma: analiz katmani hicbir kosulda paneli/asistani catlatmamali.
        return dict(empty)
