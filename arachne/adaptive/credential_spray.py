"""
Faz 74 - Kimlik-Doldurma / Parola Spreyi Dedektoru (davranissal).

--- Ko-evrim fikri ---
Saldirgan, klasik kaba-kuvvetin (tek kullanici, cok parola) hesap kilitleme
ve hiz-esigi tespitleriyle yakalandigini OGRENIR ve taktik degistirir: artik
COK sayida FARKLI kullaniciya AZ (cogu zaman 1-2) parola dener - "parola
spreyi" (password spray) / kimlik-doldurma (credential stuffing). Boylece
kullanici basina deneme sayisi kilitleme esiginin altinda kalir ve tek-hesap
kaba-kuvvet tespitinden kacar. Ama davranisin DOGASI hala istatistiksel olarak
gorunur: tek bir kaynak, KISA surede COK farkli kimlige dokunur.

--- Kaba-kuvvet ile spreyi AYIRAN eksen ---
  * Kaba-kuvvet = TEK kullanici, COK parola  -> yuksek "kullanici-basi deneme".
  * Parola spreyi = COK kullanici, AZ parola  -> yuksek "distinct_users",
    DUSUK "kullanici-basi deneme". Yatay yayilim (genislik) belirgindir.
Bu modul spreyi yatay yayilimdan (cok farkli kullanici adi) ve dusuk
kullanici-basi deneme oranindan tanir; boylece iki taktigi karistirmaz.

--- Kullanici adi cikarimi (savunmaci, saglam) ---
Olay payload'inda kullanici adi cesitli bicimlerde gecebilir:
  user=, username=, login=, uid=, email=, usr=, log= (form/GET alanlari),
  JSON alanlari ("username": "x"), ve FTP/SMTP tarzi "USER x" komutu.
Ayristirma tamamen desen-tabanli ve defansiftir; cozulemezse o olay
kullanici sayimina katilmaz (uydurma yok). Olay sozlugunde dogrudan bir
`username` alani varsa oncelikle o kullanilir.

--- Esikler (belgeli, deterministik) ---
  * SPRAY_MIN_USERS (varsayilan 5): sprey suphesi icin gereken en az farkli
    kullanici adi. Az sayida kullaniciya deneme sprey degildir.
  * SPRAY_MAX_ATTEMPTS_PER_USER (varsayilan 3.0): spreyi kaba-kuvvetten ayiran
    kritik esik. Kullanici basi ortalama deneme bunun altinda olmali; ustunde
    ise "cok kullanici ama derin" -> kaba-kuvvet karakteri baskindir.
  * users_per_min: distinct kullanici / dakika (window==0 icin taban 1 sn).

--- DURUSTLUK NOTU ---
Bu bir *tespit gostergesidir*, kesin kanit DEGILDIR. Mesru cok-kullanicili
akislar (SSO gecisi, toplu login sonrasi yonlendirme, test otomasyonu) da
benzer gorunebilir; bu yuzden cikti bir INSAN-INCELEME sinyalidir, otomatik
blok gerekcesi degil. Her sayi gercek olay kaydindan turer; veri yoksa 0 doner.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca kendi izleme yuzeyimize gelen olaylarin
meta-verisini analiz eder; hicbir baska sisteme dokunmaz, disari paket
gondermez, hack-back yoktur. Parola DEGERLERI ayristirilmaz ya da saklanmaz -
yalnizca hedeflenen kullanici adlarinin CESITLILIGI olculur.

Harici bagimlilik yok - sadece stdlib.
"""
import datetime as _dt
import re
from collections import defaultdict


# --- Varsayilan esikler (deterministik, belgeli) -------------------------
SPRAY_MIN_USERS = 5             # sprey icin gereken en az farkli kullanici
SPRAY_MAX_ATTEMPTS_PER_USER = 3.0  # spreyi kaba-kuvvetten ayiran ust sinir


# --- Kullanici adi cikarim desenleri (defansif, salt-okur) ----------------
# Her desen tek bir yakalama grubu dondurur; deger 1-64 karakter, ayirici
# (tirnak, &, bosluk, virgul, suslu parantez) gormeden alinir.
_USER_PATTERNS = [
    # key=value / key: value / JSON "key": "value" (kapanis tirnagi opsiyonel).
    re.compile(r'\b(?:user(?:name)?|login|uid|usr|log)"?\s*[=:]\s*"?([^"&\s,;}]{1,64})', re.I),
    re.compile(r'\bemail"?\s*[=:]\s*"?([^"&\s,;}]{1,64})', re.I),
    # FTP/SMTP tarzi "USER x" komutu (satir basi ya da bosluk sonrasi).
    re.compile(r'(?:^|\s)USER\s+([^\s"&,;}]{1,64})', re.I),
]


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
    try:
        return float(s)
    except ValueError:
        pass
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def extract_username(ev) -> str:
    """Bir olaydan hedeflenen kullanici adini (varsa) cikarir; yoksa None.

    Once olay sozlugundeki dogrudan `username` (ya da `user`) alanina bakar;
    yoksa payload uzerinde desen eslemesi dener. Tamamen defansif: cozulemezse
    None doner, asla uydurmaz. Kullanici adi kucuk harfe indirilir ki ayni
    kimligin buyuk/kucuk varyantlari tek kullanici sayilsin.
    """
    if not isinstance(ev, dict):
        return None
    direct = ev.get("username")
    if direct in (None, ""):
        direct = ev.get("user")
    if direct not in (None, ""):
        return str(direct).strip().lower()[:64] or None

    payload = ev.get("payload") or ev.get("text") or ""
    text = str(payload)
    for pattern in _USER_PATTERNS:
        m = pattern.search(text)
        if m:
            val = m.group(1).strip().lower()
            if val:
                return val[:64]
    return None


def _window(stamps) -> float:
    """Sirali zaman damgalarindan pencere genisligini (sn) hesaplar."""
    if len(stamps) < 2:
        return 0.0
    return round(stamps[-1] - stamps[0], 3)


def spray_score(events, min_users: int = SPRAY_MIN_USERS,
                max_attempts_per_user: float = SPRAY_MAX_ATTEMPTS_PER_USER) -> dict:
    """TEK bir IP'nin olaylarindan parola-spreyi skorunu hesaplar.

    `events`: ayni kaynaga ait, payload'inda (ya da `username` alaninda)
    hedeflenen kullanici adi bulunabilen olay sozlukleri.

    Donus dict:
      is_spray       : bool  - parola spreyi suphesi var mi
      distinct_users : int   - dokunulan farkli kullanici adi sayisi
      attempts       : int   - kullanici adi ayristirilabilen deneme sayisi
      users_per_min  : float - dakika basi farkli kullanici temposu
      verdict_tr     : str   - kisa Turkce hukum
      reason         : str   - ayrintili Turkce aciklama
    """
    users = []
    stamps = []
    for ev in events or []:
        u = extract_username(ev)
        if u is None:
            continue
        users.append(u)
        t = _to_epoch(ev.get("timestamp") or ev.get("ts"))
        if t is not None:
            stamps.append(t)

    attempts = len(users)
    distinct = len(set(users))
    stamps.sort()
    window = _window(stamps)
    denom = window if window and window > 0 else 1.0
    users_per_min = round(distinct * 60.0 / denom, 2)

    if attempts == 0:
        return {
            "is_spray": False, "distinct_users": 0, "attempts": 0,
            "users_per_min": 0.0,
            "verdict_tr": "veri yok",
            "reason": "Kullanici adi tasiyan olay yok - sprey degerlendirilemez.",
        }

    per_user = attempts / distinct if distinct else float(attempts)
    enough_users = distinct >= min_users
    shallow = per_user <= max_attempts_per_user
    is_spray = enough_users and shallow

    if is_spray:
        verdict = f"PAROLA SPREYI suphesi ({distinct} farkli kullanici)"
        reason = (
            f"Tek kaynak {distinct} farkli kullanici adina toplam {attempts} "
            f"deneme yapti (kullanici basi ~{per_user:.1f} deneme, tempo "
            f"~{users_per_min:.0f} kullanici/dk). Cok kullanici + az deneme = "
            f"parola spreyi / kimlik-doldurma profili (MITRE T1110.003). Hesap "
            f"kilitleme esigi altinda kalarak tek-hesap kaba-kuvvet tespitinden "
            f"kaciyor. INSAN INCELEMESINE yukselt - otomatik blok DEGIL."
        )
    elif enough_users and not shallow:
        verdict = "cok kullanici ama derin (sprey degil)"
        reason = (
            f"{distinct} farkli kullanici var ama kullanici basi ~{per_user:.1f} "
            f"deneme ({attempts} toplam) - sprey yerine kaba-kuvvet karakteri "
            f"baskin (kullanici basi deneme esik {max_attempts_per_user:.0f} ustunde)."
        )
    else:
        verdict = "sprey degil"
        reason = (
            f"Yalnizca {distinct} farkli kullanici (esik {min_users}) - yatay "
            f"kimlik yayilimi sprey esiginin altinda, dar hedefli deneme."
        )

    return {
        "is_spray": is_spray,
        "distinct_users": distinct,
        "attempts": attempts,
        "users_per_min": users_per_min,
        "verdict_tr": verdict,
        "reason": reason,
    }


class SprayMonitor:
    """Cok sayida IP'yi izleyip parola-spreyi davranisini toplayan monitor.

    Her IP icin (payload/username + zaman) gozlemlerini biriktirir ve
    `report()` ile hepsini birden skorlar. Deterministik: rastgelelik/enjekte
    saat yok - zaman damgalari cagiran tarafindan verilir.
    """

    def __init__(self, min_users: int = SPRAY_MIN_USERS,
                 max_attempts_per_user: float = SPRAY_MAX_ATTEMPTS_PER_USER):
        self.min_users = min_users
        self.max_attempts_per_user = max_attempts_per_user
        self._events = defaultdict(list)   # ip -> [event dict, ...]

    def observe(self, ip, payload=None, username=None, ts=None) -> None:
        """Bir IP'den gelen tek bir kimlik-denemesi olayini kaydeder."""
        if ip is None:
            return
        self._events[ip].append(
            {"payload": payload, "username": username, "timestamp": ts})

    def report(self) -> dict:
        """Tum izlenen IP'leri skorlar; sprey kaynaklarini listeler.

        Donus dict:
          sprayers : is_spray olan IP'lerin ozet listesi (skor alanlariyla)
          counts   : {ips, sprayers, events}
        """
        sprayers = []
        total_events = 0
        for ip, evs in self._events.items():
            total_events += len(evs)
            s = spray_score(evs, min_users=self.min_users,
                            max_attempts_per_user=self.max_attempts_per_user)
            if s["is_spray"]:
                sprayers.append({"ip": ip, **s})

        # En agir once: en cok farkli kullaniciya dokunan.
        sprayers.sort(key=lambda x: -x["distinct_users"])

        return {
            "sprayers": sprayers,
            "counts": {
                "ips": len(self._events),
                "sprayers": len(sprayers),
                "events": total_events,
            },
        }


def analyze_recent(db_path=None, since_seconds: int = 7200) -> dict:
    """Son olaylari veritabanindan cekip IP basi parola-spreyi analizi yapar.

    GERCEK veriden calisir; veri yoksa ya da bir hata olursa 0/bos doner
    (asla catlamaz, asla uydurmaz).

    Donus dict:
      spray_ips           : sprey isaretlenen IP'ler (str listesi)
      top_sprayer         : {ip, distinct_users} | None - en cok kullaniciya
                            dokunan kaynak
      distinct_user_total : int - sprey IP'lerinin toplam (birlesik) farkli
                            hedef kullanici sayisi
      count               : int - sprey isaretlenen IP sayisi
    """
    empty = {
        "spray_ips": [], "top_sprayer": None,
        "distinct_user_total": 0, "count": 0,
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

        sprayers = []
        all_users = set()
        for ip, evs in by_ip.items():
            s = spray_score(evs)
            if s["is_spray"]:
                sprayers.append({"ip": ip, "distinct_users": s["distinct_users"]})
                # Bu IP'nin hedefledigi kullanicilari birlesik sayima ekle.
                for ev in evs:
                    u = extract_username(ev)
                    if u is not None:
                        all_users.add(u)

        sprayers.sort(key=lambda x: -x["distinct_users"])

        return {
            "spray_ips": [x["ip"] for x in sprayers],
            "top_sprayer": sprayers[0] if sprayers else None,
            "distinct_user_total": len(all_users),
            "count": len(sprayers),
        }
    except Exception:
        # Salt-savunma: analiz katmani hicbir kosulda paneli/asistani catlatmamali.
        return dict(empty)
