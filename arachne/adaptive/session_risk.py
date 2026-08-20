"""
Faz 75 - Oturum Riski / Etkilesim Derinligi Skorlayici.

--- Fikir ---
Tek bir olayin ne oldugu bir seydir; ama bir saldirganin honeypot'ta NE KADAR
DERINE indigini bilmek bambaska bir seydir. Bu modul, IP basi olay zaman
cizelgesini kill-chain (saldiri zinciri) asamalarina yerlestirir ve saldirganin
ulastigi EN DERIN noktaya + kat ettigi asama cesitliligine gore TIRMANAN,
birikimli bir risk skoru uretir. Boylece "sadece kapiyi yoklayan" bir tarayici
ile "honeytoken'a dokunup kalicilik deneyen" bir aktor ayni kefeye konmaz.

--- Kill-chain derinlik tierleri (artan agirlik) ---
  kesif -> tarama -> somuru denemesi -> honeytoken/aldatma temasi ->
  kalicilik / yatay hareket / veri sizdirma.
Her asama artan bir agirlik tasir; skor, zaman cizelgesi boyunca ULASILAN
farkli asamalarin agirliklarinin birikimidir. Daha derine inildikce skor
tirmanir. Honeytoken/aldatma temasi ozel ve agir bir sinyaldir: mesru kullanici
bir tuzak varligina dokunmaz, dolayisiyla bu neredeyse-kesin kotu-niyet
gostergesidir.

--- Asama tespiti ---
Oncelikle mevcut `arachne.intel.attack_stages` siniflandiricisini kullanir
(9 kanonik asama, payload/servis/olay-turu imzalarindan). O katman yoksa ya da
catlarsa, olay-turu/servis/payload uzerinde kendi basit, defansif eslememize
duseriz - hicbir kosulda catlamaz. Honeytoken/aldatma temasi ayrica olay-turu
ve servis anahtarlarindan dogrudan tespit edilir (imza payload'i olmasa bile).

--- Bantlar (belgeli, deterministik) ---
  score >= 75 -> KRITIK, >= 45 -> YUKSEK, >= 20 -> ORTA, aksi -> DUSUK.
Skor 0..100'e sikistirilir (birden fazla derin asama toplaminda tavana oturur).

--- DURUSTLUK NOTU ---
Bu bir *risk tahminidir*, kesin bir yargi degildir. Asama siniflandirmasi
gostergeseldir; tek bir istek birden fazla asamaya uyabilir. Cikti bir
INSAN-INCELEME/onceliklendirme sinyalidir, otomatik blok gerekcesi degil. Her
sayi gercek olay kaydindan turer; veri yoksa 0 doner (uydurma yok).

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca kendi honeypot/izleme yuzeyimizde GOZLEMLENEN
olaylari siniflandirir; hicbir baska sisteme dokunmaz, disari paket gondermez,
hack-back yoktur.

Harici bagimlilik yok - sadece stdlib (ve varsa dahili attack_stages).
"""


# --- Kill-chain asama -> agirlik (deterministik, belgeli) -----------------
# Agirliklar zincirde ilerledikce artar: kesif ucuz, sizdirma en agir. Aldatma
# temasi (honeytoken) ozel yuksek sinyaldir - somuru ile kalicilik arasina
# konumlanir cunku tuzaga dokunmak niyeti ele verir.
_STAGE_WEIGHT = {
    "Reconnaissance": 5,
    "Scanning": 10,
    "Initial Access": 20,        # somuru denemesi
    "Execution": 22,
    "Credential Access": 24,
    "Privilege Escalation": 28,
    "Persistence": 30,
    "Lateral Movement": 35,
    "Exfiltration": 40,
}

# Asama -> Turkce ad (attack_stages yoksa da yerel calisabilmek icin burada).
_STAGE_TR = {
    "Reconnaissance": "Kesif",
    "Scanning": "Tarama",
    "Initial Access": "Ilk Erisim",
    "Execution": "Calistirma",
    "Credential Access": "Kimlik Bilgisi Erisimi",
    "Privilege Escalation": "Yetki Yukseltme",
    "Persistence": "Kalicilik",
    "Lateral Movement": "Yanal Hareket",
    "Exfiltration": "Veri Sizdirma",
}

# Honeytoken/aldatma temasi: ozel derinlik tieri (payload imzasi gerekmez).
_DECEPTION_STAGE = "Deception Contact"
_DECEPTION_TR = "Honeytoken/Aldatma Temasi"
_DECEPTION_WEIGHT = 26

# Honeytoken/aldatma temasini ele veren olay-turu ve servis anahtarlari.
_DECEPTION_EVENT_TYPES = {
    "HONEYTOKEN", "HONEYTOKEN_TRIGGER", "HONEYTOKEN_TRIGGERED", "CANARY",
    "CANARYTOKEN", "DECEPTION", "DECOY", "TARPIT", "TRAP",
}
_DECEPTION_KEYWORDS = ("honeytoken", "canary", "decoy", "aldatma", "tuzak",
                       "deception", "tarpit")

# Bant esikleri (deterministik).
_BAND_CRITICAL = 75
_BAND_HIGH = 45
_BAND_MEDIUM = 20


def _band(score: int) -> str:
    """Birikimli skoru Turkce risk bandina cevirir (deterministik)."""
    if score >= _BAND_CRITICAL:
        return "KRITIK"
    if score >= _BAND_HIGH:
        return "YUKSEK"
    if score >= _BAND_MEDIUM:
        return "ORTA"
    return "DUSUK"


# attack_stages'i bir kez, tembel yukle (yoksa None kalir - yerel esleme devreye girer).
def _load_stager():
    try:
        from ..intel import attack_stages
        return attack_stages
    except Exception:
        return None


def _fallback_stage(payload: str, service, event_type) -> str:
    """attack_stages yoksa/catlarsa basit, defansif asama eslemesi.

    Kaba anahtar-kelime eslemesi; kesin degil ama hicbir kosulda catlamaz.
    Eslesme yoksa None doner ("bilmiyorum"u durustce ifade eder).
    """
    text = (str(payload or "")).lower()
    et = (str(event_type or "")).upper()

    if et in ("PORT_SCAN", "SCAN"):
        return "Scanning"
    if et in ("LOGIN_FAILED", "AUTH_FAIL", "BRUTE_FORCE"):
        return "Credential Access"

    # Payload anahtar kelimeleri (ileri asama once denenir ki en derin kazansin).
    if any(k in text for k in ("curl http", "wget http", "base64", "exfil", "scp ")):
        return "Exfiltration"
    if any(k in text for k in ("psexec", "wmic", "smbclient", "crackmapexec",
                               "ssh ", "net use")):
        return "Lateral Movement"
    if any(k in text for k in ("crontab", "/etc/cron", "authorized_keys",
                               "<?php", "systemctl enable")):
        return "Persistence"
    if any(k in text for k in ("sudo", "setuid", "/etc/sudoers", "pkexec",
                               "dirtycow")):
        return "Privilege Escalation"
    if any(k in text for k in ("/etc/shadow", "password=", "passwd=", "id_rsa",
                               "api_key", "secret_key")):
        return "Credential Access"
    if any(k in text for k in (";cat", "; cat", "/bin/sh", "/bin/bash",
                               "system(", "exec(", "eval(", "powershell")):
        return "Execution"
    if any(k in text for k in ("${jndi:", "union select", "../../", "..\\..\\",
                               "() {")):
        return "Initial Access"
    if any(k in text for k in ("robots.txt", "sitemap.xml", ".well-known",
                               "nikto", "nmap", "masscan", "favicon.ico")):
        return "Reconnaissance"
    if any(k in text for k in ("gobuster", "dirbuster", "ffuf", "nuclei",
                               "/admin", "/wp-admin", "/.env", "/.git", "fuzz")):
        return "Scanning"
    return None


def _is_deception_contact(ev, stager=None) -> bool:
    """Bir olayin honeytoken/aldatma temasi olup olmadigini tespit eder."""
    et = str(ev.get("event_type") or "").upper()
    if et in _DECEPTION_EVENT_TYPES:
        return True
    svc = str(ev.get("service") or "").lower()
    if any(k in svc for k in _DECEPTION_KEYWORDS):
        return True
    et_low = et.lower()
    if any(k in et_low for k in _DECEPTION_KEYWORDS):
        return True
    return False


def _stage_for_event(ev, stager) -> str:
    """Tek bir olay icin kill-chain asamasini dondurur (attack_stages ya da yerel)."""
    payload = ev.get("payload") or ev.get("text") or ""
    service = ev.get("service")
    event_type = ev.get("event_type")
    if stager is not None:
        try:
            res = stager.classify_stage(payload, service, event_type)
            stage = res.get("stage")
            if stage:
                return stage
        except Exception:
            pass
    return _fallback_stage(payload, service, event_type)


def engagement_score(events_for_ip) -> dict:
    """TEK bir IP'nin olaylarindan etkilesim-derinligi / oturum risk skoru.

    `events_for_ip`: ayni kaynaga ait olay sozlukleri (payload/service/
    event_type/timestamp iceren). Sirali olmasi gerekmez.

    Donus dict:
      score          : int   - 0..100 birikimli, tirmanan risk skoru
      band_tr        : str   - DUSUK/ORTA/YUKSEK/KRITIK
      reached_stages : list  - ulasilan asamalarin Turkce adlari (derinlik sirasi)
      depth          : int   - ulasilan farkli asama/tier sayisi
      top_signal     : str   - en agir (en derin) asama/sinyal (Turkce)
      reason         : str   - Turkce aciklama
    """
    stager = _load_stager()
    tr_map = dict(_STAGE_TR)
    if stager is not None:
        # attack_stages kendi Turkce adlarini tasir; onlari tercih et.
        try:
            tr_map.update(getattr(stager, "STAGE_TR", {}))
        except Exception:
            pass

    reached = {}  # stage_key -> weight
    for ev in events_for_ip or []:
        if not isinstance(ev, dict):
            continue
        if _is_deception_contact(ev, stager):
            reached[_DECEPTION_STAGE] = _DECEPTION_WEIGHT
        stage = _stage_for_event(ev, stager)
        if stage and stage in _STAGE_WEIGHT:
            reached[stage] = _STAGE_WEIGHT[stage]

    if not reached:
        return {
            "score": 0,
            "band_tr": "DUSUK",
            "reached_stages": [],
            "depth": 0,
            "top_signal": None,
            "reason": ("Bu kaynaktan siniflandirilabilir bir kill-chain asamasi "
                       "gozlenmedi - etkilesim derinligi olculemez (skor 0)."),
        }

    raw = sum(reached.values())
    score = min(100, raw)
    band = _band(score)
    depth = len(reached)

    # Asamalari agirliga gore artan sirala (kill-chain derinlik sirasi).
    ordered = sorted(reached.items(), key=lambda kv: (kv[1], kv[0]))

    def _tr(stage_key):
        if stage_key == _DECEPTION_STAGE:
            return _DECEPTION_TR
        return tr_map.get(stage_key, stage_key)

    reached_stages = [_tr(k) for k, _ in ordered]
    top_key = ordered[-1][0]
    top_signal = _tr(top_key)

    reason = (
        f"Saldirgan kill-chain'de {depth} farkli asamaya ulasti "
        f"({' -> '.join(reached_stages)}); en derin nokta: {top_signal}. "
        f"Birikimli etkilesim riski {score}/100 -> {band}. Bu bir "
        f"onceliklendirme gostergesidir, otomatik blok gerekcesi DEGIL."
    )

    return {
        "score": score,
        "band_tr": band,
        "reached_stages": reached_stages,
        "depth": depth,
        "top_signal": top_signal,
        "reason": reason,
    }


class SessionRiskMonitor:
    """Cok sayida IP'nin oturum etkilesim derinligini toplayan monitor.

    Her IP icin olaylari biriktirir ve `report()` ile hepsini birden skorlar.
    Deterministik: enjekte saat/rastgelelik yok.
    """

    def __init__(self):
        self._events = {}  # ip -> [event dict, ...]

    def observe(self, ip, payload=None, service=None, event_type=None, ts=None) -> None:
        """Bir IP'den gelen tek bir olayi kaydeder."""
        if ip is None:
            return
        self._events.setdefault(ip, []).append({
            "payload": payload, "service": service,
            "event_type": event_type, "timestamp": ts,
        })

    def report(self) -> dict:
        """Tum izlenen IP'leri skorlar ve etkilesim derinligine gore siralar.

        Donus dict:
          ranked     : [{ip, score, band_tr, depth, top_signal}] - azalan skor
          top_ip     : {ip, score, band_tr} | None - en derin etkilesim
          high_count : int - YUKSEK veya KRITIK bandindaki IP sayisi
          count      : int - skorlanan IP sayisi
        """
        ranked = []
        high_count = 0
        for ip, evs in self._events.items():
            s = engagement_score(evs)
            if s["score"] <= 0:
                continue
            ranked.append({"ip": ip, "score": s["score"],
                           "band_tr": s["band_tr"], "depth": s["depth"],
                           "top_signal": s["top_signal"]})
            if s["band_tr"] in ("YUKSEK", "KRITIK"):
                high_count += 1

        ranked.sort(key=lambda x: (-x["score"], -x["depth"]))
        top = ranked[0] if ranked else None
        return {
            "ranked": ranked,
            "top_ip": ({"ip": top["ip"], "score": top["score"],
                        "band_tr": top["band_tr"]} if top else None),
            "high_count": high_count,
            "count": len(ranked),
        }


def analyze_recent(db_path=None, since_seconds: int = 7200) -> dict:
    """Son olaylari veritabanindan cekip IP basi oturum-risk analizi yapar.

    GERCEK veriden calisir; veri yoksa ya da bir hata olursa 0/bos doner
    (asla catlamaz, asla uydurmaz).

    Donus dict:
      ranked     : [{ip, score, band_tr, depth}] - azalan etkilesim skoru
      top_ip     : {ip, score, band_tr} | None - en derin etkilesim
      high_count : int - YUKSEK/KRITIK bandindaki IP sayisi
      count      : int - skorlanan IP sayisi
    """
    empty = {"ranked": [], "top_ip": None, "high_count": 0, "count": 0}
    try:
        from .. import storage
        events = storage.get_recent_events(since_seconds=since_seconds, db_path=db_path)
        if not events:
            return dict(empty)

        by_ip = {}
        for ev in events:
            ip = ev.get("source_ip")
            if ip:
                by_ip.setdefault(ip, []).append(ev)

        ranked = []
        high_count = 0
        for ip, evs in by_ip.items():
            s = engagement_score(evs)
            if s["score"] <= 0:
                continue
            ranked.append({"ip": ip, "score": s["score"],
                           "band_tr": s["band_tr"], "depth": s["depth"]})
            if s["band_tr"] in ("YUKSEK", "KRITIK"):
                high_count += 1

        ranked.sort(key=lambda x: (-x["score"], -x["depth"]))
        top = ranked[0] if ranked else None
        return {
            "ranked": ranked,
            "top_ip": ({"ip": top["ip"], "score": top["score"],
                        "band_tr": top["band_tr"]} if top else None),
            "high_count": high_count,
            "count": len(ranked),
        }
    except Exception:
        return dict(empty)
