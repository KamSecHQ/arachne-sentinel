"""
Faz 22 - Istemci parmak izi ve kimlik rotasyonu (Sybil) tespiti.

--- Ko-evrim fikri ---
Saldirgan tek bir kaynaktan gelmenin isaretlendigini OGRENIR (rate-limit,
IP itibar listesi) ve taktik degistirir: user-agent'ini ve IP'sini surekli
DEGISTIREREK bir cok farkli istemci gibi gorunur (Sybil saldirisi). Ust
katman (UA, IP) mutable/sahte oldugu icin sayim tabanli savunma aldanir.
Bu modul, mutable katmanin ALTINDAKI daha kararli sinyalleri parmak izi
alarak bu numarayi bozar: TLS versiyonu, cipher suite sirasi, uzantilar,
egriler, HTTP header sirasi, HTTP/2 ayarlari. Bu dusuk-katman ozellikler
istemci yiginina (stack) baglidir ve UA/IP degistirmek onlari degistirmez.

--- Iki sinyal ---
  1. Parmak izi (JA3/JA4 mantigi): SIRALI bir ozellik demetinden deterministik
     bir hash. Sira onemlidir - ayni ozellikler farkli sirada farkli istemci
     demektir; bu yuzden liste alanlari sirasiyla birlestirilir.
  2. Imkansiz kombinasyon: UA bir seyi iddia ederken TLS yigini baskasini
     ele verir - ornek "Chrome" UA ama `python-requests`/`curl`/`go-http`
     TLS parmak izi. Bu bir yalan/otomasyon tellidir.
  Ve korelasyon: TEK parmak izi COK farkli IP/UA'ya esleniyorsa -> Sybil.

--- DURUSTLUK NOTU ---
Buradaki hash gercek JA3/JA4 spesifikasyonunun birebir uyarlamasi DEGILDIR;
onun cekirdek fikrini (sirali dusuk-katman ozelliklerinden deterministik
parmak izi) kucuk ve deterministik gosterir. Gercek dagitimlarda me sru
paylasilan altyapi (kurumsal NAT, mobil tasiyici CGNAT, ortak TLS kutuphanesi)
ayni parmak izini paylasabilir - yani "cok IP = Sybil" bir gostergedir,
kesin kanit degil. Cikti aciklanabilir `verdict` ile gelir.

--- Gercek cerceve eslemesi ---
JA3/JA4 TLS parmak izi (Salesforce/FoxIO), HTTP header-order parmak izi,
Cloudflare/Suricata/Zeek bot tespiti, MITRE D3FEND "Identifier Analysis"
(D3-IAA), Sybil saldirisi.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca bize BAGLANAN istemcinin bize sundugu meta
verisini analiz eder; hicbir baska sisteme dokunmaz, hack-back yoktur.
Parmak izi kendi izleme yuzeyimizde kalir.

Harici bagimlilik yok - sadece stdlib hashlib.
"""
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field


# Parmak izini olusturan ozellikler - SIRA onemlidir (JA3/JA4 mantigi).
_FP_FIELDS = (
    "tls_version",
    "cipher_suites",
    "extensions",
    "curves",
    "header_order",
    "http2_settings",
)


def compute_fingerprint(attrs: dict) -> str:
    """Sirali istemci ozelliklerinden deterministik kisa hex parmak izi.

    JA3/JA4 gibi: ozellikleri SABIT bir sirada, liste alanlarini da ic
    sirasini koruyarak birlestirir ve sha256 alir, ilk 16 hex karakteri
    doner. Ayni ozellikler + ayni sira -> ayni parmak izi (deterministik).
    Eksik anahtarlar bos olarak nazikce ele alinir (default gracefully).

    `attrs` beklenen anahtarlar: tls_version (str), cipher_suites (list),
    extensions (list), curves (list), header_order (list), http2_settings
    (str/dict). Bilinmeyen ekstra anahtarlar goz ardi edilir.
    """
    parts = []
    for key in _FP_FIELDS:
        val = attrs.get(key)
        if val is None:
            token = ""
        elif isinstance(val, (list, tuple)):
            # Ic sirayi KORU - sira parmak izinin bir parcasi.
            token = "-".join(str(x) for x in val)
        elif isinstance(val, dict):
            # Deterministik olmasi icin anahtarlara gore sirala.
            token = ";".join(f"{k}={val[k]}" for k in sorted(val))
        else:
            token = str(val)
        parts.append(f"{key}:{token}")
    payload = "|".join(parts)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:16]


# UA ailesi -> beklenen "gercek" TLS istemci ailesi(leri) eslemesi.
# Bir tarayici UA'si bir HTTP kutuphanesi/aracina ait TLS yigini sunuyorsa
# bu imkansiz (yani sahte UA / otomasyon) sayilir.
_BROWSER_UA_FAMILIES = frozenset({"chrome", "firefox", "safari", "edge"})
# Tarayici olmayan, betik/arac istemci TLS aileleri.
_TOOL_TLS_FAMILIES = frozenset({
    "python-requests", "requests", "urllib", "curl", "go-http", "go",
    "okhttp", "java", "python", "libwww-perl", "wget",
})


def impossible_combo(ua_family: str, tls_client_family: str) -> bool:
    """UA ile TLS yigini celisiyor mu? (sahte UA / otomasyon telli)

    True doner: iddia edilen UA bir TARAYICI ailesi iken (chrome, firefox,
    safari, edge) sunulan TLS yigini bir betik/arac ailesi ise (python-requests,
    curl, go-http, okhttp, java, wget...). Ornek: "Chrome" gorunumlu bir
    istemci `python-requests` TLS parmak izi sunuyorsa -> True.

    Bilinmeyen/bos degerlerde temkinli davranir ve False doner (asiri
    isaretlemeyi onlemek icin).
    """
    if not ua_family or not tls_client_family:
        return False
    ua = ua_family.strip().lower()
    tls = tls_client_family.strip().lower()
    return ua in _BROWSER_UA_FAMILIES and tls in _TOOL_TLS_FAMILIES


@dataclass
class _Identity:
    """Bir parmak izinin gordugu kimlikler (IP/UA)."""
    ips: set = field(default_factory=set)
    uas: set = field(default_factory=set)
    hits: int = 0


class IdentityCorrelator:
    """Parmak izi -> kimlik korelasyonu ile Sybil (kimlik rotasyonu) tespiti.

    Ayni dusuk-katman parmak izi COK sayida farkli IP veya UA ile
    gorunuyorsa, tek bir aktorun bir cok istemci gibi davrandigina (Sybil)
    dair guclu bir gostergedir - cunku IP/UA degistirmek TLS/HTTP yigin
    parmak izini degistirmez.
    """

    def __init__(self, ip_threshold=3, ua_threshold=3):
        # Varsayilan: bir parmak izi >=3 farkli IP -> Sybil supheli.
        self.ip_threshold = ip_threshold
        self.ua_threshold = ua_threshold
        self._by_fp = defaultdict(_Identity)

    def observe(self, fingerprint: str, claimed_ip: str, ua: str = None) -> None:
        ident = self._by_fp[fingerprint]
        ident.hits += 1
        if claimed_ip:
            ident.ips.add(claimed_ip)
        if ua:
            ident.uas.add(ua)

    def _is_sybil(self, ident: _Identity) -> bool:
        return (len(ident.ips) >= self.ip_threshold or
                len(ident.uas) >= self.ua_threshold)

    def sybil_report(self) -> list:
        """Her parmak izi icin Sybil degerlendirmesi (aciklanabilir)."""
        report = []
        for fp, ident in self._by_fp.items():
            ip_count = len(ident.ips)
            ua_count = len(ident.uas)
            is_sybil = self._is_sybil(ident)
            if is_sybil:
                verdict = (
                    f"Sybil supheli: tek parmak izi ({fp}) {ip_count} farkli "
                    f"IP ve {ua_count} farkli UA ile gorundu - tek aktor cok "
                    f"kimlik rotasyonu yapiyor (IP/UA degisse de yigin ayni)")
            else:
                verdict = (
                    f"Tekil kimlik: {fp} {ip_count} IP / {ua_count} UA - "
                    f"rotasyon esigi altinda (esik IP>={self.ip_threshold})")
            report.append({
                "fingerprint": fp,
                "identities": sorted(ident.ips),
                "identity_count": ip_count,
                "ua_variants": ua_count,
                "verdict": verdict,
                "is_sybil": is_sybil,
            })
        # En supheli (cok IP) ustte.
        report.sort(key=lambda r: -r["identity_count"])
        return report

    def summary(self) -> dict:
        """Genel korelasyon ozeti."""
        rows = self.sybil_report()
        sybil_rows = [r for r in rows if r["is_sybil"]]
        return {
            "total_fingerprints": len(rows),
            "sybil_fingerprints": len(sybil_rows),
            "total_observations": sum(i.hits for i in self._by_fp.values()),
            "distinct_ips": len({ip for i in self._by_fp.values() for ip in i.ips}),
            "assessment_tr": (
                f"{len(sybil_rows)}/{len(rows)} parmak izi kimlik rotasyonu "
                f"(Sybil) belirtisi gosteriyor"
                if sybil_rows else
                "Kimlik rotasyonu (Sybil) belirtisi yok"
            ),
        }
