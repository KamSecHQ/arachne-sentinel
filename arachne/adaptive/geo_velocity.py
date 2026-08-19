"""
Faz 44 - Imkansiz Seyahat / Cografi Hiz (Impossible Travel / Geo-Velocity).

--- Ko-evrim fikri ---
Bir saldirgan calinmis bir kimlik/kimlik-bilgisiyle (credential) oturum
acabilir. Tekil olaylar mesru gorunur; ama AYNI kimlik kisa bir zaman
araliginda cografi olarak COK UZAK iki yerden kullanilirsa, bu fiziksel
olarak imkansizdir - klasik hesap-ele-gecirme (account takeover) ya da
proxy/VPN rotasyonu sinyalidir. Bu modul bir kimligin ardisik konumlarini
izler ve aralarindaki GEREKLI HIZ'i (required speed) hesaplar; makul bir
tavani (ornek ticari jet ~900 km/s) asan hareketi "imkansiz seyahat" olarak
isaretler.

--- Nasil (belgeli) ---
  1. Iki konum arasindaki buyuk-cember mesafesi haversine formuluyle
     hesaplanir (km).
  2. gerekli_hiz = mesafe_km / gecen_saat. Ayni ana denk gelen (gap=0) ama
     farkli konumdaki iki gozlem sonsuz hiz gerektirir -> imkansiz.
  3. gerekli_hiz > max_speed_kmh ise -> imkansiz seyahat.

--- DURUSTLUK NOTU ---
Bu proje CEVRIMDISI, bolge-seviyeli (RIR/region) cografi konumlama kullanir;
gercek sokak-seviyesi GeoIP degil. REGION_COORDS sozlugu her bolge icin
YAKLASIK bir merkez (centroid) sunar. Dolayisiyla bu modul KESIN konum
iddia etmez; yalnizca INANDIRICI OLMAYAN (implausible) hareketi isaretler.
Ayrica mesru sebeplerle de tetiklenebilir: kurumsal VPN cikisi, mobil
operator CGNAT, uydu/uçak Wi-Fi, seyahat eden kullanicilar. Bu yuzden cikti
bir HUMAN-REVIEW / dogrulama girdisidir, otomatik blok gerekcesi degildir.
max_speed_kmh esigi kabadir ve ortama gore ayarlanmalidir.

--- Gercek cerceve eslemesi ---
MITRE ATT&CK T1078 (Valid Accounts), imkansiz-seyahat tespiti (Azure AD /
Entra ID risk algilama, Okta ThreatInsight, AWS GuardDuty), haversine
buyuk-cember mesafesi, hiz-tabanli davranissal analitik (UEBA).

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca bize verilen kimlik/konum/zaman gozlemlerini
yerel olarak degerlendirir; hicbir baska sisteme dokunmaz, hack-back yoktur,
disari veri gondermez. Deterministiktir. Karar daima insana yukseltmedir.

Harici bagimlilik yok - sadece stdlib math.
"""
import math
from dataclasses import dataclass, field

_EARTH_RADIUS_KM = 6371.0088   # ortalama Dunya yaricapi (IUGG)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Iki (enlem, boylam) noktasi arasindaki buyuk-cember mesafesi (km).

    Haversine formulu: kureyi kabul edip iki nokta arasindaki en kisa yay
    uzunlugunu hesaplar. Girdi/donus derece; ic hesap radyan. Ayni nokta ->
    0.0. Deterministik.
    """
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2.0) ** 2)
    c = 2.0 * math.asin(min(1.0, math.sqrt(a)))
    return _EARTH_RADIUS_KM * c


def required_speed_kmh(km: float, seconds: float) -> float:
    """Verilen mesafeyi verilen surede katetmek icin gereken hiz (km/s).

    hiz = km / saat. `seconds` <= 0 ise (ayni an, farkli yer) sonsuz hiz
    gerekir -> float('inf') doner (fiziksel imkansizlik isareti). km=0 ise
    (ayni yer) hiz 0'dir - zaman ne olursa olsun hareket yok.
    """
    if km <= 0:
        return 0.0
    if seconds <= 0:
        return float("inf")
    hours = seconds / 3600.0
    return km / hours


@dataclass
class _LastSeen:
    """Bir kimligin en son bilinen konumu ve zamani."""
    lat: float
    lon: float
    ts_epoch: float


@dataclass
class _Flag:
    """Isaretlenmis bir imkansiz-seyahat olayinin ozeti."""
    identity: str
    required_speed_kmh: float
    distance_km: float
    gap_sec: float


class GeoVelocityMonitor:
    """Kimlik basina ardisik konumlari izleyip imkansiz seyahati isaretler.

    `max_speed_kmh`: makul ust hiz siniri (varsayilan 900 ~ ticari jet). Iki
    gozlem arasinda gereken hiz bunu asarsa 'imkansiz seyahat' isaretlenir.
    Bir kimligin ILK gozlemi asla imkansiz degildir (karsilastirilacak onceki
    konum yok). Deterministik: rastgelelik yok, enjekte edilen saat yok
    (zaman damgalari cagiran tarafindan verilir).
    """

    def __init__(self, max_speed_kmh: float = 900.0):
        self.max_speed_kmh = max_speed_kmh
        self._last = {}          # identity -> _LastSeen
        self._flags = {}         # identity -> _Flag (en son isaret)

    def observe(self, identity: str, lat: float, lon: float,
                ts_epoch: float) -> dict:
        """Bir kimlik icin yeni bir konum gozlemi kaydeder ve degerlendirir.

        En son bilinen konumla karsilastirir; gereken hiz max_speed_kmh'i
        asarsa imkansiz seyahat isaretler. Her cagri kimligin 'en son konum'unu
        gunceller (kronolojik cagrildigi varsayilir).

        Donus dict:
          identity            : kimlik.
          impossible_travel   : bool.
          required_speed_kmh  : float (ilk gozlemde 0.0).
          distance_km         : float (ilk gozlemde 0.0).
          gap_sec             : float, onceki gozlemden gecen sure (ilk 0.0).
          verdict_tr          : Turkce degerlendirme.
        """
        prev = self._last.get(identity)
        # Konumu her durumda guncelle (sonraki karsilastirma icin).
        self._last[identity] = _LastSeen(lat=lat, lon=lon, ts_epoch=ts_epoch)

        if prev is None:
            return {
                "identity": identity,
                "impossible_travel": False,
                "required_speed_kmh": 0.0,
                "distance_km": 0.0,
                "gap_sec": 0.0,
                "verdict_tr": (
                    f"Ilk gozlem ({identity}): karsilastirilacak onceki konum "
                    f"yok - imkansiz seyahat degerlendirilemez (baseline kuruldu)."
                ),
            }

        gap = ts_epoch - prev.ts_epoch
        dist = haversine_km(prev.lat, prev.lon, lat, lon)
        speed = required_speed_kmh(dist, gap)
        # Sira-disi (negatif gap) girdi kronolojik degildir; guvenilir hiz
        # hesaplanamaz -> imkansiz SAYILMAZ (yalnizca gap>=0 degerlendirilir).
        impossible = gap >= 0 and speed > self.max_speed_kmh

        if impossible:
            self._flags[identity] = _Flag(
                identity=identity,
                required_speed_kmh=speed,
                distance_km=dist,
                gap_sec=gap,
            )
            speed_txt = "sonsuz" if math.isinf(speed) else f"{speed:.0f}"
            verdict = (
                f"IMKANSIZ SEYAHAT ({identity}): {dist:.0f} km, {gap:.0f} sn "
                f"icinde -> gereken hiz {speed_txt} km/s > tavan "
                f"{self.max_speed_kmh:.0f} km/s. Olasi hesap-ele-gecirme / "
                f"proxy rotasyonu. INSAN INCELEMESINE yukselt (otomatik blok DEGIL). "
                f"DURUSTLUK: bolge merkezleri yaklasiktir."
            )
        elif gap < 0:
            # Sira disi (out-of-order) zaman damgasi - durustce belirt.
            verdict = (
                f"SIRA-DISI zaman damgasi ({identity}): yeni gozlem oncekinden "
                f"eski (gap {gap:.0f} sn) - kronolojik olmayan girdi, atlandi."
            )
        else:
            speed_txt = f"{speed:.0f}"
            verdict = (
                f"Makul hareket ({identity}): {dist:.0f} km / {gap:.0f} sn -> "
                f"gereken hiz {speed_txt} km/s, tavan {self.max_speed_kmh:.0f} "
                f"km/s altinda - fiziksel olarak mumkun."
            )

        return {
            "identity": identity,
            "impossible_travel": impossible,
            "required_speed_kmh": (float("inf") if math.isinf(speed)
                                   else round(speed, 2)),
            "distance_km": round(dist, 2),
            "gap_sec": round(gap, 2),
            "verdict_tr": verdict,
        }

    def report(self) -> dict:
        """Isaretlenmis kimliklerin ozetini doner.

        Donus dict:
          flagged_count : imkansiz seyahat isaretlenen kimlik sayisi.
          identities    : isaretlenen kimlik adlari.
          flags         : her biri {identity, required_speed_kmh, distance_km,
                          gap_sec} olan ozet listesi.
          tracked       : izlenen (en az bir gozlemi olan) toplam kimlik sayisi.
        """
        flags = []
        for f in self._flags.values():
            flags.append({
                "identity": f.identity,
                "required_speed_kmh": (float("inf")
                                       if math.isinf(f.required_speed_kmh)
                                       else round(f.required_speed_kmh, 2)),
                "distance_km": round(f.distance_km, 2),
                "gap_sec": round(f.gap_sec, 2),
            })
        return {
            "flagged_count": len(flags),
            "identities": [f["identity"] for f in flags],
            "flags": flags,
            "tracked": len(self._last),
        }


# Bolge (RIR/region) etiketlerinden temsili (enlem, boylam) merkezlerine
# esleme. Bu proje cevrimdisi, bolge-seviyeli cografi konumlama kullandigi
# icin cagiran, bir IP'nin bolgesini bir merkez koordinata cevirip observe()'e
# besleyebilir. DURUSTLUK: bunlar KABA centroid'lerdir; kesin konum degil,
# yalnizca inandirici-olmayan hareketi isaretlemek icindir.
REGION_COORDS = {
    "north-america": (39.8283, -98.5795),    # ABD cografi merkezi civari
    "europe": (50.1109, 8.6821),             # Orta Avrupa (Frankfurt civari)
    "asia-pacific": (1.3521, 103.8198),      # Singapur (APAC dugumu)
    "latin-america": (-15.7939, -47.8828),   # Brasilia civari
    "africa": (0.3476, 32.5825),             # Dogu Afrika (Kampala civari)
    "middle-east": (25.2048, 55.2708),       # Dubai civari
}
