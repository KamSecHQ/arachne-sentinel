"""
Faz 29 - Kolektif Savunma & Gosterge Paylasimi (herd immunity / surunun bagisikligi).

--- Ko-evrim / kolektif fikri ---
Tek bir sensor saldirgani tespit ettiginde, o bilgiyi KENDINE saklarsa her
sensor ayni saldirgani sifirdan yeniden kesfetmek zorunda kalir - saldirgan
sensorden sensore gecerek uzun sure kazanir. Kolektif savunma bunu tersine
cevirir: bir sensor bir gosterge (IOC: parmak izi / IP / token) yakaladiginda
onu YAPISAL bir gosterge olarak PAYLASIR; boylece diger tum sensorler saldirgan
onlara ULASMADAN ONCE "bagisiklik" kazanir. Bu, surunun bagisikligi (herd
immunity) analojisidir: yeterince sensor paylasirsa, saldirganin ilk kurban
disindaki herkese karsi avantaji cöker.

--- Model (STIX 2.1 / TAXII, ulusal-CERT koordinasyonu) ---
  * to_stix_like: bir gostergeyi minimal STIX-2.1-benzeri bir 'indicator'
    nesnesine cevirir (deterministik id, STIX-pattern-benzeri desen). Gercek
    STIX/TAXII paylasiminin cekirdek bicimini modeller.
  * CollectiveDefense: sensorlerin kayit oldugu, gosterge paylastigi ve
    "bu deger bilinen kotu mu?" diye sorabildigi paylasilan bir bilgi havuzu.
    Bir sensorun paylastigi gosterge aninda TUM sensorlere bilinir olur
    (yayilim/propagation) - kolektif bagisiklik.

--- DURUSTLUK NOTU ---
Bu, STIX 2.1 / TAXII ve ulusal-CERT koordineli savunmasinin CEKIRDEK mantigini
(yapisal gosterge, deterministik kimlik, tum sensorlere yayilim, kesif tasarrufu)
kucuk ve deterministik gosterir. Tam bir STIX 2.1 uygulamasi ya da bir TAXII
sunucusu DEGILDIR: uretilen nesne minimal ve "benzeri"dir (tam sema dogrulamasi,
imzalama, guven halkalari, ret/geri-cekme akislari yok). Deger karsilastirmasi
birebir esitliktir (bulanik/benzerlik eslemesi degil). Amac bilgi paylasiminin
savunma kazancini gostermektir.

--- Gercek cerceve eslemesi ---
STIX 2.1 / TAXII (yapisal tehdit istihbarati paylasimi), ulusal CERT/CSIRT
koordineli savunmasi, MITRE Engage (dusman katilimi/paylasim), surunun
bagisikligi (herd immunity) analojisi.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Paylasilan gostergeler yalnizca KENDI sensor filomuzdaki
savunmayi guclendirir; hicbir baska sisteme dokunmaz, hack-back yoktur.
"Bagisiklik" saldirgani engellemek/tuzaga yonlendirmek demektir - ona karsi
saldiri degil.

Harici bagimlilik yok - sadece stdlib (hashlib).
"""
import hashlib
from dataclasses import dataclass, field


# Gosterge turu -> STIX-benzeri desen sablonu. Bilinmeyen tur ozel-nesne
# (x-arachne) alanina duser.
_PATTERN_BUILDERS = {
    "ip": lambda v: f"[ipv4-addr:value = '{v}']",
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "fingerprint": lambda v: f"[x-arachne:fingerprint = '{v}']",
    "token": lambda v: f"[x-arachne:token = '{v}']",
}


def _deterministic_id(kind: str, value: str) -> str:
    """Deger+turden UUID-benzeri deterministik bir STIX id uretir.

    Ayni (kind, value) her zaman ayni id'yi verir - wallclock/rastgelelik yok.
    Bicim: 'indicator--8-4-4-4-12' (UUID gorunumu)."""
    digest = hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()
    h = digest[:32]
    uuid_like = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    return f"indicator--{uuid_like}"


def to_stix_like(indicator: dict, valid_from: str = None) -> dict:
    """Bir gostergeyi minimal STIX-2.1-benzeri 'indicator' nesnesine cevirir.

    `indicator`: {kind: 'fingerprint'|'ip'|'token'|..., value: ...}.
    Deterministik id degerden turetilir (wallclock kullanilmaz; `valid_from`
    yalnizca acikca gecilirse ciktida yer alir).

    Doner: {type, spec_version, id, pattern, pattern_type, labels,
            [valid_from]}.
    """
    kind = str(indicator.get("kind", "unknown"))
    value = str(indicator.get("value", ""))
    builder = _PATTERN_BUILDERS.get(kind, lambda v: f"[x-arachne:{kind} = '{v}']")
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _deterministic_id(kind, value),
        "pattern": builder(value),
        "pattern_type": "stix",
        "labels": ["malicious-activity", kind],
    }
    if valid_from is not None:
        obj["valid_from"] = valid_from
    return obj


@dataclass
class _IndicatorRecord:
    """Havuzda saklanan paylasilmis bir gosterge kaydi."""
    value: str
    kind: str
    first_reported_by: str
    stix: dict = field(default_factory=dict)


class CollectiveDefense:
    """Sensor filosu icin paylasilan gosterge havuzu (kolektif bagisiklik).

    Bir sensor bir gosterge paylastiginda, o gosterge aninda TUM sensorlere
    bilinir olur. Ayni deger tekrar paylasilirsa yinelenmez (deduplication) -
    ilk paylasan sensor kaydi korunur; bu, "havuz zaten bagisik" demektir.
    """

    def __init__(self):
        self._sensors = set()               # kayitli sensor id'leri
        self._contributors = set()          # en az bir gosterge paylasan sensorler
        self._indicators = {}               # value -> _IndicatorRecord

    def register_sensor(self, sensor_id: str) -> dict:
        """Bir sensoru filoya kaydeder."""
        self._sensors.add(sensor_id)
        return {"sensor_id": sensor_id, "registered": True,
                "total_sensors": len(self._sensors)}

    def share_indicator(self, sensor_id: str, indicator: dict) -> dict:
        """Bir sensor bir IOC yayinlar; gosterge tum filoya bilinir olur.

        `indicator`: {kind: 'fingerprint'|'ip'|'token', value: ...}.
        Ilk paylasan sensor kaydedilir; ayni deger tekrar gelirse yinelenmez.

        Doner: {value, kind, first_reported_by, newly_added (bool),
                immunized_sensors (int), stix, reason}.
        """
        # Paylasan sensor otomatik olarak kayitli ve katilimci sayilir.
        self._sensors.add(sensor_id)
        self._contributors.add(sensor_id)

        value = str(indicator.get("value", ""))
        kind = str(indicator.get("kind", "unknown"))

        if value in self._indicators:
            rec = self._indicators[value]
            newly = False
            reason = (
                f"'{value}' gostergesi zaten havuzda ('{rec.first_reported_by}' "
                f"tarafindan bildirilmisti) - filo zaten bagisik, yinelenmedi."
            )
        else:
            rec = _IndicatorRecord(
                value=value, kind=kind, first_reported_by=sensor_id,
                stix=to_stix_like(indicator))
            self._indicators[value] = rec
            newly = True
            reason = (
                f"'{sensor_id}' yeni gostergeyi ({kind}) paylasti; filodaki diger "
                f"tum sensorler saldirgan onlara ulasmadan bagisiklik kazandi."
            )

        immunized = max(0, len(self._sensors) - 1)
        return {
            "value": value,
            "kind": rec.kind,
            "first_reported_by": rec.first_reported_by,
            "newly_added": newly,
            "immunized_sensors": immunized,
            "stix": rec.stix,
            "reason": reason,
        }

    def is_known_bad(self, value: str) -> dict:
        """Bir degerin paylasilan havuzda bilinen-kotu olup olmadigini sorar.

        Doner: {known (bool), first_reported_by, kind, reason}.
        """
        rec = self._indicators.get(value)
        if rec is None:
            return {
                "known": False,
                "first_reported_by": None,
                "kind": None,
                "reason": f"'{value}' henuz paylasilmadi - havuzda kayit yok.",
            }
        return {
            "known": True,
            "first_reported_by": rec.first_reported_by,
            "kind": rec.kind,
            "reason": (
                f"'{value}' bilinen kotu: '{rec.first_reported_by}' tarafindan "
                f"paylasildi, tum filo bagisik."
            ),
        }

    def immunity_report(self) -> dict:
        """Kolektif bagisiklik durusunun ozeti.

        Doner: {shared_indicators, contributing_sensors, total_sensors,
                coverage_pct, herd_immunity_note_tr}.
        coverage_pct = katilimci sensorlerin toplam sensorlere orani (%).
        """
        total = len(self._sensors)
        contributing = len(self._contributors)
        coverage = round(100.0 * contributing / total, 1) if total else 0.0
        return {
            "shared_indicators": len(self._indicators),
            "contributing_sensors": contributing,
            "total_sensors": total,
            "coverage_pct": coverage,
            "herd_immunity_note_tr": (
                f"{total} sensordan {contributing} tanesi gosterge paylasti "
                f"(kapsam %{coverage}); paylasilan {len(self._indicators)} gosterge "
                f"filodaki HERKESI bagisik kilar. Yeterli sensor katildikca "
                f"saldirganin ilk kurban disindaki hedeflere karsi avantaji cöker "
                f"- surunun bagisikligi."
            ),
        }

    def propagation_savings(self) -> dict:
        """Kolektif savunmanin getirisi: kac sensorun saldirgani BAGIMSIZ olarak
        yeniden kesfetmek zorunda KALMADIGI.

        Naif dunyada her sensor her gostergeyi tek basina kesfetmeliydi
        (naive_cost = gosterge * sensor). Paylasimla her gosterge yalnizca BIR
        kez kesfedilir (collective_cost = gosterge). Fark, onlenen bagimsiz
        yeniden-kesiflerdir.

        Doner: {shared_indicators, total_sensors, naive_cost, collective_cost,
                independent_rediscoveries_avoided, savings_ratio, explanation_tr}.
        """
        total = len(self._sensors)
        shared = len(self._indicators)
        naive_cost = shared * total          # herkes her seyi ayri kesfetseydi
        collective_cost = shared             # her gosterge bir kez kesfedildi
        avoided = max(0, naive_cost - collective_cost)
        savings_ratio = (round(avoided / naive_cost, 3) if naive_cost else 0.0)
        return {
            "shared_indicators": shared,
            "total_sensors": total,
            "naive_cost": naive_cost,
            "collective_cost": collective_cost,
            "independent_rediscoveries_avoided": avoided,
            "savings_ratio": savings_ratio,
            "explanation_tr": (
                f"Paylasim olmasaydi {total} sensorun her biri {shared} gostergeyi "
                f"ayri ayri kesfetmeliydi ({naive_cost} kesif). Kolektif havuzla "
                f"her gosterge bir kez kesfedildi ({collective_cost} kesif); boylece "
                f"{avoided} bagimsiz yeniden-kesif onlendi (%{round(savings_ratio*100,1)} "
                f"tasarruf). Iste kolektif savunmanin getirisi budur."
            ),
        }
