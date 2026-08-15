"""
Cevrimdisi IP kapsam siniflandirmasi ve kaba bolge tahmini.

--- DURUSTLUK NOTU (onemli) ---
Bu modul GERCEK bir GeoIP veritabani DEGILDIR. Ticari GeoIP servisleri
(MaxMind vb.) surekli guncellenen, lisansli, yuzlerce MB'lik veri
kullanir. Biz internete cikmadan, harici bagimlilik olmadan calisan kucuk
bir yaklasim kullaniyoruz:

  1. Once IP'nin KAPSAMINI kesin olarak belirleriz (loopback/ozel/genel).
     Bu %100 dogrudur - RFC tanimli araliklar.
  2. Genel (public) IP'ler icin, IANA'nin /8 blok tahsis kayitlarina
     dayanan kaba bir BOLGE tahmini yaparız (kita/kayit kurumu seviyesi).
     Bu bir TAHMINDIR ve panelde "tahmin" olarak etiketlenir.

Neden boyle yaptik: Lab ortaminda tum trafik 127.0.0.1'den gelir. Bunu
sahte bir sekilde "Rusya'dan saldiri" diye gostermek, juri karsisinda
savunulamaz bir aldatmaca olurdu. Bunun yerine loopback trafigi acikca
"LAB" olarak isaretliyoruz; kuresel harita ise gercek genel IP'ler
geldiginde (ornegin mesh sensorlerinden) anlamli olur.
"""
import ipaddress

# RFC 5737 / RFC 3849 dokumantasyon araliklari. Python'un `is_private`
# ozelligi bunlari "ozel" sayar - teknik olarak dogru ama bizim icin
# YANILTICI: bu adresler gercek bir cihaza ait DEGILDIR ve tam da
# ornek/demo amaciyla ayrilmistir. Bu yuzden ayri bir kapsam olarak
# ele aliyoruz: haritada gosterilebilir, guvenle "engellenebilir"
# (arkasinda gercek bir kurban yok), ama gercek trafik de degildir.
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),     # IPv6 dokumantasyon
]


def is_documentation_ip(ip) -> bool:
    """RFC 5737/3849 dokumantasyon araligina mi ait?"""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in DOCUMENTATION_NETWORKS)

# IANA /8 tahsislerine dayali kaba bolge haritasi. Kayit kurumu (RIR)
# seviyesinde dogru, sehir seviyesinde DEGIL. Panelde harita uzerinde
# yaklasik konumlandirma icin kullanilir.
# Format: ilk oktet -> (bolge kodu, bolge adi, yaklasik enlem, boylam)
_OCTET_REGIONS = {
    # Kuzey Amerika (ARIN)
    3: ("NA", "Kuzey Amerika", 39.0, -98.0), 4: ("NA", "Kuzey Amerika", 39.0, -98.0),
    6: ("NA", "Kuzey Amerika", 39.0, -98.0), 8: ("NA", "Kuzey Amerika", 39.0, -98.0),
    9: ("NA", "Kuzey Amerika", 39.0, -98.0), 11: ("NA", "Kuzey Amerika", 39.0, -98.0),
    12: ("NA", "Kuzey Amerika", 39.0, -98.0), 13: ("NA", "Kuzey Amerika", 39.0, -98.0),
    15: ("NA", "Kuzey Amerika", 39.0, -98.0), 16: ("NA", "Kuzey Amerika", 39.0, -98.0),
    17: ("NA", "Kuzey Amerika", 39.0, -98.0), 18: ("NA", "Kuzey Amerika", 39.0, -98.0),
    19: ("NA", "Kuzey Amerika", 39.0, -98.0), 20: ("NA", "Kuzey Amerika", 39.0, -98.0),
    23: ("NA", "Kuzey Amerika", 39.0, -98.0), 24: ("NA", "Kuzey Amerika", 39.0, -98.0),
    26: ("NA", "Kuzey Amerika", 39.0, -98.0), 32: ("NA", "Kuzey Amerika", 39.0, -98.0),
    34: ("NA", "Kuzey Amerika", 39.0, -98.0), 35: ("NA", "Kuzey Amerika", 39.0, -98.0),
    38: ("NA", "Kuzey Amerika", 39.0, -98.0), 40: ("NA", "Kuzey Amerika", 39.0, -98.0),
    44: ("NA", "Kuzey Amerika", 39.0, -98.0), 47: ("NA", "Kuzey Amerika", 39.0, -98.0),
    50: ("NA", "Kuzey Amerika", 39.0, -98.0), 52: ("NA", "Kuzey Amerika", 39.0, -98.0),
    54: ("NA", "Kuzey Amerika", 39.0, -98.0), 63: ("NA", "Kuzey Amerika", 39.0, -98.0),
    64: ("NA", "Kuzey Amerika", 39.0, -98.0), 65: ("NA", "Kuzey Amerika", 39.0, -98.0),
    66: ("NA", "Kuzey Amerika", 39.0, -98.0), 67: ("NA", "Kuzey Amerika", 39.0, -98.0),
    68: ("NA", "Kuzey Amerika", 39.0, -98.0), 69: ("NA", "Kuzey Amerika", 39.0, -98.0),
    70: ("NA", "Kuzey Amerika", 39.0, -98.0), 71: ("NA", "Kuzey Amerika", 39.0, -98.0),
    72: ("NA", "Kuzey Amerika", 39.0, -98.0), 73: ("NA", "Kuzey Amerika", 39.0, -98.0),
    74: ("NA", "Kuzey Amerika", 39.0, -98.0), 75: ("NA", "Kuzey Amerika", 39.0, -98.0),
    76: ("NA", "Kuzey Amerika", 39.0, -98.0), 96: ("NA", "Kuzey Amerika", 39.0, -98.0),
    97: ("NA", "Kuzey Amerika", 39.0, -98.0), 98: ("NA", "Kuzey Amerika", 39.0, -98.0),
    99: ("NA", "Kuzey Amerika", 39.0, -98.0), 104: ("NA", "Kuzey Amerika", 39.0, -98.0),
    107: ("NA", "Kuzey Amerika", 39.0, -98.0), 108: ("NA", "Kuzey Amerika", 39.0, -98.0),
    142: ("NA", "Kuzey Amerika", 56.0, -106.0), 173: ("NA", "Kuzey Amerika", 39.0, -98.0),
    174: ("NA", "Kuzey Amerika", 39.0, -98.0), 184: ("NA", "Kuzey Amerika", 39.0, -98.0),
    192: ("NA", "Kuzey Amerika", 39.0, -98.0), 198: ("NA", "Kuzey Amerika", 39.0, -98.0),
    199: ("NA", "Kuzey Amerika", 39.0, -98.0), 204: ("NA", "Kuzey Amerika", 39.0, -98.0),
    205: ("NA", "Kuzey Amerika", 39.0, -98.0), 206: ("NA", "Kuzey Amerika", 39.0, -98.0),
    207: ("NA", "Kuzey Amerika", 39.0, -98.0), 208: ("NA", "Kuzey Amerika", 39.0, -98.0),
    209: ("NA", "Kuzey Amerika", 39.0, -98.0), 216: ("NA", "Kuzey Amerika", 39.0, -98.0),
    # Avrupa (RIPE NCC)
    2: ("EU", "Avrupa", 50.0, 10.0), 5: ("EU", "Avrupa", 50.0, 10.0),
    31: ("EU", "Avrupa", 50.0, 10.0), 37: ("EU", "Avrupa", 50.0, 10.0),
    46: ("EU", "Avrupa", 50.0, 10.0), 51: ("EU", "Avrupa", 52.0, -1.0),
    53: ("EU", "Avrupa", 51.0, 10.0), 57: ("EU", "Avrupa", 46.0, 2.0),
    62: ("EU", "Avrupa", 50.0, 10.0), 77: ("EU", "Avrupa", 50.0, 10.0),
    78: ("EU", "Avrupa", 50.0, 10.0), 79: ("EU", "Avrupa", 50.0, 10.0),
    80: ("EU", "Avrupa", 50.0, 10.0), 81: ("EU", "Avrupa", 50.0, 10.0),
    82: ("EU", "Avrupa", 50.0, 10.0), 83: ("EU", "Avrupa", 50.0, 10.0),
    84: ("EU", "Avrupa", 50.0, 10.0), 85: ("EU", "Avrupa", 50.0, 10.0),
    86: ("EU", "Avrupa", 50.0, 10.0), 87: ("EU", "Avrupa", 50.0, 10.0),
    88: ("EU", "Avrupa", 50.0, 10.0), 89: ("EU", "Avrupa", 50.0, 10.0),
    90: ("EU", "Avrupa", 50.0, 10.0), 91: ("EU", "Avrupa", 50.0, 10.0),
    92: ("EU", "Avrupa", 50.0, 10.0), 93: ("EU", "Avrupa", 50.0, 10.0),
    94: ("EU", "Avrupa", 50.0, 10.0), 95: ("EU", "Avrupa", 50.0, 10.0),
    109: ("EU", "Avrupa", 50.0, 10.0), 128: ("EU", "Avrupa", 50.0, 10.0),
    141: ("EU", "Avrupa", 50.0, 10.0), 145: ("EU", "Avrupa", 52.0, 5.0),
    151: ("EU", "Avrupa", 42.0, 12.0), 176: ("EU", "Avrupa", 50.0, 10.0),
    178: ("EU", "Avrupa", 50.0, 10.0), 185: ("EU", "Avrupa", 50.0, 10.0),
    188: ("EU", "Avrupa", 50.0, 10.0), 193: ("EU", "Avrupa", 50.0, 10.0),
    194: ("EU", "Avrupa", 50.0, 10.0), 195: ("EU", "Avrupa", 50.0, 10.0),
    212: ("EU", "Avrupa", 50.0, 10.0), 213: ("EU", "Avrupa", 50.0, 10.0),
    217: ("EU", "Avrupa", 50.0, 10.0),
    # Turkiye'nin yogun oldugu RIPE bloklari (kaba)
    78 + 0: ("EU", "Avrupa", 50.0, 10.0),
    # Asya-Pasifik (APNIC)
    1: ("AP", "Asya-Pasifik", 25.0, 115.0), 14: ("AP", "Asya-Pasifik", 25.0, 115.0),
    27: ("AP", "Asya-Pasifik", 25.0, 115.0), 36: ("AP", "Asya-Pasifik", 25.0, 115.0),
    39: ("AP", "Asya-Pasifik", 25.0, 115.0), 42: ("AP", "Asya-Pasifik", 25.0, 115.0),
    43: ("AP", "Asya-Pasifik", 25.0, 115.0), 49: ("AP", "Asya-Pasifik", 37.0, 127.0),
    58: ("AP", "Asya-Pasifik", 25.0, 115.0), 59: ("AP", "Asya-Pasifik", 25.0, 115.0),
    60: ("AP", "Asya-Pasifik", 25.0, 115.0), 61: ("AP", "Asya-Pasifik", 25.0, 115.0),
    101: ("AP", "Asya-Pasifik", 25.0, 115.0), 103: ("AP", "Asya-Pasifik", 25.0, 115.0),
    106: ("AP", "Asya-Pasifik", 25.0, 115.0), 110: ("AP", "Asya-Pasifik", 25.0, 115.0),
    111: ("AP", "Asya-Pasifik", 36.0, 138.0), 112: ("AP", "Asya-Pasifik", 25.0, 115.0),
    113: ("AP", "Asya-Pasifik", 25.0, 115.0), 114: ("AP", "Asya-Pasifik", 25.0, 115.0),
    115: ("AP", "Asya-Pasifik", 25.0, 115.0), 116: ("AP", "Asya-Pasifik", 25.0, 115.0),
    117: ("AP", "Asya-Pasifik", 25.0, 115.0), 118: ("AP", "Asya-Pasifik", 25.0, 115.0),
    119: ("AP", "Asya-Pasifik", 25.0, 115.0), 120: ("AP", "Asya-Pasifik", 25.0, 115.0),
    121: ("AP", "Asya-Pasifik", 25.0, 115.0), 122: ("AP", "Asya-Pasifik", 25.0, 115.0),
    123: ("AP", "Asya-Pasifik", 25.0, 115.0), 124: ("AP", "Asya-Pasifik", 25.0, 115.0),
    125: ("AP", "Asya-Pasifik", 25.0, 115.0), 126: ("AP", "Asya-Pasifik", 36.0, 138.0),
    175: ("AP", "Asya-Pasifik", 25.0, 115.0), 180: ("AP", "Asya-Pasifik", 25.0, 115.0),
    182: ("AP", "Asya-Pasifik", 25.0, 115.0), 183: ("AP", "Asya-Pasifik", 25.0, 115.0),
    202: ("AP", "Asya-Pasifik", 25.0, 115.0), 203: ("AP", "Asya-Pasifik", 25.0, 115.0),
    210: ("AP", "Asya-Pasifik", 25.0, 115.0), 211: ("AP", "Asya-Pasifik", 37.0, 127.0),
    218: ("AP", "Asya-Pasifik", 25.0, 115.0), 219: ("AP", "Asya-Pasifik", 25.0, 115.0),
    220: ("AP", "Asya-Pasifik", 25.0, 115.0), 221: ("AP", "Asya-Pasifik", 25.0, 115.0),
    222: ("AP", "Asya-Pasifik", 25.0, 115.0), 223: ("AP", "Asya-Pasifik", 25.0, 115.0),
    # Latin Amerika (LACNIC)
    177: ("LA", "Latin Amerika", -14.0, -51.0), 179: ("LA", "Latin Amerika", -14.0, -51.0),
    181: ("LA", "Latin Amerika", -34.0, -64.0), 186: ("LA", "Latin Amerika", -14.0, -51.0),
    187: ("LA", "Latin Amerika", -14.0, -51.0), 189: ("LA", "Latin Amerika", 23.0, -102.0),
    190: ("LA", "Latin Amerika", -14.0, -51.0), 200: ("LA", "Latin Amerika", -14.0, -51.0),
    201: ("LA", "Latin Amerika", -14.0, -51.0),
    # Afrika (AFRINIC)
    41: ("AF", "Afrika", 0.0, 20.0), 102: ("AF", "Afrika", 0.0, 20.0),
    105: ("AF", "Afrika", 0.0, 20.0), 154: ("AF", "Afrika", 0.0, 20.0),
    196: ("AF", "Afrika", 0.0, 20.0), 197: ("AF", "Afrika", 0.0, 20.0),
}

# Lab/loopback trafigi harita uzerinde tek bir "LAB" dugumunde toplanir.
LAB_LOCATION = {"region": "LAB", "region_name": "Yerel Lab", "lat": 41.0, "lon": 29.0}


def classify_ip_scope(ip: str) -> str:
    """IP kapsamini RFC tanimlarina gore kesin olarak siniflandirir.

    Donen degerler:
      loopback | private | documentation | reserved | public | invalid
    Bu fonksiyon TAHMIN yapmaz - sonucu %100 kesindir."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    # Dokumantasyon kontrolu, is_private'dan ONCE gelmeli: Python bu
    # araliklari ozel sayar ama biz ayirmak istiyoruz (yukaridaki nota bkz).
    if is_documentation_ip(addr):
        return "documentation"
    if addr.is_private:
        return "private"
    if addr.is_multicast or addr.is_reserved or addr.is_link_local or addr.is_unspecified:
        return "reserved"
    return "public"


def region_hint(ip: str):
    """Genel bir IPv4 icin kaba bolge tahmini (RIR seviyesi).

    Bilinmiyorsa None doner. Bu bir TAHMINDIR ve arayuzde oyle etiketlenir.
    Dokumantasyon adresleri de haritalanabilir (demo/senaryo amacli)."""
    scope = classify_ip_scope(ip)
    if scope not in ("public", "documentation"):
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    first = int(str(addr).split(".")[0])
    entry = _OCTET_REGIONS.get(first)
    if not entry:
        return None
    code, name, lat, lon = entry
    return {"region": code, "region_name": name, "lat": lat, "lon": lon}


def _jitter_from_ip(ip: str, spread: float = 7.0):
    """Ayni bolgedeki farkli IP'lerin harita uzerinde ust uste binmemesi icin,
    IP'den TURETILEN (rastgele degil - deterministik) kucuk bir kaydirma.

    Deterministik olmasi onemli: ayni IP her zaman ayni noktada gorunur,
    yoksa harita her yenilemede zipladigi icin okunamaz hale gelir."""
    try:
        parts = [int(p) for p in ip.split(".")]
    except (ValueError, AttributeError):
        return 0.0, 0.0
    if len(parts) != 4:
        return 0.0, 0.0
    lat_off = ((parts[2] / 255.0) - 0.5) * 2 * spread
    lon_off = ((parts[3] / 255.0) - 0.5) * 2 * spread * 1.6
    return lat_off, lon_off


def geo_for_ip(ip: str) -> dict:
    """Bir IP icin harita uzerinde gosterilecek tam konum bilgisi.

    Her zaman bir sonuc doner (bilinmeyenler icin bile) ki harita kodu
    None kontrolu yapmak zorunda kalmasin. `precision` alani, sonucun ne
    kadar guvenilir oldugunu acikca belirtir - bu durustluk gostergesi
    dogrudan arayuzde gosterilir."""
    scope = classify_ip_scope(ip)

    if scope in ("loopback", "private"):
        lat_off, lon_off = _jitter_from_ip(ip, spread=1.5)
        return {
            "ip": ip, "scope": scope,
            "region": LAB_LOCATION["region"],
            "region_name": LAB_LOCATION["region_name"],
            "lat": LAB_LOCATION["lat"] + lat_off,
            "lon": LAB_LOCATION["lon"] + lon_off,
            "precision": "lab",
            "precision_tr": "Yerel lab (gercek konum yok)",
        }

    hint = region_hint(ip)
    if hint:
        lat_off, lon_off = _jitter_from_ip(ip)
        is_doc = scope == "documentation"
        return {
            "ip": ip, "scope": scope,
            "region": hint["region"], "region_name": hint["region_name"],
            "lat": hint["lat"] + lat_off, "lon": hint["lon"] + lon_off,
            "precision": "documentation" if is_doc else "region-estimate",
            "precision_tr": (
                "RFC 5737 dokumantasyon adresi (senaryo/demo trafigi)" if is_doc
                else "Bolge tahmini (RIR seviyesi)"
            ),
        }

    return {
        "ip": ip, "scope": scope,
        "region": "??", "region_name": "Bilinmiyor",
        "lat": 0.0, "lon": 0.0,
        "precision": "unknown",
        "precision_tr": "Konum belirlenemedi",
    }
