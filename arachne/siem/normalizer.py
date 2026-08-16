"""
Faz 32 - SIEM olay normalizasyonu ve zenginlestirmesi.

Ham honeypot olaylarini ECS-uyumlu (Elastic Common Schema) yapisal
kayitlara cevirir; ardindan tehdit baglami (etiket, kapsam, bilinen-kotu
eslesmesi) ekler.

--- idea ---
Normalizasyon = korelasyonun on kosuludur. Tum olaylar ayni alan
adlarini (src_ip, dst_service, entities.*) kullanirsa; IP'ler, hash'ler,
kullanicilar ve cihazlar olaylar arasinda BAGLANABILIR hale gelir.

--- Gercek dunya eslesmesi ---
  * Alan adlandirma: Elastic Common Schema (ECS) - source.ip, source.port,
    destination.service, event.category/type, related.ip/user/hash.
  * Varlik cikarimi: IOC cikarici (arachne/reverse/ioc_extractor.py) yeniden
    kullanilir; kullanici/surec/cihaz icin ek regex'ler eklenir.

--- DURUSTLUK NOTU ---
Regex tabanli cikarim mukemmel degildir (yanlis pozitif/negatif olabilir);
amac ham metni "aranabilir varliklar"a cevirmektir, adli-delil kesinligi
degil. Kapsam siniflandirmasi ise RFC tanimlarina dayanir ve %100 kesindir.

--- Savunma amacli etik not ---
Yalnizca gelen olay verisini isler; hicbir dis kaynaga baglanmaz, saf
fonksiyonlardan olusur (ayni girdi -> ayni cikti). Test edilebilirlik icin
IOC cikarici enjekte edilebilir (`extract_fn`).

Harici bagimlilik yok - sadece stdlib re + ipaddress.
"""
import ipaddress
import re

# --- Ek varlik regex'leri (IOC cikaricisinin kapsamadigi alanlar) ----------
# Kullanici: user= / login= / username= / usr= kaliplari.
_USER_RE = re.compile(
    r"\b(?:user(?:name)?|login|usr)\s*[=:]\s*[\"']?([A-Za-z0-9._\-\\@]+)", re.I
)

# Surec: cmd= / command= / exec= / process= yakalar (deger tokeni).
_CMD_KV_RE = re.compile(
    r"\b(?:cmd|command|exec|process|proc)\s*[=:]\s*[\"']?([^\s\"'&;|]+)", re.I
)
# /bin/... /usr/bin/... gibi mutlak ikili yollari.
_BIN_PATH_RE = re.compile(r"/(?:usr/)?s?bin/[A-Za-z0-9._\-]+")
# Serbest metinde gecen bilinen surec/kabuk adlari.
_PROCESS_WORDS = [
    "bash", "sh", "zsh", "python", "python3", "perl", "ruby", "php",
    "powershell", "cmd.exe", "wget", "curl", "nc", "ncat", "netcat",
]
_PROCESS_WORD_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in _PROCESS_WORDS) + r")\b", re.I
)

# Cihaz: host= / device= / hostname= / dev= kaliplari.
_DEVICE_KV_RE = re.compile(
    r"\b(?:hostname|host|device|dev)\s*[=:]\s*[\"']?([A-Za-z0-9._\-]+)", re.I
)
# Kullanici-Ajani (User-Agent) icindeki platform/cihaz ipuclari.
_UA_DEVICE_WORDS = [
    "Windows NT", "Android", "iPhone", "iPad", "Macintosh", "Linux",
    "X11", "CrOS", "Windows Phone",
]
_UA_DEVICE_RE = re.compile(
    r"(" + "|".join(re.escape(w) for w in _UA_DEVICE_WORDS) + r")"
)


def _dedupe(items):
    """Sirayi koruyarak tekrarlari siler (kayit okunakliligi icin)."""
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _ip_scope(ip: str) -> str:
    """Kucuk, kendine yeten IP kapsam siniflandiricisi.

    Donen: loopback / private / documentation / public / invalid.
    RFC 5737 dokumantasyon araliklari ayrica isaretlenir (lab trafigi bu
    araliktadir ve gercek bir kurbani yoktur - durustce etiketlenir)."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return "invalid"
    doc_nets = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )
    if addr.is_loopback:
        return "loopback"
    if any(addr in net for net in doc_nets):
        return "documentation"
    if addr.is_private:
        return "private"
    return "public"


def _default_extract_fn(text: str) -> dict:
    """Varsayilan varlik cikarici: mevcut IOC cikaricisini kullanir."""
    from ..reverse.ioc_extractor import extract_iocs
    return extract_iocs(text)


def normalize_event(event: dict, extract_fn=None) -> dict:
    """Ham bir honeypot olayini yapisal, ECS-uyumlu bir kayda cevirir.

    Ham alanlar: source_ip, service, event_type, payload, timestamp,
    dest_port, source_port. Yuk (payload) icinden varliklar cikarilir:
    ip/domain/hash/url IOC cikaricisiyla; kullanici/surec/cihaz ek
    regex'lerle. `extract_fn` enjekte edilebilir (varsayilan: IOC cikarici).
    """
    event = event or {}
    extract = extract_fn or _default_extract_fn
    payload = event.get("payload") or ""
    if not isinstance(payload, str):
        payload = str(payload)

    src_ip = event.get("source_ip")

    iocs = extract(payload) or {}
    ips = list(iocs.get("ipv4", [])) + list(iocs.get("ipv6", []))
    if src_ip:
        ips = [src_ip] + ips
    hashes = (list(iocs.get("md5", [])) + list(iocs.get("sha1", []))
              + list(iocs.get("sha256", [])))
    domains = list(iocs.get("domains", []))
    urls = list(iocs.get("urls", []))

    users = _USER_RE.findall(payload)

    processes = _CMD_KV_RE.findall(payload)
    processes += _BIN_PATH_RE.findall(payload)
    processes += [m.lower() for m in _PROCESS_WORD_RE.findall(payload)]

    devices = _DEVICE_KV_RE.findall(payload)
    devices += _UA_DEVICE_RE.findall(payload)

    return {
        "ts": event.get("timestamp"),
        "src_ip": src_ip,
        "src_port": event.get("source_port"),
        "dst_service": event.get("service"),
        "dst_port": event.get("dest_port"),
        "event_type": event.get("event_type"),
        "entities": {
            "ips": _dedupe(ips),
            "domains": _dedupe(domains),
            "hashes": _dedupe(hashes),
            "urls": _dedupe(urls),
            "users": _dedupe(users),
            "processes": _dedupe(processes),
            "devices": _dedupe(devices),
        },
        "raw_payload": payload,
    }


# Olay turu / varlik -> saldiri tipi etiketi eslesmeleri (kaba, aciklayici).
_EVENT_TYPE_TAGS = {
    "login": "credential-access",
    "auth": "credential-access",
    "brute": "brute-force",
    "scan": "reconnaissance",
    "connect": "reconnaissance",
    "exploit": "exploitation",
    "upload": "payload-delivery",
    "download": "payload-delivery",
    "command": "execution",
    "exec": "execution",
}


def enrich_event(normalized: dict, known_bad: set = None) -> dict:
    """Normalize kayda tehdit baglami ekler.

    Ekler: ioc_count (toplam varlik sayisi), known_bad_hit (bilinen-kotu
    listesiyle eslesme), tags (saldiri tipi etiketleri), scope (kaynak IP
    kapsami: loopback/private/documentation/public)."""
    normalized = dict(normalized or {})
    entities = normalized.get("entities", {}) or {}
    known_bad = known_bad or set()

    ioc_count = sum(len(v) for v in entities.values() if isinstance(v, list))

    # Bilinen-kotu eslesmesi: ip / domain / hash / url uzerinden bakilir.
    checkable = []
    for key in ("ips", "domains", "hashes", "urls"):
        checkable.extend(entities.get(key, []))
    known_bad_hit = any(item in known_bad for item in checkable)

    tags = []
    event_type = (normalized.get("event_type") or "").lower()
    for keyword, tag in _EVENT_TYPE_TAGS.items():
        if keyword in event_type and tag not in tags:
            tags.append(tag)
    if entities.get("hashes"):
        tags.append("malware-hash")
    if entities.get("urls") or entities.get("domains"):
        tags.append("remote-resource")
    if entities.get("processes"):
        tags.append("shell-activity")
    if entities.get("users"):
        tags.append("account-activity")
    tags = _dedupe(tags)

    scope = _ip_scope(normalized.get("src_ip"))

    normalized["enrichment"] = {
        "ioc_count": ioc_count,
        "known_bad_hit": known_bad_hit,
        "tags": tags,
        "scope": scope,
    }
    return normalized


# Olay turu -> ECS event.category kaba eslesmesi.
_ECS_CATEGORY = {
    "login": "authentication",
    "auth": "authentication",
    "brute": "authentication",
    "scan": "network",
    "connect": "network",
    "exploit": "intrusion_detection",
    "upload": "file",
    "download": "file",
    "command": "process",
    "exec": "process",
}


def to_ecs(normalized: dict) -> dict:
    """Normalize kaydi ECS-benzeri (Elastic Common Schema) ic ice sozluge
    esler. Bu, kaydin gercek SIEM'lere tasinabilirligini saglar.

    related.* alanlari korelasyon icindir: ayni IP/kullanici/hash farkli
    olaylarda gorunuyorsa SIEM bunlari otomatik baglar."""
    normalized = normalized or {}
    entities = normalized.get("entities", {}) or {}
    event_type = (normalized.get("event_type") or "")

    category = "network"
    for keyword, cat in _ECS_CATEGORY.items():
        if keyword in event_type.lower():
            category = cat
            break

    return {
        "@timestamp": normalized.get("ts"),
        "source": {
            "ip": normalized.get("src_ip"),
            "port": normalized.get("src_port"),
        },
        "destination": {
            "port": normalized.get("dst_port"),
            "service": normalized.get("dst_service"),
        },
        "event": {
            "category": category,
            "type": event_type or None,
        },
        "related": {
            "ip": list(entities.get("ips", [])),
            "user": list(entities.get("users", [])),
            "hash": list(entities.get("hashes", [])),
        },
    }


def normalize_batch(events: list, extract_fn=None) -> list:
    """Bir olay listesini toplu normalize eder (ingestion boru hatti girisi)."""
    return [normalize_event(e, extract_fn=extract_fn) for e in (events or [])]
