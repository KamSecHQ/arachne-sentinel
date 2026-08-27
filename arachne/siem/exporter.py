"""
Faz 104 - Gercek SIEM uyumlulugu: CEF (Common Event Format) + syslog disa
aktarim.

Faz 32'nin `normalizer.py`'si olaylari ECS-benzeri bir Python sozluguyle
temsil eder - bu iyi bir IC temsildir ama hicbir gercek SIEM (Wazuh/QRadar/
Splunk/ArcSight) onu doğrudan "dinlemez". Bu modul, o ECS temsilini
sektorun fiilen bekledigi TEL FORMATINA (ArcSight CEF, syslog uzerinden
tasinir) cevirir - boylece Arachne Sentinel'in ciktisi harici bir SIEM'e
gercekten aktarilabilir.

--- Guvenlik notu: CEF enjeksiyonu ---
CEF, pipe (`|`) ile ayrilan bir basliktan ve bosluklarla ayrilan
`anahtar=deger` uzantilarindan olusur. Saldirgan-kontrollu yuk (payload)
dogrudan bir CEF alanina yazilirsa, icindeki `|`, `=` ya da satir sonu
karakterleri format'i BOZABILIR ya da SAHTE alanlar enjekte edebilir
(log/CEF enjeksiyonu - klasik bir log injection sinifi). Bu yuzden HER
baslik alani `_cef_escape_header` (`\\`, `|`), HER uzantı degeri
`_cef_escape_extension` (`\\`, `=`, `\\n`, `\\r`) ile kacirilir - spec'in
kendisinin ongordugu kural budur.

--- Varsayilan: ag cagrisi YOK ---
`export_recent()` varsayilan olarak (sink=None) sadece formatlanmis
satirlari dondurur/dosyaya yazar - hicbir ag baglantisi acmaz. Gercek
zamanli iletim icin acikca bir `SyslogSender` (host'u
ARACHNE_SIEM_HOST/--syslog-host ile yapilandirilmis) verilmelidir. Bu,
projenin "opsiyonel/dis-etkiye acikca izin verilmeden hicbir sey disari
gitmez" ilkesiyle birebir ayni (bkz. ai/llm_backend.py, intel/threat_intel.py).
"""
import logging
import os
import socket
import time

from . import normalizer
from .. import storage

logger = logging.getLogger(__name__)

ENV_HOST = "ARACHNE_SIEM_HOST"
ENV_PORT = "ARACHNE_SIEM_PORT"
ENV_PROTOCOL = "ARACHNE_SIEM_PROTOCOL"

CEF_VERSION = 0
CEF_VENDOR = "ArachneSentinel"
CEF_PRODUCT = "Arachne"
CEF_PRODUCT_VERSION = "1.0"

# ECS event.category -> CEF severity (0-10). Sadece kaba bir varsayilan;
# gercek onem duzeyi zaten kendi kural motorumuzdaki skorlamadan gelir,
# burada amac SIEM'in varsayilan sunum/renklendirmesi icin makul bir deger
# vermek.
_CATEGORY_TO_CEF_SEVERITY = {
    "authentication": 6,
    "network": 3,
    "intrusion_detection": 9,
    "file": 5,
    "process": 7,
}


def _cef_escape_header(value) -> str:
    """CEF baslik alanlari icin: `\\` ve `|` kacirilir (spec'in kurali)."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension(value) -> str:
    """CEF uzanti degerleri icin: `\\`, `=` ve satir sonlari kacirilir.

    `=` kacirilmasi ozellikle onemlidir - aksi halde saldirgan payload'u
    icine `anahtar=deger` kalibi yerlestirerek SAHTE bir CEF alani enjekte
    edebilir (alici SIEM bunu ayri bir alan sanabilir)."""
    text = str(value)
    text = text.replace("\\", "\\\\").replace("=", "\\=")
    text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")
    return text


def to_cef(normalized: dict) -> str:
    """Bir `normalizer.normalize_event()` ciktisini tek satirlik CEF'e cevirir."""
    ecs = normalizer.to_ecs(normalized)
    event_type = normalized.get("event_type") or "unknown"
    category = ecs["event"]["category"]
    severity = _CATEGORY_TO_CEF_SEVERITY.get(category, 3)

    header = "|".join([
        f"CEF:{CEF_VERSION}",
        _cef_escape_header(CEF_VENDOR),
        _cef_escape_header(CEF_PRODUCT),
        _cef_escape_header(CEF_PRODUCT_VERSION),
        _cef_escape_header(event_type),
        _cef_escape_header(f"Arachne honeypot event: {event_type}"),
        str(severity),
    ])

    ext_parts = []

    def add(key, value):
        if value in (None, "", [], {}):
            return
        ext_parts.append(f"{key}={_cef_escape_extension(value)}")

    add("src", normalized.get("src_ip"))
    add("spt", normalized.get("src_port"))
    add("dpt", normalized.get("dst_port"))
    add("cat", category)
    add("act", event_type)

    entities = normalized.get("entities", {}) or {}
    if entities.get("users"):
        add("suser", ",".join(entities["users"][:5]))
    if entities.get("hashes"):
        add("fileHash", ",".join(entities["hashes"][:5]))

    raw_payload = normalized.get("raw_payload") or ""
    if raw_payload:
        add("msg", raw_payload[:1000])  # asiri uzun tek satiri sinirla

    return header + "|" + " ".join(ext_parts)


def _rfc3164_timestamp(when: float = None) -> str:
    """RFC 3164 zaman damgasi: `Mmm dd HH:MM:SS` (gun tek haneliyse bosluk
    doldurulur - `strftime` platformlar arasi bunu tutarli yapmaz, bu yuzden
    elle kuruluyor)."""
    t = time.localtime(when if when is not None else time.time())
    day = time.strftime("%d", t)
    if day.startswith("0"):
        day = " " + day[1:]
    return time.strftime("%b ", t) + day + time.strftime(" %H:%M:%S", t)


def to_syslog_line(message: str, hostname: str = "arachne-sentinel",
                   facility: int = 1, severity: int = 5,
                   tag: str = "ArachneSentinel") -> bytes:
    """CEF (ya da herhangi bir metin) mesajini RFC 3164 syslog satirina sarar.

    Bu, ArcSight/QRadar/Splunk/Wazuh gibi urunlerin CEF'i fiilen bekledigi
    tasima formatidir ("CEF-over-syslog"). PRI = facility*8 + severity."""
    pri = facility * 8 + severity
    timestamp = _rfc3164_timestamp()
    line = f"<{pri}>{timestamp} {hostname} {tag}: {message}"
    return line.encode("utf-8")


class SyslogSender:
    """Gercek zamanli syslog iletimi - stdlib `socket` disinda bagimlilik yok.

    Varsayilan olarak yapilandirilmamistir (host=None); bu durumda `send()`
    hicbir ag cagrisi yapmadan sessizce False doner. Sadece host acikca
    verildiginde (parametre ya da ARACHNE_SIEM_HOST) gercek bir paket gider -
    "acikca yapilandirilmadan disariya hicbir sey gitmez" ilkesi."""

    def __init__(self, host: str = None, port: int = None, protocol: str = None,
                timeout: float = 5.0):
        self.host = host or os.environ.get(ENV_HOST) or None
        self.port = port or int(os.environ.get(ENV_PORT, "514"))
        self.protocol = (protocol or os.environ.get(ENV_PROTOCOL, "udp")).lower()
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.host)

    def send(self, line: bytes) -> bool:
        if not self.is_configured():
            return False
        try:
            if self.protocol == "tcp":
                with socket.create_connection((self.host, self.port),
                                              timeout=self.timeout) as sock:
                    sock.sendall(line + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(line, (self.host, self.port))
            return True
        except OSError as exc:
            logger.warning("Syslog gonderimi basarisiz (%s:%s, %s): %s",
                           self.host, self.port, self.protocol, exc)
            return False


def export_recent(db_path=None, since_seconds: int = 3600, sink: SyslogSender = None) -> dict:
    """Son `since_seconds` icindeki olaylari CEF/syslog satirlarina cevirir.

    `sink` verilmezse (varsayilan) hicbir ag cagrisi yapilmaz - sadece
    satirlar dondurulur (dosyaya yazmak icin, main.py'nin `siem-export`
    komutunun varsayilan davranisi budur). `sink` verilirse her satir ayrica
    gonderilmeye calisilir; gonderim hatasi disa aktarim islemini durdurmaz
    (best-effort, `SyslogSender.send` zaten kendi hatasini yutar)."""
    events = storage.get_recent_events(since_seconds=since_seconds, db_path=db_path)
    lines = []
    sent = 0
    for event in events:
        normalized = normalizer.normalize_event(dict(event))
        cef = to_cef(normalized)
        syslog_line = to_syslog_line(cef)
        lines.append(syslog_line.decode("utf-8", errors="replace"))
        if sink is not None and sink.send(syslog_line):
            sent += 1

    return {
        "count": len(lines),
        "sent": sent,
        "sample": lines[:3],
        "lines": lines,
    }
