"""
Sahte servisleri (honeypot) asyncio ile ayaga kaldirir.

Her servis gercek bir sistem gibi davranan minimal bir banner gonderir,
gelen veriyi kisa bir sure dinler, storage'a kaydeder ve baglantiyi kapatir.
HICBIR GERCEK KOMUT CALISTIRILMAZ, dosya sistemine erisim verilmez - bu
tamamen pasif, "dusuk etkilesimli" (low-interaction) bir honeypot'tur.
Sadece izole/lab ortaminda calistirin (bkz. docs/ETHICS_AND_LEGAL.md).
"""
import asyncio
import logging

from .. import config
from .. import storage
from ..detection import scorer

logger = logging.getLogger("arachne.honeypot")


def _peer_info(writer):
    peer = writer.get_extra_info("peername")
    return (peer[0], peer[1]) if peer else ("unknown", None)


async def _read_payload(reader):
    try:
        data = await asyncio.wait_for(
            reader.read(config.MAX_PAYLOAD_BYTES), timeout=config.READ_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        data = b""
    return data.decode(errors="replace") if data else None


async def _close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


def _evaluate_and_log_alarm(source_ip):
    result = scorer.evaluate_ip(source_ip)
    if result["triggered_alert"]:
        logger.warning(
            "ALARM! kaynak=%s skor=%s siddet=%s sebepler=%s",
            source_ip, result["score"], result["severity"], result["reasons"],
        )
    return result


async def _handle_generic(service_name: str, dest_port: int, reader, writer, rotator=None):
    source_ip, source_port = _peer_info(writer)
    storage.log_event(source_ip, service_name, "connect", source_port=source_port,
                       dest_port=dest_port)
    logger.info("baglanti: %s -> %s (port %s)", source_ip, service_name, dest_port)

    # Faz 4 (Moving Target Defense) aktifse rotator'dan zaman icinde degisen
    # banner'i kullan; aktif degilse (varsayilan) config.py'deki sabit
    # banner'i kullan - davranis Faz 1-3 ile birebir ayni kalir.
    banner = (rotator.current_banner(service_name) if rotator else None) \
        or config.FAKE_SERVICES[service_name].get("banner")
    try:
        if banner:
            writer.write(banner.encode(errors="ignore"))
            await writer.drain()

        payload = await _read_payload(reader)
        if payload:
            storage.log_event(source_ip, service_name, "data", source_port=source_port,
                               dest_port=dest_port, payload=payload)
    finally:
        storage.log_event(source_ip, service_name, "disconnect", source_port=source_port,
                           dest_port=dest_port)
        await _close(writer)

    _evaluate_and_log_alarm(source_ip)


def _make_generic_handler(service_name: str, dest_port: int, rotator=None):
    async def handler(reader, writer):
        await _handle_generic(service_name, dest_port, reader, writer, rotator=rotator)
    return handler


async def _handle_http_admin(dest_port: int, reader, writer):
    """Sahte bir 'yonetici paneli' HTTP servisi - istekleri loglar, sahte bir
    giris formu doner. Girilen kullanici adi/sifre gercek hicbir sisteme
    gonderilmez, sadece loglanir (tuzak/deception amacli)."""
    source_ip, source_port = _peer_info(writer)
    storage.log_event(source_ip, "http-admin", "connect", source_port=source_port,
                       dest_port=dest_port)

    try:
        payload = await _read_payload(reader)
        if payload:
            storage.log_event(source_ip, "http-admin", "data", source_port=source_port,
                               dest_port=dest_port, payload=payload)

        body = (
            "<html><head><title>Admin Panel</title></head><body>"
            "<h2>Yonetici Girisi</h2>"
            "<form method='POST'><input name='user' placeholder='kullanici'>"
            "<input name='pass' type='password' placeholder='sifre'>"
            "<button type='submit'>Giris</button></form></body></html>"
        )
        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n\r\n" + body
        )
        writer.write(response.encode())
        await writer.drain()
    finally:
        storage.log_event(source_ip, "http-admin", "disconnect", source_port=source_port,
                           dest_port=dest_port)
        await _close(writer)

    _evaluate_and_log_alarm(source_ip)


async def start_all_services(rotator=None):
    """Config.FAKE_SERVICES icinde tanimli tum sahte servisleri baslatir ve
    sonsuza kadar (Ctrl+C ile durdurulana dek) calistirir.

    rotator verilirse (bkz. arachne/mtd/identity_rotator.py), servisler
    sabit banner yerine zaman icinde donen bir banner kullanir (Faz 4:
    Moving Target Defense) - varsayilan (rotator=None) davranis Faz 1-3
    ile birebir aynidir."""
    storage.init_db()
    servers = []
    for service_name, cfg in config.FAKE_SERVICES.items():
        port = cfg["port"]
        if service_name == "http-admin":
            handler = lambda r, w, p=port: _handle_http_admin(p, r, w)
        else:
            handler = _make_generic_handler(service_name, port, rotator=rotator)
        server = await asyncio.start_server(handler, "0.0.0.0", port)
        servers.append(server)
        logger.info("%s honeypot dinlemede: 0.0.0.0:%s", service_name, port)

    try:
        await asyncio.gather(*(s.serve_forever() for s in servers))
    finally:
        for s in servers:
            s.close()
