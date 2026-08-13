"""Gercekten port degistiren bir 'hayalet admin paneli' servisi.

Diger honeypot servisleri sabit bir portta dinlerken, bu servis bir port
havuzu icinde belirli araliklarla yer degistirir: bir saldirgan onceki
taramasinda bulundugu portu tekrar denerse artik orada kimse yoktur,
servis baska bir portta dinlemektedir. Her sicrama storage.mtd_rotations
tablosuna kaydedilir, boylece canli panelde "su an hangi portta" ve
"ne zaman sicradi" gorulebilir.

Yine dusuk etkilesimlidir (low-interaction): gercek bir kabuk/komut
calistirmaz, sadece sahte bir "admin panel" HTTP yaniti doner ve gelen
veriyi diger honeypot servisleriyle ayni sekilde loglar/skorlar - bkz.
arachne/honeypot/listeners.py."""
import asyncio
import logging

from .. import storage
from ..detection import scorer

logger = logging.getLogger("arachne.mtd.port_hopper")

DEFAULT_PORT_POOL = [9101, 9102, 9103, 9104, 9105]
COMPONENT_NAME = "port:ghost-admin"


class PortHopper:
    def __init__(self, port_pool=None, hop_interval_seconds=60, host="0.0.0.0", db_path=None):
        self.port_pool = list(port_pool or DEFAULT_PORT_POOL)
        self.hop_interval_seconds = hop_interval_seconds
        self.host = host
        self.db_path = db_path
        self._index = 0
        self._server = None
        self._current_port = None

    @property
    def current_port(self):
        return self._current_port

    async def _handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        source_ip, source_port = (peer[0], peer[1]) if peer else ("unknown", None)
        dest_port = self._current_port
        storage.log_event(source_ip, "ghost-admin", "connect", source_port=source_port,
                           dest_port=dest_port, db_path=self.db_path)
        try:
            try:
                data = await asyncio.wait_for(reader.read(2048), timeout=5)
            except asyncio.TimeoutError:
                data = b""
            payload = data.decode(errors="replace") if data else None
            if payload:
                storage.log_event(source_ip, "ghost-admin", "data", source_port=source_port,
                                   dest_port=dest_port, payload=payload, db_path=self.db_path)

            body = (
                "<html><head><title>Ghost Admin</title></head><body>"
                "<h2>Bu panel hareketli bir hedeftir</h2>"
                "<p>Bu portun kalici olmasi beklenmesin - periyodik olarak baska "
                "bir porta tasinir (bkz. Arachne Sentinel Moving Target Defense).</p>"
                "</body></html>"
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
            storage.log_event(source_ip, "ghost-admin", "disconnect", source_port=source_port,
                               dest_port=dest_port, db_path=self.db_path)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        result = scorer.evaluate_ip(source_ip, db_path=self.db_path)
        if result["triggered_alert"]:
            logger.warning("ALARM! (ghost-admin) kaynak=%s skor=%s siddet=%s",
                            source_ip, result["score"], result["severity"])

    async def _bind(self, port):
        server = await asyncio.start_server(self._handle, self.host, port)
        self._current_port = port
        return server

    async def start(self):
        """Havuzdaki ilk portta dinlemeye baslar ve ilk rotasyonu kaydeder."""
        self._server = await self._bind(self.port_pool[self._index])
        storage.log_mtd_rotation(component=COMPONENT_NAME, old_identity=None,
                                  new_identity=str(self._current_port),
                                  reason="ilk baslatma", db_path=self.db_path)
        logger.info("ghost-admin dinlemede: %s:%s", self.host, self._current_port)

    async def hop(self):
        """Bir sonraki porta sicrar (havuz sonuna gelince basa doner)."""
        old_port = self._current_port
        self._server.close()
        await self._server.wait_closed()
        self._index = (self._index + 1) % len(self.port_pool)
        self._server = await self._bind(self.port_pool[self._index])
        storage.log_mtd_rotation(
            component=COMPONENT_NAME, old_identity=str(old_port),
            new_identity=str(self._current_port),
            reason=f"{self.hop_interval_seconds}sn sicrama araligi doldu",
            db_path=self.db_path,
        )
        logger.info("ghost-admin sicradi: %s -> %s", old_port, self._current_port)

    async def run_forever(self):
        await self.start()
        try:
            while True:
                await asyncio.sleep(self.hop_interval_seconds)
                await self.hop()
        finally:
            if self._server:
                self._server.close()
