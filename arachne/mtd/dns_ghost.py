"""Basit bir 'hayalet DNS' yanitlayicisi (Moving Target Defense, Faz 4).

GERCEK bir DNS sunucusu/cozumleyicisi DEGILDIR: sistem DNS ayarlarinizi
degistirmez, port 53'u kullanmaz (yetki gerektirir ve tehlikelidir), sadece
belgelenmis bir lab portunda (varsayilan UDP 5300) calisir. Amaci "DNS
tabanli moving target defense" kavramini somut, calisan bir kodla
gostermek: ayni isim sorgulandiginda zaman icinde FARKLI (rotasyonlu) bir
IP donerek, saldirganin "bu isim hep ayni IP'ye cozulur" varsayimina
dayanan bir hedefleme/takip stratejisini bozmak.

DNS paket formatinin minimal bir alt kumesini (tek soru, A kaydi) elle
ayristirir/uretir - egitim amacli, harici bir DNS kutuphanesi kullanmaz.
Sadece izole/lab ortaminda calistirin (bkz. docs/ETHICS_AND_LEGAL.md)."""
import asyncio
import logging
import struct

from .. import storage

logger = logging.getLogger("arachne.mtd.dns_ghost")

DEFAULT_IP_POOL = ["127.0.0.21", "127.0.0.22", "127.0.0.23", "127.0.0.24", "127.0.0.25"]
COMPONENT_NAME = "dns:ghost"
DEFAULT_TTL = 5


def parse_qname(data: bytes, offset: int = 12):
    """DNS soru bolumundeki QNAME'i (etiket dizisi) coz ve okumanin bittigi
    offset'i dondurur. Sadece sikistirilmamis (uncompressed) sorgu
    isimlerini destekler - istemci taraflari sorgularinda bu yeterlidir."""
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    return ".".join(labels), offset


def build_response(query: bytes, answer_ip: str) -> bytes:
    """Gelen sorgu paketine karsilik, tek bir A kaydi iceren minimal bir DNS
    yanit paketi uretir (RFC 1035'in kucuk bir alt kumesi)."""
    txn_id = query[0:2]
    flags = struct.pack("!H", 0x8180)  # standart yanit, hata yok, RD/RA set
    qdcount = struct.pack("!H", 1)
    ancount = struct.pack("!H", 1)
    ns_ar_count = struct.pack("!HH", 0, 0)
    header = txn_id + flags + qdcount + ancount + ns_ar_count

    qname_end = 12
    while query[qname_end] != 0:
        qname_end += query[qname_end] + 1
    qname_end += 1
    question = query[12:qname_end + 4]  # QNAME + QTYPE(2) + QCLASS(2)

    answer_name = b"\xc0\x0c"  # soru bolumune isaretci (DNS naim sikistirma)
    answer_type_class = struct.pack("!HH", 1, 1)  # TYPE=A, CLASS=IN
    answer_ttl = struct.pack("!I", DEFAULT_TTL)
    answer_rdlength = struct.pack("!H", 4)
    answer_rdata = bytes(int(octet) for octet in answer_ip.split("."))
    answer = answer_name + answer_type_class + answer_ttl + answer_rdlength + answer_rdata

    return header + question + answer


class GhostDNSResponder:
    """Sorgulanan her isim icin rotasyonlu bir IP dondurur.

    rotate_every_n_queries=1 (varsayilan) ile her sorguda bir sonraki IP'ye
    gecilir - ayni isim ust uste sorgulansa bile farkli yanitlar alinir.
    Rotasyonlar storage.mtd_rotations tablosuna kaydedilir."""

    def __init__(self, ip_pool=None, rotate_every_n_queries=1, db_path=None):
        self.ip_pool = list(ip_pool or DEFAULT_IP_POOL)
        self.rotate_every_n_queries = max(1, rotate_every_n_queries)
        self.db_path = db_path
        self._index = 0
        self._query_count = 0

    def resolve(self, qname: str) -> str:
        current_ip = self.ip_pool[self._index % len(self.ip_pool)]
        self._query_count += 1
        if self._query_count % self.rotate_every_n_queries == 0:
            new_index = self._index + 1
            new_ip = self.ip_pool[new_index % len(self.ip_pool)]
            storage.log_mtd_rotation(
                component=COMPONENT_NAME,
                old_identity=f"{qname} -> {current_ip}",
                new_identity=f"{qname} -> {new_ip}",
                reason=f"{self.rotate_every_n_queries} sorguda bir rotasyon",
                db_path=self.db_path,
            )
            self._index = new_index
        return current_ip


class GhostDNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, responder: GhostDNSResponder):
        self.responder = responder
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            qname, _ = parse_qname(data, 12)
            ip = self.responder.resolve(qname)
            response = build_response(data, ip)
            self.transport.sendto(response, addr)
            logger.info("dns-ghost: %s '%s' sordu, %s dondu", addr[0], qname, ip)
        except (IndexError, struct.error) as exc:
            logger.debug("dns-ghost: gecersiz sorgu goz ardi edildi (%s)", exc)


async def run_forever(host="127.0.0.1", port=5300, ip_pool=None,
                       rotate_every_n_queries=1, db_path=None):
    responder = GhostDNSResponder(ip_pool=ip_pool,
                                   rotate_every_n_queries=rotate_every_n_queries,
                                   db_path=db_path)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: GhostDNSProtocol(responder), local_addr=(host, port)
    )
    logger.info(
        "dns-ghost dinlemede: udp %s:%s (SADECE lab amacli - sistem DNS "
        "ayarlarinizi degistirmez, port 53 kullanmaz)", host, port,
    )
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        transport.close()
