"""arachne/mtd/* (Faz 4: Moving Target Defense) icin testler."""
import asyncio
import socket
import struct
import tempfile
from pathlib import Path

from arachne import storage
from arachne.mtd.dns_ghost import GhostDNSResponder, build_response, parse_qname
from arachne.mtd.identity_rotator import BANNER_POOL, IdentityRotator
from arachne.mtd.port_hopper import PortHopper


def _tmp_db():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=tmp)
    return tmp


# ---------- identity_rotator.py ----------

def test_banner_does_not_rotate_before_interval():
    fake_now = [1000.0]
    rotator = IdentityRotator(rotate_interval_seconds=60, clock=lambda: fake_now[0],
                               db_path=_tmp_db())
    first = rotator.current_banner("ssh")
    fake_now[0] += 10  # henuz 60sn gecmedi
    second = rotator.current_banner("ssh")
    assert first == second == BANNER_POOL["ssh"][0]


def test_banner_rotates_after_interval_and_logs():
    fake_now = [1000.0]
    db = _tmp_db()
    rotator = IdentityRotator(rotate_interval_seconds=60, clock=lambda: fake_now[0], db_path=db)
    first = rotator.current_banner("ssh")
    fake_now[0] += 61  # araligi asti
    second = rotator.current_banner("ssh")
    assert first != second
    assert second == BANNER_POOL["ssh"][1]

    rotations = storage.get_mtd_rotations(db_path=db)
    assert len(rotations) == 1
    assert rotations[0]["component"] == "banner:ssh"
    assert rotations[0]["old_identity"] == first
    assert rotations[0]["new_identity"] == second


def test_banner_rotation_cycles_through_pool():
    fake_now = [0.0]
    rotator = IdentityRotator(rotate_interval_seconds=10, clock=lambda: fake_now[0],
                               db_path=_tmp_db())
    seen = []
    for _ in range(len(BANNER_POOL["ftp"]) + 1):
        seen.append(rotator.current_banner("ftp"))
        fake_now[0] += 11
    # havuzun sonuna gelince basa donmus olmali
    assert seen[0] == seen[-1]


def test_unknown_service_returns_none():
    rotator = IdentityRotator(db_path=_tmp_db())
    assert rotator.current_banner("does-not-exist") is None


# ---------- dns_ghost.py ----------

def _build_query(name="ghost.arachne.local", txn_id=0x1234):
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def test_parse_qname_roundtrip():
    query = _build_query("ghost.arachne.local")
    name, offset = parse_qname(query, 12)
    assert name == "ghost.arachne.local"
    assert query[offset - 1] == 0  # qname'in bitis (0 uzunluklu) etiketi


def test_build_response_contains_requested_ip():
    query = _build_query("ghost.arachne.local", txn_id=0xABCD)
    response = build_response(query, "127.0.0.23")
    assert response[0:2] == struct.pack("!H", 0xABCD)  # ayni transaction id
    assert response[-4:] == bytes([127, 0, 0, 23])  # RDATA = istenen IP


def test_ghost_dns_responder_rotates_every_query_by_default():
    db = _tmp_db()
    responder = GhostDNSResponder(ip_pool=["1.1.1.1", "2.2.2.2", "3.3.3.3"], db_path=db)
    a = responder.resolve("ghost.local")
    b = responder.resolve("ghost.local")
    c = responder.resolve("ghost.local")
    assert [a, b, c] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert len(storage.get_mtd_rotations(db_path=db)) == 3


def test_ghost_dns_responder_can_rotate_less_often():
    responder = GhostDNSResponder(ip_pool=["1.1.1.1", "2.2.2.2"], rotate_every_n_queries=2,
                                   db_path=_tmp_db())
    a = responder.resolve("x")
    b = responder.resolve("x")  # burada rotasyon tetiklenir (2. sorgu)
    c = responder.resolve("x")
    assert a == "1.1.1.1"
    assert b == "1.1.1.1"
    assert c == "2.2.2.2"


# ---------- port_hopper.py ----------

def _free_ports(n=2):
    ports = []
    socks = []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
        socks.append(s)
    for s in socks:
        s.close()
    return ports


def test_port_hopper_starts_and_hops():
    db = _tmp_db()
    pool = _free_ports(2)

    async def scenario():
        hopper = PortHopper(port_pool=pool, hop_interval_seconds=9999,
                             host="127.0.0.1", db_path=db)
        await hopper.start()
        first_port = hopper.current_port
        assert first_port == pool[0]

        await hopper.hop()
        second_port = hopper.current_port
        assert second_port == pool[1]
        assert second_port != first_port

        hopper._server.close()
        await hopper._server.wait_closed()

    asyncio.run(scenario())

    # timestamp cozunurlugu saniye oldugu icin iki rotasyon ayni saniyeye
    # denk gelebilir - sirasina degil, icerigine gore dogrulariz.
    rotations = storage.get_mtd_rotations(db_path=db)
    assert len(rotations) == 2  # ilk baslatma + 1 sicrama
    assert {r["component"] for r in rotations} == {"port:ghost-admin"}
    start_rotation = next(r for r in rotations if r["old_identity"] is None)
    hop_rotation = next(r for r in rotations if r["old_identity"] is not None)
    assert start_rotation["new_identity"] == str(pool[0])
    assert hop_rotation["old_identity"] == str(pool[0])
    assert hop_rotation["new_identity"] == str(pool[1])


def test_port_hopper_serves_ghost_page_on_current_port():
    db = _tmp_db()
    pool = _free_ports(1)

    async def scenario():
        hopper = PortHopper(port_pool=pool, hop_interval_seconds=9999,
                             host="127.0.0.1", db_path=db)
        await hopper.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", hopper.current_port)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=5)
        writer.close()
        hopper._server.close()
        await hopper._server.wait_closed()
        return response

    response = asyncio.run(scenario())
    assert b"200 OK" in response
    assert b"hareketli bir hedeftir" in response

    events = storage.get_recent_events(db_path=db)
    services = {e["service"] for e in events}
    assert "ghost-admin" in services
