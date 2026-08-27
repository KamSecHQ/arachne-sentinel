"""Faz 103 - Genisletilmis honeypot yuzeyi (Redis/Docker API/Elasticsearch/
Telnet/RDP/SMB) testleri.

Saf yanit-uretim fonksiyonlari dogrudan test edilir; ayrica gercek asyncio
sunuculariyle uctan uca birkac entegrasyon testi (bkz. tests/test_mtd.py'nin
"asyncio.run(scenario())" kalibi) veritabani `config.DB_PATH`'i gecici bir
dosyaya monkeypatch ederek yapilir.
"""
import asyncio
import socket

from arachne import config, storage
from arachne.honeypot import listeners


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- Yeni servisler config'e dogru eklendi mi --------------------------------

def test_new_services_registered_on_nonprivileged_ports():
    for name in ("telnet", "redis", "docker-api", "elasticsearch", "rdp", "smb"):
        assert name in config.FAKE_SERVICES
        assert config.FAKE_SERVICES[name]["port"] > 1024

    # Cakisma olmamali
    ports = [cfg["port"] for cfg in config.FAKE_SERVICES.values()]
    assert len(ports) == len(set(ports))


# --- Redis yanit uretimi (saf fonksiyon, ag/DB yok) -------------------------

def test_redis_ping_returns_pong():
    assert listeners._redis_response("PING\r\n") == b"+PONG\r\n"


def test_redis_info_contains_version():
    response = listeners._redis_response("INFO\r\n")
    assert b"redis_version" in response


def test_redis_unknown_command_returns_error():
    response = listeners._redis_response("FLUSHALL\r\n")
    assert response.startswith(b"-ERR")


def test_redis_empty_payload_returns_none():
    assert listeners._redis_response("") is None


# --- Docker API yanit uretimi ------------------------------------------------

def test_docker_api_version_endpoint():
    response = listeners._docker_api_response("GET /version HTTP/1.1\r\nHost: x\r\n\r\n")
    assert b"200 OK" in response
    assert b"ApiVersion" in response


def test_docker_api_containers_endpoint_returns_empty_list():
    response = listeners._docker_api_response("GET /containers/json HTTP/1.1\r\n\r\n")
    assert b"[]" in response


def test_docker_api_unknown_path_returns_404():
    response = listeners._docker_api_response("GET /exec HTTP/1.1\r\n\r\n")
    assert b"404 Not Found" in response


# --- Elasticsearch yanit uretimi ---------------------------------------------

def test_elasticsearch_root_returns_cluster_info():
    response = listeners._elasticsearch_response("GET / HTTP/1.1\r\n\r\n")
    assert b"cluster_name" in response
    assert b"200 OK" in response


def test_elasticsearch_unknown_path_returns_404():
    response = listeners._elasticsearch_response("POST /_search HTTP/1.1\r\n\r\n{}")
    assert b"404 Not Found" in response
    assert b"index_not_found_exception" in response


# --- Uctan uca entegrasyon: gercek sunucu + gercek TCP baglantisi -----------

def _isolated_db(tmp_path, monkeypatch):
    db = tmp_path / "honeypot_ext.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    storage.init_db()
    return db


def test_redis_server_end_to_end(tmp_path, monkeypatch):
    db = _isolated_db(tmp_path, monkeypatch)
    port = _free_port()

    async def scenario():
        handler = listeners._make_bespoke_handler("redis", port, listeners._redis_response)
        server = await asyncio.start_server(handler, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"PING\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=5)
        writer.close()
        server.close()
        await server.wait_closed()
        return response

    response = asyncio.run(scenario())
    assert response == b"+PONG\r\n"

    events = storage.get_recent_events(db_path=db)
    services = {e["service"] for e in events}
    assert "redis" in services
    event_types = {e["event_type"] for e in events if e["service"] == "redis"}
    assert {"connect", "data", "disconnect"} <= event_types


def test_docker_api_server_end_to_end(tmp_path, monkeypatch):
    db = _isolated_db(tmp_path, monkeypatch)
    port = _free_port()

    async def scenario():
        handler = listeners._make_bespoke_handler("docker-api", port,
                                                   listeners._docker_api_response)
        server = await asyncio.start_server(handler, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /version HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=5)
        writer.close()
        server.close()
        await server.wait_closed()
        return response

    response = asyncio.run(scenario())
    assert b"ApiVersion" in response

    events = storage.get_recent_events(db_path=db)
    assert any(e["service"] == "docker-api" and e["event_type"] == "data" for e in events)


def test_generic_handler_covers_telnet_rdp_smb(tmp_path, monkeypatch):
    """RDP/SMB/Telnet generic handler ile calisir - dogruluk notu: tam
    protokol muzakeresi yapilmaz, sadece baglanti+ham bayt loglanir."""
    db = _isolated_db(tmp_path, monkeypatch)
    port = _free_port()

    async def scenario():
        handler = listeners._make_generic_handler("rdp", port)
        server = await asyncio.start_server(handler, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00")  # sahte TPKT/X.224
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        server.close()
        await server.wait_closed()

    asyncio.run(scenario())

    events = storage.get_recent_events(db_path=db)
    rdp_events = [e for e in events if e["service"] == "rdp"]
    assert any(e["event_type"] == "connect" for e in rdp_events)
    assert any(e["event_type"] == "data" for e in rdp_events)
