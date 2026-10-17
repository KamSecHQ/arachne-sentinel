"""Faz 116 — Son Hat yaptirimlari: SOAR engeli, aldatma karantinasi, hizli sicrama.

Son Hat GERCEK sinyalle acilinca sistemin geri kalaninda gercekten degisen
seyleri dogrular. Tatbikat hicbir yaptirim uygulamaz; korunan adresler
(loopback/ozel ag) engellenmez ve karantinaya alinmaz.
"""
import asyncio
import importlib.util
import json
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from arachne import config, storage
from arachne.honeypot import listeners
from arachne.lastline import enforcement
from arachne.lastline.base import DefenseContext
from arachne.mtd.port_hopper import PortHopper
from arachne.soar import blocklist, notifications

ROOT = Path(__file__).resolve().parent.parent
ATTACKER = "203.0.113.200"     # RFC 5737: engellenebilir dokumantasyon adresi


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "enforce.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    storage.init_db()
    blocklist._invalidate_cache()
    yield str(path)
    blocklist._invalidate_cache()


def _free_ports(n):
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports


# ---------------------------------------------------------------------------
# storage: yaptirim penceresi yasam dongusu
# ---------------------------------------------------------------------------
def test_engagement_window_lifecycle(db):
    storage.start_lastline_engagement(ATTACKER, "test", 900, db_path=db)
    assert storage.active_lastline_engagement(db_path=db)["target_ip"] == ATTACKER
    assert storage.is_lastline_quarantined(ATTACKER, db_path=db) is True
    assert storage.is_lastline_quarantined("198.51.100.1", db_path=db) is False
    assert storage.extend_lastline_engagement(900, db_path=db) is True

    assert storage.release_lastline_engagements(db_path=db) == 1
    assert storage.active_lastline_engagement(db_path=db) is None
    assert storage.is_lastline_quarantined(ATTACKER, db_path=db) is False


def test_engagement_window_expires(db):
    storage.start_lastline_engagement(ATTACKER, "test", 0, db_path=db)
    assert storage.active_lastline_engagement(db_path=db) is None


def test_new_engagement_closes_previous_window(db):
    storage.start_lastline_engagement("198.51.100.1", "eski", 900, db_path=db)
    storage.start_lastline_engagement(ATTACKER, "yeni", 900, db_path=db)
    assert storage.is_lastline_quarantined("198.51.100.1", db_path=db) is False
    assert storage.is_lastline_quarantined(ATTACKER, db_path=db) is True


def test_lastline_table_created_lazily_on_old_db(tmp_path):
    """init_db cagirmamis (Faz 116 oncesi) veritabaninda da calisir."""
    old = str(tmp_path / "old.db")
    assert storage.active_lastline_engagement(db_path=old) is None


# ---------------------------------------------------------------------------
# enforcement: hedef secimi + yaptirimlar
# ---------------------------------------------------------------------------
def test_core_bait_ip_is_blocked_and_quarantined(db):
    st = enforcement.engage_sanctions(DefenseContext(), "Cekirdek yemi", trigger_ip=ATTACKER,
                                      db_path=db)
    assert st["target_ip"] == ATTACKER
    assert st["target_source"] == "cekirdek yemi"
    assert st["blocked"] is True
    assert st["quarantined"] is True
    assert st["hop_interval_seconds"] == config.LASTLINE_HOP_INTERVAL_SECONDS
    assert storage.is_ip_blocked(ATTACKER, db_path=db)
    soar = storage.get_soar_actions(target=ATTACKER, db_path=db)
    assert any(a["action"] == "block_ip" and a["playbook"] == "son-hat" for a in soar)


def test_fusion_top_ip_used_when_no_core_bait(db):
    ctx = DefenseContext(extra={"fusion_top_ip": "198.51.100.9"})
    st = enforcement.engage_sanctions(ctx, "Yuksek fuzyon", db_path=db)
    assert st["target_ip"] == "198.51.100.9"
    assert st["target_source"] == "tehdit fuzyonu"


def test_placeholder_attacker_ip_is_never_sanctioned(db):
    """DefenseContext.attacker_ip varsayilani bir yer tutucudur, hedef olamaz."""
    st = enforcement.engage_sanctions(DefenseContext(), "18 halka", db_path=db)
    assert st["target_ip"] is None
    assert st["note"] == "kaynak IP belirlenemedi"
    assert storage.get_active_blocks(db_path=db) == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.20"])
def test_protected_ip_not_blocked_or_quarantined(db, ip):
    st = enforcement.engage_sanctions(DefenseContext(), "test", trigger_ip=ip, db_path=db)
    assert st["target_ip"] is None
    assert "korunan" in st["note"]
    assert storage.is_ip_blocked(ip, db_path=db) is False
    assert storage.is_lastline_quarantined(ip, db_path=db) is False
    # hedef olmasa da hayalet port sicramasi yine hizlanir
    assert enforcement.hop_interval(45, db_path=db) == config.LASTLINE_HOP_INTERVAL_SECONDS


def test_refresh_renews_expired_block(db):
    enforcement.engage_sanctions(DefenseContext(), "test", trigger_ip=ATTACKER, db_path=db)
    storage.remove_block(ATTACKER, db_path=db)
    st = enforcement.refresh_sanctions(db_path=db)
    assert st["blocked"] is True


def test_refresh_without_window_returns_none(db):
    assert enforcement.refresh_sanctions(db_path=db) is None


def test_release_ends_quarantine_but_soar_block_keeps_ttl(db):
    enforcement.engage_sanctions(DefenseContext(), "test", trigger_ip=ATTACKER, db_path=db)
    enforcement.release_sanctions(db_path=db)
    assert enforcement.status(db_path=db) is None
    assert storage.is_lastline_quarantined(ATTACKER, db_path=db) is False
    assert storage.is_ip_blocked(ATTACKER, db_path=db) is True


# ---------------------------------------------------------------------------
# port_hopper: Son Hat devredeyken hizli sicrama
# ---------------------------------------------------------------------------
def test_hop_interval_shortens_only_while_engaged(db):
    hopper = PortHopper(hop_interval_seconds=45, db_path=db)
    assert hopper.current_interval() == 45
    storage.start_lastline_engagement(None, "test", 900, db_path=db)
    assert hopper.current_interval() == config.LASTLINE_HOP_INTERVAL_SECONDS
    assert enforcement.hop_interval(3, db_path=db) == 3      # zaten kisaysa uzatmaz
    storage.release_lastline_engagements(db_path=db)
    assert hopper.current_interval() == 45


def test_run_forever_hops_fast_without_waiting_full_interval(db, monkeypatch):
    """Eski dongu tek bir sleep(hop_interval) yapardi; Son Hat acilinca
    9999 sn'lik uyku bitmeden sicramaya baslamali."""
    monkeypatch.setattr(config, "LASTLINE_HOP_INTERVAL_SECONDS", 0.05)
    storage.start_lastline_engagement(None, "test", 900, db_path=db)
    hopper = PortHopper(port_pool=_free_ports(2), hop_interval_seconds=9999,
                        host="127.0.0.1", db_path=db)

    async def scenario():
        task = asyncio.create_task(hopper.run_forever(tick_seconds=0.01))
        await asyncio.sleep(0.4)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())
    hops = [r for r in storage.get_mtd_rotations(component="port:ghost-admin", db_path=db)
            if "Son Hat" in (r.get("reason") or "")]
    assert len(hops) >= 2


# ---------------------------------------------------------------------------
# honeypot: karantina engelden once gelir (ret yerine tarpit + aldatma)
# ---------------------------------------------------------------------------
def _quarantine_loopback(monkeypatch):
    """Test trafigi 127.0.0.1'den gelir; korunan adres enforcement'tan gecmez,
    bu yuzden pencere dogrudan storage'a yazilir (sicak yol yine gercek)."""
    storage.start_lastline_engagement("127.0.0.1", "test", 900)
    blocklist.block("127.0.0.1", 900, reason="test", force=True)
    monkeypatch.setattr(listeners, "_quarantine_delay", lambda: 0.05)


def _events(db, service):
    return [e for e in storage.get_recent_events(db_path=db) if e["service"] == service]


def test_generic_service_quarantine_trickles_banner_instead_of_refusing(db, monkeypatch):
    _quarantine_loopback(monkeypatch)
    port = _free_ports(1)[0]
    banner = config.FAKE_SERVICES["ssh"]["banner"].encode()

    async def scenario():
        handler = listeners._make_generic_handler("ssh", port, soar_enabled=True)
        server = await asyncio.start_server(handler, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        got = await asyncio.wait_for(reader.readexactly(len(banner)), timeout=5)
        writer.write(b"root:toor\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=5)      # sunucu kapatana kadar
        writer.close()
        server.close()
        await server.wait_closed()
        return got

    assert asyncio.run(scenario()) == banner
    ssh = _events(db, "ssh")
    assert [e["event_type"] for e in ssh] == ["quarantine"]   # ne "blocked" ne "connect"
    assert ssh[0]["payload"].startswith("root:toor")


def test_http_admin_quarantine_serves_fake_success_without_decoy_marker(db, monkeypatch):
    _quarantine_loopback(monkeypatch)
    port = _free_ports(1)[0]

    async def scenario():
        async def handler(r, w):
            await listeners._handle_http_admin(port, r, w, soar_enabled=True)
        server = await asyncio.start_server(handler, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"POST /login HTTP/1.1\r\nHost: x\r\n\r\nuser=admin&pass=admin")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        server.close()
        await server.wait_closed()
        return response

    response = asyncio.run(scenario())
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b"Hos geldiniz, admin" in response
    assert b"SAHTE" not in response and b"honeytoken" not in response
    assert [e["event_type"] for e in _events(db, "http-admin")] == ["quarantine"]


def test_bespoke_service_quarantine_keeps_protocol_answer(db, monkeypatch):
    _quarantine_loopback(monkeypatch)
    port = _free_ports(1)[0]

    async def scenario():
        handler = listeners._make_bespoke_handler("redis", port, listeners._redis_response,
                                                  soar_enabled=True)
        server = await asyncio.start_server(handler, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"PING\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        server.close()
        await server.wait_closed()
        return response

    assert asyncio.run(scenario()) == b"+PONG\r\n"
    assert [e["event_type"] for e in _events(db, "redis")] == ["quarantine"]


def test_blocked_but_not_quarantined_is_still_refused(db):
    blocklist.block("127.0.0.1", 900, reason="test", force=True)
    port = _free_ports(1)[0]

    async def scenario():
        handler = listeners._make_generic_handler("ssh", port, soar_enabled=True)
        server = await asyncio.start_server(handler, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        data = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        server.close()
        await server.wait_closed()
        return data

    assert asyncio.run(scenario()) == b""
    assert [e["event_type"] for e in _events(db, "ssh")] == ["blocked"]


# ---------------------------------------------------------------------------
# /api/fortress: yaptirimlar gercek karari izler, tatbikat dokunmaz
# ---------------------------------------------------------------------------
def _scenario():
    spec = importlib.util.spec_from_file_location(
        "demo_core_breach", ROOT / "scripts" / "demo_core_breach.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def client(db, monkeypatch):
    from arachne.reporting import dashboard
    monkeypatch.setattr(dashboard, "_FORTRESS", None)
    monkeypatch.setattr(notifications, "notify_critical_event", lambda **kw: False)
    return dashboard.app.test_client()


def test_drill_applies_no_sanctions(db, client):
    d = client.post("/api/fortress/engage").get_json()
    assert d["engaged"] is True
    assert enforcement.status(db_path=db) is None
    assert storage.get_active_blocks(db_path=db) == []


def test_api_real_signal_applies_then_releases_sanctions(db, client, monkeypatch):
    _scenario().run_core_breach(db_path=db, soar_enabled=False, speed=0, verbose=False)

    on = client.get("/api/fortress").get_json()
    assert on["should_engage"] is True
    assert on["sanctions"]["target_ip"] == ATTACKER
    assert on["sanctions"]["blocked"] is True
    assert on["sanctions"]["quarantined"] is True
    assert storage.is_lastline_quarantined(ATTACKER, db_path=db)

    # sinyal bitti (yem kaydi 5 dk penceresinden cikti)
    monkeypatch.setattr(storage, "core_vault_recently_touched", lambda **kw: False)
    off = client.get("/api/fortress").get_json()
    assert off["should_engage"] is False
    assert off["sanctions"] is None
    assert storage.is_lastline_quarantined(ATTACKER, db_path=db) is False
    assert storage.is_ip_blocked(ATTACKER, db_path=db) is True     # SOAR TTL'i surer


# ---------------------------------------------------------------------------
# bunker3d.js yaptirim ozeti — Node.js ile (yoksa atlanir)
# ---------------------------------------------------------------------------
_NODE_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const sandbox = {
  window: {}, console, TextEncoder, setTimeout, clearTimeout, setInterval, clearInterval,
  document: { readyState: "complete", getElementById: () => null,
              querySelector: () => null, addEventListener() {} },
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), sandbox);
const t = sandbox.window.ArachneBunkerLogic.sanctionText;
console.log(JSON.stringify({
  none: t(null),
  full: t({ target_ip: "203.0.113.200", blocked: true, quarantined: true, hop_interval_seconds: 5 }),
  noTarget: t({ target_ip: null, blocked: false, quarantined: false, hop_interval_seconds: 5 }),
}));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js yok")
def test_bunker_sanction_text_js():
    js = ROOT / "arachne" / "reporting" / "static" / "js" / "bunker3d.js"
    out = subprocess.run(["node", "-e", _NODE_HARNESS, str(js)],
                         capture_output=True, text=True, timeout=30, check=True)
    got = json.loads(out.stdout.strip().splitlines()[-1])
    assert got == {
        "none": "",
        "full": "203.0.113.200 SOAR ile engellendi + aldatma karantinası (tarpit) + port sıçrama 5 sn",
        "noTarget": "hedef IP yok/korunan adres + port sıçrama 5 sn",
    }
