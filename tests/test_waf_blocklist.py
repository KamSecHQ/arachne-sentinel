"""Faz 118 — WAF, SOAR/Son Hat engel listesini gercek varligin onunde uygular.

Onceden SOAR engeli yalnizca honeypot'ta uygulaniyordu: honeypot'ta engellenen
bir IP, WAF'in korudugu gercek uygulamaya girmeye devam edebiliyordu.
"""
import json

import pytest

from arachne import storage
from arachne.lastline import enforcement
from arachne.lastline.base import DefenseContext
from arachne.waf import middleware
from arachne.waf.middleware import WAFMiddleware

ATTACKER = "203.0.113.200"


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "waf_block.db")
    storage.init_db(db_path=path)
    return path


def _app_calls():
    calls = []

    def app(environ, start_response):
        calls.append(environ["PATH_INFO"])
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"gercek varlik"]
    return app, calls


def _request(waf, ip, path="/", body=b""):
    status = {}

    def start_response(s, headers):
        status["code"] = s
        status["headers"] = dict(headers)

    environ = {"REMOTE_ADDR": ip, "REQUEST_METHOD": "GET", "PATH_INFO": path,
               "QUERY_STRING": "", "CONTENT_LENGTH": str(len(body))}
    from io import BytesIO
    environ["wsgi.input"] = BytesIO(body)
    out = b"".join(waf(environ, start_response))
    return status["code"], out, environ


def test_blocked_ip_refused_even_for_benign_request(db):
    storage.add_block(ATTACKER, 900, reason="test", db_path=db)
    app, calls = _app_calls()
    code, _, _ = _request(WAFMiddleware(app, db_path=db), ATTACKER, "/fiyatlar")
    assert code.startswith("403")
    assert calls == []                                   # gercek uygulamaya hic ulasmadi
    event = storage.get_waf_events(db_path=db)[0]
    reasons = event["reasons"]
    reasons = json.loads(reasons) if isinstance(reasons, str) else reasons
    assert event["blocked"] and reasons == [middleware.SOAR_BLOCK_REASON]


def test_blocked_request_body_is_never_read(db):
    storage.add_block(ATTACKER, 900, reason="test", db_path=db)
    app, _ = _app_calls()
    _, _, environ = _request(WAFMiddleware(app, db_path=db), ATTACKER, body=b"x" * 64)
    assert environ["wsgi.input"].tell() == 0


def test_other_ips_pass(db):
    storage.add_block(ATTACKER, 900, reason="test", db_path=db)
    app, calls = _app_calls()
    code, out, _ = _request(WAFMiddleware(app, db_path=db), "198.51.100.7", "/")
    assert code.startswith("200") and out == b"gercek varlik"
    assert calls == ["/"]


def test_expired_block_no_longer_enforced(db):
    storage.add_block(ATTACKER, 900, reason="test", db_path=db)
    storage.remove_block(ATTACKER, db_path=db)
    app, _ = _app_calls()
    assert _request(WAFMiddleware(app, db_path=db), ATTACKER)[0].startswith("200")


def test_enforcement_can_be_turned_off(db):
    storage.add_block(ATTACKER, 900, reason="test", db_path=db)
    app, _ = _app_calls()
    waf = WAFMiddleware(app, db_path=db, enforce_soar_blocklist=False)
    assert _request(waf, ATTACKER)[0].startswith("200")


def test_new_block_applies_after_cache_window(db, monkeypatch):
    monkeypatch.setattr(middleware, "BLOCKLIST_CACHE_SECONDS", 0)
    app, _ = _app_calls()
    waf = WAFMiddleware(app, db_path=db)
    assert _request(waf, ATTACKER)[0].startswith("200")
    storage.add_block(ATTACKER, 900, reason="test", db_path=db)
    assert _request(waf, ATTACKER)[0].startswith("403")


def test_storage_error_fails_open(db, monkeypatch):
    def boom(**kw):
        raise RuntimeError("disk")
    monkeypatch.setattr(storage, "get_active_blocks", boom)
    app, _ = _app_calls()
    assert _request(WAFMiddleware(app, db_path=db), ATTACKER)[0].startswith("200")


def test_son_hat_sanction_reaches_real_asset_website(db):
    """Uctan uca: Son Hat yaptirimi -> tanitim sitesi (WAF korumali) reddeder."""
    from website.app import create_app

    site = create_app(protected=True, db_path=db).test_client()
    assert site.get("/", environ_base={"REMOTE_ADDR": ATTACKER}).status_code == 200

    enforcement.engage_sanctions(DefenseContext(), "Cekirdek yemi", trigger_ip=ATTACKER,
                                 db_path=db)
    site = create_app(protected=True, db_path=db).test_client()   # taze onbellek
    assert site.get("/", environ_base={"REMOTE_ADDR": ATTACKER}).status_code == 403
    assert site.get("/", environ_base={"REMOTE_ADDR": "198.51.100.7"}).status_code == 200
