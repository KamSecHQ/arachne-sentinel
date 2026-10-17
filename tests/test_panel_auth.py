"""Faz 117 — Komuta merkezi kimlik dogrulamasi.

conftest.py mevcut panel testleri icin ARACHNE_PANEL_AUTH=0 koyar; burada
kimlik dogrulama acikca ACILIR ve davranisi uctan uca dogrulanir.
"""
import os
import stat
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from arachne import config, storage
from arachne.reporting import dashboard, panel_auth

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "test-panel-anahtari-123"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(panel_auth.AUTH_ENV, "1")
    monkeypatch.setenv(panel_auth.TOKEN_ENV, TOKEN)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "auth.db")
    storage.init_db()
    panel_auth._reset_state()
    yield dashboard.app.test_client()
    panel_auth._reset_state()


def _code(url):
    return parse_qs(urlparse(url).query)["code"][0]


# --- kapali kapilar --------------------------------------------------------
def test_api_requires_login(client):
    r = client.get("/api/live")
    assert r.status_code == 401
    assert r.get_json()["error"] == "kimlik dogrulama gerekli"


def test_control_endpoints_require_login(client):
    for path in ("/api/fortress/engage", "/api/fortress/standby", "/api/analyze",
                 "/api/assistant"):
        assert client.post(path).status_code == 401, path


def test_page_redirects_to_login(client):
    r = client.get("/")
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/login")


def test_static_and_login_page_are_open(client):
    assert client.get("/login").status_code == 200
    assert client.get("/static/css/app.css").status_code == 200


def test_mesh_ingest_keeps_its_own_hmac_gate(client):
    """Sensorler oturum acamaz; /mesh/ingest kendi HMAC imzasiyla korunur."""
    r = client.post("/mesh/ingest", json={"bogus": True})
    # istek panel kapisina degil, toplayicinin KENDI imza kontrolune ulasti
    assert r.get_json()["error"] == "Dogrulama basarisiz"


# --- giris yollari ---------------------------------------------------------
def test_wrong_token_rejected_right_token_opens_session(client):
    assert client.post("/login", data={"token": "yanlis"}).status_code == 401
    r = client.post("/login", data={"token": TOKEN})
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    assert client.get("/api/live").status_code == 200


def test_one_time_code_works_once(client):
    code = _code(panel_auth.login_url("127.0.0.1", 5001))
    assert client.get(f"/login?code={code}").status_code == 302
    assert client.get("/api/live").status_code == 200

    other = dashboard.app.test_client()
    assert other.get(f"/login?code={code}").status_code == 401     # tekrar kullanilamaz


def test_expired_code_rejected(client, monkeypatch):
    monkeypatch.setattr(panel_auth, "CODE_TTL_SECONDS", 0)
    code = _code(panel_auth.login_url("127.0.0.1", 5001))
    assert client.get(f"/login?code={code}").status_code == 401


def test_native_code_redirects_to_native_mode(client):
    url = panel_auth.login_url("127.0.0.1", 5001, native=True)
    r = client.get(urlparse(url).path + "?" + urlparse(url).query)
    assert r.headers["Location"].endswith("/?mode=native")


def test_wildcard_listen_address_not_used_in_link():
    assert panel_auth.login_url("0.0.0.0", 5001).startswith("http://127.0.0.1:5001/login?code=")


def test_brute_force_lockout_blocks_even_correct_token(client):
    for _ in range(panel_auth.MAX_FAILURES):
        assert client.post("/login", data={"token": "yanlis"}).status_code == 401
    assert client.post("/login", data={"token": TOKEN}).status_code == 429


def test_logout_ends_session(client):
    client.post("/login", data={"token": TOKEN})
    assert client.get("/api/live").status_code == 200
    client.post("/logout")
    assert client.get("/api/live").status_code == 401


# --- cerez + basliklar -----------------------------------------------------
def test_session_cookie_is_httponly_and_samesite_strict(client):
    r = client.post("/login", data={"token": TOKEN})
    cookie = r.headers["Set-Cookie"]
    assert "arachne_panel=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


def test_security_headers_on_every_response(client):
    r = client.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"


# --- anahtar kaynagi ---------------------------------------------------------
def test_token_file_created_private_and_stable(tmp_path, monkeypatch):
    monkeypatch.delenv(panel_auth.TOKEN_ENV, raising=False)
    path = tmp_path / "panel_token"
    monkeypatch.setattr(panel_auth, "TOKEN_FILE", path)
    first = panel_auth.panel_token()
    assert len(first) >= 40
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert panel_auth.panel_token() == first


def test_env_token_wins_over_file(tmp_path, monkeypatch):
    monkeypatch.setattr(panel_auth, "TOKEN_FILE", tmp_path / "panel_token")
    monkeypatch.setenv(panel_auth.TOKEN_ENV, "ortamdan")
    assert panel_auth.panel_token() == "ortamdan"
    assert not (tmp_path / "panel_token").exists()


def test_token_file_is_gitignored():
    assert "data/panel_token" in (ROOT / ".gitignore").read_text().splitlines()


def test_auth_can_be_disabled_only_explicitly(monkeypatch):
    monkeypatch.delenv(panel_auth.AUTH_ENV, raising=False)
    assert panel_auth.enabled() is True              # varsayilan ACIK
    monkeypatch.setenv(panel_auth.AUTH_ENV, "0")
    assert panel_auth.enabled() is False
