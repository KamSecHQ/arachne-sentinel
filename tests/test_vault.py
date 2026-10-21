"""Kasa (crown jewel) uc noktasi — /api/vault (bkz. reporting/vault.py).

Flag yalnizca Arachne'nin savunma kanalindan (panel auth arkasinda) sunulur;
auth'suz her dokunus kritik bir canary alarmi uretir; icerik hep AES sifreli
(duz metin uc noktadan asla cikmaz).
"""
import base64

import pytest

from arachne import config, storage
from arachne.reporting import dashboard, panel_auth, vault

TOKEN = "test-panel-anahtari-xyz"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv(panel_auth.AUTH_ENV, "1")
    monkeypatch.setenv(panel_auth.TOKEN_ENV, TOKEN)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "vault.db")
    storage.init_db()
    panel_auth._reset_state()
    yield tmp_path
    panel_auth._reset_state()


def _login(client):
    assert client.post("/login", data={"token": TOKEN}).status_code == 302


def test_unauth_vault_is_401_and_fires_canary(env, monkeypatch):
    vfile = env / "vault.enc"
    vfile.write_bytes(b"Salted__\x00\x01gizlibaytlar")
    monkeypatch.setenv(vault.VAULT_FILE_ENV, str(vfile))

    r = dashboard.app.test_client().get("/api/vault")
    assert r.status_code == 401  # Arachne'nin auth kapisi: asmadan flag yok

    alerts = storage.get_all_alerts()
    assert any(a["severity"] == "critical" and "Kasa" in (a["reasons"] or "")
               for a in alerts), "auth'suz denemede canary kritik alarmi uretmeliydi"


def test_authed_vault_returns_only_ciphertext(env, monkeypatch):
    raw = b"Salted__\x11\x22sifreli-icerik-baytlari"
    vfile = env / "vault.enc"
    vfile.write_bytes(raw)
    monkeypatch.setenv(vault.VAULT_FILE_ENV, str(vfile))

    client = dashboard.app.test_client()
    _login(client)
    r = client.get("/api/vault")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    # Uc nokta ham AES sifreli baytlari doner — duz metin/flag asla cikmaz.
    assert base64.b64decode(data["vault"]) == raw


def test_authed_vault_404_when_not_configured(env, monkeypatch):
    monkeypatch.setenv(vault.VAULT_FILE_ENV, str(env / "yok.enc"))
    client = dashboard.app.test_client()
    _login(client)
    assert client.get("/api/vault").status_code == 404
