"""Yem (honeytoken) uc noktalari — "YAKALANDIN" tuzagi (bkz. reporting/decoy.py).

Yem uclari KIMLIK DOGRULAMASIZ erisilebilir (tuzak davetkar olmali); acildiginda
kritik alarm + cekirdek-yemi (Son Hat) tetiklenir ve saldirganin ekranina tuzak
yaniti doner. Gercek /api/ uclari bu mantiktan etkilenmez, auth istemeye devam eder.
"""
import pytest

from arachne import config, storage
from arachne.reporting import dashboard, panel_auth


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(panel_auth.AUTH_ENV, "1")  # auth ACIK (yem yine de erisilebilir olmali)
    monkeypatch.setenv(panel_auth.TOKEN_ENV, "t-123")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "decoy.db")
    storage.init_db()
    panel_auth._reset_state()
    yield dashboard.app.test_client()
    panel_auth._reset_state()


def test_decoy_reachable_without_auth_with_believable_fake_loot(client):
    r = client.get("/flag.txt")
    assert r.status_code == 200  # auth ACIK ama yem auth'suz erisilebilir
    body = r.get_data(as_text=True)
    assert "FLAG{" in body            # inandirici sahte ganimet
    assert "YAKALANDIN" not in body   # SESSIZ yakalama: saldirgana bagirmaz


def test_env_decoy_serves_fake_credentials(client):
    body = client.get("/.env").get_data(as_text=True)
    assert "AWS_ACCESS_KEY_ID" in body and "SECRET_KEY" in body


def test_decoy_fires_critical_alert_and_core_bait(client):
    client.get("/api/backup")
    alerts = storage.get_all_alerts()
    assert any(a["severity"] == "critical" and "Yem" in (a["reasons"] or "")
               for a in alerts), "yem kritik alarm uretmeliydi"
    assert storage.core_vault_recently_touched(), "cekirdek-yemi tetiklenmeliydi (Son Hat)"


def test_non_decoy_api_still_requires_auth(client):
    assert client.get("/api/state").status_code == 401
