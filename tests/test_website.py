"""Faz 112 - Arachne Sentinel'in kendi tanitim sitesi testleri.

Dogfooding iddiasini (site kendi WAF'iyla korunuyor) GERCEKTEN dogrular -
sahte/varsayilan bir sonuc degil, ayni middleware zincirinden gecen
gercek bir Flask test_client istegi.

NOT: `website.app.app` modul-seviyesinde TEK bir Flask ornegidir
(arachne/waf/demo_app.py ile ayni kalip). `create_app()` her cagrildiginda
`app.wsgi_app`'i SARAR - testler arasinda sifirlanmazsa katman katman
ustuste biner. Bu yuzden her testten once orijinal (sarilmamis) wsgi_app'e
donuyoruz."""
import tempfile
from pathlib import Path

from arachne import storage
import website.app as website_app
from website.app import create_app, DEFAULT_CONTACT_EMAIL, GITHUB_URL

_ORIGINAL_WSGI_APP = website_app.app.wsgi_app


def setup_function(_):
    website_app.app.wsgi_app = _ORIGINAL_WSGI_APP


def _tmp_db():
    db = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=db)
    return db


def test_homepage_renders_with_default_contact_and_github_link(monkeypatch):
    monkeypatch.delenv("ARACHNE_WEBSITE_CONTACT_EMAIL", raising=False)
    app = create_app(protected=True, db_path=_tmp_db())
    client = app.test_client()

    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert DEFAULT_CONTACT_EMAIL in body
    assert GITHUB_URL in body
    assert "Arachne Sentinel" in body


def test_health_endpoint():
    app = create_app(protected=True, db_path=_tmp_db())
    client = app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_dogfooding_waf_actually_blocks_sql_injection():
    """Sitenin pazarlama kopyasindaki 'bu sayfa da ayni satirla korunuyor'
    iddiasinin GERCEKTEN dogru oldugunu kanitlar - ayni middleware zinciri
    uzerinden gercek bir SQLi denemesi gonderilir."""
    app = create_app(protected=True, db_path=_tmp_db())
    client = app.test_client()

    response = client.get("/", query_string={"id": "1' OR 1=1--"})
    assert response.status_code == 403
    assert "engelledi" in response.get_data(as_text=True).lower()


def test_dogfooding_waf_logs_the_block(tmp_path):
    db = tmp_path / "t.db"
    storage.init_db(db_path=db)
    app = create_app(protected=True, db_path=db)
    client = app.test_client()

    client.get("/", query_string={"id": "' OR 1=1--"})
    events = storage.get_waf_events(db_path=db)
    assert len(events) == 1
    assert events[0]["blocked"] == 1


def test_benign_request_is_not_blocked(tmp_path):
    db = tmp_path / "t.db"
    storage.init_db(db_path=db)
    app = create_app(protected=True, db_path=db)
    client = app.test_client()

    response = client.get("/")
    assert response.status_code == 200


def test_contact_email_configurable_via_env(monkeypatch):
    monkeypatch.setenv("ARACHNE_WEBSITE_CONTACT_EMAIL", "gercek@musteri-alani.com")
    app = create_app(protected=True, db_path=_tmp_db())
    client = app.test_client()

    response = client.get("/")
    body = response.get_data(as_text=True)
    assert "gercek@musteri-alani.com" in body
    assert DEFAULT_CONTACT_EMAIL not in body


def test_unprotected_mode_skips_waf(tmp_path):
    """`--unprotected` (sadece karsilastirma/test icin) WAF'i devre disi
    biraktigini dogrular - gercek dagitimda kullanilmamasi gerektigi
    docstring'de acikca yaziyor."""
    db = tmp_path / "t.db"
    storage.init_db(db_path=db)
    app = create_app(protected=False, db_path=db)
    client = app.test_client()

    response = client.get("/", query_string={"id": "1' OR 1=1--"})
    assert response.status_code == 200  # WAF devre disi - engellenmedi
