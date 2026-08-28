"""Faz 110 - Musteri varlik profili testleri."""
from arachne.customer import profile as customer_profile


def test_not_configured_by_default(tmp_path, monkeypatch):
    fake_path = tmp_path / "does_not_exist.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", fake_path)
    monkeypatch.delenv(customer_profile.ENV_PROFILE_PATH, raising=False)
    assert customer_profile.is_configured() is False


def test_load_profile_returns_default_when_unconfigured(tmp_path, monkeypatch):
    fake_path = tmp_path / "does_not_exist.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", fake_path)
    monkeypatch.delenv(customer_profile.ENV_PROFILE_PATH, raising=False)
    profile = customer_profile.load_profile()
    assert profile["company_name"] == "Arachne Sentinel"
    assert profile["alert_webhook_url"] is None


def test_save_and_load_round_trip(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    monkeypatch.delenv(customer_profile.ENV_PROFILE_PATH, raising=False)

    customer_profile.save_profile({
        "company_name": "ACME A.S.",
        "asset_name": "Ana Web Sitesi",
        "alert_webhook_url": "https://hooks.example.com/acme",
    })

    assert customer_profile.is_configured() is True
    profile = customer_profile.load_profile()
    assert profile["company_name"] == "ACME A.S."
    assert profile["asset_name"] == "Ana Web Sitesi"
    assert profile["alert_webhook_url"] == "https://hooks.example.com/acme"
    # Doldurulmayan alanlar varsayilana duser
    assert profile["contact_name"] is None


def test_save_profile_rejects_real_db_uri_as_secret(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    try:
        customer_profile.save_profile({
            "company_name": "ACME",
            "asset_name": "DB",
            "alert_email": "postgres://user:pass@real-prod-db:5432/app",
        })
        assert False, "gercek sir gibi gorunen deger reddedilmeliydi"
    except ValueError as exc:
        assert "sir" in str(exc).lower() or "gizli" in str(exc).lower() or \
            "kimlik bilgisi" in str(exc).lower()
    assert not path.exists()


def test_save_profile_rejects_password_marker(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    try:
        customer_profile.save_profile({
            "company_name": "ACME", "asset_name": "X",
            "contact_name": "password=SuperGercekSifre123",
        })
        assert False
    except ValueError:
        pass


def test_status_never_leaks_contact_values(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_email": "gizli-kisi@acme.com",
        "alert_webhook_url": "https://hooks.example.com/gizli-token-abc",
    })
    status = customer_profile.status()
    assert status["alert_email_configured"] is True
    assert "gizli-kisi@acme.com" not in str(status)
    assert "gizli-token-abc" not in str(status)


def test_corrupted_profile_file_falls_back_safely(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    path.write_text("bu gecerli bir json degil {{{", encoding="utf-8")
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    profile = customer_profile.load_profile()
    assert profile["company_name"] == "Arachne Sentinel"


def test_env_var_overrides_default_path(tmp_path, monkeypatch):
    custom_path = tmp_path / "custom_profile.json"
    monkeypatch.setenv(customer_profile.ENV_PROFILE_PATH, str(custom_path))
    customer_profile.save_profile({"company_name": "X", "asset_name": "Y"})
    assert custom_path.exists()
