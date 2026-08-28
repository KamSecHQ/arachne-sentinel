"""Faz 110 - Musteri webhook bildirimi testleri.

Gercek ag cagrisi YAPILMAZ - `_send` monkeypatch edilir ya da gercek ama
YEREL bir soket kullanilir (test_notifications_delivers_to_local_http gibi
adlandirilmis testler haric, burada sadece monkeypatch kullanildi)."""
from arachne.customer import profile as customer_profile
from arachne.soar import notifications


def setup_function(_):
    notifications.clear_rate_limit()


def test_no_network_call_when_webhook_not_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH",
                        tmp_path / "no_profile.json")

    def _boom(url, payload):
        raise AssertionError("webhook yapilandirilmamisken ag cagrisi yapilmamali")

    monkeypatch.setattr(notifications, "_send", _boom)
    result = notifications.notify_critical_event("alert", "203.0.113.5", "critical")
    assert result is False


def test_sends_when_webhook_configured(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_webhook_url": "https://hooks.example.com/acme",
    })

    sent = {}

    def _fake_send(url, payload):
        sent["url"] = url
        sent["payload"] = payload

    monkeypatch.setattr(notifications, "_send", _fake_send)
    result = notifications.notify_critical_event(
        "alert", "203.0.113.9", "critical", score=95, detail="test detay")
    assert result is True
    assert sent["url"] == "https://hooks.example.com/acme"
    assert sent["payload"]["source_ip"] == "203.0.113.9"
    assert sent["payload"]["severity"] == "critical"
    assert sent["payload"]["asset_name"] == "X"


def test_payload_never_includes_webhook_url_or_email(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_email": "gizli@acme.com",
        "alert_webhook_url": "https://hooks.example.com/gizli-token",
    })

    sent = {}
    monkeypatch.setattr(notifications, "_send",
                        lambda url, payload: sent.update(payload=payload))
    notifications.notify_critical_event("alert", "203.0.113.9", "high")
    assert "gizli@acme.com" not in str(sent["payload"])
    assert "gizli-token" not in str(sent["payload"])


def test_send_failure_returns_false_never_raises(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_webhook_url": "https://hooks.example.com/acme",
    })

    def _boom(url, payload):
        raise OSError("ag hatasi simulasyonu")

    monkeypatch.setattr(notifications, "_send", _boom)
    result = notifications.notify_critical_event("alert", "203.0.113.9", "critical")
    assert result is False


def test_rate_limiter_blocks_after_limit(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_webhook_url": "https://hooks.example.com/acme",
    })

    calls = {"n": 0}
    monkeypatch.setattr(notifications, "_send",
                        lambda url, payload: calls.__setitem__("n", calls["n"] + 1))

    for _ in range(notifications.MAX_NOTIFICATIONS_PER_HOUR):
        notifications.notify_critical_event("alert", "203.0.113.9", "high")
    assert calls["n"] == notifications.MAX_NOTIFICATIONS_PER_HOUR

    result = notifications.notify_critical_event("alert", "203.0.113.9", "high")
    assert result is False
    assert calls["n"] == notifications.MAX_NOTIFICATIONS_PER_HOUR


# --- SOAR entegrasyonu -------------------------------------------------

def test_soar_respond_to_alert_notifies_on_high_severity(tmp_path, monkeypatch):
    from arachne import storage
    from arachne.soar import engine

    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_webhook_url": "https://hooks.example.com/acme",
    })

    sent = []
    monkeypatch.setattr(notifications, "_send",
                        lambda url, payload: sent.append(payload))

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    engine.respond_to_alert("203.0.113.9", score=90, severity="critical",
                            attack_classes=["SQL Injection"], db_path=db)
    assert len(sent) == 1
    assert sent[0]["severity"] == "critical"


def test_soar_respond_to_alert_no_notify_on_low_severity(tmp_path, monkeypatch):
    from arachne import storage
    from arachne.soar import engine

    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_webhook_url": "https://hooks.example.com/acme",
    })

    sent = []
    monkeypatch.setattr(notifications, "_send",
                        lambda url, payload: sent.append(payload))

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    engine.respond_to_alert("203.0.113.9", score=10, severity="low", db_path=db)
    assert sent == []


def test_fortress_engage_notifies_customer(tmp_path, monkeypatch):
    from arachne.lastline.fortress import LastLineFortress
    from arachne.lastline.base import DefenseContext

    path = tmp_path / "profile.json"
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", path)
    customer_profile.save_profile({
        "company_name": "ACME", "asset_name": "X",
        "alert_webhook_url": "https://hooks.example.com/acme",
    })

    sent = []
    monkeypatch.setattr(notifications, "_send",
                        lambda url, payload: sent.append(payload))

    fortress = LastLineFortress(seed="test")
    ctx = DefenseContext(core_vault_touched=True, attacker_ip="203.0.113.9")
    fortress.engage(ctx)

    assert len(sent) == 1
    assert sent[0]["event_type"] == "son_hat_devrede"
    assert sent[0]["severity"] == "critical"
