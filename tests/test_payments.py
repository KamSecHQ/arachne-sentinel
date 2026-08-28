"""Faz 113 - Iyzico odeme entegrasyonu testleri.

Gercek Iyzico API'sine HICBIR cagri yapilmaz - `iyzipay.CheckoutFormInitialize`/
`iyzipay.CheckoutForm` monkeypatch edilir. Gercek para/kart bilgisi bu
testlerin hicbirinde yer almaz."""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from website import payments


def setup_function(_):
    # Her testten once modul-ici durumu bilinen bir hale getir (env
    # degiskenleri monkeypatch ile testler arasi izole edilir zaten).
    pass


# --- Guvenli varsayilanlar ---------------------------------------------------

def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv(payments.ENV_ENABLED, raising=False)
    assert payments.is_enabled() is False


def test_requires_both_keys(monkeypatch):
    monkeypatch.setenv(payments.ENV_ENABLED, "1")
    monkeypatch.delenv(payments.ENV_API_KEY, raising=False)
    monkeypatch.delenv(payments.ENV_SECRET_KEY, raising=False)
    assert payments.is_enabled() is False

    monkeypatch.setenv(payments.ENV_API_KEY, "test-key")
    assert payments.is_enabled() is False  # secret key hala yok

    monkeypatch.setenv(payments.ENV_SECRET_KEY, "test-secret")
    assert payments.is_enabled() is True


def test_sandbox_is_default_true(monkeypatch):
    monkeypatch.delenv(payments.ENV_SANDBOX, raising=False)
    assert payments.is_sandbox() is True


def test_sandbox_requires_explicit_opt_out(monkeypatch):
    monkeypatch.setenv(payments.ENV_SANDBOX, "0")
    assert payments.is_sandbox() is False
    monkeypatch.setenv(payments.ENV_SANDBOX, "1")
    assert payments.is_sandbox() is True


def test_status_never_leaks_keys(monkeypatch):
    monkeypatch.setenv(payments.ENV_API_KEY, "gizli-anahtar-123")
    status = payments.status()
    assert status["api_key_present"] is True
    assert "gizli-anahtar-123" not in str(status)


def test_create_checkout_form_returns_none_when_disabled(monkeypatch):
    monkeypatch.delenv(payments.ENV_ENABLED, raising=False)
    result = payments.create_checkout_form("profesyonel", {}, {}, "http://x", "conv-1")
    assert result is None


def test_create_checkout_form_returns_none_for_unknown_plan(monkeypatch):
    monkeypatch.setenv(payments.ENV_ENABLED, "1")
    monkeypatch.setenv(payments.ENV_API_KEY, "k")
    monkeypatch.setenv(payments.ENV_SECRET_KEY, "s")
    result = payments.create_checkout_form("olmayan-paket", {}, {}, "http://x", "conv-1")
    assert result is None


# --- Basarili akis (sahte Iyzico yaniti) ------------------------------------

def _enable_iyzico(monkeypatch, sandbox=True):
    monkeypatch.setenv(payments.ENV_ENABLED, "1")
    monkeypatch.setenv(payments.ENV_API_KEY, "sandbox-test-key")
    monkeypatch.setenv(payments.ENV_SECRET_KEY, "sandbox-test-secret")
    monkeypatch.setenv(payments.ENV_SANDBOX, "1" if sandbox else "0")


def test_create_checkout_form_success(monkeypatch):
    _enable_iyzico(monkeypatch)

    fake_response = MagicMock()
    fake_response.read.return_value = None
    import io
    import json as _json

    payload = _json.dumps({
        "status": "success",
        "checkoutFormContent": "<script>iyzico-widget</script>",
        "token": "tok_123",
        "conversationId": "conv-1",
    }).encode()

    mock_checkout_instance = MagicMock()
    mock_checkout_instance.create.return_value = io.BytesIO(payload)

    with patch("iyzipay.CheckoutFormInitialize", return_value=mock_checkout_instance):
        result = payments.create_checkout_form(
            "profesyonel",
            buyer={"name": "Test"}, address={"city": "Istanbul"},
            callback_url="http://localhost/checkout/callback",
            conversation_id="conv-1",
        )

    assert result is not None
    assert result["checkoutFormContent"] == "<script>iyzico-widget</script>"
    # Fiyat/plan bilgisi Iyzico'ya dogru gonderildi mi?
    sent_request = mock_checkout_instance.create.call_args[0][0]
    assert sent_request["price"] == "49.00"
    assert sent_request["currency"] == "TRY"
    assert sent_request["callbackUrl"] == "http://localhost/checkout/callback"


def test_create_checkout_form_failure_response(monkeypatch):
    _enable_iyzico(monkeypatch)
    import io
    import json as _json

    payload = _json.dumps({"status": "failure", "errorMessage": "gecersiz kart"}).encode()
    mock_checkout_instance = MagicMock()
    mock_checkout_instance.create.return_value = io.BytesIO(payload)

    with patch("iyzipay.CheckoutFormInitialize", return_value=mock_checkout_instance):
        result = payments.create_checkout_form(
            "topluluk", {}, {}, "http://x", "conv-2")
    assert result is None


def test_create_checkout_form_network_error_returns_none(monkeypatch):
    _enable_iyzico(monkeypatch)
    mock_checkout_instance = MagicMock()
    mock_checkout_instance.create.side_effect = OSError("ag hatasi simulasyonu")

    with patch("iyzipay.CheckoutFormInitialize", return_value=mock_checkout_instance):
        result = payments.create_checkout_form(
            "topluluk", {}, {}, "http://x", "conv-3")
    assert result is None


def test_verify_payment_result_success(monkeypatch):
    _enable_iyzico(monkeypatch)
    import io
    import json as _json

    payload = _json.dumps({
        "status": "success", "paymentStatus": "SUCCESS", "paymentId": "pay_999",
    }).encode()
    mock_retrieve_instance = MagicMock()
    mock_retrieve_instance.retrieve.return_value = io.BytesIO(payload)

    with patch("iyzipay.CheckoutForm", return_value=mock_retrieve_instance):
        result = payments.verify_payment_result("tok_123", "conv-1")

    assert result is not None
    assert result["paymentStatus"] == "SUCCESS"


def test_verify_payment_result_does_not_trust_missing_token(monkeypatch):
    _enable_iyzico(monkeypatch)
    result = payments.verify_payment_result("", "conv-1")
    assert result is None


def test_verify_payment_result_disabled_returns_none(monkeypatch):
    monkeypatch.delenv(payments.ENV_ENABLED, raising=False)
    result = payments.verify_payment_result("tok_123", "conv-1")
    assert result is None


# --- Flask checkout route entegrasyonu --------------------------------------

def _tmp_db():
    from arachne import storage
    db = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=db)
    return db


def test_checkout_page_shows_unavailable_when_not_configured(monkeypatch):
    import website.app as website_app
    monkeypatch.delenv(payments.ENV_ENABLED, raising=False)

    app = website_app.create_app(protected=True, db_path=_tmp_db())
    client = app.test_client()
    response = client.get("/checkout/profesyonel")
    assert response.status_code == 200
    assert "aktif değil" in response.get_data(as_text=True)


def test_checkout_page_unknown_plan_404(monkeypatch):
    import website.app as website_app
    app = website_app.create_app(protected=True, db_path=_tmp_db())
    client = app.test_client()
    response = client.get("/checkout/olmayan-paket")
    assert response.status_code == 404


def test_checkout_post_renders_iyzico_widget(monkeypatch):
    import io
    import json as _json
    import website.app as website_app

    _enable_iyzico(monkeypatch)
    payload = _json.dumps({
        "status": "success",
        "checkoutFormContent": "<div id='iyzico-marker'>widget</div>",
        "token": "tok_abc",
    }).encode()
    mock_checkout_instance = MagicMock()
    mock_checkout_instance.create.return_value = io.BytesIO(payload)

    app = website_app.create_app(protected=True, db_path=_tmp_db())
    client = app.test_client()

    with patch("iyzipay.CheckoutFormInitialize", return_value=mock_checkout_instance):
        response = client.post("/checkout/profesyonel", data={
            "name": "Emirhan", "surname": "Baydere",
            "email": "test@example.com", "phone": "+905551112233",
            "address": "Test Mah. Test Sk.", "city": "Istanbul",
            "zip_code": "34000", "country": "Turkey",
        })

    assert response.status_code == 200
    assert "iyzico-marker" in response.get_data(as_text=True)
