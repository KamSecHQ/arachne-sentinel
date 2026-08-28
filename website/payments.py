"""
Faz 113 - Iyzico odeme entegrasyonu (opsiyonel, "karantina" ilkesiyle).

--- Guvenli varsayilan ---
`ARACHNE_IYZICO_ENABLED` acikca "1" yapilmadan VE hem
`ARACHNE_IYZICO_API_KEY` hem `ARACHNE_IYZICO_SECRET_KEY` tanimlanmadan
HICBIR odeme cagrisi yapilmaz - `llm_backend.py`/`threat_intel.py` ile
ayni "acikca yapilandirilmadan disariya hicbir sey gitmez" ilkesi.
Yapilandirilmamissa checkout sayfasi sessizce "odeme henuz aktif degil,
bize yazin" mesaji gosterir - sistem cokmez, cakisma yasanmaz.

--- Sandbox varsayilani (KRITIK guvenlik) ---
`ARACHNE_IYZICO_SANDBOX` varsayilan olarak "1" kabul edilir - yani anahtar
girilse bile sistem varsayilan olarak SANDBOX'a (gercek para GECMEZ)
baglanir. Canliya gecmek icin bu degiskenin ACIKCA "0" yapilmasi gerekir -
kazara gercek odeme almaya karsi bilincli bir cift kilit (Faz 107'nin NVD
--nvd bayragi + ortam degiskeni "cift kilit" ilkesiyle ayni tasarim).

--- Neden resmi SDK, stdlib degil? ---
Iyzico'nun IYZWSv2 imza semasini (HMAC tabanli) elle yeniden uygulamak
gercek para islemlerinde risklidir - bir imza hatasi ya sessizce
reddedilir ya da (cok daha kotu) yanlis dogrulanir. Bu proje genelde
"sadece stdlib" ilkesini takip eder (bkz. requirements.txt) ama BURADA
dogruluk/guvenlik, minimum bagimlilik ilkesinin bilincli olarak onune
geciyor - resmi `iyzipay` paketi (github.com/iyzico/iyzipay-python)
kullanilir.

--- Odeme akisi (Checkout Form - kart bilgisi bize hic dokunmaz) ---
1. Musteri `/checkout/<plan>` formunu doldurur (ad/e-posta/adres - KART
   BILGISI DEGIL).
2. `create_checkout_form()` Iyzico'ya istek atar; donen `checkoutFormContent`
   (gomulecek HTML/JS) sayfada gosterilir - kart numarasini Iyzico'nun
   KENDI guvenli formu alir, bizim sunucumuza hic ulasmaz (PCI-DSS
   kapsamimizi minimize eder).
3. Odeme sonrasi Iyzico `callbackUrl`'e (POST, sadece `token`) yonlendirir.
4. `/checkout/callback` bu token'a GUVENMEZ - `verify_payment_result()` ile
   Iyzico'ya SORAR (gercek odeme durumunu dogrulamak icin). Callback
   govdesine dogrudan guvenmek klasik bir odeme entegrasyonu hatasidir.

--- DURUSTLUK NOTU ---
Bu, TEK SEFERLIK bir odeme akisidir (Checkout Form) - otomatik aylik
yenileme YAPMAZ. Gercek tekrarlayan faturalandirma icin Iyzico'nun ayri
Subscription API'si (Product/PricingPlan on-kurulumu gerektirir) daha
uygun olur; bu, dogal bir sonraki adimdir ve simdiden "otomatik yenileme"
diye sunulmaz."""
import logging
import os
import uuid

logger = logging.getLogger(__name__)

ENV_ENABLED = "ARACHNE_IYZICO_ENABLED"
ENV_API_KEY = "ARACHNE_IYZICO_API_KEY"
ENV_SECRET_KEY = "ARACHNE_IYZICO_SECRET_KEY"
ENV_SANDBOX = "ARACHNE_IYZICO_SANDBOX"

SANDBOX_BASE_URL = "https://sandbox-api.iyzipay.com"
PRODUCTION_BASE_URL = "https://api.iyzipay.com"

# Faz 111'in fiyatlandirma paketleri (docs/PRICING.md) - TRY cinsinden.
# Iyzico Turkiye merchant hesaplari icin varsayilan/en genis desteklenen
# para birimi budur; hesabinizin USD/EUR destekleyip desteklemedigini
# Iyzico panelinizden dogrulayin (bkz. docs/PAYMENTS.md).
PLANS = {
    "topluluk": {"name": "Topluluk", "price": "10.00", "currency": "TRY"},
    "profesyonel": {"name": "Profesyonel", "price": "49.00", "currency": "TRY"},
}


def is_enabled() -> bool:
    """Varsayilan KAPALI - guvenli varsayilan ilkesi."""
    if os.environ.get(ENV_ENABLED, "").lower() not in ("1", "true", "yes", "evet"):
        return False
    return bool(os.environ.get(ENV_API_KEY)) and bool(os.environ.get(ENV_SECRET_KEY))


def is_sandbox() -> bool:
    """Varsayilan SANDBOX (True) - canliya gecmek icin ACIKCA "0" gerekir."""
    return os.environ.get(ENV_SANDBOX, "1").lower() not in ("0", "false", "no", "hayir")


def status() -> dict:
    """Panelde/checkout sayfasinda gosterilecek durum (anahtarlari ASLA
    sizdirmaz)."""
    enabled = is_enabled()
    sandbox = is_sandbox()
    return {
        "enabled": enabled,
        "sandbox": sandbox,
        "api_key_present": bool(os.environ.get(ENV_API_KEY)),
        "mode_tr": (
            ("SANDBOX modunda aktif (gercek para GECMEZ)" if sandbox
             else "CANLI MOD - gercek odeme aliniyor")
            if enabled else
            "Kapali - odeme sayfasi 'henuz aktif degil' mesaji gosterir"
        ),
    }


def _options() -> dict:
    return {
        "api_key": os.environ.get(ENV_API_KEY, ""),
        "secret_key": os.environ.get(ENV_SECRET_KEY, ""),
        "base_url": SANDBOX_BASE_URL if is_sandbox() else PRODUCTION_BASE_URL,
    }


def new_conversation_id() -> str:
    return str(uuid.uuid4())


def create_checkout_form(plan_id: str, buyer: dict, address: dict,
                         callback_url: str, conversation_id: str):
    """Odeme formu baslatir (Iyzico'ya gercek bir API cagrisi).

    Basarisizlik/kapali/bilinmeyen-plan durumunda None doner - ASLA istisna
    firlatmaz; cagiran taraf (Flask route) bunu 'odeme baslatilamadi,
    lutfen bizimle iletisime gecin' olarak gostermelidir."""
    if not is_enabled():
        return None
    plan = PLANS.get(plan_id)
    if not plan:
        return None

    try:
        import iyzipay
    except ImportError:
        logger.warning("iyzipay paketi kurulu degil - 'pip install iyzipay'")
        return None

    request_data = {
        "locale": "tr",
        "conversationId": conversation_id,
        "price": plan["price"],
        "paidPrice": plan["price"],
        "currency": plan["currency"],
        "basketId": f"arachne-{plan_id}-{conversation_id}",
        "paymentGroup": "SUBSCRIPTION",
        "callbackUrl": callback_url,
        "enabledInstallments": ["1"],
        "buyer": buyer,
        "shippingAddress": address,
        "billingAddress": address,
        "basketItems": [{
            "id": f"arachne-{plan_id}",
            "name": f"Arachne Sentinel {plan['name']} Paketi (aylik)",
            "category1": "Yazilim",
            "itemType": "VIRTUAL",
            "price": plan["price"],
        }],
    }

    try:
        import json as _json
        checkout = iyzipay.CheckoutFormInitialize()
        raw_result = checkout.create(request_data, _options())
        response = _json.load(raw_result)
    except Exception as exc:
        logger.warning("Iyzico checkout baslatma basarisiz (%s)", exc)
        return None

    if response.get("status") != "success":
        logger.warning("Iyzico checkout reddetti: %s", response.get("errorMessage"))
        return None
    return response


def verify_payment_result(token: str, conversation_id: str = None):
    """Odeme SONUCUNU Iyzico'dan dogrudan SORARAK dogrular.

    KRITIK: callback isteginin govdesindeki hicbir alana (basari/basarisiz
    gibi) DOGRUDAN guvenilmez - bu fonksiyon Iyzico'ya ayrica sorup gercek
    durumu alir. Basarisizlik durumunda None doner."""
    if not is_enabled() or not token:
        return None
    try:
        import iyzipay
        import json as _json
    except ImportError:
        return None

    request_data = {
        "locale": "tr",
        "conversationId": conversation_id or new_conversation_id(),
        "token": token,
    }
    try:
        retrieve = iyzipay.CheckoutForm()
        raw_result = retrieve.retrieve(request_data, _options())
        response = _json.load(raw_result)
    except Exception as exc:
        logger.warning("Iyzico odeme dogrulama basarisiz (%s)", exc)
        return None

    if response.get("status") != "success":
        return None
    return response
