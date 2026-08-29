"""
Faz 112 - Arachne Sentinel'in kendi tanitim/pazarlama sitesi.

--- Dogfooding ---
Bu site, urunun kendisiyle korunur: `arachne.waf.middleware.WAFMiddleware`
onune, tam da musterilere onerdigimiz sekilde (bkz. docs/INTEGRATION.md
Adim 3) tek satirla konur. "Kendi urunumuzu kendi urunumuzle koruyoruz"
somut, gosterilebilir bir kanittir - baska hicbir demo uygulamasi degil,
GERCEK pazarlama sitesi.

--- Iletisim bilgisi ---
Sayfadaki CTA'lar mailto: baglantilaridir - ayri bir e-posta/form
altyapisi kurmadan calisir. Adres ARACHNE_WEBSITE_CONTACT_EMAIL ortam
degiskeniyle degistirilebilir (varsayilan bir yer tutucudur - gercek
alan adi alindiginda buraya gercek iletisim adresiniz yazilmali).

Kullanim:
  python main.py website                 # WAF ile korumali (varsayilan)
  python main.py website --unprotected    # karsilastirma icin (ONERILMEZ)
"""
import os
import re
from collections import Counter

from flask import Flask, abort, jsonify, render_template, request, url_for

from arachne import storage
from arachne.waf.middleware import WAFMiddleware
from website import payments

app = Flask(__name__)

# Faz 114 - "Şebeke" radyal görselleştirmesi için gerçek WAF kategori
# etiketleri. `arachne/waf/rules.py`'deki gerçek kural motorunun kategori
# adlarıyla birebir eşleşir (middleware.py bu adları "reasons" alanına
# "<kategori> supesi (...)" biçiminde yazar).
_WAF_CATEGORIES = ["SQL Injection", "XSS", "Path Traversal", "Command Injection", "SSTI"]

ENV_CONTACT_EMAIL = "ARACHNE_WEBSITE_CONTACT_EMAIL"
DEFAULT_CONTACT_EMAIL = "emirhanbaydere00@outlook.com"
GITHUB_URL = "https://github.com/KamSecHQ/arachne-sentinel"


def _contact_email() -> str:
    return os.environ.get(ENV_CONTACT_EMAIL, DEFAULT_CONTACT_EMAIL)


@app.route("/")
def index():
    return render_template(
        "index.html",
        contact_email=_contact_email(),
        github_url=GITHUB_URL,
        payments_enabled=payments.is_enabled(),
    )


@app.route("/checkout/<plan_id>", methods=["GET", "POST"])
def checkout(plan_id):
    """Faz 113: Iyzico Checkout Form akisinin ilk adimi.

    GET: alici bilgi formunu gosterir (kart bilgisi ISTEMEZ).
    POST: Iyzico'ya odeme formu baslatma istegi atar, donen gomulu
    HTML/JS'i (`checkoutFormContent`) render eder - kart numarasi
    dogrudan Iyzico'nun kendi formuna girilir, bize hic ulasmaz."""
    plan = payments.PLANS.get(plan_id)
    if not plan:
        abort(404)

    if not payments.is_enabled():
        return render_template("checkout_unavailable.html", plan=plan,
                               contact_email=_contact_email())

    if request.method == "GET":
        return render_template("checkout.html", plan=plan, plan_id=plan_id,
                               contact_email=_contact_email())

    conversation_id = payments.new_conversation_id()
    full_name = request.form.get("name", "").strip()
    surname = request.form.get("surname", "").strip()
    buyer = {
        "id": conversation_id,
        "name": full_name or "Musteri",
        "surname": surname or "-",
        "email": request.form.get("email", "").strip(),
        "gsmNumber": request.form.get("phone", "").strip(),
        # Yabanci/TC kimlik numarasi olmayan aliciler icin Iyzico'nun
        # kendi dokumantasyonunda onerdigi yer tutucu deger kullanilir.
        "identityNumber": request.form.get("identity_number", "").strip() or "11111111111",
        "registrationAddress": request.form.get("address", "").strip(),
        "ip": request.remote_addr or "85.34.78.112",
        "city": request.form.get("city", "").strip() or "Istanbul",
        "country": request.form.get("country", "").strip() or "Turkey",
        "zipCode": request.form.get("zip_code", "").strip() or "34000",
    }
    address = {
        "contactName": f"{buyer['name']} {buyer['surname']}".strip(),
        "city": buyer["city"],
        "country": buyer["country"],
        "address": buyer["registrationAddress"],
        "zipCode": buyer["zipCode"],
    }

    result = payments.create_checkout_form(
        plan_id, buyer, address,
        callback_url=url_for("checkout_callback", _external=True),
        conversation_id=conversation_id,
    )
    if not result:
        return render_template("checkout_error.html", plan=plan,
                               contact_email=_contact_email())

    return render_template(
        "checkout_form.html", plan=plan,
        checkout_form_content=result.get("checkoutFormContent", ""),
        sandbox=payments.is_sandbox(),
    )


@app.route("/checkout/callback", methods=["POST"])
def checkout_callback():
    """Iyzico odeme sonrasi buraya (POST, sadece `token`) yonlendirir.

    KRITIK: gelen istegin govdesine DOGRUDAN guvenilmez - gercek durum
    Iyzico'ya ayrica sorularak (`verify_payment_result`) dogrulanir."""
    token = request.form.get("token", "")
    result = payments.verify_payment_result(token)

    if not result or result.get("paymentStatus") != "SUCCESS":
        return render_template("checkout_result.html", success=False,
                               contact_email=_contact_email())

    return render_template("checkout_result.html", success=True,
                           payment_id=result.get("paymentId"),
                           contact_email=_contact_email())


@app.route("/api/waf-live")
def api_waf_live():
    """Faz 114 - Şebeke görselleştirmesinin verisi: bu sitenin KENDİ gerçek
    WAF olay kaydı (dogfooding). Sahte/örnek satır YOK — sadece bu sitenin
    kendi WAFMiddleware'ının gerçekten işlediği isteklerin sayımı.

    Trafik yoksa tüm sayılar dürüstçe 0 döner (bkz. projenin genel
    "0 ise 0 göster" ilkesi)."""
    db_path = app.config.get("ARACHNE_DB_PATH")
    try:
        events = storage.get_waf_events(limit=500, db_path=db_path)
        stats = storage.waf_summary_stats(db_path=db_path)
    except Exception:
        events, stats = [], {"total_requests": 0, "blocked_requests": 0}

    category_counts = Counter()
    for ev in events:
        if not ev.get("blocked"):
            continue
        reasons = ev.get("reasons") or ""
        for cat in _WAF_CATEGORIES:
            if re.search(re.escape(cat), reasons, re.IGNORECASE):
                category_counts[cat] += 1

    nodes = [{"id": cat, "label": cat, "count": category_counts.get(cat, 0)}
             for cat in _WAF_CATEGORIES]
    return jsonify({
        "nodes": nodes,
        "total_requests": stats.get("total_requests", 0),
        "blocked_requests": stats.get("blocked_requests", 0),
        "recent": [
            {"id": ev.get("id"), "path": (ev.get("path") or "")[:80],
             "blocked": bool(ev.get("blocked")), "timestamp": ev.get("timestamp")}
            for ev in events[:10]
        ],
    })


@app.route("/health")
def health():
    """Basit saglik kontrolu - reverse proxy/yuk dengeleyici icin (bkz.
    docs/WEBSITE.md, gercek alan adina baglama adimi)."""
    return {"status": "ok", "product": "Arachne Sentinel"}


def create_app(protected: bool = True, db_path=None):
    """WAF korumasini uygular. `protected=False` SADECE yerel
    karsilastirma/test icindir - gercek dagitimda ASLA kullanilmamali.

    `db_path`, `/api/waf-live`'in (Faz 114 - Sebeke gorsellestirmesi)
    dogru veritabanini okumasi icin app.config'e de yazilir - aksi halde
    testlerde/ozel db_path'lerde hep varsayilan DB okunurdu."""
    app.config["ARACHNE_DB_PATH"] = db_path
    if protected:
        app.wsgi_app = WAFMiddleware(app.wsgi_app, db_path=db_path)
    return app


def run(protected: bool = True, host: str = "127.0.0.1", port: int = 8088):
    application = create_app(protected=protected)
    mode = "WAF ILE KORUMALI (dogfooding)" if protected else "KORUMASIZ - ONERILMEZ"
    print(f"[Arachne Sentinel - Tanitim Sitesi] {mode} - http://{host}:{port}")
    if not protected:
        print("  UYARI: --unprotected sadece karsilastirma icindir, gercek "
              "dagitimda kullanmayin.")
    application.run(host=host, port=port, debug=False)
