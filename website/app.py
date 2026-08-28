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

from flask import Flask, render_template

from arachne.waf.middleware import WAFMiddleware

app = Flask(__name__)

ENV_CONTACT_EMAIL = "ARACHNE_WEBSITE_CONTACT_EMAIL"
DEFAULT_CONTACT_EMAIL = "iletisim@arachne-sentinel.com"
GITHUB_URL = "https://github.com/KamSecHQ/arachne-sentinel"


def _contact_email() -> str:
    return os.environ.get(ENV_CONTACT_EMAIL, DEFAULT_CONTACT_EMAIL)


@app.route("/")
def index():
    return render_template(
        "index.html",
        contact_email=_contact_email(),
        github_url=GITHUB_URL,
    )


@app.route("/health")
def health():
    """Basit saglik kontrolu - reverse proxy/yuk dengeleyici icin (bkz.
    docs/WEBSITE.md, gercek alan adina baglama adimi)."""
    return {"status": "ok", "product": "Arachne Sentinel"}


def create_app(protected: bool = True, db_path=None):
    """WAF korumasini uygular. `protected=False` SADECE yerel
    karsilastirma/test icindir - gercek dagitimda ASLA kullanilmamali."""
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
