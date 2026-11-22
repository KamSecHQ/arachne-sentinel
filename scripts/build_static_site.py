#!/usr/bin/env python3
"""
Tanitim sitesini (website/) GitHub Pages icin statik HTML'e cevirir.

  python scripts/build_static_site.py            # -> _site/

Neden: arachnesentinel.com artik ucretli bir sunucu yerine GitHub Pages'ten
yayinlaniyor. Pages yalnizca statik dosya sunar, bu yuzden:

  * Sayfa, gercek Flask uygulamasinin urettigi HTML'in kendisidir (elle
    kopyalanmis ikinci bir surum yok - website/ degisince site de degisir).
  * Odeme (Iyzico) akisi sunucu gerektirir ve zaten hic acilmamisti:
    plan butonlari e-posta talebine doner.
  * Canli WAF sayaci sunucu gerektirir: statik sitede WAF calismadigi icin
    "bu sitenin gercek WAF kaydi" iddiasi KALDIRILIR, sayaclar durustce 0
    gosterilir ve canli surumun nasil calistirilacagi yazilir.
    (Ilke: olcmedigimiz hicbir seyi iddia etmeyiz.)

Her metin degisikligi assert ile korunur: sablon degisirse build sessizce
yanlis bir site uretmek yerine hata verir.
"""
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT = ROOT / "_site"
DOMAIN = "arachnesentinel.com"
CATEGORIES = ["SQL Injection", "XSS", "Path Traversal", "Command Injection", "SSTI"]


def replace_once(html: str, old: str, new: str) -> str:
    count = html.count(old)
    assert count >= 1, f"Beklenen metin sablonda yok: {old[:70]!r}"
    return html.replace(old, new)


def build() -> Path:
    from website.app import app, _contact_email

    with app.test_client() as client:
        resp = client.get("/")
        assert resp.status_code == 200, resp.status_code
        html = resp.get_data(as_text=True)

    email = _contact_email()

    # Statik dosya yollari: kok-goreli -> sayfa-goreli
    html = replace_once(html, '"/static/', '"static/')

    # Odeme sayfalari sunucu ister -> plan talebi e-postasi
    for plan_id, plan_name in (("topluluk", "Topluluk"), ("profesyonel", "Profesyonel")):
        subject = quote(f"Arachne Sentinel - {plan_name} paketi")
        html = replace_once(html, f'href="/checkout/{plan_id}"',
                            f'href="mailto:{email}?subject={subject}"')

    # Canli WAF iddiasi statik sitede dogru degil -> durust metin
    html = replace_once(
        html,
        "arachne · şebeke · bu sitenin gerçek WAF kaydı",
        "arachne · şebeke · WAF kategori haritası",
    )
    html = replace_once(
        html,
        "Şebeke düğümleri bu sitenin kendi gerçek WAF olay kaydından besleniyor — "
        "örnek veri değil (dogfooding). Trafik yoksa düğümler dürüstçe sönük kalır.",
        "Bu sayfa statik olarak yayınlanıyor; burada WAF çalışmadığı için düğümler "
        "sönük durur. Kendi sunucunuzda <code>python main.py website</code> ile "
        "çalıştırdığınızda şebeke, sitenin kendi gerçek WAF kaydıyla canlı dolar.",
    )

    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(ROOT / "website" / "static", OUT / "static")

    # webnet.js /api/waf-live'i okur -> statik, durust sifir yaniti
    js_path = OUT / "static" / "js" / "webnet.js"
    js = js_path.read_text(encoding="utf-8")
    js_path.write_text(replace_once(js, 'fetch("/api/waf-live"', 'fetch("api/waf-live.json"'),
                       encoding="utf-8")
    (OUT / "api").mkdir()
    (OUT / "api" / "waf-live.json").write_text(json.dumps({
        "static": True,
        "nodes": [{"id": c, "label": c, "count": 0} for c in CATEGORIES],
        "total_requests": 0,
        "blocked_requests": 0,
        "recent": [],
    }, ensure_ascii=False), encoding="utf-8")

    (OUT / "index.html").write_text(html, encoding="utf-8")
    (OUT / "CNAME").write_text(DOMAIN + "\n", encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")
    return OUT


if __name__ == "__main__":
    out = build()
    print(f"Statik site hazir: {out}")
