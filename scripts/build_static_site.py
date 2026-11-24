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
import re
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

    # Ana sayfadan kayitli komuta merkezi demosuna giris
    # Ust menu: iki buton sagda yan yana (nav flex space-between oldugu icin
    # tek bir kapsayiciya alinir); panel linki ikincil (cerceveli) stilde.
    nav_cta = re.search(r'<a class="nav-cta"[^>]*>Pilot talep et</a>', html)
    assert nav_cta, "nav-cta bulunamadi"
    html = html.replace(nav_cta.group(0), (
        '<style>@media (max-width:640px){.nav-panel{display:none!important}}</style>'
        '<div style="display:flex;align-items:center;gap:10px">'
        '<a class="nav-cta nav-panel" href="panel/" style="background:transparent;color:#52ddc7;'
        'box-shadow:inset 0 0 0 1px rgba(82,221,199,.55)">Komuta merkezini aç</a>'
        + nav_cta.group(0) + '</div>'), 1)
    # Hero: en guclu kanit (calisan panel) birincil buton olur
    hero = re.search(r'<a class="btn-primary" (href="[^"]*INTEGRATION\.md"[^>]*)>Entegrasyonu incele</a>', html)
    assert hero, "hero butonu bulunamadi"
    html = html.replace(hero.group(0), (
        '<a class="btn-primary" href="panel/">Komuta merkezini aç →</a>\n            '
        f'<a class="btn-ghost" {hero.group(1)}>Entegrasyonu incele</a>'), 1)
    html = replace_once(html, '<a class="btn-ghost" href="#depth">Nasıl çalışır →</a>',
                        '<a class="btn-ghost" href="#depth" style="border:0;padding-left:.2rem">Nasıl çalışır →</a>')

    # Link onizlemesi (LinkedIn/WhatsApp/X): kapak gorseli + kanonik adres
    html = replace_once(
        html, '<meta property="og:type" content="website">',
        '<meta property="og:type" content="website">\n'
        + og_tags(f"https://{DOMAIN}/"))

    build_panel()

    (OUT / "index.html").write_text(html, encoding="utf-8")
    (OUT / "CNAME").write_text(DOMAIN + "\n", encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")
    return OUT


PANEL_SRC = ROOT / "website" / "panel_demo"   # scripts/snapshot_panel.py uretir
OG_IMAGE = f"https://{DOMAIN}/static/og/arachne-panel.jpg"   # 1200x630, gercek panel goruntusu


def og_tags(url: str) -> str:
    return (
        f'  <meta property="og:url" content="{url}">\n'
        f'  <meta property="og:image" content="{OG_IMAGE}">\n'
        '  <meta property="og:image:width" content="1200">\n'
        '  <meta property="og:image:height" content="630">\n'
        '  <meta property="og:image:alt" content="Arachne Sentinel komuta merkezi - Çelik Kubbe katmanlı savunma görünümü">\n'
        '  <meta name="twitter:card" content="summary_large_image">\n'
        f'  <meta name="twitter:image" content="{OG_IMAGE}">'
    )


def build_panel():
    """Kayitli komuta merkezi demosu -> _site/panel/ (bkz. snapshot_panel.py)."""
    panel = OUT / "panel"
    shutil.copytree(PANEL_SRC, panel)
    shutil.copytree(ROOT / "arachne" / "reporting" / "static", panel / "static")
    shutil.copy2(ROOT / "website" / "panel_demo_shim.js", panel / "demo-shim.js")

    html = (panel / "index.html").read_text(encoding="utf-8")
    html = replace_once(html, '"/static/', '"static/')
    html = replace_once(html, 'href="/report"', 'href="report.html"')
    html = replace_once(html, 'href="/api/stix"', 'href="api/stix.json"')
    html = replace_once(html, 'location.href = "/login"', 'void 0')
    # Demo'ya ozgu: donmus saat ve "canli" ibaresi kayitli veride yaniltici olur
    html = replace_once(html, '<div class="clock" id="clock">', '<div class="clock" id="clock" hidden style="display:none">')
    html = replace_once(html, '<span class="live-dot">canlı</span>', '<span class="live-dot">demo</span>')

    # Kayitli demo seridi: ust ortada, kucuk; dar ekranda alta iner
    banner = (
        '<style>'
        '#demo-banner{position:fixed;top:14px;left:50%;transform:translateX(-50%);z-index:9999;'
        'display:flex;align-items:center;gap:10px;padding:5px 12px 5px 6px;border-radius:999px;'
        'background:rgba(5,10,18,.82);border:1px solid rgba(34,211,238,.28);'
        'backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);'
        'font:600 11px/1.3 var(--font-mono,ui-monospace,monospace);letter-spacing:.06em;color:#b9d6e6;white-space:nowrap}'
        '#demo-banner .db-tag{padding:3px 8px;border-radius:999px;background:rgba(34,211,238,.14);color:#67e8f9;letter-spacing:.12em}'
        '#demo-banner a{color:#67e8f9;text-decoration:none}#demo-banner a:hover{text-decoration:underline}'
        '@media (max-width:1180px){#demo-banner{top:auto;bottom:12px}}'
        '@media (max-width:560px){#demo-banner .db-src{display:none}}'
        '</style>'
        '<div id="demo-banner"><span class="db-tag">KAYITLI DEMO</span>'
        '<span class="db-src">gerçek lab tatbikatı verisi</span>'
        '<a href="https://github.com/KamSecHQ/arachne-sentinel" target="_blank" rel="noopener">GitHub ↗</a></div>'
    )
    desc = ("Honeypot, WAF ve SOAR'ı birleştiren katmanlı savunma platformunun komuta merkezi — "
            "gerçek lab tatbikatı verisiyle kayıtlı demo. Kurulum gerektirmez.")
    head = (
        '<head>\n<script src="demo-shim.js"></script>\n'
        f'  <meta name="description" content="{desc}">\n'
        '  <meta property="og:title" content="Arachne Sentinel — Komuta Merkezi">\n'
        f'  <meta property="og:description" content="{desc}">\n'
        '  <meta property="og:type" content="website">\n'
        + og_tags(f"https://{DOMAIN}/panel/") + "\n"
    )
    html = replace_once(html, "<head>", head)
    html = replace_once(html, "</body>", banner + "\n</body>")
    (panel / "index.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    out = build()
    print(f"Statik site hazir: {out}")
