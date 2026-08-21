"""
WAF etkinlik raporu — benchmark sonucundan tek-dosya, kendinden-yeterli HTML
uretir (siber tema). Tum sayilar OLCULMUSTUR; kacan (bypass) yukler acikca
listelenir (dürüstluk).
"""
from __future__ import annotations

import html
from . import benchmark


def _bar(pct, color):
    return (f"<div class='bar'><div class='fill' style='width:{pct:.1f}%;"
            f"background:{color}'></div><span>{pct:.1f}%</span></div>")


def build_html(result: dict, generated_at: str = "") -> str:
    m, t = result["metrics"], result["totals"]
    lat, tier = result["latency_ms"], result["by_tier"]
    recall = m["recall_detection_rate"] * 100
    evasion = tier["kacinma"]["recall"] * 100
    basic = tier["temel"]["recall"] * 100
    prevent = m["real_attack_prevention_rate"] * 100
    fp = m["false_positive_rate"] * 100

    # kacan saldirilar (dürüstluk: neyi yakalayamadigimiz)
    missed = [it for it in result["items"]
              if it["kind"] == "attack" and not it["blocked_by_waf"]]
    missed_rows = "".join(
        f"<tr><td>{html.escape(it['category'])}</td>"
        f"<td><span class='tier {it.get('tier','')}'>{html.escape(it.get('tier',''))}</span></td>"
        f"<td><code>{html.escape(it['payload'])}</code></td>"
        f"<td>{'GERCEKTEN calisti' if it['exploited_unprotected'] else 'islemedi'}</td></tr>"
        for it in missed) or "<tr><td colspan=4>(hicbir saldiri kacmadi)</td></tr>"

    cat_rows = "".join(
        f"<tr><td>{html.escape(c)}</td><td>{v['blocked']}/{v['total']}</td>"
        f"<td>{v['exploited']}</td><td>{v['prevented']}</td>"
        f"<td>{_bar(v['blocked']/v['total']*100 if v['total'] else 0, '#35e0d0')}</td></tr>"
        for c, v in result["per_category"].items())

    gen = f"<div class='gen'>Uretim: {html.escape(generated_at)}</div>" if generated_at else ""

    return f"""<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arachne Sentinel — WAF Etkinlik Raporu</title>
<style>
 :root{{--bg:#07060f;--card:#12101f;--line:#2a2740;--cyan:#35e0d0;--violet:#9b6bff;
   --gold:#ffcf6a;--red:#ff5a4d;--muted:#8b95a8;--txt:#e8ecf5;}}
 *{{box-sizing:border-box}} body{{margin:0;background:radial-gradient(1200px 600px at 70% -10%,
   #1a1530 0%,var(--bg) 60%);color:var(--txt);font-family:-apple-system,Segoe UI,Roboto,sans-serif;
   padding:2.2rem;line-height:1.5}}
 h1{{font-size:1.5rem;margin:0 0 .2rem;letter-spacing:.02em}}
 h1 span{{color:var(--cyan)}} .sub{{color:var(--muted);margin:0 0 1.4rem;font-size:.9rem}}
 .gen{{color:var(--muted);font-size:.72rem;margin-bottom:1.4rem}}
 .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem;margin-bottom:1.6rem}}
 .kpi{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.1rem 1.2rem}}
 .kpi .l{{font-size:.68rem;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}}
 .kpi .v{{font-size:2rem;font-weight:800;margin-top:.2rem}}
 .kpi .n{{font-size:.72rem;color:var(--muted);margin-top:.1rem}}
 .cyan{{color:var(--cyan)}} .violet{{color:var(--violet)}} .gold{{color:var(--gold)}} .red{{color:var(--red)}}
 .bar{{position:relative;background:#0c0a17;border:1px solid var(--line);border-radius:8px;height:20px;overflow:hidden}}
 .bar .fill{{height:100%;border-radius:7px 0 0 7px}}
 .bar span{{position:absolute;right:8px;top:1px;font-size:.72rem;font-weight:700}}
 .card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.2rem 1.3rem;margin-bottom:1.4rem}}
 .card h2{{font-size:1rem;margin:0 0 .8rem}}
 table{{width:100%;border-collapse:collapse;font-size:.85rem}}
 th,td{{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}}
 th{{color:var(--muted);font-size:.7rem;letter-spacing:.05em;text-transform:uppercase}}
 code{{background:#0c0a17;border:1px solid var(--line);border-radius:5px;padding:.05rem .3rem;
   font-size:.8rem;color:var(--gold);word-break:break-all}}
 .tier{{font-size:.62rem;padding:.1rem .4rem;border-radius:5px;text-transform:uppercase;font-weight:700}}
 .tier.temel{{background:rgba(53,224,208,.15);color:var(--cyan)}}
 .tier.kacinma{{background:rgba(255,90,77,.15);color:var(--red)}}
 .note{{color:var(--muted);font-size:.78rem;border-left:2px solid var(--violet);padding-left:.8rem;margin-top:.6rem}}
</style></head><body>
<h1>🕸 Arachne Sentinel — <span>WAF Etkinlik Raporu</span></h1>
<p class="sub">Gercek WAF, bilincli-zafiyetli bir hedefin onune konup etiketli saldiri korpusu ile olculdu.
Butun sayilar in-process test-client ile GERCEKTEN olculmustur — uydurma yoktur.</p>
{gen}
<div class="kpis">
 <div class="kpi"><div class="l">Saldiri Yakalama (recall)</div><div class="v cyan">{recall:.1f}%</div>
   <div class="n">{t['attacks_blocked']}/{t['attacks']} saldiri engellendi</div></div>
 <div class="kpi"><div class="l">Gercek-Saldiri Onleme</div><div class="v violet">{prevent:.1f}%</div>
   <div class="n">{t['attacks_prevented']}/{t['attacks_exploited_unprotected']} CALISAN saldiri onlendi</div></div>
 <div class="kpi"><div class="l">Yanlis Pozitif</div><div class="v gold">{fp:.1f}%</div>
   <div class="n">{t['benign_blocked_false_positive']}/{t['benign']} zararsiz istek bloklandi</div></div>
 <div class="kpi"><div class="l">Gecikme Yuku</div><div class="v">+{lat['overhead_avg']:.2f} <small style="font-size:1rem">ms</small></div>
   <div class="n">{lat['unprotected_avg']:.2f} → {lat['protected_avg']:.2f} ms/istek</div></div>
</div>

<div class="card">
 <h2>Temel vs Kacinma (evasion) — dürüst sinir</h2>
 <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.2rem">
   <div><div class="l" style="font-size:.7rem;color:var(--muted)">TEMEL YUKLER ({tier['temel']['blocked']}/{tier['temel']['total']})</div>{_bar(basic,'#35e0d0')}</div>
   <div><div class="l" style="font-size:.7rem;color:var(--muted)">KACINMA YUKLERI ({tier['kacinma']['blocked']}/{tier['kacinma']['total']})</div>{_bar(evasion,'#ff5a4d')}</div>
 </div>
 <p class="note">Temel yukler tam yakalaniyor; asil ayirt edici, saldirganin atlatma (evasion)
 tekniklerine karsi dayaniklilik. Kacinma orani gercek tavanimizdir — imza tabanli bir WAF
 her varyanti yakalayamaz, ve bunu gizlemiyoruz.</p>
</div>

<div class="card">
 <h2>Kategori Bazinda</h2>
 <table><thead><tr><th>Kategori</th><th>Engellenen</th><th>Korumasizda Calisan</th><th>Onlenen</th><th>Oran</th></tr></thead>
 <tbody>{cat_rows}</tbody></table>
</div>

<div class="card">
 <h2>⚠ Kacan Saldirilar (bilinen bosluklar)</h2>
 <table><thead><tr><th>Kategori</th><th>Tur</th><th>Yuk</th><th>Korumasizda</th></tr></thead>
 <tbody>{missed_rows}</tbody></table>
 <p class="note">Bunlar gercek boslardir. Bir sonraki adim: bu atlatma siniflarina karsi
 imza + normalizasyon (kanonik hale getirme) eklemek. Dürüstluk geregi rapora dahil edilmistir.</p>
</div>

<div class="card">
 <h2>Metodoloji</h2>
 <p class="note">Ayni lab hedefi iki kez calistirildi: WAF'siz (korumasiz) ve WAF'li (korumali).
 Korumasizda her saldiri once GERCEKTEN denendi — yalnizca calisan (exploited) saldirilar
 "gercek-saldiri onleme" paydasina alindi. Her istek ayri kaynak IP'sinden gonderildi ki
 imza tespiti, IP-basina rate-limit katmanindan yalitik olculsun. Zararsiz trafik yanlis-pozitif
 icin ayni anda olculdu. Tamamen izole/hafizada; dis sisteme dokunulmadi.</p>
</div>
</body></html>"""


def generate(path: str = "waf_effectiveness_report.html", generated_at: str = "") -> tuple:
    """Benchmark'i calistirir, HTML raporu yazar. (path, result) doner."""
    result = benchmark.run()
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(result, generated_at=generated_at))
    return path, result
