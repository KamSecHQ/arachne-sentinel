"""
Statik HTML saldiri raporu ureticisi. Bilincli olarak harici bir bagimlilik
(orn. matplotlib) kullanmiyoruz ki `pip install` adimi kucuk ve guvenilir
kalsin; gorsellestirme icin sadece duz HTML/CSS kullaniyoruz (+ tek bir
Google Fonts CDN cagrisi - internet yoksa da sistem fontuna sessizce duser).

Gorsel dil canli panelle (arachne/reporting/templates/dashboard.html) ayni:
koyu "SOC" temasi, ayni renk paleti/fontlar - ama bu dosya TAMAMEN statik
(JS/canvas/canli guncelleme yok), tek basina acilabilen bir anlik goruntu."""
from datetime import datetime
from pathlib import Path

from .. import storage


def _bar(count, max_count, max_width_px=220):
    pct = int((count / max_count) * 100) if max_count else 0
    return (
        f'<div class="bar-track"><div class="bar-fill" '
        f'style="width:{pct}%;max-width:{max_width_px}px;"></div></div>'
    )


def generate_html_report(output_path="data/report.html", db_path=None) -> str:
    stats = storage.summary_stats(db_path=db_path)
    alerts = storage.get_all_alerts(limit=50, db_path=db_path)
    waf_stats = storage.waf_summary_stats(db_path=db_path)
    scan_findings = storage.get_scan_findings(limit=50, db_path=db_path)
    mtd_rotations = storage.get_mtd_rotations(limit=50, db_path=db_path)
    mtd_stats = storage.mtd_summary_stats(db_path=db_path)
    max_ip_count = max((c for _, c in stats["top_ips"]), default=0)

    total_waf = waf_stats.get("total_requests") or 0
    blocked_waf = waf_stats.get("blocked_requests") or 0
    waf_blocked_pct = round((blocked_waf / total_waf) * 100) if total_waf else 0

    top_ip_rows = "".join(
        f'<div class="ip-row"><span class="mono ip-addr">{ip}</span>'
        f'{_bar(count, max_ip_count)}<span class="mono ip-count">{count}</span></div>'
        for ip, count in stats["top_ips"]
    ) or '<p class="empty-hint">Henuz kaynak IP verisi yok.</p>'

    severity_order = ["critical", "high", "medium", "low"]
    severity_rows = "".join(
        f'<tr><td><span class="badge badge-{sev}">{sev}</span></td><td class="mono">{stats["by_severity"].get(sev, 0)}</td></tr>'
        for sev in severity_order if stats["by_severity"].get(sev)
    ) or '<tr><td colspan="2" class="empty-hint">Henuz alarm yok</td></tr>'

    alert_rows = "".join(
        f"<tr><td class='mono muted'>{a['timestamp']}</td><td class='mono'>{a['source_ip']}</td>"
        f"<td><span class='badge badge-{a['severity']}'>{a['severity']}</span></td>"
        f"<td class='mono'>{a['score']}</td><td class='reasons'>{a['reasons']}</td></tr>"
        for a in alerts
    ) or "<tr><td colspan='5' class='empty-hint'>Henuz alarm yok</td></tr>"

    scan_rows = "".join(
        f"<tr><td class='mono muted'>{f['timestamp']}</td><td class='mono'>{f['target']}</td><td class='mono'>{f['port']}</td>"
        f"<td>{f['service_guess']}</td><td><span class='badge badge-{f['severity']}'>{f['severity']}</span></td><td class='reasons'>{f['finding']}</td></tr>"
        for f in scan_findings
    ) or "<tr><td colspan='6' class='empty-hint'>Henuz tarama yapilmadi</td></tr>"

    mtd_rows = "".join(
        f"<tr><td class='mono muted'>{r['timestamp']}</td><td class='mono'>{r['component']}</td>"
        f"<td class='mono muted'>{r['old_identity'] or '&mdash;'}</td><td class='mono'>{r['new_identity']}</td><td class='reasons'>{r['reason']}</td></tr>"
        for r in mtd_rotations
    ) or "<tr><td colspan='5' class='empty-hint'>Henuz rotasyon yok &mdash; once 'python main.py mtd-demo' calistirin</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arachne Sentinel &mdash; Saldiri Raporu</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%95%B8%3C/text%3E%3C/svg%3E">
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;500;700&display=swap');
:root{{
  --bg:#05070a; --panel:#0d1117; --panel-2:#131a24; --border:#1c2532;
  --text:#e9edf5; --muted:#8b95a8; --dim:#5c667a;
  --accent:#ff3b45; --accent-2:#22d3ee; --ok:#22c55e; --warn:#f5a623;
  --high:#ff7a45; --med:#f5a623; --low:#4da3ff; --teal:#2dd4bf;
  --font-display:'Orbitron',sans-serif; --font-mono:'JetBrains Mono','SF Mono',Menlo,Consolas,monospace;
  --font-body:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Arial,sans-serif;
}}
*{{box-sizing:border-box;}}
body{{
  font-family:var(--font-body); margin:0; padding:0 0 4rem;
  background:radial-gradient(ellipse at top left,#0f1720 0%,var(--bg) 55%); color:var(--text);
}}
.wrap{{max-width:1180px; margin:0 auto; padding:0 2rem;}}
.report-header{{padding:3rem 2rem 2.2rem; text-align:center; border-bottom:1px solid var(--border); margin-bottom:2.4rem;}}
.eyebrow{{font-family:var(--font-mono); font-size:.7rem; letter-spacing:.26em; color:var(--accent-2); text-transform:uppercase; opacity:.85; margin-bottom:.9rem;}}
h1{{font-family:var(--font-display); font-weight:900; font-size:2.1rem; margin:0 0 .6rem;
  background:linear-gradient(120deg,#fff 0%,var(--accent-2) 55%,var(--accent) 100%);
  -webkit-background-clip:text; background-clip:text; color:transparent;}}
.report-meta{{color:var(--muted); font-size:.85rem; font-family:var(--font-mono);}}
h2{{font-family:var(--font-display); font-size:.95rem; letter-spacing:.02em; margin:0 0 1rem; padding-bottom:.6rem; border-bottom:1px solid var(--border);}}
section{{margin-top:2.6rem;}}
table{{border-collapse:collapse; width:100%; font-size:.82rem;}}
th,td{{border-bottom:1px solid var(--border); padding:.6rem .8rem; text-align:left; vertical-align:top;}}
th{{background:var(--panel-2); color:var(--muted); font-weight:700; text-transform:uppercase; font-size:.66rem; letter-spacing:.05em; font-family:var(--font-mono);}}
.table-card{{background:var(--panel); border:1px solid var(--border); border-radius:12px; overflow:hidden;}}
.table-card.padded{{padding:1.1rem 1.3rem;}}
.mono{{font-family:var(--font-mono); font-size:.78rem;}}
.muted{{color:var(--muted);}}
.reasons{{color:var(--muted); font-size:.78rem; max-width:340px;}}
.empty-hint{{padding:1.6rem; text-align:center; color:var(--muted); font-size:.85rem;}}

.stat-cards{{display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:2.4rem;}}
.card{{background:linear-gradient(160deg,var(--panel-2),var(--panel)); border:1px solid var(--border);
  border-radius:12px; padding:1.05rem 1.25rem; position:relative; overflow:hidden;}}
.card::before{{content:"";position:absolute;top:0;left:0;width:3px;height:100%;background:var(--accent-card,var(--accent-2));}}
.card.c-events::before{{--accent-card:var(--accent-2);}}
.card.c-alerts::before{{--accent-card:var(--accent);}}
.card.c-waf::before{{--accent-card:var(--warn);}}
.card.c-scan::before{{--accent-card:var(--ok);}}
.card.c-mtd::before{{--accent-card:var(--teal);}}
.card .label{{color:var(--muted); font-size:.68rem; text-transform:uppercase; letter-spacing:.07em; margin-bottom:.35rem; font-family:var(--font-mono);}}
.card .n{{font-family:var(--font-display); font-size:1.7rem; font-weight:700;}}

.intel-grid{{display:grid; grid-template-columns:1fr 1fr; gap:1.1rem;}}
.ip-row{{display:flex; align-items:center; gap:.7rem; padding:.4rem 0;}}
.ip-addr{{width:110px; flex-shrink:0; font-size:.78rem;}}
.bar-track{{flex:1; height:9px; border-radius:5px; background:#1a2029; overflow:hidden;}}
.bar-fill{{height:100%; background:linear-gradient(90deg,var(--accent-2),var(--accent)); border-radius:5px;}}
.ip-count{{width:32px; text-align:right; font-size:.78rem; color:var(--muted); flex-shrink:0;}}

.badge{{display:inline-block; padding:.18rem .55rem; border-radius:20px; font-size:.66rem; font-weight:700;
  letter-spacing:.03em; text-transform:uppercase; font-family:var(--font-mono);}}
.badge-critical{{background:rgba(255,59,69,.15); color:var(--accent); border:1px solid rgba(255,59,69,.35);}}
.badge-high{{background:rgba(255,122,69,.15); color:var(--high); border:1px solid rgba(255,122,69,.35);}}
.badge-medium{{background:rgba(245,166,35,.15); color:var(--med); border:1px solid rgba(245,166,35,.35);}}
.badge-low{{background:rgba(77,163,255,.15); color:var(--low); border:1px solid rgba(77,163,255,.35);}}

footer{{max-width:1180px; margin:3.5rem auto 0; padding:0 2rem; color:var(--dim); font-size:.75rem; text-align:center;}}
@media (max-width:760px){{ .intel-grid{{grid-template-columns:1fr;}} }}
</style>
</head>
<body>

<div class="report-header">
  <div class="eyebrow">SIBER GÜVENLİK ARAŞTIRMA PROJESİ &middot; STATİK ANLIK GÖRÜNTÜ</div>
  <h1>ARACHNE SENTINEL &mdash; Saldırı Raporu</h1>
  <div class="report-meta">Oluşturulma zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &middot; Canlı panel için <code>python main.py dashboard</code></div>
</div>

<div class="wrap">

<div class="stat-cards">
  <div class="card c-events"><div class="label">Toplam Olay (Honeypot)</div><div class="n">{stats['total_events']}</div></div>
  <div class="card c-alerts"><div class="label">Toplam Alarm (Honeypot)</div><div class="n">{stats['total_alerts']}</div></div>
  <div class="card c-waf"><div class="label">WAF Engellenen/Toplam</div><div class="n" style="font-size:1.3rem">{blocked_waf}/{total_waf}</div></div>
  <div class="card c-scan"><div class="label">Zafiyet Bulgusu</div><div class="n">{len(scan_findings)}</div></div>
  <div class="card c-mtd"><div class="label">MTD Rotasyonu (Faz 4)</div><div class="n">{mtd_stats['total_rotations']}</div></div>
</div>

<section>
  <h2>🎯 Saldırgan İstihbaratı</h2>
  <div class="intel-grid">
    <div class="table-card padded">{top_ip_rows}</div>
    <div class="table-card padded">
      <table><tr><th>Şiddet</th><th>Adet</th></tr>{severity_rows}</table>
    </div>
  </div>
</section>

<section>
  <h2>🛑 Son Alarmlar (Honeypot)</h2>
  <div class="table-card">
  <table><tr><th>Zaman</th><th>IP</th><th>Şiddet</th><th>Skor</th><th>Sebepler</th></tr>
  {alert_rows}
  </table>
  </div>
</section>

<section>
  <h2>🔍 Zafiyet Tarama Bulguları</h2>
  <div class="table-card">
  <table><tr><th>Zaman</th><th>Hedef</th><th>Port</th><th>Servis</th><th>Şiddet</th><th>Bulgu</th></tr>
  {scan_rows}
  </table>
  </div>
</section>

<section>
  <h2>👻 Faz 4 &mdash; Moving Target Defense Rotasyonları</h2>
  <div class="table-card">
  <table><tr><th>Zaman</th><th>Bileşen</th><th>Eski Kimlik</th><th>Yeni Kimlik</th><th>Sebep</th></tr>
  {mtd_rows}
  </table>
  </div>
</section>

</div>
<footer>Arachne Sentinel &mdash; Topkapı Üniversitesi ekip projesi &middot; sadece izole/lab ortamında kullanın</footer>
</body>
</html>"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return str(out)
