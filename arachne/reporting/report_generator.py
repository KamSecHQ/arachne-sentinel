"""
Statik HTML saldiri raporu ureticisi. Bilincli olarak harici bir bagimlilik
(orn. matplotlib) kullanmiyoruz ki `pip install` adimi kucuk ve guvenilir
kalsin; gorsellestirme icin sadece duz HTML/CSS kullaniyoruz.
"""
from datetime import datetime
from pathlib import Path

from .. import storage


def _bar(count, max_count, max_width_px=200):
    pct = int((count / max_count) * 100) if max_count else 0
    return (
        f'<div style="background:#e74c3c;height:14px;width:{pct}%;'
        f'max-width:{max_width_px}px;border-radius:3px;"></div>'
    )


def generate_html_report(output_path="data/report.html", db_path=None) -> str:
    stats = storage.summary_stats(db_path=db_path)
    alerts = storage.get_all_alerts(limit=50, db_path=db_path)
    max_ip_count = max((c for _, c in stats["top_ips"]), default=0)

    top_ip_rows = "".join(
        f"<tr><td>{ip}</td><td>{count}</td><td>{_bar(count, max_ip_count)}</td></tr>"
        for ip, count in stats["top_ips"]
    ) or "<tr><td colspan='3'>Henuz olay yok</td></tr>"

    severity_rows = "".join(
        f"<tr><td>{sev}</td><td>{count}</td></tr>"
        for sev, count in stats["by_severity"].items()
    ) or "<tr><td colspan='2'>Henuz alarm yok</td></tr>"

    alert_rows = "".join(
        f"<tr><td>{a['timestamp']}</td><td>{a['source_ip']}</td>"
        f"<td>{a['severity']}</td><td>{a['score']}</td><td>{a['reasons']}</td></tr>"
        for a in alerts
    ) or "<tr><td colspan='5'>Henuz alarm yok</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>Arachne Sentinel - Saldiri Raporu</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 2rem; background:#0f1115; color:#e6e6e6; }}
  h1 {{ color:#e74c3c; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
  th, td {{ border: 1px solid #333; padding: 8px; text-align: left; font-size: 14px; }}
  th {{ background:#1b1e26; }}
  .stat-cards {{ display:flex; gap:1rem; margin-bottom:2rem; }}
  .card {{ background:#1b1e26; padding:1rem 1.5rem; border-radius:8px; flex:1; }}
  .card .n {{ font-size:28px; font-weight:bold; color:#e74c3c; }}
</style>
</head>
<body>
<h1>Arachne Sentinel &mdash; Saldiri Raporu</h1>
<p>Olusturulma zamani: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="stat-cards">
  <div class="card"><div class="n">{stats['total_events']}</div>Toplam olay</div>
  <div class="card"><div class="n">{stats['total_alerts']}</div>Toplam alarm</div>
  <div class="card"><div class="n">{len(stats['top_ips'])}</div>Farkli kaynak IP</div>
</div>

<h2>Siddet Dagilimi</h2>
<table><tr><th>Siddet</th><th>Adet</th></tr>{severity_rows}</table>

<h2>En Aktif Kaynak IP'ler</h2>
<table><tr><th>IP</th><th>Olay Sayisi</th><th></th></tr>{top_ip_rows}</table>

<h2>Son Alarmlar</h2>
<table><tr><th>Zaman</th><th>IP</th><th>Siddet</th><th>Skor</th><th>Sebepler</th></tr>
{alert_rows}
</table>

</body>
</html>"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return str(out)
