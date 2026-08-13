"""Canli izleme paneli (Flask): honeypot + WAF + tarama bulgularini tek
sayfada birlestirir. Sadece localhost'ta calistirin."""
from flask import Flask, render_template_string

from .. import storage
from .report_generator import generate_html_report

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Arachne Sentinel - Canli</title>
<style>
body{font-family:-apple-system,Arial;background:#0f1115;color:#e6e6e6;margin:2rem;}
table{border-collapse:collapse;width:100%;margin-bottom:1.5rem;}
th,td{border:1px solid #333;padding:6px;font-size:13px;}
th{background:#1b1e26;}
h1{color:#e74c3c;}
h2{margin-top:2rem;border-bottom:1px solid #333;padding-bottom:4px;}
a{color:#e6e6e6;}
.stat-cards{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap;}
.card{background:#1b1e26;padding:1rem 1.5rem;border-radius:8px;flex:1;min-width:160px;}
.card .n{font-size:26px;font-weight:bold;color:#e74c3c;}
.blocked{color:#e74c3c;font-weight:bold;}
.passed{color:#4caf50;}
</style></head><body>
<h1>Arachne Sentinel &mdash; Canli Panel</h1>
<p>Sayfa 5 saniyede bir otomatik yenilenir. Statik/indirilebilir rapor: <a href="/report">/report</a></p>

<div class="stat-cards">
  <div class="card"><div class="n">{{ honeypot_stats.total_events }}</div>Honeypot olayi</div>
  <div class="card"><div class="n">{{ honeypot_stats.total_alerts }}</div>Honeypot alarmi</div>
  <div class="card"><div class="n">{{ waf_stats.blocked_requests }}/{{ waf_stats.total_requests }}</div>WAF: engellenen/toplam istek</div>
  <div class="card"><div class="n">{{ scan_findings|length }}</div>Tarama bulgusu</div>
</div>

<h2>Honeypot &mdash; Son Alarmlar</h2>
<table><tr><th>Zaman</th><th>IP</th><th>Siddet</th><th>Skor</th><th>Sebepler</th></tr>
{% for a in alerts %}
<tr><td>{{a.timestamp}}</td><td>{{a.source_ip}}</td><td>{{a.severity}}</td>
<td>{{a.score}}</td><td>{{a.reasons}}</td></tr>
{% else %}
<tr><td colspan="5">Henuz alarm yok</td></tr>
{% endfor %}
</table>

<h2>Honeypot &mdash; Son Olaylar</h2>
<table><tr><th>Zaman</th><th>IP</th><th>Servis</th><th>Tip</th><th>Veri (ilk 80 karakter)</th></tr>
{% for e in events %}
<tr><td>{{e.timestamp}}</td><td>{{e.source_ip}}</td><td>{{e.service}}</td>
<td>{{e.event_type}}</td><td>{{ (e.payload or '')[:80] }}</td></tr>
{% else %}
<tr><td colspan="5">Henuz olay yok</td></tr>
{% endfor %}
</table>

<h2>WAF &mdash; Son Istekler</h2>
<table><tr><th>Zaman</th><th>IP</th><th>Metod</th><th>Yol</th><th>Skor</th><th>Durum</th><th>Sebepler</th></tr>
{% for w in waf_events %}
<tr><td>{{w.timestamp}}</td><td>{{w.source_ip}}</td><td>{{w.method}}</td>
<td>{{w.path}}</td><td>{{w.score}}</td>
<td class="{{ 'blocked' if w.blocked else 'passed' }}">{{ 'ENGELLENDI' if w.blocked else 'gecti' }}</td>
<td>{{w.reasons}}</td></tr>
{% else %}
<tr><td colspan="7">Henuz WAF istegi yok - once "python main.py waf-demo" calistirin</td></tr>
{% endfor %}
</table>

<h2>Zafiyet Tarama Bulgulari</h2>
<table><tr><th>Zaman</th><th>Hedef</th><th>Port</th><th>Servis</th><th>Siddet</th><th>Bulgu</th></tr>
{% for f in scan_findings %}
<tr><td>{{f.timestamp}}</td><td>{{f.target}}</td><td>{{f.port}}</td>
<td>{{f.service_guess}}</td><td>{{f.severity}}</td><td>{{f.finding}}</td></tr>
{% else %}
<tr><td colspan="6">Henuz tarama yapilmadi - once "python main.py scan --host 127.0.0.1" calistirin</td></tr>
{% endfor %}
</table>

</body></html>
"""


@app.route("/")
def index():
    alerts = storage.get_all_alerts(limit=30)
    events = storage.get_recent_events(since_seconds=600)[:50]
    waf_events = storage.get_waf_events(limit=30)
    scan_findings = storage.get_scan_findings(limit=30)
    honeypot_stats = storage.summary_stats()
    waf_stats = storage.waf_summary_stats()
    return render_template_string(
        TEMPLATE, alerts=alerts, events=events, waf_events=waf_events,
        scan_findings=scan_findings, honeypot_stats=honeypot_stats, waf_stats=waf_stats,
    )


@app.route("/report")
def report():
    path = generate_html_report()
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_dashboard(host="127.0.0.1", port=5000):
    app.run(host=host, port=port, debug=False)
