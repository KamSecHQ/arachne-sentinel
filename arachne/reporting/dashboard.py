"""Basit canli izleme paneli (Flask). Sadece localhost'ta calistirin."""
from flask import Flask, render_template_string

from .. import storage
from .report_generator import generate_html_report

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Arachne Sentinel - Canli</title>
<style>
body{font-family:Arial;background:#0f1115;color:#e6e6e6;margin:2rem;}
table{border-collapse:collapse;width:100%;margin-bottom:2rem;}
th,td{border:1px solid #333;padding:6px;font-size:13px;}
th{background:#1b1e26;}
h1{color:#e74c3c;}
a{color:#e6e6e6;}
</style></head><body>
<h1>Arachne Sentinel &mdash; Canli Olaylar</h1>
<p>Sayfa 5 saniyede bir otomatik yenilenir. Statik rapor: <a href="/report">/report</a></p>
<h2>Son Alarmlar</h2>
<table><tr><th>Zaman</th><th>IP</th><th>Siddet</th><th>Skor</th><th>Sebepler</th></tr>
{% for a in alerts %}
<tr><td>{{a.timestamp}}</td><td>{{a.source_ip}}</td><td>{{a.severity}}</td>
<td>{{a.score}}</td><td>{{a.reasons}}</td></tr>
{% endfor %}
</table>
<h2>Son Olaylar</h2>
<table><tr><th>Zaman</th><th>IP</th><th>Servis</th><th>Tip</th><th>Veri (ilk 80 karakter)</th></tr>
{% for e in events %}
<tr><td>{{e.timestamp}}</td><td>{{e.source_ip}}</td><td>{{e.service}}</td>
<td>{{e.event_type}}</td><td>{{ (e.payload or '')[:80] }}</td></tr>
{% endfor %}
</table>
</body></html>
"""


@app.route("/")
def index():
    alerts = storage.get_all_alerts(limit=30)
    events = storage.get_recent_events(since_seconds=600)[:50]
    return render_template_string(TEMPLATE, alerts=alerts, events=events)


@app.route("/report")
def report():
    path = generate_html_report()
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_dashboard(host="127.0.0.1", port=5000):
    app.run(host=host, port=port, debug=False)
