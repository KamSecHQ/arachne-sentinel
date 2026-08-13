"""Canli izleme paneli (Flask): honeypot + WAF + tarama bulgularini tek
sayfada birlestirir. Sadece localhost'ta calistirin."""
from datetime import datetime, timezone

from flask import Flask, render_template_string

from .. import storage
from .report_generator import generate_html_report

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>Arachne Sentinel &mdash; Canli Panel</title>
<style>
:root{
  --bg:#0b0d12; --panel:#12151c; --panel-2:#171b24; --border:#242a38;
  --text:#e8eaf0; --muted:#8b93a7; --accent:#ff4d4f; --accent-2:#4da3ff;
  --ok:#2ecc71; --warn:#f5a623; --crit:#ff4d4f; --high:#ff7a45; --med:#f5a623; --low:#4da3ff;
}
*{box-sizing:border-box;}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Arial,sans-serif;
  background:radial-gradient(circle at top left,#151a24,var(--bg) 60%);
  color:var(--text); margin:0; padding:0 0 3rem 0;
}
.topbar{
  position:sticky; top:0; z-index:10;
  display:flex; align-items:center; justify-content:space-between;
  padding:1rem 2rem; background:rgba(11,13,18,0.9); backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border);
}
.brand{display:flex; align-items:center; gap:.6rem; font-size:1.15rem; font-weight:700;}
.brand .dot{width:9px;height:9px;border-radius:50%;background:var(--accent);box-shadow:0 0 8px var(--accent);}
.topbar .meta{color:var(--muted); font-size:.8rem; display:flex; gap:1.2rem; align-items:center;}
.topbar a{color:var(--accent-2); text-decoration:none; font-weight:600;}
.topbar a:hover{text-decoration:underline;}
.live{display:flex; align-items:center; gap:.4rem;}
.live .pulse{width:7px;height:7px;border-radius:50%;background:var(--ok);animation:pulse 1.6s infinite;}
@keyframes pulse{0%{opacity:1;}50%{opacity:.25;}100%{opacity:1;}}

.wrap{max-width:1180px; margin:0 auto; padding:0 2rem;}

.stat-cards{display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:1rem; margin:1.75rem 0;}
.card{
  background:linear-gradient(160deg,var(--panel-2),var(--panel));
  border:1px solid var(--border); border-radius:12px; padding:1.1rem 1.3rem;
  position:relative; overflow:hidden;
}
.card::before{content:"";position:absolute;top:0;left:0;width:3px;height:100%;background:var(--accent-card,var(--accent-2));}
.card.c-events::before{--accent-card:var(--accent-2);}
.card.c-alerts::before{--accent-card:var(--crit);}
.card.c-waf::before{--accent-card:var(--warn);}
.card.c-scan::before{--accent-card:var(--ok);}
.card .label{color:var(--muted); font-size:.72rem; text-transform:uppercase; letter-spacing:.06em; margin-bottom:.35rem;}
.card .n{font-size:1.9rem; font-weight:800; line-height:1;}
.card .sub{margin-top:.5rem; font-size:.75rem; color:var(--muted);}

.ratio-bar{height:8px; border-radius:6px; background:#232838; overflow:hidden; margin-top:.6rem; display:flex;}
.ratio-bar .blocked-seg{background:var(--crit);}
.ratio-bar .passed-seg{background:var(--ok);}

section{margin-top:2.5rem;}
h2{
  display:flex; align-items:center; gap:.5rem;
  font-size:1.02rem; letter-spacing:.02em; margin:0 0 .9rem 0;
  padding-bottom:.6rem; border-bottom:1px solid var(--border); color:var(--text);
}
h2 .count{
  margin-left:auto; font-size:.72rem; font-weight:600; color:var(--muted);
  background:var(--panel-2); border:1px solid var(--border); border-radius:20px; padding:.15rem .6rem;
}

.table-card{background:var(--panel); border:1px solid var(--border); border-radius:12px; overflow:hidden;}
table{border-collapse:collapse; width:100%; font-size:.82rem;}
thead th{
  text-align:left; padding:.7rem .9rem; background:var(--panel-2); color:var(--muted);
  font-weight:600; text-transform:uppercase; font-size:.68rem; letter-spacing:.05em;
  border-bottom:1px solid var(--border); white-space:nowrap;
}
tbody td{padding:.6rem .9rem; border-bottom:1px solid var(--border); vertical-align:top;}
tbody tr:last-child td{border-bottom:none;}
tbody tr:hover{background:rgba(255,255,255,0.02);}
.mono{font-family:"SF Mono",Menlo,Consolas,monospace; font-size:.78rem; color:var(--text);}
.muted{color:var(--muted);}
.empty-row td{padding:2rem; text-align:center; color:var(--muted); font-size:.85rem;}
.empty-row .hint{display:block; margin-top:.3rem; font-family:monospace; color:#5c6478; font-size:.75rem;}

.badge{
  display:inline-block; padding:.2rem .55rem; border-radius:20px; font-size:.7rem;
  font-weight:700; letter-spacing:.03em; text-transform:uppercase;
}
.badge-blocked{background:rgba(255,77,79,0.15); color:var(--crit); border:1px solid rgba(255,77,79,0.35);}
.badge-passed{background:rgba(46,204,113,0.12); color:var(--ok); border:1px solid rgba(46,204,113,0.3);}
.badge-critical{background:rgba(255,77,79,0.15); color:var(--crit); border:1px solid rgba(255,77,79,0.35);}
.badge-high{background:rgba(255,122,69,0.15); color:var(--high); border:1px solid rgba(255,122,69,0.35);}
.badge-medium{background:rgba(245,166,35,0.15); color:var(--med); border:1px solid rgba(245,166,35,0.35);}
.badge-low{background:rgba(77,163,255,0.15); color:var(--low); border:1px solid rgba(77,163,255,0.35);}
.badge-info{background:rgba(139,147,167,0.15); color:var(--muted); border:1px solid rgba(139,147,167,0.35);}

.reasons{color:var(--muted); font-size:.78rem; max-width:340px;}
footer{max-width:1180px; margin:3rem auto 0; padding:0 2rem; color:var(--muted); font-size:.75rem; text-align:center;}
</style></head>
<body>

<div class="topbar">
  <div class="brand"><span class="dot"></span> Arachne Sentinel &mdash; Canli Panel</div>
  <div class="meta">
    <span class="live"><span class="pulse"></span> 5sn'de bir otomatik yenilenir</span>
    <span>{{ now }}</span>
    <a href="/report">Statik rapor &rarr;</a>
  </div>
</div>

<div class="wrap">

<div class="stat-cards">
  <div class="card c-events">
    <div class="label">Honeypot Olayi</div>
    <div class="n">{{ honeypot_stats.total_events }}</div>
    <div class="sub">Son 10 dakikada gorulen toplam baglanti/istek</div>
  </div>
  <div class="card c-alerts">
    <div class="label">Honeypot Alarmi</div>
    <div class="n">{{ honeypot_stats.total_alerts }}</div>
    <div class="sub">Kural motorunun tetiklendigi olaylar</div>
  </div>
  <div class="card c-waf">
    <div class="label">WAF: Engellenen / Toplam</div>
    <div class="n">{{ waf_stats.blocked_requests }}/{{ waf_stats.total_requests }}</div>
    <div class="ratio-bar">
      <div class="blocked-seg" style="width:{{ waf_blocked_pct }}%"></div>
      <div class="passed-seg" style="width:{{ 100 - waf_blocked_pct }}%"></div>
    </div>
    <div class="sub">%{{ waf_blocked_pct }} istek engellendi</div>
  </div>
  <div class="card c-scan">
    <div class="label">Tarama Bulgusu</div>
    <div class="n">{{ scan_findings|length }}</div>
    <div class="sub">Bilinen zafiyet eslesmesi</div>
  </div>
</div>

<section>
  <h2>🛑 Honeypot &mdash; Son Alarmlar <span class="count">{{ alerts|length }}</span></h2>
  <div class="table-card">
  <table><thead><tr><th>Zaman</th><th>IP</th><th>Siddet</th><th>Skor</th><th>Sebepler</th></tr></thead><tbody>
  {% for a in alerts %}
  <tr><td class="mono muted">{{a.timestamp}}</td><td class="mono">{{a.source_ip}}</td>
  <td><span class="badge badge-{{a.severity}}">{{a.severity}}</span></td>
  <td class="mono">{{a.score}}</td><td class="reasons">{{a.reasons}}</td></tr>
  {% else %}
  <tr class="empty-row"><td colspan="5">Henuz alarm yok<span class="hint">honeypot calisiyor ve saldiri bekleniyor</span></td></tr>
  {% endfor %}
  </tbody></table>
  </div>
</section>

<section>
  <h2>📡 Honeypot &mdash; Son Olaylar <span class="count">{{ events|length }}</span></h2>
  <div class="table-card">
  <table><thead><tr><th>Zaman</th><th>IP</th><th>Servis</th><th>Tip</th><th>Veri (ilk 80 karakter)</th></tr></thead><tbody>
  {% for e in events %}
  <tr><td class="mono muted">{{e.timestamp}}</td><td class="mono">{{e.source_ip}}</td>
  <td>{{e.service}}</td><td class="mono">{{e.event_type}}</td>
  <td class="mono muted">{{ (e.payload or '')[:80] }}</td></tr>
  {% else %}
  <tr class="empty-row"><td colspan="5">Henuz olay yok<span class="hint">python main.py run</span></td></tr>
  {% endfor %}
  </tbody></table>
  </div>
</section>

<section>
  <h2>🧱 WAF &mdash; Son Istekler <span class="count">{{ waf_events|length }}</span></h2>
  <div class="table-card">
  <table><thead><tr><th>Zaman</th><th>IP</th><th>Metod</th><th>Yol</th><th>Skor</th><th>Durum</th><th>Sebepler</th></tr></thead><tbody>
  {% for w in waf_events %}
  <tr><td class="mono muted">{{w.timestamp}}</td><td class="mono">{{w.source_ip}}</td>
  <td class="mono">{{w.method}}</td><td class="mono">{{w.path}}</td><td class="mono">{{w.score}}</td>
  <td>{% if w.blocked %}<span class="badge badge-blocked">Engellendi</span>{% else %}<span class="badge badge-passed">Gecti</span>{% endif %}</td>
  <td class="reasons">{{w.reasons}}</td></tr>
  {% else %}
  <tr class="empty-row"><td colspan="7">Henuz WAF istegi yok<span class="hint">python main.py waf-demo</span></td></tr>
  {% endfor %}
  </tbody></table>
  </div>
</section>

<section>
  <h2>🔍 Zafiyet Tarama Bulgulari <span class="count">{{ scan_findings|length }}</span></h2>
  <div class="table-card">
  <table><thead><tr><th>Zaman</th><th>Hedef</th><th>Port</th><th>Servis</th><th>Siddet</th><th>Bulgu</th></tr></thead><tbody>
  {% for f in scan_findings %}
  <tr><td class="mono muted">{{f.timestamp}}</td><td class="mono">{{f.target}}</td>
  <td class="mono">{{f.port}}</td><td>{{f.service_guess}}</td>
  <td><span class="badge badge-{{f.severity}}">{{f.severity}}</span></td>
  <td class="reasons">{{f.finding}}</td></tr>
  {% else %}
  <tr class="empty-row"><td colspan="6">Henuz tarama yapilmadi<span class="hint">python main.py scan --host 127.0.0.1</span></td></tr>
  {% endfor %}
  </tbody></table>
  </div>
</section>

</div>
<footer>Arachne Sentinel &mdash; Topkapı Üniversitesi ekip projesi &middot; sadece izole/lab ortaminda kullanin</footer>
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

    total_waf = waf_stats.get("total_requests") or 0
    blocked_waf = waf_stats.get("blocked_requests") or 0
    waf_blocked_pct = round((blocked_waf / total_waf) * 100) if total_waf else 0

    return render_template_string(
        TEMPLATE, alerts=alerts, events=events, waf_events=waf_events,
        scan_findings=scan_findings, honeypot_stats=honeypot_stats, waf_stats=waf_stats,
        waf_blocked_pct=waf_blocked_pct,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


@app.route("/report")
def report():
    path = generate_html_report()
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_dashboard(host="127.0.0.1", port=5000):
    app.run(host=host, port=port, debug=False)
