"""Canli izleme paneli (Flask): honeypot + WAF + tarama bulgularini tek
sayfada birlestirir. Sadece localhost'ta calistirin."""
import random
import re
import string
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template_string

from .. import storage
from ..native import signature_engine
from .report_generator import generate_html_report

app = Flask(__name__)

GITHUB_URL = "https://github.com/KamSecHQ/arachne-sentinel"


def _count_tests() -> int:
    """tests/ altindaki `def test_...` satirlarini sayar - pytest'i
    calistirmadan, hizli ve her zaman guncel bir sayi verir."""
    tests_dir = Path(__file__).resolve().parents[2] / "tests"
    try:
        total = 0
        for path in tests_dir.glob("test_*.py"):
            total += len(re.findall(r"^def test_", path.read_text(encoding="utf-8"), re.M))
        return total
    except OSError:
        return 0


def _naive_python_find(hay: str, needle: str) -> int:
    """az_find ile birebir ayni naif algoritma, saf Python'da (dogru kiyaslama icin)."""
    n, m = len(hay), len(needle)
    if m == 0:
        return 0
    if m > n:
        return -1
    for i in range(n - m + 1):
        if hay[i:i + m] == needle:
            return i
    return -1


def _quick_benchmark():
    """Sayfa her yenilendiginde calisan, hafif (birkaç ms) canli bir olcum.
    Tam istatistiksel titizlikte degil (bkz. scripts/benchmark_native_scan.py
    daha ciddi bir kiyaslama icin) ama gercek zamanli, gercek sayilar verir."""
    rng = random.Random(7)
    needle = "union select"
    rows = []
    for size, repeat in ((2_000, 40), (20_000, 8)):
        haystack = "".join(rng.choice(string.ascii_lowercase) for _ in range(size)) + needle

        t0 = time.perf_counter()
        for _ in range(repeat):
            _naive_python_find(haystack, needle)
        naive_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        for _ in range(repeat):
            signature_engine.find(haystack, needle)
        native_ms = (time.perf_counter() - t0) * 1000

        speedup = round(naive_ms / native_ms, 1) if native_ms > 0 else 0
        rows.append({
            "size": size, "naive_ms": round(naive_ms, 2),
            "native_ms": round(native_ms, 3), "speedup": speedup,
        })
    return rows

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

.hero{
  margin-top:2rem; padding:1.6rem 1.8rem; border-radius:16px;
  background:linear-gradient(135deg,rgba(255,77,79,0.08),rgba(77,163,255,0.06) 60%,transparent);
  border:1px solid var(--border);
}
.hero h1{margin:0 0 .3rem 0; font-size:1.7rem; letter-spacing:-.01em;}
.hero p{margin:0 0 1.1rem 0; color:var(--muted); font-size:.9rem; max-width:640px;}
.phase-badges{display:flex; flex-wrap:wrap; gap:.55rem; margin-bottom:1rem;}
.phase{
  display:flex; align-items:center; gap:.4rem; font-size:.78rem; font-weight:600;
  padding:.4rem .8rem; border-radius:20px; background:rgba(46,204,113,0.1);
  border:1px solid rgba(46,204,113,0.3); color:var(--ok);
}
.phase .n{opacity:.7; font-weight:700;}
.phase.phase-pending{background:rgba(139,147,167,0.08); border-color:rgba(139,147,167,0.25); color:var(--muted);}
.hero-meta{display:flex; flex-wrap:wrap; gap:.55rem;}
.pill{
  font-size:.75rem; font-weight:600; padding:.35rem .75rem; border-radius:20px;
  background:var(--panel-2); border:1px solid var(--border); color:var(--text);
}
.pill.link{color:var(--accent-2); text-decoration:none;}
.pill.link:hover{text-decoration:underline;}

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
.card.c-native::before{--accent-card:#a78bfa;}
.card.c-mtd::before{--accent-card:#2dd4bf;}
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

<div class="hero">
  <h1>Arachne Sentinel</h1>
  <p>Honeypot + acilanabilir kural motoru + WAF + otonom zafiyet tarayici + ML siniflandirici
     + native ARM64 assembly cekirdegi ile uctan uca test edilmis bir saldiri tespit sistemi.</p>
  <div class="phase-badges">
    <span class="phase">&check; Faz 1 <span class="n">Honeypot</span></span>
    <span class="phase">&check; Faz 2 <span class="n">WAF / Tarayici / ML</span></span>
    <span class="phase">&check; Faz 3 <span class="n">Native ARM64 Assembly</span></span>
    <span class="phase {{ '' if mtd_stats.total_rotations else 'phase-pending' }}">{{ '&check;' if mtd_stats.total_rotations else '○' }} Faz 4 <span class="n">Moving Target Defense</span></span>
  </div>
  <div class="hero-meta">
    <span class="pill">{{ test_count }} birim testi</span>
    <span class="pill">{{ 'Native cekirdek AKTIF' if native_active else 'Native cekirdek pasif (Python yedegi)' }}</span>
    <span class="pill">Topkapı Üniversitesi ekip projesi</span>
    <a class="pill link" href="{{ github_url }}" target="_blank" rel="noopener">Kaynak kod (GitHub) &rarr;</a>
  </div>
</div>

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
  <div class="card c-native">
    <div class="label">Native ARM64 Cekirdek</div>
    <div class="n" style="font-size:1.5rem">{{ 'AKTIF' if native_active else 'PASIF' }}</div>
    <div class="sub">{{ native_status }}</div>
  </div>
  <div class="card c-mtd">
    <div class="label">Hayalet Admin (Faz 4)</div>
    <div class="n" style="font-size:1.5rem">{{ ':' ~ ghost_admin_port if ghost_admin_port else 'baslatilmadi' }}</div>
    <div class="sub">{{ mtd_stats.total_rotations }} rotasyon kaydedildi &mdash; python main.py mtd-demo</div>
  </div>
</div>

<section>
  <h2>⚙️ Faz 3 &mdash; Native ARM64 Assembly Cekirdegi</h2>
  <div class="table-card" style="padding:1.1rem 1.3rem;">
    <p class="reasons" style="max-width:100%; margin:0 0 1rem 0;">
      Honeypot kural motorunun kullandigi imza taramasi
      (<code>rule_known_signature</code>), elle yazilmis ARM64 assembly ile
      (<code>arachne/native/arm64/fast_scan.s</code>) hizlandirilir; native
      kutuphane yoksa (bu ortamda oldugu gibi) otomatik olarak birebir ayni
      sonucu ureten bir Python yedegine duser. Asagidaki sayilar bu sayfa her
      yenilendiginde canli olarak hesaplanir (bkz.
      <code>scripts/benchmark_native_scan.py</code> daha kapsamli bir
      kiyaslama icin).
    </p>
    <table><thead><tr><th>Haystack boyutu</th><th>El-yazimi Python dongusu</th>
    <th>Native ARM64 / yedek</th><th>Fark</th></tr></thead><tbody>
    {% for row in bench_rows %}
    <tr><td class="mono">{{ row.size }} byte</td><td class="mono">{{ row.naive_ms }} ms</td>
    <td class="mono">{{ row.native_ms }} ms</td><td class="mono">{{ row.speedup }}x</td></tr>
    {% endfor %}
    </tbody></table>
  </div>
</section>

<section>
  <h2>👻 Faz 4 &mdash; Moving Target Defense <span class="count">{{ mtd_rotations|length }}</span></h2>
  <div class="table-card" style="padding:1.1rem 1.3rem;">
    <p class="reasons" style="max-width:100%; margin:0 0 1rem 0;">
      Korunan yuzeyin kimligi zamanla degisir: honeypot banner'lari periyodik
      rotasyona ugrar, "hayalet admin" paneli gercekten port degistirir, ve
      lab-ici bir "hayalet DNS" yanitlayicisi ayni isim icin farkli IP
      dondurur. Amac gercek internete karsi anonimlik iddiasi degil,
      saldirganin parmak izi cikarma/hedef sabitleme surecini zorlastirmak.
      Baslatmak icin: <code>python main.py mtd-demo</code>
    </p>
    <table><thead><tr><th>Zaman</th><th>Bilesen</th><th>Eski Kimlik</th><th>Yeni Kimlik</th><th>Sebep</th></tr></thead><tbody>
    {% for r in mtd_rotations %}
    <tr><td class="mono muted">{{ r.timestamp }}</td><td class="mono">{{ r.component }}</td>
    <td class="mono muted">{{ r.old_identity or '&mdash;' }}</td>
    <td class="mono">{{ r.new_identity }}</td><td class="reasons">{{ r.reason }}</td></tr>
    {% else %}
    <tr class="empty-row"><td colspan="5">Henuz rotasyon yok<span class="hint">python main.py mtd-demo</span></td></tr>
    {% endfor %}
    </tbody></table>
  </div>
</section>

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
    mtd_rotations = storage.get_mtd_rotations(limit=30)
    mtd_stats = storage.mtd_summary_stats()

    total_waf = waf_stats.get("total_requests") or 0
    blocked_waf = waf_stats.get("blocked_requests") or 0
    waf_blocked_pct = round((blocked_waf / total_waf) * 100) if total_waf else 0

    ghost_admin_port = next(
        (r["new_identity"] for r in mtd_rotations if r["component"] == "port:ghost-admin"),
        None,
    )

    return render_template_string(
        TEMPLATE, alerts=alerts, events=events, waf_events=waf_events,
        scan_findings=scan_findings, honeypot_stats=honeypot_stats, waf_stats=waf_stats,
        waf_blocked_pct=waf_blocked_pct,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        test_count=_count_tests(),
        native_active=signature_engine.NATIVE_ENGINE_ACTIVE,
        native_status=signature_engine.engine_status(),
        github_url=GITHUB_URL,
        bench_rows=_quick_benchmark(),
        mtd_rotations=mtd_rotations,
        mtd_stats=mtd_stats,
        ghost_admin_port=ghost_admin_port,
    )


@app.route("/report")
def report():
    path = generate_html_report()
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_dashboard(host="127.0.0.1", port=5000):
    app.run(host=host, port=port, debug=False)
