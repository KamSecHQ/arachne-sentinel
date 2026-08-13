"""Canli izleme paneli (Flask): honeypot + WAF + tarama bulgularini tek
sayfada birlestirir. Sadece localhost'ta calistirin.

Sayfa `templates/dashboard.html` + `static/css/style.css` +
`static/js/dashboard.js` uzerinden render edilir; ilk yukleme normal
sunucu-taraf render (SSR), sonrasinda tarayici `/api/live` uzerinden
birkac saniyede bir GERCEK verileri poll edip sayfayi (tam yenileme
yapmadan) canli gunceller - tehdit radari ve canli akis paneli de ayni
gercek verilerle tetiklenir, hicbir sahte/simule veri uretilmez."""
import random
import re
import string
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template

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



def _gather_dashboard_data():
    """Panel + /api/live tarafindan ortak kullanilan, GERCEK veritabani
    verisini toplayan tek yer (tekrar etmesin diye)."""
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

    return {
        "alerts": alerts,
        "events": events,
        "waf_events": waf_events,
        "scan_findings": scan_findings,
        "honeypot_stats": honeypot_stats,
        "waf_stats": waf_stats,
        "waf_blocked_pct": waf_blocked_pct,
        "mtd_rotations": mtd_rotations,
        "mtd_stats": mtd_stats,
        "ghost_admin_port": ghost_admin_port,
    }


@app.route("/")
def index():
    data = _gather_dashboard_data()
    return render_template(
        "dashboard.html",
        **data,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        test_count=_count_tests(),
        native_active=signature_engine.NATIVE_ENGINE_ACTIVE,
        native_status=signature_engine.engine_status(),
        github_url=GITHUB_URL,
        bench_rows=_quick_benchmark(),
    )


@app.route("/api/live")
def api_live():
    """Tarayicinin birkac saniyede bir poll ettigi, tamamen GERCEK
    verilerle dolu JSON uc noktasi - canli radar/akis/sayaclar burayi besler."""
    data = _gather_dashboard_data()
    data["bench_rows"] = _quick_benchmark()
    return jsonify(data)


@app.route("/report")
def report():
    path = generate_html_report()
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_dashboard(host="127.0.0.1", port=5000):
    app.run(host=host, port=port, debug=False)
