"""Canli izleme paneli (Flask): honeypot + WAF + tarama bulgularini tek
sayfada birlestirir. Sadece localhost'ta calistirin.

Sayfa `templates/dashboard.html` + `static/css/style.css` +
`static/js/dashboard.js` uzerinden render edilir; ilk yukleme normal
sunucu-taraf render (SSR), sonrasinda tarayici `/api/live` uzerinden
birkac saniyede bir GERCEK verileri poll edip sayfayi (tam yenileme
yapmadan) canli gunceller - tehdit radari ve canli akis paneli de ayni
gercek verilerle tetiklenir, hicbir sahte/simule veri uretilmez."""
import logging
import os
import random
import re
import string
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template

from .. import storage
from ..native import signature_engine
from . import command_center
from .report_generator import generate_html_report

logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Onbellek kontrolu -------------------------------------------------------
# Sorun: tarayici eski CSS/JS'i onbellekten servis edip (HTTP 304) yeni
# tasarimi hic gormeyebiliyor - siyah ekrana yol aciyordu. Lab paneli oldugu
# icin statik dosyalari HIC onbelleklemiyoruz; her yenileme taze dosya ceker.
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def _no_cache_static(response):
    """Statik varliklar (CSS/JS) icin onbellegi tamamen kapat."""
    from flask import request
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# Faz 9: sensor agi toplayicisini panele bagla. Boylece tek bir surecte
# hem komuta merkezi hem toplayici calisir (kucuk lab kurulumu); gercek
# dagitik senaryoda ayri calistirilabilir - kod degismeden.
try:
    from ..mesh.collector import mesh_bp
    app.register_blueprint(mesh_bp)
except Exception:  # pragma: no cover
    logging.getLogger(__name__).warning("Mesh toplayicisi yuklenemedi", exc_info=True)

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

    alerts_timeline = storage.alerts_timeline(buckets=12, bucket_minutes=5)

    # --- Faz 7: SOAR ---
    soar_actions = storage.get_soar_actions(limit=40)
    soar_stats = storage.soar_summary_stats()
    try:
        from ..soar import blocklist
        active_blocks = blocklist.active_blocks()
    except Exception:
        active_blocks = []
    soar_stats["active_blocks"] = len(active_blocks)

    # --- Faz 9: sensor agi ---
    sensors = storage.get_sensors()
    mesh_stats = storage.mesh_summary_stats()

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
        "alerts_timeline": alerts_timeline,
        "soar_actions": soar_actions,
        "soar_stats": soar_stats,
        "active_blocks": active_blocks,
        "sensors": sensors,
        "mesh_stats": mesh_stats,
    }


def _gather_intel_data():
    """Faz 5/6/8 verileri - hesaplama maliyeti daha yuksek oldugu icin
    ayri bir uc noktada (/api/intel) sunulur; canli panel dongusunu
    yavaslatmaz."""
    from ..ai import report_writer

    try:
        data = report_writer.situation_report()
    except Exception:
        logger.exception("Durum raporu uretilemedi")
        return {
            "report": None, "profiles": [], "campaigns": [],
            "llm_status": {"mode_tr": "hata"},
        }
    return data


@app.route("/")
def index():
    """Faz 20: yeniden tasarlanan tek-sayfa komuta merkezi (SPA).

    Sayfa artik tek bir dev kaydirmali blok degil; sol menuden gecis yapilan
    temiz gorunumlerden olusur. Icerik `/api/*` uc noktalarindan canli gelir."""
    return render_template(
        "app.html",
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        test_count=_count_tests(),
        native_active=signature_engine.NATIVE_ENGINE_ACTIVE,
        native_status=signature_engine.engine_status(),
        github_url=GITHUB_URL,
    )


@app.route("/api/live")
def api_live():
    """Tarayicinin birkac saniyede bir poll ettigi, tamamen GERCEK
    verilerle dolu JSON uc noktasi - canli radar/akis/sayaclar burayi besler."""
    data = _gather_dashboard_data()
    data["bench_rows"] = _quick_benchmark()
    data["dome"] = command_center.build_dome_state()
    data["attack_map"] = command_center.build_attack_map()
    data["layer_health"] = command_center.build_layer_health()
    return jsonify(data)


@app.route("/api/state")
def api_state():
    """Faz 20: SPA'nin hizli poll dongusu (4sn). Tum canli/sayac verisi -
    overview, kubbe, harita, katman sagligi, SOAR/aktif savunma/sensor."""
    from . import aggregator

    live = _gather_dashboard_data()
    live["bench_rows"] = _quick_benchmark()
    return jsonify({
        "overview": aggregator.overview(),
        "dome": command_center.build_dome_state(),
        "attack_map": command_center.build_attack_map(),
        "defense_layers": aggregator.defense_layers(),
        "active_defense": aggregator.active_defense_view(),
        "live": live,
        "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    })


@app.route("/api/deep")
def api_deep():
    """Faz 20: SPA'nin yavas poll dongusu (20sn). Pahali hesaplamalar -
    tehdit istihbarati, risk, saldiri grafikleri, kural motoru, butunluk."""
    from . import aggregator

    try:
        threats = aggregator.threat_intel_view()
    except Exception:
        logger.exception("Tehdit istihbarati uretilemedi")
        threats = {"report": None, "profiles": [], "campaigns": []}
    try:
        rules = aggregator.rules_and_integrity()
    except Exception:
        logger.exception("Kural/butunluk verisi uretilemedi")
        rules = {"rules": [], "integrity": {}, "synthesized_signatures": {}}
    try:
        adaptive = aggregator.adaptive_view()
    except Exception:
        logger.exception("Adaptif savunma verisi uretilemedi")
        adaptive = {}
    try:
        metrics = aggregator.metrics_view()
    except Exception:
        logger.exception("Metrik verisi uretilemedi")
        metrics = {}
    try:
        correlation = aggregator.correlation_view()
    except Exception:
        logger.exception("Korelasyon verisi uretilemedi")
        correlation = {}
    try:
        replay = aggregator.replay_view()
    except Exception:
        logger.exception("Replay verisi uretilemedi")
        replay = {}

    return jsonify({"threats": threats, "rules_integrity": rules, "adaptive": adaptive,
                    "metrics": metrics, "correlation": correlation, "replay": replay})


@app.route("/api/intel")
def api_intel():
    """Faz 5/6/8: tersine muhendislik, profilleme, kampanya korelasyonu ve
    AI durum raporu. Canli dongoden ayri, daha seyrek cagrilir."""
    return jsonify(_gather_intel_data())


# --- SON HAT KALESI (Yer Alti Ultra Savunma) — GERCEK motor ------------------
# Tek bir kale ornegi tum surec boyunca yasar; devreye girme durumu poll'lar
# arasinda korunur. Kubbe delinince (should_engage) ya da tatbikatla devreye
# girer; 50 GERCEK katman + HAYALET hiper-MTD calisir. Tamamen savunma.
_FORTRESS = None


def _get_fortress():
    global _FORTRESS
    if _FORTRESS is None:
        from ..lastline import LastLineFortress
        _FORTRESS = LastLineFortress()
    return _FORTRESS


@app.route("/api/fortress")
def api_fortress():
    """Son Hat kalesinin GERCEK durumu. Kubbe sinyallerinden ihlal karari
    verilir; esik asilinca kale otomatik devreye girer (kimlik 100 ms'de
    doner, 50 katman muhurlenir). Rastgele degil — deterministik, dogrulanabilir."""
    from ..lastline import context_from_live

    fort = _get_fortress()
    ctx = context_from_live()
    should, reason = fort.should_engage(ctx)
    if should and not fort.engaged:
        fort.engage(ctx)              # kubbe delindi -> son hat devreye
    elif not should and fort.engaged and not ctx.extra.get("drill"):
        # esik altina dondu ve manuel tatbikat degil -> beklemeye al
        pass                          # devreye girmis kale beklemede birakilmaz
    st = fort.status()
    st["should_engage"] = should
    st["engage_reason"] = reason
    return jsonify(st)


@app.route("/api/fortress/engage", methods=["POST"])
def api_fortress_engage():
    """Tatbikat: kaleyi elle devreye al (kubbe delinmis gibi). Savunma
    sistemine dokunmaz — sadece son hat motorunu baslatir ve tepki suresini olcer."""
    from ..lastline import context_from_live

    fort = _get_fortress()
    ctx = context_from_live(drill=True)
    fort.engage(ctx)
    return jsonify(fort.status())


@app.route("/api/fortress/standby", methods=["POST"])
def api_fortress_standby():
    """Kaleyi beklemeye al (tatbikat sonrasi)."""
    fort = _get_fortress()
    fort.standby()
    return jsonify(fort.status())


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Tek bir yuku tersine muhendislik + AI analistine gonderir.

    GUVENLIK: gelen yuk hicbir zaman calistirilmaz, bir kabuga ya da
    sorguya gecirilmez - sadece metin olarak analiz edilir. AI katmanina
    giderken datamarking uygulanir (bkz. arachne/ai/sanitizer.py)."""
    from flask import request
    from ..ai import report_writer

    body = request.get_json(silent=True) or {}
    payload = str(body.get("payload", ""))[:4000]
    if not payload.strip():
        return jsonify({"error": "Bos yuk"}), 400

    try:
        result = report_writer.analyze_attack(payload)
        # Faz 36: aciklanabilir tespit (neden + pattern + confidence + MITRE)
        try:
            from ..reverse import explainer
            result["explanation"] = explainer.explain_detection(payload)
        except Exception:
            logger.exception("Aciklanabilir tespit uretilemedi")
        return jsonify(result)
    except Exception:
        logger.exception("Yuk analizi basarisiz")
        return jsonify({"error": "Analiz sirasinda hata olustu"}), 500


@app.route("/api/assistant", methods=["POST"])
def api_assistant():
    """Faz 48: AI Komuta Asistani. Dogal dilde soru -> gercek veriden Turkce yanit.

    GUVENLIK: salt-okunur. Asistan yalnizca durum raporlar; hicbir mudahale
    eylemi baslatmaz, hicbir dis sisteme dokunmaz."""
    from flask import request
    from ..ai import assistant
    body = request.get_json(silent=True) or {}
    question = str(body.get("question", ""))[:500]
    if not question.strip():
        return jsonify({"error": "Bos soru"}), 400
    try:
        return jsonify(assistant.answer(question))
    except Exception:
        logger.exception("Asistan yaniti uretilemedi")
        return jsonify({"intent": "error",
                        "text_tr": "Yanit uretilirken bir hata olustu.",
                        "spoken_tr": "Bir hata olustu.", "data": {}}), 500


@app.route("/api/stix")
def api_stix():
    """Bulgulari STIX 2.1 Bundle olarak disari aktarir.

    Bu uc nokta, sistemin ciktisinin baska guvenlik platformlari
    (MISP, OpenCTI, ticari SIEM'ler) tarafindan okunabilir oldugunu
    kanitlar - birlikte calisabilirlik (interoperability) gostergesi."""
    from ..intel import stix_export

    data = _gather_intel_data()
    bundle = stix_export.build_stix_bundle(data["profiles"], data["campaigns"])
    response = jsonify(bundle)
    response.headers["Content-Disposition"] = "attachment; filename=arachne-stix-bundle.json"
    return response


@app.route("/report")
def report():
    path = generate_html_report()
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.route("/ai-report")
def ai_report():
    """AI analist raporunu Markdown olarak dondurur (indirilebilir)."""
    from flask import Response
    from ..ai import report_writer

    try:
        path = report_writer.generate_ai_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
    except Exception:
        logger.exception("AI raporu uretilemedi")
        content = "# Rapor uretilemedi\n\nAyrintilar icin sunucu kayitlarina bakin."

    return Response(content, mimetype="text/markdown; charset=utf-8")


def run_dashboard(host="127.0.0.1", port=5000, cinematic=True, open_browser=True):
    # Sinematik acilis dizisi (kozmetik; --no-intro ile kapatilabilir).
    if cinematic:
        try:
            from . import boot_sequence
            boot_sequence.play(host, port, open_browser=open_browser,
                               voice=True, fast=bool(os.environ.get("ARACHNE_FAST_BOOT")))
        except Exception:
            logger.exception("Acilis dizisi oynatilamadi (kozmetik, atlaniyor)")
    app.run(host=host, port=port, debug=False)
