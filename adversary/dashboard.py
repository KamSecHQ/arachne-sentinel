"""
Arachne Adversary — Saldiri Komuta Merkezi (Flask paneli).

Kirmizi-mavi ko-evrimi CANLI izleyebilecegin bir gosterge paneli. Yalnizca
localhost'ta calisir; motor loopback disina cikamaz (safety.py). Amac savunma
testidir.

  python -m adversary.dashboard          # panel, http://127.0.0.1:8099
"""
from __future__ import annotations

import os
from flask import Flask, jsonify, render_template

app = Flask(__name__, template_folder="templates")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.route("/")
def index():
    return render_template("arena.html")


@app.route("/panel")
def panel():
    return render_template("panel.html")


@app.route("/api/coevolve")
def api_coevolve():
    """Ko-evrim dongusunu (yalnizca yerel) calistirir ve tum turlari doner."""
    from . import coevolution
    rounds = int(os.environ.get("ADV_ROUNDS", "6"))
    res = coevolution.run(rounds=rounds)
    return jsonify(res)


@app.route("/api/campaign")
def api_campaign():
    """Tek bir saldiri kampanyasi (sabit savunmaya karsi)."""
    from . import engine
    res = engine.run_campaign(use_mutations=True)
    return jsonify({
        "totals": res["totals"], "metrics": res["metrics"],
        "per_category": res["per_category"], "per_mutation": res["per_mutation"],
        "bypassed": res["bypassed"][:12],
    })


def run(host: str = "127.0.0.1", port: int = 8099, open_browser: bool = True):
    url = f"http://{host}:{port}"
    print("=" * 60)
    print("  Arachne Adversary — Saldiri Komuta Merkezi")
    print(f"  {url}   (yalnizca yerel · loopback disi reddedilir)")
    print("=" * 60)
    if open_browser:
        try:
            import webbrowser, threading
            threading.Timer(1.2, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run()
