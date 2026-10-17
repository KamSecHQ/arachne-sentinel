"""
Faz 117 — Komuta merkezi kimlik dogrulamasi.

Onceden panelde hicbir kimlik dogrulama yoktu; docker-compose paneli
0.0.0.0:5001'de actigi icin agdaki herkes tum istihbarati gorebilir ve kontrol
uc noktalarini (Son Hat tatbikat/bekleme, analiz, asistan) cagirabilirdi.

Tasarim:
  * Panel anahtari: ARACHNE_PANEL_TOKEN ortam degiskeni; yoksa ilk calismada
    data/panel_token dosyasina 0600 izniyle rastgele uretilir (git disi).
  * Tek kullanimlik giris linki: sunucu acilisinda uretilir; tarayici/native
    pencere bununla acilir. 10 dk gecerli ve BIR kez kullanilir - URL gecmise
    ya da loglara dusse bile tekrar kullanilamaz.
  * Oturum: imzali Flask cerezi, HttpOnly + SameSite=Strict (CSRF'e karsi).
    Gizli anahtar surec basina rastgeledir: yeniden baslatinca oturum duser.
  * Kaba kuvvet korumasi: IP basina 5 hatali deneme / 5 dk -> 429. Anahtar
    karsilastirmasi sabit surelidir (hmac.compare_digest).
  * Muaf yollar: /login, /static/, /mesh/ingest (kendi HMAC imzasi var).
  * ARACHNE_PANEL_AUTH=0 yalnizca testler / izole lab icindir; varsayilan ACIK.
"""
import hmac
import os
import secrets
import threading
import time
from html import escape
from pathlib import Path

from flask import Response, jsonify, redirect, request, session

from .. import config

TOKEN_ENV = "ARACHNE_PANEL_TOKEN"
AUTH_ENV = "ARACHNE_PANEL_AUTH"
TOKEN_FILE = config.DATA_DIR / "panel_token"
CODE_TTL_SECONDS = 600
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 300
EXEMPT_PATHS = {"/login"}
EXEMPT_PREFIXES = ("/static/", "/mesh/ingest")

_lock = threading.Lock()
_codes = {}       # tek kullanimlik kod -> son gecerlilik (monotonic)
_failures = {}    # ip -> hatali deneme zamanlari (monotonic)


def enabled() -> bool:
    return os.environ.get(AUTH_ENV, "1") != "0"


def panel_token() -> str:
    """Ortam degiskeni > data/panel_token > yeni uret (0600, git disi)."""
    token = os.environ.get(TOKEN_ENV)
    if token:
        return token
    path = Path(TOKEN_FILE)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text().strip()
    token = secrets.token_urlsafe(32)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    return token


def issue_login_code() -> str:
    code = secrets.token_urlsafe(24)
    with _lock:
        _purge_codes()
        _codes[code] = time.monotonic() + CODE_TTL_SECONDS
    return code


def login_url(host: str, port: int, native: bool = False) -> str:
    # 0.0.0.0 bir dinleme adresidir, tarayicida acilamaz
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    return (f"http://{shown}:{port}/login?code={issue_login_code()}"
            + ("&native=1" if native else ""))


def _purge_codes():
    now = time.monotonic()
    for code in [c for c, exp in _codes.items() if exp <= now]:
        del _codes[code]


def _consume_code(code: str) -> bool:
    with _lock:
        _purge_codes()
        return _codes.pop(code, None) is not None


def check_token(candidate: str) -> bool:
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode(), panel_token().encode())


def _locked_out(ip: str) -> bool:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _failures.get(ip, []) if now - t < FAILURE_WINDOW_SECONDS]
        _failures[ip] = recent
        return len(recent) >= MAX_FAILURES


def _record_failure(ip: str):
    with _lock:
        _failures.setdefault(ip, []).append(time.monotonic())


def _reset_state():
    """Testler icin: kodlari ve hatali deneme sayaclarini temizler."""
    with _lock:
        _codes.clear()
        _failures.clear()


_PAGE = """<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Arachne Sentinel — Giris</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#05080d;
color:#d7e3f4;font:15px/1.5 system-ui,-apple-system,sans-serif}}
form{{width:min(360px,90vw);padding:28px;border:1px solid #1d2a3a;border-radius:12px;background:#0a1018}}
h1{{margin:0 0 6px;font-size:18px;letter-spacing:.08em}}
p{{margin:0 0 16px;color:#8aa0b8;font-size:13px}}
input{{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #2a3b50;
background:#05080d;color:#d7e3f4}}
button{{margin-top:12px;width:100%;padding:10px;border:0;border-radius:8px;background:#38bdf8;
color:#03131f;font-weight:600;cursor:pointer}}
.err{{color:#f87171}}
</style></head><body><form method="post" action="/login">
<h1>ARACHNE SENTINEL</h1>
<p>Komuta merkezi kimlik dogrulamasi. Anahtar: <code>ARACHNE_PANEL_TOKEN</code>
ya da <code>data/panel_token</code>.</p>
{message}
<input type="password" name="token" placeholder="Panel anahtari" autocomplete="current-password" autofocus>
<button type="submit">Giris</button></form></body></html>"""


def _page(message: str = "", status: int = 200) -> Response:
    msg = f'<p class="err">{escape(message)}</p>' if message else ""
    return Response(_PAGE.format(message=msg), status=status,
                    mimetype="text/html; charset=utf-8")


def _grant(native: bool):
    session.clear()                      # oturum sabitlemeye karsi
    session["panel_auth"] = True
    return redirect("/?mode=native" if native else "/")


def install(app):
    """Kimlik dogrulamayi, giris/cikis yollarini ve guvenlik basliklarini ekler."""
    if not app.secret_key:
        app.secret_key = secrets.token_bytes(32)
    app.config.update(SESSION_COOKIE_NAME="arachne_panel",
                      SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict")

    @app.before_request
    def _require_login():
        if not enabled():
            return None
        path = request.path
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            return None
        if session.get("panel_auth"):
            return None
        if path.startswith("/api/") or request.method != "GET":
            return jsonify({"error": "kimlik dogrulama gerekli"}), 401
        return redirect("/login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        ip = request.remote_addr or "?"
        if _locked_out(ip):
            return _page("Cok fazla hatali deneme. 5 dakika sonra tekrar deneyin.", 429)
        native = request.args.get("native") == "1"
        if request.method == "POST":
            if check_token(request.form.get("token", "")):
                return _grant(native)
            _record_failure(ip)
            return _page("Hatali anahtar.", 401)
        code = request.args.get("code")
        if code:
            if _consume_code(code):
                return _grant(native)
            _record_failure(ip)
            return _page("Giris linki gecersiz, suresi dolmus ya da kullanilmis.", 401)
        return _page()

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect("/login")

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response
