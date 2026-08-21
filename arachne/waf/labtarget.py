"""
LAB HEDEFI — bilincli olarak zafiyetli, KUCUK, tamamen YEREL/HAFIZADA calisan
bir web uygulamasi. Amaci: Arachne WAF'in gercek bir saldiriyi ne olcude
engelledigini OLCULEBILIR sekilde gostermek.

Bes gercek zafiyet sinifi barindirir:
  * /search  — SQL Injection (string birlestirme ile sorgu)
  * /comment — Yansitilmis XSS (kacislama yok, ham HTML)
  * /file    — Path Traversal (kullanici yolu dogrudan "okunur")
  * /ping    — Command Injection (GUVENLI taklit kabuk — asagida aciklama)
  * /render  — SSTI (Jinja render_template_string, sunucu-tarafi sablon)

GUVENLIK / DURUSTLUK:
  - Veritabani in-memory SQLite; hicbir gercek dosya/sistem/ag baglantisi yok.
  - /file gercek diskten OKUMAZ; sabit, sahte bir "dosya sistemi" sozlugunden
    servis eder — yani traversal "calisir" (ogretici) ama gercek dosya sizmaz.
  - /ping GERCEK kabuk CALISTIRMAZ; enjeksiyonu tespit edip whitelist'li,
    sabit lab ciktisi doner (whoami/id/cat...). Boylece enjeksiyon "basarili"
    gorunur ama keyfi komut asla calismaz — canli proxy'de bile guvenli.
  - /render Jinja ile GERCEKTEN degerlendirir ({{7*7}} -> 49); yalnizca izole,
    ephemeral lab konteynerinde calistirilmalidir.

Bu uygulama SADECE kendi izole lab ortaminizda calistirilmalidir.
"""
from __future__ import annotations

import re
import sqlite3

from flask import Flask, request, render_template_string

from .middleware import WAFMiddleware

# --- sahte, sadece-hafiza "dosya sistemi" (traversal hedefi) -----------------
_FAKE_FS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nemir:x:1000:1000::/home/emir:/bin/zsh\n",
    "/etc/shadow": "root:$6$LABONLY$sahte-hash:19000:0:99999:7:::\n",
    "app/public/welcome.txt": "Lab hedefine hos geldiniz. Bu dosya herkese aciktir.\n",
    "app/public/logo.txt": "ARACHNE-SENTINEL-LAB\n",
}
_PUBLIC_PREFIX = "app/public/"

# --- guvenli taklit kabuk (command injection hedefi) -------------------------
_SHELL_OUTPUTS = {
    "whoami": "labuser",
    "id": "uid=1000(labuser) gid=1000(labuser) groups=1000(labuser)",
    "uname": "Linux arachne-lab 6.1.0-lab x86_64 GNU/Linux",
    "hostname": "arachne-lab",
    "cat /etc/passwd": _FAKE_FS["/etc/passwd"].strip(),
    "ls": "app  bin  etc  home  var",
}
_INJECT_META = re.compile(r"[;&|`]|\$\(")


def _mock_shell(host: str) -> tuple[str, bool]:
    """GERCEK kabuk CALISTIRMAZ. `ping <host>` taklidi; eger girdide kabuk
    meta-karakteri varsa enjekte edilen komutu whitelist'ten yanitlar.
    Doner: (cikti, enjeksiyon_basarili_mi)."""
    base = f"PING {host.split(';')[0].split('&')[0].split('|')[0].strip()} : 56 data bytes"
    if not _INJECT_META.search(host):
        return base + "\n64 bytes: icmp_seq=0 ttl=64 time=0.05 ms", False
    # enjekte edilen komut parcasini ayikla ve whitelist'ten yanitla
    tail = re.split(r"[;&|]|\$\(|`", host, maxsplit=1)
    injected = tail[-1].strip().strip("`) ")
    for cmd, out in _SHELL_OUTPUTS.items():
        if injected.startswith(cmd):
            return base + "\n" + out, True     # enjeksiyon "basarili"
    return base + "\n(taklit kabuk: bilinmeyen komut, calistirilmadi)", True


def _make_app() -> Flask:
    app = Flask(__name__)

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
    conn.executemany(
        "INSERT INTO users (name, secret) VALUES (?, ?)",
        [("emirhan", "gizli-not-1"), ("arkadasi", "gizli-not-2"),
         ("admin", "cok-gizli-admin-notu")],
    )
    conn.commit()
    app.config["_conn"] = conn

    @app.route("/")
    def index():
        return (
            "<h2>Arachne Sentinel — LAB Hedefi (bilincli zafiyetli)</h2>"
            "<p>Tamamen yerel/hafizada. Gercek bir sistem degildir.</p>"
            "<ul>"
            "<li><code>/search?name=emirhan</code> — SQLi</li>"
            "<li><code>/comment?text=merhaba</code> — XSS</li>"
            "<li><code>/file?path=app/public/welcome.txt</code> — Path Traversal</li>"
            "<li><code>/ping?host=127.0.0.1</code> — Command Injection</li>"
            "<li><code>/render?name=dunya</code> — SSTI</li>"
            "</ul>"
        )

    @app.route("/search")
    def search():
        name = request.args.get("name", "")
        # KASITLI GUVENSIZ: parametreli sorgu yerine string birlestirme
        query = f"SELECT id, name FROM users WHERE name = '{name}'"
        try:
            rows = app.config["_conn"].execute(query).fetchall()
        except sqlite3.Error as e:
            return f"<p>Sorgu hatasi: {e}</p><pre>{query}</pre>", 200
        items = "".join(f"<li>id={r[0]} name={r[1]}</li>" for r in rows)
        return f"<p>Sorgu: <code>{query}</code></p><ul>{items}</ul>"

    @app.route("/comment")
    def comment():
        text = request.args.get("text", "")
        # KASITLI GUVENSIZ: kacislama yok -> yansitilmis XSS
        return f"<p>Yorumunuz: {text}</p>"

    @app.route("/file")
    def file_read():
        path = request.args.get("path", "")
        # KASITLI GUVENSIZ: normalize edip erisim kontrolu yapmadan "okur".
        # Gercek diskten okumaz; sahte FS'ten servis eder (guvenli).
        norm = path.replace("\\", "/")
        # traversal'i coz: "app/public/../../etc/passwd" -> "/etc/passwd"
        resolved = _resolve_traversal(norm)
        if resolved in _FAKE_FS:
            return f"<pre>{_FAKE_FS[resolved]}</pre>"
        return f"<p>Bulunamadi: {resolved}</p>", 404

    @app.route("/ping")
    def ping():
        host = request.args.get("host", "127.0.0.1")
        out, _ = _mock_shell(host)
        return f"<pre>{out}</pre>"

    @app.route("/render")
    def render():
        name = request.args.get("name", "dunya")
        # KASITLI GUVENSIZ: kullanici girdisi sablon olarak degerlendirilir (SSTI)
        try:
            return render_template_string("<p>Merhaba " + name + "!</p>")
        except Exception as e:
            return f"<p>Sablon hatasi: {e}</p>", 200

    return app


def _resolve_traversal(path: str) -> str:
    """`../` adimlarini uygulayarak nihai hedefi bulur (sahte FS anahtari icin).
    Public prefix altinda baslar; `..` ile prefix'ten disari cikilabilir."""
    if path.startswith("/"):
        return path                       # mutlak yol dogrudan
    parts = (_PUBLIC_PREFIX + path).split("/") if not path.startswith(_PUBLIC_PREFIX) \
        else path.split("/")
    stack = []
    for p in parts:
        if p in ("", "."):
            continue
        if p == "..":
            if stack:
                stack.pop()
        else:
            stack.append(p)
    resolved = "/".join(stack)
    # etc/passwd gibi kok-benzeri hedefleri "/etc/..." anahtarina esle
    if resolved.startswith("etc/") or resolved in ("etc/passwd", "etc/shadow"):
        return "/" + resolved
    return resolved


# --- saldiri BASARILI mi? (zemin-dogru: yukler gercekten calisiyor mu) -------
def attack_succeeded(category: str, status: int, body: str, payload: str) -> bool:
    """Korumasiz uygulamada saldirinin GERCEKTEN ise yaradigini dogrular.
    Bu, korpusun 'gercek saldiri' oldugunu kanitlar (uydurma yok)."""
    b = body or ""
    if category == "SQL Injection":
        # union/or-1=1 ile fazladan satir ya da gizli veri sizmasi / hata
        return ("cok-gizli-admin-notu" in b or "gizli-not" in b
                or b.count("<li>") >= 3 or "Sorgu hatasi" in b)
    if category == "XSS":
        return "<script" in b.lower() or "onerror=" in b.lower() or "<img" in b.lower()
    if category == "Path Traversal":
        return "root:x:0:0" in b or "LABONLY" in b
    if category == "Command Injection":
        return any(tok in b for tok in ("labuser", "uid=1000", "Linux arachne-lab",
                                        "root:x:0:0"))
    if category == "SSTI":
        return "49" in b and "{{" not in b     # {{7*7}} -> 49 (degerlendirildi)
    return False


# --- WAF'li / WAF'siz uygulama uretimi ---------------------------------------
def build(protected: bool = True, db_path=None, block_threshold: int = 50) -> Flask:
    app = _make_app()
    if protected:
        app.wsgi_app = WAFMiddleware(app.wsgi_app, block_threshold=block_threshold,
                                     db_path=db_path)
    return app


def run(protected: bool = True, host: str = "127.0.0.1", port: int = 8090):
    application = build(protected=protected)
    mode = "KORUMALI (WAF aktif)" if protected else "KORUMASIZ (WAF kapali)"
    print(f"[Arachne LAB Hedefi] {mode} — http://{host}:{port}")
    application.run(host=host, port=port, debug=False)
