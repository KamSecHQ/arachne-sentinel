"""
Bilincli olarak zafiyetli, KUCUK ve YEREL bir demo web uygulamasi.

Amaci: WAFMiddleware'in gercek bir saldiriyi nasil engellediğini somut
olarak gostermek. Veritabani tamamen icinde bulunulan islem belleginde
(in-memory SQLite) yasar, disariya hicbir gercek veri/sistem baglantisi
yoktur - bu yuzden SQLi denemesi gercekten calisir (ogretici olsun diye)
ama hicbir zarar vermez.

Kullanim:
  python main.py waf-demo              # WAF korumali (varsayilan, port 8090)
  python main.py waf-demo --unprotected  # WAF'siz - farki karsilastirmak icin
"""
import sqlite3

from flask import Flask, request

from .middleware import WAFMiddleware

app = Flask(__name__)

_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
_conn.executemany(
    "INSERT INTO users (name, secret) VALUES (?, ?)",
    [
        ("emirhan", "gizli-not-1"),
        ("arkadasi", "gizli-not-2"),
        ("admin", "cok-gizli-admin-notu"),
    ],
)
_conn.commit()


@app.route("/")
def index():
    return (
        "<h2>Arachne Sentinel - WAF Demo Uygulamasi</h2>"
        "<p>Bu, bilincli olarak zafiyetli, tamamen yerel/hafizada calisan bir "
        "demo uygulamasidir. Gercek bir sistem degildir.</p>"
        "<p><code>/search?name=emirhan</code> - kullanici arama (SQLi'ye acik)</p>"
        "<p><code>/comment?text=merhaba</code> - yorum gosterme (XSS'e acik)</p>"
    )


@app.route("/search")
def search():
    name = request.args.get("name", "")
    # KASITLI OLARAK GUVENSIZ: parametreli sorgu yerine string birlestirme.
    # Bu satir, WAF olmadan SQL injection'a nasil acik oldugumuzu gostermek icindir.
    query = f"SELECT id, name FROM users WHERE name = '{name}'"
    try:
        rows = _conn.execute(query).fetchall()
    except sqlite3.Error as e:
        return f"<p>Sorgu hatasi: {e}</p><p>Calistirilan sorgu: {query}</p>"
    result = "".join(f"<li>id={r[0]} name={r[1]}</li>" for r in rows)
    return f"<p>Calistirilan sorgu: <code>{query}</code></p><ul>{result}</ul>"


@app.route("/comment")
def comment():
    text = request.args.get("text", "")
    # KASITLI OLARAK GUVENSIZ: kullanici girdisi hicbir kacislama yapilmadan
    # dogrudan HTML'e gomuluyor (yansitilmis XSS).
    return f"<p>Yorumunuz: {text}</p>"


def create_app(protected: bool = True, db_path=None):
    if protected:
        app.wsgi_app = WAFMiddleware(app.wsgi_app, db_path=db_path)
    return app


def run(protected: bool = True, host="127.0.0.1", port=8090):
    application = create_app(protected=protected)
    mode = "KORUMALI (WAF aktif)" if protected else "KORUMASIZ (WAF kapali)"
    print(f"[Arachne WAF Demo] {mode} - http://{host}:{port}")
    application.run(host=host, port=port, debug=False)
