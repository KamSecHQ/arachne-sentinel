#!/usr/bin/env python3
"""
Komuta merkezinin KAYITLI DEMO kopyasini uretir (arachnesentinel.com/panel/).

  python scripts/snapshot_panel.py        # -> website/panel_demo/

Neden: arkadaslar / ziyaretciler linke tiklayinca kurulum, hesap ya da
bekleme olmadan komuta merkezini gorebilsin. GitHub Pages sunucu
calistiramadigi icin panel, GERCEK bir lab calismasinin veritabanindan
alinmis anlik goruntuyle (snapshot) statik olarak sunulur.

Durustluk kurallari (proje ilkesi: olcmedigimiz hicbir seyi iddia etmeyiz):
  * Veri uydurulmaz: her JSON, gercek panel uc noktasinin gercek
    veritabanina verdigi yanittir (Flask test istemcisiyle alinir).
  * Sayfanin ustunde "KAYITLI DEMO" seridi ve verinin tarih araligi durur.
  * Sunucu gerektiren eylemler (yuk analizi, Son Hat tatbikati) demoda
    kapali oldugunu acikca soyler; asistan yalnizca hazir sorulari
    kayitli veriyle yanitlar.

Honeytoken (yem) degerleri maskelenir: sahte ama gercek anahtar bicimindeler
(AKIA..., sk_live_...). Acik depoda/sitede durmalari tuzagin amacini bozar ve
gizli anahtar tarayicilarini (GitHub push protection) haksiz yere tetikler.

Yayinlamadan once: veritabanindaki IP'ler yalnizca test/dokumantasyon
araliklarinda olmali (RFC 5737, 198.18/15, loopback) - betik bunu denetler
ve gercek bir genel IP gorurse DURUR.
"""
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT = ROOT / "website" / "panel_demo"
SRC_DB = ROOT / "data" / "arachne.db"

GET_ENDPOINTS = ["state", "live", "deep", "intel", "fortress"]
ASSISTANT_QUESTIONS = [
    "Savunma durumumuz ne?", "Saldırı durumu ne?", "En riskli saldırgan kim?",
    "Metrikler nasıl?", "Honeytoken tetiklendi mi?", "Kaç IP engellendi?",
    "Beacon durumu?", "Sıfır-gün var mı?", "İmkansız seyahat?", "Tarama var mı?",
    "Bayes füzyon?", "Parola spreyi var mı?", "En derin saldırgan kim?",
]

_SAFE_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "0.0.0.0/32", "192.0.2.0/24", "198.51.100.0/24",
    "203.0.113.0/24", "198.18.0.0/15", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16",
)]
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def assert_no_public_ips(text: str, where: str):
    bad = set()
    for m in _IP_RE.findall(text):
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue  # surum numarasi vb.
        if not any(ip in net for net in _SAFE_NETS):
            bad.add(m)
    if bad:
        raise SystemExit(f"DURDU: {where} icinde genel IP var, yayinlanmaz: {sorted(bad)[:10]}")


_TOKEN_RES = [re.compile(p) for p in (
    r"AKIA[0-9A-Z]{8,}", r"sk_live_[0-9A-Za-z]{6,}", r"AAAAB3NzaC1yc2E[0-9A-Za-z+/]{6,}",
    r"eyJ[0-9A-Za-z_\-]{10,}", r"postgres://[^\s\"']+",
)]


def make_masker(db_path: Path):
    with sqlite3.connect(db_path) as c:
        values = [v for (v,) in c.execute("select value from honeytokens") if v]
    values.sort(key=len, reverse=True)

    def mask(text: str) -> str:
        for v in values:
            text = text.replace(v, v[:4] + "••••[demo-maskeli]")
        for rx in _TOKEN_RES:
            text = rx.sub(lambda m: m.group(0)[:4] + "••••[demo-maskeli]", text)
        return text
    return mask


def main():
    if not SRC_DB.exists():
        raise SystemExit(f"Veritabani yok: {SRC_DB} (once bir demo calistirin)")

    # Kaynak DB'ye asla yazilmaz: kopyasi uzerinden calisilir
    tmp = Path(tempfile.mkdtemp(prefix="arachne-snapshot-"))
    db_copy = tmp / "arachne.db"
    shutil.copy2(SRC_DB, db_copy)
    dump = "\n".join(sqlite3.connect(db_copy).iterdump())
    assert_no_public_ips(dump, "veritabani")
    with sqlite3.connect(db_copy) as c:
        first, last = c.execute("select min(timestamp), max(timestamp) from events").fetchone()

    mask = make_masker(db_copy)

    os.environ["ARACHNE_PANEL_AUTH"] = "0"
    from arachne import config
    config.DB_PATH = db_copy
    from arachne.reporting.dashboard import app

    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "api").mkdir(parents=True)

    with app.test_client() as client:
        def get(path):
            r = client.get(path)
            assert r.status_code == 200, (path, r.status_code)
            return mask(r.get_data(as_text=True))

        for name in GET_ENDPOINTS:
            body = get(f"/api/{name}")
            json.loads(body)
            assert_no_public_ips(body, f"/api/{name}")
            (OUT / "api" / f"{name}.json").write_text(body, encoding="utf-8")

        stix = get("/api/stix")
        assert_no_public_ips(stix, "/api/stix")
        (OUT / "api" / "stix.json").write_text(stix, encoding="utf-8")

        report = get("/report")
        assert_no_public_ips(report, "/report")
        (OUT / "report.html").write_text(report, encoding="utf-8")

        answers = {}
        for q in ASSISTANT_QUESTIONS:
            r = client.post("/api/assistant", json={"question": q})
            assert r.status_code == 200, (q, r.status_code)
            answers[q] = json.loads(mask(r.get_data(as_text=True)))
        blob = json.dumps(answers, ensure_ascii=False)
        assert_no_public_ips(blob, "asistan yanitlari")
        (OUT / "api" / "assistant.json").write_text(blob, encoding="utf-8")

        html = get("/")

    (OUT / "index.html").write_text(html, encoding="utf-8")
    (OUT / "meta.json").write_text(json.dumps(
        {"first_event": first, "last_event": last}, ensure_ascii=False), encoding="utf-8")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"Panel anlik goruntusu hazir: {OUT}  (veri: {first} -> {last})")


if __name__ == "__main__":
    main()
