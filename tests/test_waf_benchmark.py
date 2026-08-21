"""
WAF etkinlik olcumu + genisletilmis lab hedefi testleri.

Dogrular:
  * 5 zafiyet sinifi korumasiz hedefte GERCEKTEN calisir (zemin-dogru),
  * WAF temel yukleri %100 engeller, zararsiz trafigi engellemez (0 yanlis poz),
  * benchmark metrikleri tutarli ve dürüst (calisan saldiri onleme olcusu),
  * yeni imzalar (SSTI, tautoloji) calisiyor, kacinma bosluklari raporlaniyor.
"""
import pytest

from arachne import storage
from arachne.waf import labtarget as LT
from arachne.waf import benchmark, rules, report


# --- lab hedefi: zafiyetler korumasizda GERCEKTEN calisir --------------------
@pytest.mark.parametrize("cat,url", [
    ("SQL Injection", "/search?name=' OR '1'='1"),
    ("XSS", "/comment?text=<script>alert(1)</script>"),
    ("Path Traversal", "/file?path=app/public/../../etc/passwd"),
    ("Command Injection", "/ping?host=127.0.0.1; whoami"),
    ("SSTI", "/render?name={{7*7}}"),
])
def test_zafiyet_korumasizda_calisir(cat, url):
    c = LT.build(protected=False).test_client()
    r = c.get(url)
    assert LT.attack_succeeded(cat, r.status_code, r.get_data(as_text=True), url)


def test_mock_shell_gercek_komut_calistirmaz():
    # taklit kabuk: enjeksiyon "basarili" gorunur ama whitelist disi calismaz
    out, injected = LT._mock_shell("127.0.0.1; whoami")
    assert injected is True and "labuser" in out
    out2, inj2 = LT._mock_shell("127.0.0.1; rm -rf /")
    assert inj2 is True and "calistirilmadi" in out2   # keyfi komut asla calismaz


def test_ssti_gercekten_degerlendirir():
    c = LT.build(protected=False).test_client()
    body = c.get("/render?name={{7*7}}").get_data(as_text=True)
    assert "49" in body and "{{" not in body


# --- WAF: temel yukleri engeller, zararsizi gecirir --------------------------
def test_waf_temel_yukleri_engeller(tmp_path):
    db = str(tmp_path / "waf.db"); storage.init_db(db)
    c = LT.build(protected=True, db_path=db).test_client()
    for url in ["/search?name=' OR '1'='1", "/comment?text=<script>alert(1)</script>",
                "/file?path=../../../../etc/passwd", "/ping?host=127.0.0.1; whoami",
                "/render?name={{7*7}}"]:
        r = c.get(url, environ_base={"REMOTE_ADDR": "198.51.100.9"})
        assert r.status_code == 403, url


def test_waf_zararsizi_gecirir(tmp_path):
    db = str(tmp_path / "waf.db"); storage.init_db(db)
    c = LT.build(protected=True, db_path=db).test_client()
    for i, url in enumerate(["/search?name=emirhan", "/comment?text=Merhaba dunya",
                             "/file?path=app/public/welcome.txt", "/ping?host=127.0.0.1",
                             "/render?name=Emirhan", "/"]):
        r = c.get(url, environ_base={"REMOTE_ADDR": f"203.0.113.{i+1}"})
        assert r.status_code != 403, url


# --- yeni imzalar ------------------------------------------------------------
def test_ssti_imzasi_var():
    assert any(cat == "SSTI" for cat, _w in rules.scan_text("{{7*7}}"))
    assert any(cat == "SSTI" for cat, _w in rules.scan_text("{{ ''.__class__ }}"))


def test_tautoloji_imzasi_rakamsiz():
    assert any(cat == "SQL Injection" for cat, _w in rules.scan_text("' OR 'a'='a"))


def test_zararsiz_metin_yanlis_pozitif_uretmez():
    for benign in ["emirhan", "Merhaba, bu proje cok guzel!", "Fiyat 100 TL, indirim %20",
                   "Ali Veli", "1 < 2 dogru mu"]:
        assert rules.scan_text(benign) == [], benign


# --- benchmark metrikleri ----------------------------------------------------
def test_benchmark_metrikleri_tutarli(tmp_path):
    res = benchmark.run(db_path=str(tmp_path / "b.db"))
    m, t = res["metrics"], res["totals"]
    # temel yukler tam yakalanir
    assert res["by_tier"]["temel"]["recall"] == 1.0
    # yanlis pozitif yok
    assert m["false_positive_rate"] == 0.0
    assert t["benign_blocked_false_positive"] == 0
    # calisan saldirilarin buyuk cogunlugu onlenir
    assert m["real_attack_prevention_rate"] >= 0.85
    # kacinma yukleri gercek bir bosluk gosterir (100% degil — dürüstluk)
    assert res["by_tier"]["kacinma"]["recall"] < 1.0
    # her calisan saldiri gercekten exploited olarak dogrulanmis olmali
    assert t["attacks_exploited_unprotected"] >= 15
    # gecikme yuku pozitif ama makul (ms)
    assert res["latency_ms"]["overhead_avg"] >= 0.0


def test_benchmark_her_kategoriyi_kapsar(tmp_path):
    res = benchmark.run(db_path=str(tmp_path / "b.db"))
    for cat in ("SQL Injection", "XSS", "Path Traversal", "Command Injection", "SSTI"):
        assert cat in res["per_category"]
        assert res["per_category"][cat]["total"] >= 1


def test_rapor_html_sayilari_icerir(tmp_path):
    res = benchmark.run(db_path=str(tmp_path / "b.db"))
    hdoc = report.build_html(res, generated_at="test")
    assert "WAF Etkinlik Raporu" in hdoc
    assert "Kacan Saldirilar" in hdoc          # dürüstluk: bosluklar listelenir
    assert "recall" in hdoc.lower() or "Yakalama" in hdoc
