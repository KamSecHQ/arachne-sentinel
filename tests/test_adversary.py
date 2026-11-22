"""
Arachne Adversary (kirmizi takim test motoru) testleri.

En kritik test: guvenlik kapisi loopback DISINI reddediyor mu. Ayrica mutasyon
motoru, kampanya olçumleri ve ko-evrim yakinsamasi dogrulanir. Hepsi yereldir.
"""
import pytest

from adversary import safety, mutators, payloads
from adversary.safety import RedTeamSafetyError


# --- GUVENLIK KAPISI (en onemli) --------------------------------------------
@pytest.mark.parametrize("bad", [
    "http://example.com", "https://8.8.8.8", "http://google.com/admin",
    "http://192.168.1.5", "http://10.0.0.1", "http://169.254.1.1",
    "ftp://evil.tr", "http://türkiye.gov.tr",
])
def test_disari_hedef_reddedilir(bad):
    with pytest.raises(RedTeamSafetyError):
        safety.assert_local_target(bad)


@pytest.mark.parametrize("good", [
    "http://127.0.0.1:8090", "http://localhost:5000", "http://[::1]:80",
    "http://127.5.5.5", "http://sub.localhost:3000",
])
def test_loopback_hedef_kabul(good):
    safety.assert_local_target(good)   # firlatmamali
    assert safety.is_local_target(good) is True


def test_in_process_uygulama_guvenli():
    class FakeApp:
        def wsgi_app(self):
            pass
    safety.assert_local_target(FakeApp())          # WSGI nesnesi -> guvenli
    safety.assert_local_target(lambda e, s: None)  # cagirilabilir -> guvenli


# --- MUTASYON MOTORU --------------------------------------------------------
def test_mutasyon_deterministik():
    a = mutators.mutate("SQL Injection", "' OR '1'='1")
    b = mutators.mutate("SQL Injection", "' OR '1'='1")
    assert a == b                        # ayni girdi -> ayni cikti
    assert a[0] == ("base", "' OR '1'='1")
    names = [n for n, _ in a]
    assert "inline_comment" in names and "ws_comment" in names


def test_inline_comment_keyword_kirar():
    _n, mutated = next(m for m in mutators.mutate("SQL Injection", "x UNION SELECT")
                       if m[0] == "inline_comment")
    assert "/**/" in mutated and "UNION" not in mutated  # keyword parcalandi


def test_newline_mutasyonu_komut_enjeksiyonu():
    variants = dict(mutators.mutate("Command Injection", "127.0.0.1; whoami"))
    assert "newline" in variants and "\n" in variants["newline"]


# --- KAMPANYA + KO-EVRIM ----------------------------------------------------
def test_kampanya_yerel_ve_olçer():
    from adversary import engine
    res = engine.run_campaign(use_mutations=True)
    t = res["totals"]
    assert t["attempts"] > 0
    assert t["exploited"] > 0                         # bazi saldirilar gercekten calisir
    assert res["metrics"]["false_positive_rate"] == 0.0
    # mutasyon sayesinde en az bir atlatma bulunur (savunma sabit iken)
    assert t["bypassed"] >= 1


def test_koevrim_savunmayi_yukari_ceker():
    from adversary import coevolution as co
    res = co.run(rounds=5)
    s = res["summary"]
    # atlatma orani baslangictan sona DUSMELI (savunma ogrenir)
    assert s["end_bypass_rate"] <= s["start_bypass_rate"]
    assert s["start_bypassed"] >= 1                   # baslangicta atlatma vardi
    assert s["end_bypassed"] < s["start_bypassed"]    # savunma ilerledi
    assert s["final_false_positive_rate"] == 0.0      # FP artmadan


def test_koevrim_raporu_html_uretir(tmp_path):
    from adversary import report
    path = str(tmp_path / "r.html")
    p, res = report.generate(path, rounds=3)
    doc = open(p, encoding="utf-8").read()
    assert "Ko-Evrim" in doc and "Yalnızca yerel test" in doc


def test_payload_katalogu_bes_kategori():
    assert set(payloads.categories()) == {
        "SQL Injection", "XSS", "Path Traversal", "Command Injection", "SSTI"}
