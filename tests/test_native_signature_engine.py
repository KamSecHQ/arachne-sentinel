"""native.signature_engine icin testler.

Bu testler CI/sandbox gibi Apple Silicon olmayan ortamlarda calisir ve
Python yedek (fallback) yolunu dogrular - bu, gercek kullanicilarin buyuk
cogunlugunun (Linux CI, Intel Mac, .dylib henuz derlenmemis kurulumlar)
gorecegi yoldur. Apple Silicon'da ARM64 assembly cekirdegi aktifken ayni
testlerin ayni sonucu vermesi, fast_scan.s'in Linux ARM64 (qemu-aarch64)
uzerinde yapilan 20.000+ fuzz test + kenar durum testleriyle ayrica
dogrulanmis olmasindan kaynaklanir (bkz. arachne/native/arm64/fast_scan.s
basindaki yorum)."""
from arachne.native import signature_engine


def test_find_basic_match():
    assert signature_engine.find("hello world", "world") == 6


def test_find_no_match():
    assert signature_engine.find("hello world", "xyz") == -1


def test_find_empty_needle_matches_at_zero():
    assert signature_engine.find("abc", "") == 0


def test_find_needle_longer_than_haystack():
    assert signature_engine.find("ab", "abc") == -1


def test_contains_true_and_false():
    assert signature_engine.contains("1' or '1'='1", "' or '1'='1") is True
    assert signature_engine.contains("just a normal login", "' or '1'='1") is False


def test_contains_any_returns_matched_subset_in_order():
    text = "1 union select username,password from users; <script>alert(1)</script>"
    signatures = ["' or '1'='1", "union select", "<script>", "../../../"]
    matched = signature_engine.contains_any(text, signatures)
    assert matched == ["union select", "<script>"]


def test_contains_any_empty_signature_list():
    assert signature_engine.contains_any("anything", []) == []


def test_contains_any_handles_more_than_32_signatures():
    # native motorun bir cagrida en fazla 32 imza tarayabildigi sinirin
    # Python tarafinda otomatik parcalanarak asildigini dogrular.
    signatures = [f"needle-{i}" for i in range(70)]
    signatures[50] = "findme"
    text = "haystack with findme somewhere in the middle"
    matched = signature_engine.contains_any(text, signatures)
    assert matched == ["findme"]


def test_engine_status_reports_something_readable():
    status = signature_engine.engine_status()
    assert isinstance(status, str) and len(status) > 0


def test_native_engine_active_flag_matches_platform_reality():
    # Bu sandbox/CI x86_64 oldugu icin native motor kesinlikle pasif olmali
    # ve her sey sessizce Python yedegine dusmus olmali (crash yok).
    import platform
    if platform.system() != "Darwin" or platform.machine() not in ("arm64", "aarch64"):
        assert signature_engine.NATIVE_ENGINE_ACTIVE is False
