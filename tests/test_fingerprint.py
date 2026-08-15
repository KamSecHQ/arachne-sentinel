"""Faz 22 - Istemci parmak izi ve Sybil tespiti testleri."""
from arachne.adaptive import fingerprint


def _chrome_attrs():
    return {
        "tls_version": "771",
        "cipher_suites": ["4865", "4866", "4867"],
        "extensions": ["0", "23", "65281", "10", "11"],
        "curves": ["29", "23", "24"],
        "header_order": ["host", "user-agent", "accept"],
        "http2_settings": "1:65536;3:1000",
    }


def test_compute_fingerprint_deterministic():
    a = _chrome_attrs()
    assert fingerprint.compute_fingerprint(a) == fingerprint.compute_fingerprint(dict(a))


def test_compute_fingerprint_length_and_hex():
    fp = fingerprint.compute_fingerprint(_chrome_attrs())
    assert len(fp) == 16
    int(fp, 16)  # gecerli hex olmali


def test_compute_fingerprint_order_matters():
    # Ayni ozellikler, farkli cipher sirasi -> farkli parmak izi.
    a = _chrome_attrs()
    b = dict(a)
    b["cipher_suites"] = ["4866", "4865", "4867"]
    assert fingerprint.compute_fingerprint(a) != fingerprint.compute_fingerprint(b)


def test_compute_fingerprint_missing_keys_graceful():
    # Eksik anahtarlar hata vermez, deterministik kalir.
    partial = {"tls_version": "771"}
    fp1 = fingerprint.compute_fingerprint(partial)
    fp2 = fingerprint.compute_fingerprint(dict(partial))
    assert len(fp1) == 16 and fp1 == fp2
    # Bos dict bile calisir.
    assert len(fingerprint.compute_fingerprint({})) == 16


def test_compute_fingerprint_ignores_extra_keys():
    a = _chrome_attrs()
    b = dict(a)
    b["irrelevant"] = "xyz"
    assert fingerprint.compute_fingerprint(a) == fingerprint.compute_fingerprint(b)


def test_impossible_combo_chrome_with_requests():
    assert fingerprint.impossible_combo("chrome", "python-requests") is True
    assert fingerprint.impossible_combo("Chrome", "curl") is True
    assert fingerprint.impossible_combo("firefox", "go-http") is True


def test_possible_combo_real_browser():
    assert fingerprint.impossible_combo("chrome", "chrome") is False


def test_impossible_combo_unknown_is_false():
    assert fingerprint.impossible_combo("", "curl") is False
    assert fingerprint.impossible_combo("chrome", None) is False
    assert fingerprint.impossible_combo("somebot", "curl") is False


def test_correlator_flags_sybil_on_many_ips():
    # KILIT SENARYO: tek parmak izi (tek aktor), IP rotasyonu ile 4 kimlik.
    corr = fingerprint.IdentityCorrelator(ip_threshold=3)
    fp = "deadbeefcafef00d"
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"):
        corr.observe(fp, ip, ua="Mozilla/5.0 Chrome")
    report = corr.sybil_report()
    assert len(report) == 1
    row = report[0]
    assert row["is_sybil"] is True
    assert row["identity_count"] == 4
    assert row["identities"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    assert "Sybil" in row["verdict"]


def test_correlator_no_sybil_below_threshold():
    corr = fingerprint.IdentityCorrelator(ip_threshold=3)
    corr.observe("abc123", "10.0.0.1", ua="ua-a")
    corr.observe("abc123", "10.0.0.2", ua="ua-a")
    row = corr.sybil_report()[0]
    assert row["is_sybil"] is False
    assert row["identity_count"] == 2


def test_correlator_ua_rotation_triggers_sybil():
    # Ayni IP ama cok farkli UA (UA rotasyonu) -> ua esigi tetikler.
    corr = fingerprint.IdentityCorrelator(ip_threshold=99, ua_threshold=3)
    for ua in ("chrome-1", "firefox-2", "safari-3"):
        corr.observe("fp-ua", "10.0.0.1", ua=ua)
    row = corr.sybil_report()[0]
    assert row["is_sybil"] is True
    assert row["ua_variants"] == 3


def test_summary_counts():
    corr = fingerprint.IdentityCorrelator(ip_threshold=3)
    for ip in ("1.1.1.1", "1.1.1.2", "1.1.1.3"):
        corr.observe("sybilfp", ip)
    corr.observe("normalfp", "2.2.2.2")
    s = corr.summary()
    assert s["total_fingerprints"] == 2
    assert s["sybil_fingerprints"] == 1
    assert s["total_observations"] == 4
    assert s["distinct_ips"] == 4
