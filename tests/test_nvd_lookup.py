"""Faz 107 - NVD CVE zenginlestirmesi testleri.

Gercek ag cagrisi YAPILMAZ - `_call_nvd` monkeypatch edilir; yakalanmis bir
ornek NVD CVE 2.0 JSON semasi fixture olarak kullanilir.
"""
from arachne import storage
from arachne.scanner import known_vulnerabilities, nvd_lookup, vuln_scanner

# Gercek NVD CVE 2.0 API'sinin ("services.nvd.nist.gov/rest/json/cves/2.0")
# donduregi semanin kucultulmus, temsili bir ornegi.
_SAMPLE_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2011-2523",
                "descriptions": [
                    {"lang": "en", "value": "vsftpd 2.3.4 backdoor command execution."},
                    {"lang": "tr", "value": "Turkce aciklama (kullanilmamali)."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                    ]
                },
            }
        }
    ],
}


# --- Guvenli varsayilanlar ---------------------------------------------------

def test_disabled_by_default():
    assert nvd_lookup.is_enabled() is False


def test_lookup_returns_empty_list_when_disabled():
    assert nvd_lookup.lookup_by_keyword("vsftpd") == []


def test_status_never_leaks_api_key(monkeypatch):
    monkeypatch.setenv("ARACHNE_NVD_API_KEY", "gizli-anahtar-999")
    status = nvd_lookup.status()
    assert status["api_key_present"] is True
    assert "gizli-anahtar-999" not in str(status)


def test_rate_limit_is_higher_with_api_key(monkeypatch):
    monkeypatch.delenv("ARACHNE_NVD_API_KEY", raising=False)
    assert nvd_lookup.status()["rate_limit_per_30s"] == 5
    monkeypatch.setenv("ARACHNE_NVD_API_KEY", "anahtar")
    assert nvd_lookup.status()["rate_limit_per_30s"] == 50


# --- Parse & lookup (sahte urllib yaniti) -----------------------------------

def test_parse_nvd_response_extracts_english_description_and_severity():
    results = nvd_lookup._parse_nvd_response(_SAMPLE_NVD_RESPONSE)
    assert len(results) == 1
    assert results[0]["cve"] == "CVE-2011-2523"
    assert "backdoor" in results[0]["description"]
    assert results[0]["severity"] == "critical"
    assert results[0]["source"] == "nvd"


def test_lookup_by_keyword_enabled_uses_call_nvd(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_NVD_ENABLED", "1")
    monkeypatch.delenv("ARACHNE_NVD_API_KEY", raising=False)

    calls = []

    def _fake_call(keyword):
        calls.append(keyword)
        return _SAMPLE_NVD_RESPONSE

    monkeypatch.setattr(nvd_lookup, "_call_nvd", _fake_call)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    results = nvd_lookup.lookup_by_keyword("vsftpd", db_path=db)
    assert calls == ["vsftpd"]
    assert results[0]["cve"] == "CVE-2011-2523"


def test_lookup_by_keyword_is_cached(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_NVD_ENABLED", "1")

    calls = {"n": 0}

    def _fake_call(keyword):
        calls["n"] += 1
        return _SAMPLE_NVD_RESPONSE

    monkeypatch.setattr(nvd_lookup, "_call_nvd", _fake_call)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    nvd_lookup.lookup_by_keyword("vsftpd", db_path=db)
    nvd_lookup.lookup_by_keyword("vsftpd", db_path=db)
    assert calls["n"] == 1


def test_network_error_returns_empty_list(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_NVD_ENABLED", "1")

    def _boom(keyword):
        raise OSError("ag hatasi simulasyonu")

    monkeypatch.setattr(nvd_lookup, "_call_nvd", _boom)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    assert nvd_lookup.lookup_by_keyword("vsftpd", db_path=db) == []


def test_rate_limiter_blocks_after_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_NVD_ENABLED", "1")
    monkeypatch.delenv("ARACHNE_NVD_API_KEY", raising=False)

    calls = {"n": 0}

    def _fake_call(keyword):
        calls["n"] += 1
        return {"vulnerabilities": []}

    monkeypatch.setattr(nvd_lookup, "_call_nvd", _fake_call)
    monkeypatch.setattr(nvd_lookup, "_call_times", [])

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    # Farkli anahtar kelimeler kullanarak onbellegi atla, limiti test et
    # (anahtarsiz limit = 5/30sn).
    for i in range(5):
        nvd_lookup.lookup_by_keyword(f"keyword-{i}", db_path=db)
    assert calls["n"] == 5
    result = nvd_lookup.lookup_by_keyword("keyword-6th", db_path=db)
    assert result == []
    assert calls["n"] == 5  # 6. cagri yapilmadan once limitte durduruldu


# --- vuln_scanner.py entegrasyonu: regresyon yok, dedup calisir -----------

def test_scan_without_nvd_flag_behaves_exactly_like_before(tmp_path, monkeypatch):
    """use_nvd=False (varsayilan) - eski davranisla BIREBIR ayni olmali."""
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)

    def _fake_scan_target(host, ports=None, timeout=1.0):
        return [{"port": 21, "service_guess": "ftp",
                "banner": "220 ProFTPd 1.3.3 Server ready."}]

    monkeypatch.setattr(vuln_scanner.port_scanner, "scan_target", _fake_scan_target)

    findings = vuln_scanner.scan_and_report("127.0.0.1", db_path=db, use_nvd=False)
    assert len(findings) == 1
    assert "CVE-2010-4221" in findings[0]["finding"]
    assert findings[0]["all_matches"][0]["source"] == "static"


def test_scan_with_nvd_merges_and_dedupes_by_cve(tmp_path, monkeypatch):
    monkeypatch.setenv("ARACHNE_NVD_ENABLED", "1")
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)

    def _fake_scan_target(host, ports=None, timeout=1.0):
        return [{"port": 21, "service_guess": "vsftpd",
                "banner": "220 vsFTPd 2.3.4 ready."}]

    monkeypatch.setattr(vuln_scanner.port_scanner, "scan_target", _fake_scan_target)

    # NVD ayni CVE'yi (statikle CAKISAN) + FARKLI bir CVE dondursun.
    def _fake_lookup(keyword, db_path=None):
        return [
            {"cve": "CVE-2011-2523", "description": "duplicate", "severity": "critical",
             "source": "nvd"},
            {"cve": "CVE-9999-0001", "description": "farkli bir CVE", "severity": "high",
             "source": "nvd"},
        ]

    monkeypatch.setattr("arachne.scanner.nvd_lookup.lookup_by_keyword", _fake_lookup)

    findings = vuln_scanner.scan_and_report("127.0.0.1", db_path=db, use_nvd=True)
    matches = findings[0]["all_matches"]
    cve_ids = [m["cve"] for m in matches]
    assert cve_ids.count("CVE-2011-2523") == 1  # tekillestirildi
    assert "CVE-9999-0001" in cve_ids
    assert matches[0]["source"] == "static"  # statik ONCE gelir


def test_scan_nvd_failure_falls_back_to_static_silently(tmp_path, monkeypatch):
    monkeypatch.setenv("ARACHNE_NVD_ENABLED", "1")
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)

    def _fake_scan_target(host, ports=None, timeout=1.0):
        return [{"port": 21, "service_guess": "vsftpd",
                "banner": "220 vsFTPd 2.3.4 ready."}]

    monkeypatch.setattr(vuln_scanner.port_scanner, "scan_target", _fake_scan_target)

    def _boom(keyword, db_path=None):
        raise OSError("ag hatasi simulasyonu")

    monkeypatch.setattr("arachne.scanner.nvd_lookup.lookup_by_keyword", _boom)

    findings = vuln_scanner.scan_and_report("127.0.0.1", db_path=db, use_nvd=True)
    assert "CVE-2011-2523" in findings[0]["finding"]  # statik liste hala calisiyor
