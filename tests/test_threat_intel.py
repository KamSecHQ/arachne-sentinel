"""Faz 102 - Dis tehdit istihbarati (AbuseIPDB/OTX) karantina modulu testleri.

Gercek ag cagrisi YAPILMAZ - `_call_abuseipdb`/`_call_otx` monkeypatch edilir.
"""
from arachne import storage
from arachne.intel import threat_intel


# --- Guvenli varsayilanlar ---------------------------------------------------

def test_disabled_by_default():
    assert threat_intel.is_enabled() is False


def test_lookup_returns_none_when_disabled():
    assert threat_intel.lookup_ip("8.8.8.8") is None


def test_requires_flag_and_at_least_one_key(monkeypatch):
    monkeypatch.delenv("ARACHNE_THREAT_INTEL_ENABLED", raising=False)
    monkeypatch.delenv("ARACHNE_ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("ARACHNE_OTX_API_KEY", raising=False)
    assert threat_intel.is_enabled() is False

    monkeypatch.setenv("ARACHNE_THREAT_INTEL_ENABLED", "1")
    assert threat_intel.is_enabled() is False  # bayrak var ama anahtar yok

    monkeypatch.setenv("ARACHNE_ABUSEIPDB_API_KEY", "anahtar")
    assert threat_intel.is_enabled() is True


def test_status_never_leaks_api_key(monkeypatch):
    monkeypatch.setenv("ARACHNE_ABUSEIPDB_API_KEY", "gizli-anahtar-12345")
    status = threat_intel.status()
    assert status["abuseipdb_key_present"] is True
    assert "gizli-anahtar-12345" not in str(status)


# --- Lab guvenligi: private/loopback IP'ler asla dis API'ye gitmez ----------

def test_lab_ip_never_queried(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_THREAT_INTEL_ENABLED", "1")
    monkeypatch.setenv("ARACHNE_ABUSEIPDB_API_KEY", "anahtar")

    called = []

    def _fake_call(ip):
        called.append(ip)
        return {"abuseConfidenceScore": 99}

    monkeypatch.setattr(threat_intel, "_call_abuseipdb", _fake_call)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)

    assert threat_intel.lookup_ip("127.0.0.1", db_path=db) is None
    assert threat_intel.lookup_ip("192.168.1.5", db_path=db) is None
    assert threat_intel.lookup_ip("203.0.113.5", db_path=db) is None  # RFC 5737
    assert called == []


# --- Gercek public IP sorgusu (sahte urllib yaniti) -------------------------

def test_lookup_public_ip_uses_abuseipdb(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_THREAT_INTEL_ENABLED", "1")
    monkeypatch.setenv("ARACHNE_ABUSEIPDB_API_KEY", "anahtar")
    monkeypatch.delenv("ARACHNE_OTX_API_KEY", raising=False)

    def _fake_call(ip):
        assert ip == "8.8.8.8"
        return {"abuseConfidenceScore": 80, "totalReports": 12, "isPublic": True,
                "usageType": "Data Center"}

    monkeypatch.setattr(threat_intel, "_call_abuseipdb", _fake_call)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)

    result = threat_intel.lookup_ip("8.8.8.8", db_path=db)
    assert result is not None
    assert result["abuse_confidence_score"] == 80
    assert result["sources"]["abuseipdb"]["total_reports"] == 12


def test_lookup_result_is_cached(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_THREAT_INTEL_ENABLED", "1")
    monkeypatch.setenv("ARACHNE_ABUSEIPDB_API_KEY", "anahtar")
    monkeypatch.delenv("ARACHNE_OTX_API_KEY", raising=False)

    calls = {"n": 0}

    def _fake_call(ip):
        calls["n"] += 1
        return {"abuseConfidenceScore": 42}

    monkeypatch.setattr(threat_intel, "_call_abuseipdb", _fake_call)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)

    threat_intel.lookup_ip("8.8.8.8", db_path=db)
    threat_intel.lookup_ip("8.8.8.8", db_path=db)
    assert calls["n"] == 1  # ikinci cagri onbellekten gelmeli


def test_network_error_returns_none_gracefully(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_THREAT_INTEL_ENABLED", "1")
    monkeypatch.setenv("ARACHNE_ABUSEIPDB_API_KEY", "anahtar")
    monkeypatch.delenv("ARACHNE_OTX_API_KEY", raising=False)

    def _boom(ip):
        raise OSError("ag hatasi simulasyonu")

    monkeypatch.setattr(threat_intel, "_call_abuseipdb", _boom)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)

    assert threat_intel.lookup_ip("8.8.8.8", db_path=db) is None


# --- analyze_recent: 0-guvenli ozet, yeni API cagrisi yapmaz ----------------

def test_analyze_recent_safe_on_empty_db(tmp_path):
    db = str(tmp_path / "empty.db")
    storage.init_db(db_path=db)
    result = threat_intel.analyze_recent(db_path=db)
    assert result["enriched_ip_count"] == 0
    assert result["high_risk_ips"] == []


def test_analyze_recent_never_calls_network(monkeypatch, tmp_path):
    monkeypatch.setenv("ARACHNE_THREAT_INTEL_ENABLED", "1")
    monkeypatch.setenv("ARACHNE_ABUSEIPDB_API_KEY", "anahtar")

    def _boom(ip):
        raise AssertionError("analyze_recent yeni bir dis API cagrisi yapmamali")

    monkeypatch.setattr(threat_intel, "_call_abuseipdb", _boom)

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    storage.log_event("8.8.8.8", "ssh", "connect", db_path=db)

    result = threat_intel.analyze_recent(db_path=db)
    assert result["enriched_ip_count"] == 0


def test_analyze_recent_surfaces_high_risk_from_cache(monkeypatch, tmp_path):
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    storage.log_event("8.8.8.8", "ssh", "connect", db_path=db)
    storage.cache_threat_intel("8.8.8.8", "abuseipdb",
                               {"abuse_confidence_score": 90}, db_path=db)

    result = threat_intel.analyze_recent(db_path=db)
    assert result["enriched_ip_count"] == 1
    assert result["high_risk_ips"][0]["ip"] == "8.8.8.8"
    assert result["high_risk_ips"][0]["abuse_confidence_score"] == 90


# --- Risk motoru entegrasyonu (Faz 18 + Faz 102) ----------------------------

def test_risk_engine_accepts_optional_threat_intel_factor():
    from arachne.intel import risk_engine

    baseline = risk_engine.compute_risk(attack_classes=["Port Scan"])
    boosted = risk_engine.compute_risk(attack_classes=["Port Scan"],
                                       threat_intel_abuse_score=90)
    assert boosted["risk_score"] >= baseline["risk_score"]
    assert any("tehdit istihbarati" in f["factor"].lower()
              for f in boosted["factors"])


def test_risk_engine_zero_abuse_score_is_no_op():
    from arachne.intel import risk_engine

    a = risk_engine.compute_risk(attack_classes=["SQL Injection"])
    b = risk_engine.compute_risk(attack_classes=["SQL Injection"],
                                 threat_intel_abuse_score=0)
    assert a["risk_score"] == b["risk_score"]


# --- Aggregator sarmalayicisi: her zaman 0-guvenli, asla catlamaz -----------

def test_aggregator_view_safe_when_disabled(tmp_path):
    from arachne.reporting import aggregator

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    view = aggregator.threat_intel_enrichment_view(db_path=db)
    assert view["enabled"] is False
    assert view["enriched_ip_count"] == 0
    assert view["high_risk_ips"] == []
