"""Faz 69 - Tarama & Kaba-Kuvvet Hiz Dedektoru testleri.

Deterministik, harici bagimlilik yok. Hem pozitif hem negatif senaryolar,
bos girdi (guvenli sifirlar) ve monitor toplamasi test edilir.
"""
from arachne.adaptive import scan_bruteforce as sb


# --------------------------------------------------------------------------
# Yardimci: tek IP icin olay uretici
# --------------------------------------------------------------------------
def _events(services, start=1000.0, step=1.0):
    """Verilen servis dizisinden ardil zaman damgali olay listesi uretir."""
    out = []
    t = start
    for s in services:
        out.append({"source_ip": "10.0.0.9", "service": s, "timestamp": t})
        t += step
    return out


# --------------------------------------------------------------------------
# _to_epoch: hem ISO hem epoch
# --------------------------------------------------------------------------
def test_to_epoch_accepts_epoch_and_iso():
    assert sb._to_epoch(1000) == 1000.0
    assert sb._to_epoch(1000.5) == 1000.5
    assert sb._to_epoch("1000") == 1000.0
    iso = sb._to_epoch("2020-01-01T00:00:00")
    assert isinstance(iso, float) and iso > 0
    assert sb._to_epoch(None) is None
    assert sb._to_epoch("bozuk-tarih") is None


# --------------------------------------------------------------------------
# scan_score - pozitif
# --------------------------------------------------------------------------
def test_scan_positive_many_services_short_window():
    # 6 farkli servise 1'er sn arayla dokunma -> yatay tarama.
    evs = _events(["ssh", "http", "ftp", "smtp", "rdp", "mysql"])
    res = sb.scan_score(evs)
    assert res["is_scan"] is True
    assert res["distinct_services"] == 6
    assert res["window_sec"] <= sb.SCAN_MAX_WINDOW_SEC
    assert res["rate_per_min"] > 0
    assert "TARAMA" in res["verdict_tr"].upper()


def test_scan_positive_simultaneous():
    # Ayni ana dusen (window==0) cok servisli dokunus da tarama sayilir.
    evs = [{"service": s, "timestamp": 5000.0} for s in
           ("a", "b", "c", "d", "e", "f", "g")]
    res = sb.scan_score(evs)
    assert res["is_scan"] is True
    assert res["window_sec"] == 0.0
    # window==0 -> rate sonsuz degil, sonlu (1 sn taban)
    assert res["rate_per_min"] == sb._rate_per_min(7, 0.0)


# --------------------------------------------------------------------------
# scan_score - negatif
# --------------------------------------------------------------------------
def test_scan_negative_few_services():
    # Tek servise cok dokunus -> tarama DEGIL (dar hedef).
    evs = _events(["ssh"] * 10)
    res = sb.scan_score(evs)
    assert res["is_scan"] is False
    assert res["distinct_services"] == 1


def test_scan_negative_spread_over_hours():
    # 6 farkli servis ama saatlere yayilmis -> hizli tarama degil.
    evs = _events(["ssh", "http", "ftp", "smtp", "rdp", "mysql"],
                  start=0.0, step=3600.0)
    res = sb.scan_score(evs)
    assert res["is_scan"] is False
    assert res["distinct_services"] == 6
    assert res["window_sec"] > sb.SCAN_MAX_WINDOW_SEC


def test_scan_ports_count_as_distinct():
    # Ayni servis, farkli portlar -> port taramasi, distinct artmali.
    evs = [{"service": "tcp", "dest_port": p, "timestamp": 100.0 + i}
           for i, p in enumerate([21, 22, 23, 25, 80, 443])]
    res = sb.scan_score(evs)
    assert res["distinct_services"] == 6
    assert res["is_scan"] is True


# --------------------------------------------------------------------------
# bruteforce_score - pozitif
# --------------------------------------------------------------------------
def test_bruteforce_positive_rapid_same_service():
    # ssh'a 12 hizli deneme (0.5 sn arayla, ~120/dk) -> kaba-kuvvet.
    evs = _events(["ssh"] * 12, step=0.5)
    res = sb.bruteforce_score(evs)
    assert res["is_bruteforce"] is True
    assert res["attempts"] == 12
    assert res["top_service"] == "ssh"
    assert res["rate_per_min"] >= sb.BF_MIN_RATE_PER_MIN


def test_bruteforce_picks_top_service():
    # Karisik: ssh'a cok, http'ye az -> top_service ssh olmali.
    evs = _events(["ssh"] * 10 + ["http"] * 2, step=0.5)
    res = sb.bruteforce_score(evs)
    assert res["top_service"] == "ssh"
    assert res["attempts"] == 10


# --------------------------------------------------------------------------
# bruteforce_score - negatif
# --------------------------------------------------------------------------
def test_bruteforce_negative_too_few():
    evs = _events(["ssh"] * 3, step=0.5)
    res = sb.bruteforce_score(evs)
    assert res["is_bruteforce"] is False
    assert res["attempts"] == 3


def test_bruteforce_negative_too_slow():
    # 12 deneme ama 60 sn arayla (~1/dk) -> hizli degil, kaba-kuvvet DEGIL.
    evs = _events(["ssh"] * 12, step=60.0)
    res = sb.bruteforce_score(evs)
    assert res["is_bruteforce"] is False
    assert res["attempts"] == 12
    assert res["rate_per_min"] < sb.BF_MIN_RATE_PER_MIN


# --------------------------------------------------------------------------
# Bos girdi -> guvenli sifirlar
# --------------------------------------------------------------------------
def test_empty_input_safe_zeros():
    s = sb.scan_score([])
    assert s["is_scan"] is False
    assert s["distinct_services"] == 0
    assert s["window_sec"] == 0.0
    assert s["rate_per_min"] == 0.0

    b = sb.bruteforce_score([])
    assert b["is_bruteforce"] is False
    assert b["attempts"] == 0
    assert b["top_service"] == ""
    assert b["rate_per_min"] == 0.0

    assert sb.scan_score(None)["is_scan"] is False
    assert sb.bruteforce_score(None)["is_bruteforce"] is False


# --------------------------------------------------------------------------
# SweepMonitor - toplama
# --------------------------------------------------------------------------
def test_sweep_monitor_aggregates_scanner_and_bruteforcer():
    m = sb.SweepMonitor()
    # Tarayici IP: cok farkli servis, kisa pencere
    t = 1000.0
    for svc in ("a", "b", "c", "d", "e", "f"):
        m.observe("1.1.1.1", svc, t)
        t += 1.0
    # Kaba-kuvvetci IP: ayni servise hizli tekrar
    t = 2000.0
    for _ in range(12):
        m.observe("2.2.2.2", "ssh", t)
        t += 0.5
    # Masum IP: az olay
    m.observe("3.3.3.3", "http", 3000.0)

    rep = m.report()
    scanner_ips = [s["ip"] for s in rep["scanners"]]
    bf_ips = [b["ip"] for b in rep["bruteforcers"]]
    assert "1.1.1.1" in scanner_ips
    assert "2.2.2.2" in bf_ips
    assert "3.3.3.3" not in scanner_ips and "3.3.3.3" not in bf_ips
    assert rep["counts"]["ips"] == 3
    assert rep["counts"]["scanners"] >= 1
    assert rep["counts"]["bruteforcers"] >= 1
    assert rep["counts"]["events"] == 6 + 12 + 1


def test_sweep_monitor_empty_report():
    m = sb.SweepMonitor()
    rep = m.report()
    assert rep["scanners"] == []
    assert rep["bruteforcers"] == []
    assert rep["counts"] == {"ips": 0, "scanners": 0, "bruteforcers": 0, "events": 0}


def test_monitor_observe_ignores_none_ip():
    m = sb.SweepMonitor()
    m.observe(None, "ssh", 1000.0)
    assert m.report()["counts"]["ips"] == 0


# --------------------------------------------------------------------------
# analyze_recent - gercek DB (bos ve dolu)
# --------------------------------------------------------------------------
def test_analyze_recent_empty_db(tmp_path):
    from arachne import storage
    db = str(tmp_path / "empty.db")
    storage.init_db(db_path=db)
    res = sb.analyze_recent(db_path=db)
    assert res["scanner_count"] == 0
    assert res["bruteforce_count"] == 0
    assert res["scanner_ips"] == []
    assert res["bruteforce_ips"] == []
    assert res["top_scanner"] is None
    assert res["top_bruteforcer"] is None


def test_analyze_recent_detects_from_db(tmp_path):
    from arachne import storage
    db = str(tmp_path / "full.db")
    storage.init_db(db_path=db)
    # Tarayici IP: 6 farkli servis
    for svc in ("ssh", "http", "ftp", "smtp", "rdp", "mysql"):
        storage.log_event("9.9.9.9", svc, "connect", db_path=db)
    # Kaba-kuvvetci IP: ayni servise 12 deneme (ayni saniyeye dusebilir -> hala hizli)
    for _ in range(12):
        storage.log_event("8.8.8.8", "ssh", "login_fail", db_path=db)

    res = sb.analyze_recent(db_path=db)
    assert "9.9.9.9" in res["scanner_ips"]
    assert "8.8.8.8" in res["bruteforce_ips"]
    assert res["top_scanner"]["ip"] == "9.9.9.9"
    assert res["top_scanner"]["distinct_services"] == 6
    assert res["top_bruteforcer"]["ip"] == "8.8.8.8"
    assert res["top_bruteforcer"]["attempts"] == 12


def test_analyze_recent_never_crashes_bad_path():
    # Gecersiz db yolu bile olsa asla catlatma -> guvenli sifirlar.
    res = sb.analyze_recent(db_path="/nonexistent/dir/does_not_exist.db")
    assert res["scanner_count"] == 0
    assert res["bruteforce_count"] == 0
