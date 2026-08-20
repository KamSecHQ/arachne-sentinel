"""Faz 74 - Kimlik-Doldurma / Parola Spreyi dedektoru testleri.

Deterministik, harici bagimlilik yok. Pozitif/negatif senaryolar, bos girdi
(guvenli sifirlar), kullanici-adi cikarimi, monitor toplamasi ve gercek DB
uzerinden analyze_recent kapsanir.
"""
from arachne.adaptive import credential_spray as cs


# --------------------------------------------------------------------------
# Yardimci: tek IP icin kullanici-adi tasiyan olaylar
# --------------------------------------------------------------------------
def _events(users, ip="10.0.0.9", start=1000.0, step=1.0, per_user=1):
    """Verilen kullanici listesinden (her biri per_user kez) olay uretir."""
    out = []
    t = start
    for u in users:
        for _ in range(per_user):
            out.append({"source_ip": ip, "payload": f"username={u}", "timestamp": t})
            t += step
    return out


# --------------------------------------------------------------------------
# _to_epoch
# --------------------------------------------------------------------------
def test_to_epoch_accepts_epoch_and_iso():
    assert cs._to_epoch(1000) == 1000.0
    assert cs._to_epoch("1000") == 1000.0
    iso = cs._to_epoch("2020-01-01T00:00:00")
    assert isinstance(iso, float) and iso > 0
    assert cs._to_epoch(None) is None
    assert cs._to_epoch("bozuk") is None


# --------------------------------------------------------------------------
# Kullanici adi cikarimi - cesitli bicimler
# --------------------------------------------------------------------------
def test_extract_username_formats():
    assert cs.extract_username({"payload": "user=alice"}) == "alice"
    assert cs.extract_username({"payload": "username=Bob&pass=x"}) == "bob"
    assert cs.extract_username({"payload": "login: carol"}) == "carol"
    assert cs.extract_username({"payload": 'USER dave'}) == "dave"
    assert cs.extract_username({"payload": '{"username": "erin", "password": "y"}'}) == "erin"
    assert cs.extract_username({"payload": "email=frank@example.com"}) == "frank@example.com"


def test_extract_username_direct_field_wins():
    # Olay sozlugunde dogrudan alan varsa payload'a bakmadan onu al.
    assert cs.extract_username({"username": "Root", "payload": "user=other"}) == "root"
    assert cs.extract_username({"user": "svc"}) == "svc"


def test_extract_username_none_when_absent():
    assert cs.extract_username({"payload": "sadece rastgele metin"}) is None
    assert cs.extract_username({"payload": ""}) is None
    assert cs.extract_username("not a dict") is None


# --------------------------------------------------------------------------
# spray_score - pozitif (cok kullanici, az deneme)
# --------------------------------------------------------------------------
def test_spray_positive_many_users_shallow():
    evs = _events(["u1", "u2", "u3", "u4", "u5", "u6"], per_user=1)
    r = cs.spray_score(evs)
    assert r["is_spray"] is True
    assert r["distinct_users"] == 6
    assert r["attempts"] == 6
    assert "PAROLA SPREYI" in r["verdict_tr"]


def test_spray_positive_two_attempts_each():
    # 5 kullanici x 2 deneme = per_user 2.0 (<=3) -> hala sprey.
    evs = _events(["a", "b", "c", "d", "e"], per_user=2)
    r = cs.spray_score(evs)
    assert r["is_spray"] is True
    assert r["distinct_users"] == 5
    assert r["attempts"] == 10


# --------------------------------------------------------------------------
# spray_score - negatif
# --------------------------------------------------------------------------
def test_spray_negative_bruteforce_character():
    # 5 kullanici ama her birine 6 deneme -> per_user 6 > 3 -> sprey degil.
    evs = _events(["a", "b", "c", "d", "e"], per_user=6)
    r = cs.spray_score(evs)
    assert r["is_spray"] is False
    assert "derin" in r["verdict_tr"]


def test_spray_negative_too_few_users():
    evs = _events(["a", "b", "c"], per_user=1)
    r = cs.spray_score(evs)
    assert r["is_spray"] is False
    assert r["distinct_users"] == 3


def test_spray_ignores_events_without_username():
    evs = _events(["a", "b", "c", "d", "e", "f"], per_user=1)
    evs += [{"source_ip": "10.0.0.9", "payload": "GET /index.html", "timestamp": 2000.0}]
    r = cs.spray_score(evs)
    # Kullanici adi tasimayan olay sayima katilmaz.
    assert r["attempts"] == 6
    assert r["distinct_users"] == 6
    assert r["is_spray"] is True


# --------------------------------------------------------------------------
# Bos girdi -> guvenli sifirlar
# --------------------------------------------------------------------------
def test_empty_input_safe_zeros():
    r = cs.spray_score([])
    assert r["is_spray"] is False
    assert r["distinct_users"] == 0
    assert r["attempts"] == 0
    assert r["users_per_min"] == 0.0
    assert r["verdict_tr"] == "veri yok"

    r2 = cs.spray_score(None)
    assert r2["is_spray"] is False
    assert r2["attempts"] == 0


# --------------------------------------------------------------------------
# users_per_min hesabi
# --------------------------------------------------------------------------
def test_users_per_min_computed():
    # 6 kullanici, 60 sn pencere (10 sn arayla) -> 6*60/50 = 7.2
    evs = _events(["u1", "u2", "u3", "u4", "u5", "u6"], step=10.0)
    r = cs.spray_score(evs)
    assert r["users_per_min"] > 0


# --------------------------------------------------------------------------
# SprayMonitor - toplama
# --------------------------------------------------------------------------
def test_spray_monitor_aggregates():
    mon = cs.SprayMonitor()
    # Sprayci IP: 6 farkli kullanici
    t = 1000.0
    for u in ("a", "b", "c", "d", "e", "f"):
        mon.observe("6.6.6.6", payload=f"user={u}", ts=t)
        t += 1.0
    # Masum IP: tek kullanici
    mon.observe("1.1.1.1", payload="user=solo", ts=1000.0)

    rep = mon.report()
    assert rep["counts"]["ips"] == 2
    assert rep["counts"]["sprayers"] == 1
    assert rep["sprayers"][0]["ip"] == "6.6.6.6"
    assert rep["sprayers"][0]["distinct_users"] == 6


def test_spray_monitor_observe_ignores_none_ip():
    mon = cs.SprayMonitor()
    mon.observe(None, payload="user=x")
    rep = mon.report()
    assert rep["counts"]["ips"] == 0


def test_spray_monitor_empty_report():
    mon = cs.SprayMonitor()
    rep = mon.report()
    assert rep["sprayers"] == []
    assert rep["counts"] == {"ips": 0, "sprayers": 0, "events": 0}


# --------------------------------------------------------------------------
# analyze_recent - gercek DB (bos ve dolu)
# --------------------------------------------------------------------------
def test_analyze_recent_empty_db(tmp_path):
    from arachne import storage
    db = str(tmp_path / "empty.db")
    storage.init_db(db_path=db)
    res = cs.analyze_recent(db_path=db)
    assert res["count"] == 0
    assert res["spray_ips"] == []
    assert res["top_sprayer"] is None
    assert res["distinct_user_total"] == 0


def test_analyze_recent_detects_from_db(tmp_path):
    from arachne import storage
    db = str(tmp_path / "full.db")
    storage.init_db(db_path=db)
    # Sprayci IP: 6 farkli kullaniciya login denemesi
    for u in ("alice", "bob", "carol", "dave", "erin", "frank"):
        storage.log_event("5.5.5.5", "ssh", "login_fail",
                          payload=f"username={u}", db_path=db)
    # Masum IP: tek kullanici
    storage.log_event("1.2.3.4", "ssh", "login_fail",
                      payload="username=solo", db_path=db)

    res = cs.analyze_recent(db_path=db)
    assert "5.5.5.5" in res["spray_ips"]
    assert res["top_sprayer"]["ip"] == "5.5.5.5"
    assert res["top_sprayer"]["distinct_users"] == 6
    assert res["distinct_user_total"] == 6
    assert res["count"] == 1


def test_analyze_recent_never_crashes_bad_path():
    res = cs.analyze_recent(db_path="/nonexistent/dir/does_not_exist.db")
    assert res["count"] == 0
    assert res["spray_ips"] == []
    assert res["distinct_user_total"] == 0
