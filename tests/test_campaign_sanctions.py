"""Faz 119 — Son Hat yaptirimi tek IP'ye degil, davranissal kampanyaya uygulanir.

IP degistiren (VPN/proxy/botnet) saldirgan onceden engeli ve karantinayi
asiyordu: yaptirim tek IP'ye bagliydi. Artik ayni davranissal parmak izini
paylasan kardes IP'ler de yaptirim alir; sinyal surdukce kampanya yeniden
taranir ve sonradan gelen YENI IP de yakalanir.
"""
import pytest

from arachne import config, storage
from arachne.lastline import enforcement
from arachne.lastline.base import DefenseContext
from arachne.waf.middleware import WAFMiddleware

LEADER = "198.51.100.51"
SIBLINGS = ["198.51.100.52", "198.51.100.53"]
UNRELATED = "192.0.2.77"
SQLMAP = "GET /?id=1 HTTP/1.1\r\nUser-Agent: sqlmap/1.7.2#stable (http://sqlmap.org)"


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "campaign.db")
    storage.init_db(db_path=path)
    return path


def _campaign_member(db, ip, n=6):
    """Ayni arac (sqlmap), ayni servis, ayni ritim -> ayni davranissal parmak izi."""
    for _ in range(n):
        storage.log_event(ip, "http-admin", "data", dest_port=8081, payload=SQLMAP, db_path=db)


def _unrelated(db, ip=UNRELATED, n=6):
    for _ in range(n):
        storage.log_event(ip, "ssh", "data", dest_port=2222, payload="root:toor", db_path=db)


def _engage(db):
    return enforcement.engage_sanctions(DefenseContext(), "Cekirdek yemi", trigger_ip=LEADER,
                                        db_path=db)


def test_campaign_siblings_found_unrelated_excluded(db):
    for ip in [LEADER] + SIBLINGS:
        _campaign_member(db, ip)
    _unrelated(db)
    assert sorted(enforcement.campaign_siblings(LEADER, db_path=db)) == SIBLINGS


def test_protected_sibling_never_sanctioned(db):
    for ip in [LEADER, "10.0.0.9"] + SIBLINGS:
        _campaign_member(db, ip)
    assert "10.0.0.9" not in enforcement.campaign_siblings(LEADER, db_path=db)


def test_no_campaign_for_lone_attacker(db):
    _campaign_member(db, LEADER)
    _unrelated(db)
    assert enforcement.campaign_siblings(LEADER, db_path=db) == []


def test_engage_blocks_and_quarantines_whole_campaign(db):
    for ip in [LEADER] + SIBLINGS:
        _campaign_member(db, ip)
    _unrelated(db)
    st = _engage(db)
    assert st["campaign_ips"] == SIBLINGS
    assert st["campaign_blocked"] == len(SIBLINGS)
    for ip in [LEADER] + SIBLINGS:
        assert storage.is_ip_blocked(ip, db_path=db), ip
        assert storage.is_lastline_quarantined(ip, db_path=db), ip
    assert not storage.is_ip_blocked(UNRELATED, db_path=db)
    assert not storage.is_lastline_quarantined(UNRELATED, db_path=db)
    soar = storage.get_soar_actions(target=SIBLINGS[0], db_path=db)
    assert any("kampanya kardesi" in (a["reason"] or "") for a in soar)


def test_campaign_cap_limits_blast_radius(db, monkeypatch):
    monkeypatch.setattr(enforcement, "MAX_CAMPAIGN_TARGETS", 1)
    for ip in [LEADER] + SIBLINGS:
        _campaign_member(db, ip)
    assert len(_engage(db)["campaign_ips"]) == 1


def test_rescan_catches_attacker_rotating_to_new_ip(db, monkeypatch):
    for ip in [LEADER] + SIBLINGS:
        _campaign_member(db, ip)
    _engage(db)
    rotated = "198.51.100.54"                 # saldirgan IP degistirdi
    _campaign_member(db, rotated)
    monkeypatch.setattr(enforcement, "CAMPAIGN_RESCAN_SECONDS", 0)
    st = enforcement.refresh_sanctions(db_path=db)
    assert rotated in st["campaign_ips"]
    assert storage.is_ip_blocked(rotated, db_path=db)
    assert storage.is_lastline_quarantined(rotated, db_path=db)


def test_rescan_is_throttled(db, monkeypatch):
    for ip in [LEADER] + SIBLINGS:
        _campaign_member(db, ip)
    _engage(db)
    _campaign_member(db, "198.51.100.54")
    monkeypatch.setattr(enforcement, "CAMPAIGN_RESCAN_SECONDS", 3600)
    st = enforcement.refresh_sanctions(db_path=db)
    assert "198.51.100.54" not in st["campaign_ips"]


def test_release_ends_campaign_quarantine(db):
    for ip in [LEADER] + SIBLINGS:
        _campaign_member(db, ip)
    _engage(db)
    enforcement.release_sanctions(db_path=db)
    assert not storage.is_lastline_quarantined(SIBLINGS[0], db_path=db)
    assert storage.is_ip_blocked(SIBLINGS[0], db_path=db)       # SOAR TTL'i surer


def test_waf_refuses_campaign_sibling_at_real_asset(db):
    for ip in [LEADER] + SIBLINGS:
        _campaign_member(db, ip)
    _engage(db)

    def app(environ, start_response):
        start_response("200 OK", [])
        return [b"ok"]

    statuses = []
    waf = WAFMiddleware(app, db_path=db)
    for ip in (SIBLINGS[1], UNRELATED):
        from io import BytesIO
        waf({"REMOTE_ADDR": ip, "REQUEST_METHOD": "GET", "PATH_INFO": "/",
             "QUERY_STRING": "", "wsgi.input": BytesIO(b"")},
            lambda s, h: statuses.append(s))
    assert statuses[0].startswith("403") and statuses[1].startswith("200")


def test_old_engagement_rows_without_campaign_table_still_work(tmp_path):
    """Faz 116 penceresi (kampanya tablosu yokken) birincil hedefle calisir."""
    import sqlite3
    path = str(tmp_path / "old.db")
    storage.init_db(db_path=path)
    conn = sqlite3.connect(path)
    conn.execute("DROP TABLE lastline_campaign_targets")       # Faz 116 semasi
    conn.execute("INSERT INTO lastline_engagements (engaged_at, expires_at, target_ip, reason) "
                 "VALUES (datetime('now'), datetime('now', '+900 seconds'), ?, 'eski')", (LEADER,))
    conn.commit()
    conn.close()
    assert storage.is_lastline_quarantined(LEADER, db_path=path)
    assert enforcement.status(db_path=path)["campaign_ips"] == []
