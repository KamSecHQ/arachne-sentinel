"""Faz 7 - SOAR otonom savunma orkestrasyonu testleri."""
import tempfile
import time
from pathlib import Path

import pytest

from arachne import storage
from arachne.soar import actions, blocklist, engine, playbooks


def _tmp_db():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=tmp)
    return tmp


@pytest.fixture(autouse=True)
def _clean_blocklist():
    """Her test temiz bir engelleme listesiyle baslar (durum sizmasi olmasin)."""
    blocklist.clear_all()
    yield
    blocklist.clear_all()


# --- Engelleme listesi ------------------------------------------------------

def test_block_and_is_blocked():
    db = _tmp_db()
    result = blocklist.block("203.0.113.10", seconds=60, reason="test", db_path=db)
    assert result["blocked"] is True
    assert blocklist.is_blocked("203.0.113.10", db_path=db) is True
    assert blocklist.is_blocked("203.0.113.11", db_path=db) is False


def test_block_refuses_loopback_to_protect_lab():
    """Lab guvenligi: sistem kendi kendini kilitleyemez."""
    db = _tmp_db()
    result = blocklist.block("127.0.0.1", seconds=60, db_path=db)
    assert result["blocked"] is False
    assert blocklist.is_blocked("127.0.0.1", db_path=db) is False
    assert "korunan" in result["reason_not_blocked"].lower()


def test_block_refuses_private_network_addresses():
    db = _tmp_db()
    assert blocklist.block("192.168.1.50", seconds=60, db_path=db)["blocked"] is False


def test_block_allows_documentation_range_for_scenarios():
    """RFC 5737 adresleri arkasinda gercek cihaz yok - engellenebilir."""
    db = _tmp_db()
    assert blocklist.block("203.0.113.77", seconds=60, db_path=db)["blocked"] is True


def test_block_expires_after_ttl():
    """TTL'li engelleme: sure dolunca otomatik acilir (geri alinabilirlik)."""
    db = _tmp_db()
    blocklist.block("203.0.113.20", seconds=1, db_path=db)
    assert blocklist.is_blocked("203.0.113.20", db_path=db) is True
    time.sleep(1.4)
    assert blocklist.is_blocked("203.0.113.20", db_path=db) is False


def test_longer_block_wins_over_shorter():
    db = _tmp_db()
    blocklist.block("203.0.113.30", seconds=600, db_path=db)
    blocklist.block("203.0.113.30", seconds=10, db_path=db)
    assert blocklist.remaining_seconds("203.0.113.30", db_path=db) > 100


def test_unblock_removes_entry():
    db = _tmp_db()
    blocklist.block("203.0.113.40", seconds=300, db_path=db)
    assert blocklist.unblock("203.0.113.40", db_path=db) is True
    assert blocklist.is_blocked("203.0.113.40", db_path=db) is False


def test_block_writes_audit_record():
    """Her yaptirim denetim kaydina yazilmali - aciklanabilirlik sarti."""
    db = _tmp_db()
    blocklist.block("203.0.113.50", seconds=60, reason="sqlmap tespit edildi",
                    playbook="pb-web-exploit", db_path=db)
    records = storage.get_soar_actions(db_path=db)
    assert len(records) == 1
    assert records[0]["action"] == "block_ip"
    assert records[0]["target"] == "203.0.113.50"
    assert "sqlmap" in records[0]["reason"]


def test_active_blocks_excludes_expired():
    db = _tmp_db()
    blocklist.block("203.0.113.60", seconds=300, db_path=db)
    blocklist.block("203.0.113.61", seconds=1, db_path=db)
    time.sleep(1.4)
    active = blocklist.active_blocks(db_path=db)
    ips = {b["ip"] for b in active}
    assert "203.0.113.60" in ips
    assert "203.0.113.61" not in ips


# --- Playbook secimi --------------------------------------------------------

def test_playbook_matching_by_attack_class():
    matched = playbooks.find_matching_playbooks(
        score=60, severity="high", attack_classes=["SQL Injection"])
    assert any(pb["name"] == "pb-web-exploit" for pb in matched)


def test_playbook_not_matched_below_score_threshold():
    matched = playbooks.find_matching_playbooks(
        score=10, severity="low", attack_classes=["SQL Injection"])
    assert not any(pb["name"] == "pb-web-exploit" for pb in matched)


def test_critical_score_triggers_targeted_actor_playbook():
    matched = playbooks.find_matching_playbooks(
        score=115, severity="critical", attack_classes=["SQL Injection", "Port Scan"])
    assert any(pb["name"] == "pb-targeted-actor" for pb in matched)


def test_playbooks_sorted_most_severe_first():
    matched = playbooks.find_matching_playbooks(
        score=115, severity="critical",
        attack_classes=["SQL Injection", "Port Scan", "Brute Force"])
    scores = [pb["trigger"]["min_score"] for pb in matched]
    assert scores == sorted(scores, reverse=True)


def test_every_playbook_has_explainable_decisions():
    """Projenin temel ilkesi: her karar bir gerekce tasimali."""
    for pb in playbooks.PLAYBOOKS:
        assert pb["description_tr"], f"{pb['name']} aciklamasiz"
        for rule in pb["decision"]:
            assert rule.get("because"), f"{pb['name']} icinde gerekcesiz karar kurali"
            assert rule.get("then"), f"{pb['name']} icinde eylemsiz karar kurali"


def test_every_playbook_action_name_is_registered():
    """Playbook'lar var olmayan bir eyleme referans veremez."""
    for pb in playbooks.PLAYBOOKS:
        for name in pb["enrichment"]:
            assert actions.get_action(name), f"bilinmeyen zenginlestirme: {name}"
        for rule in pb["decision"]:
            for action_name, _ in rule["then"]:
                assert actions.get_action(action_name), f"bilinmeyen eylem: {action_name}"


# --- Eylemler ---------------------------------------------------------------

def test_enrichment_actions_are_side_effect_free():
    """Zenginlestirme eylemleri durum degistirmemeli."""
    for name in actions.ENRICHMENT_ACTIONS:
        assert actions.action_is_safe(name) is True
    for name in actions.CONTAINMENT_ACTIONS:
        assert actions.action_is_safe(name) is False


def test_escalate_to_human_never_auto_applies():
    """Insan onayi gerektiren eylem otomatik UYGULANMAZ."""
    db = _tmp_db()
    result = actions.escalate_to_human("203.0.113.70", context={"reason": "test"},
                                        db_path=db)
    assert result.outcome == "onay-bekliyor"
    assert result.requires_approval is True
    assert blocklist.is_blocked("203.0.113.70", db_path=db) is False


def test_enrich_history_detects_repeat_offender():
    db = _tmp_db()
    storage.log_alert("203.0.113.80", 60, "high", ["ilk"], db_path=db)
    storage.log_alert("203.0.113.80", 90, "critical", ["ikinci"], db_path=db)
    result = actions.enrich_history("203.0.113.80", db_path=db)
    assert result.data["repeat_offender"] is True
    assert result.data["prior_alerts"] == 2


def test_trigger_mtd_rotation_logs_to_mtd_table():
    """Faz 7, Faz 4'u tetikleyebilmeli - katmanlar birbirini guclendirir."""
    db = _tmp_db()
    result = actions.trigger_mtd_rotation("203.0.113.90",
                                           context={"reason": "kesif"}, db_path=db)
    assert result.success is True
    rotations = storage.get_mtd_rotations(db_path=db)
    assert any(r["component"] == "soar:triggered-rotation" for r in rotations)


# --- Playbook motoru --------------------------------------------------------

def test_respond_to_alert_runs_matching_playbook():
    db = _tmp_db()
    for _ in range(20):
        storage.log_event("203.0.113.100", "http-admin", "data",
                          payload="id=1' OR '1'='1", db_path=db)
    result = engine.respond_to_alert("203.0.113.100", score=75, severity="high",
                                      attack_classes=["SQL Injection"], db_path=db)
    assert result["matched_playbooks"] >= 1
    assert result["total_actions_applied"] >= 1
    assert blocklist.is_blocked("203.0.113.100", db_path=db) is True


def test_respond_to_alert_with_no_match_is_safe():
    db = _tmp_db()
    result = engine.respond_to_alert("203.0.113.110", score=5, severity="low",
                                      attack_classes=[], db_path=db)
    assert result["matched_playbooks"] == 0
    assert result["executions"] == []
    assert blocklist.is_blocked("203.0.113.110", db_path=db) is False


def test_dry_run_applies_nothing():
    """Kuru calistirma: karar verilir ama HICBIR eylem uygulanmaz."""
    db = _tmp_db()
    result = engine.respond_to_alert("203.0.113.120", score=95, severity="critical",
                                      attack_classes=["Command Injection"],
                                      db_path=db, dry_run=True)
    assert result["matched_playbooks"] >= 1
    assert blocklist.is_blocked("203.0.113.120", db_path=db) is False
    assert all(a["outcome"] == "atlandi"
               for e in result["executions"] for a in e["actions"])


def test_command_injection_escalates_to_human():
    """En yuksek etkili saldiri sinifi mutlaka insan onayina yukselmeli."""
    db = _tmp_db()
    result = engine.respond_to_alert("203.0.113.130", score=95, severity="critical",
                                      attack_classes=["Command Injection"], db_path=db)
    assert result["awaiting_approval"] >= 1


def test_decision_rules_evaluated_in_order_first_match_wins():
    pb = playbooks.PLAYBOOKS_BY_NAME["pb-web-exploit"]
    result = engine.run_playbook(
        pb, "203.0.113.140",
        {"score": 95, "severity": "critical", "attack_classes": ["Command Injection"]},
        db_path=_tmp_db(), dry_run=True,
    )
    assert result["decision_matched"] is True
    assert "komut enjeksiyonu" in result["decision_reason"].lower()


def test_engine_records_every_action_with_reason():
    db = _tmp_db()
    engine.respond_to_alert("203.0.113.150", score=75, severity="high",
                            attack_classes=["SQL Injection"], db_path=db)
    records = storage.get_soar_actions(db_path=db)
    assert records
    for record in records:
        assert record["outcome"]
        assert record["target"] == "203.0.113.150"


def test_soar_summary_stats_counts_awaiting_approval():
    db = _tmp_db()
    engine.respond_to_alert("203.0.113.160", score=95, severity="critical",
                            attack_classes=["Command Injection"], db_path=db)
    stats = storage.soar_summary_stats(db_path=db)
    assert stats["total_actions"] > 0
    assert stats["awaiting_approval"] >= 1


def test_blocklist_survives_across_processes_via_database():
    """Engellemeler bellekte DEGIL veritabaninda tutulmali.

    Bu test, uctan uca canli testte fark edilen gercek bir hatayi korur:
    honeypot ve panel ayri sureclerde calisir; bellekteki bir liste diger
    surecten gorunmez ve yaptirim sessizce ise yaramaz."""
    db = _tmp_db()
    blocklist.block("203.0.113.170", seconds=300, reason="surec testi", db_path=db)

    # Bellek onbellegini tamamen bosalt: baska bir surec taklidi
    blocklist._cache["blocked"] = set()
    blocklist._cache["fetched_at"] = 0.0

    assert blocklist.is_blocked("203.0.113.170", db_path=db) is True
    assert storage.is_ip_blocked("203.0.113.170", db_path=db) is True


def test_blocklist_fails_open_on_storage_error():
    """Depolama hatasinda engelleme UYGULANMAZ (fail-open).

    Bilincli tercih: bir veritabani hatasi yuzunden mesru trafigi kesmek,
    honeypot'un amaciyla celisir. Guvenlik sistemlerinde fail-open/fail-closed
    tercihi bilincli yapilmali ve belgelenmelidir."""
    blocklist._cache["fetched_at"] = 0.0
    assert blocklist.is_blocked("203.0.113.180", db_path="/gecersiz/yol/yok.db") is False
