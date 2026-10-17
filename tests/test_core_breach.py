"""Faz 115 — Son Hat'in GERCEK sinyalle (cekirdek yemi) devreye girmesi.

Kapsam:
  * analyze_ip, Faz 1 brute-force ritmini "Brute Force" sinifi olarak raporlar
    (oncesinde bu sinif canli akista hic uretilmiyordu -> cekirdek yemi ve
    pb-brute-force playbook'u erisilemezdi).
  * scripts/demo_core_breach.py senaryosu gercek akistan (kayit -> skor ->
    sinif -> SOAR -> aldatma) gecip should_engage'i tetikler.
  * /api/fortress gercek sinyali gorur, yemi yutan IP'yi bildirir.
  * bunker3d.js izleyici karari (decideWatch) — Node.js ile, DOM'suz.
"""
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from arachne import config, storage
from arachne.active_defense.deception import DeceptionEngine
from arachne.customer import profile as customer_profile
from arachne.reverse.attack_analyzer import analyze_ip
from arachne.soar import notifications

ROOT = Path(__file__).resolve().parent.parent


def _load_scenario():
    spec = importlib.util.spec_from_file_location(
        "demo_core_breach", ROOT / "scripts" / "demo_core_breach.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connects(service, n):
    return [{"id": i, "service": service, "event_type": "connect", "payload": None}
            for i in range(n)]


# ---------------------------------------------------------------------------
# analyze_ip: davranissal "Brute Force" sinifi
# ---------------------------------------------------------------------------
def test_analyze_ip_reports_brute_force_from_connection_rhythm():
    result = analyze_ip("203.0.113.5", _connects("ssh", config.BRUTE_FORCE_ATTEMPTS))
    assert "Brute Force" in result["attack_classes"]
    assert "T1110.001" in {t["id"] for t in result["attck_techniques"]}


def test_analyze_ip_no_brute_force_below_threshold():
    result = analyze_ip("203.0.113.5", _connects("ssh", config.BRUTE_FORCE_ATTEMPTS - 1))
    assert "Brute Force" not in result["attack_classes"]


def test_analyze_ip_brute_force_needs_same_service():
    events = []
    for service in ("ssh", "ftp", "mysql", "http-admin"):
        events += _connects(service, 2)
    assert "Brute Force" not in analyze_ip("203.0.113.5", events)["attack_classes"]


def test_analyze_ip_tolerates_events_without_type_fields():
    result = analyze_ip("203.0.113.5", [{"payload": "id=1' OR '1'='1"}])
    assert "SQL Injection" in result["attack_classes"]
    assert "Brute Force" not in result["attack_classes"]


# ---------------------------------------------------------------------------
# storage.core_vault_last_touch
# ---------------------------------------------------------------------------
def test_core_vault_last_touch_returns_source_ip(tmp_path):
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    assert storage.core_vault_last_touch(db_path=db) is None
    DeceptionEngine(db_path=db).apply("203.0.113.9", threat_score=70,
                                      attack_classes=["Brute Force"])
    touch = storage.core_vault_last_touch(db_path=db)
    assert touch["source_ip"] == "203.0.113.9"


# ---------------------------------------------------------------------------
# Senaryo: gercek akistan Son Hat'e
# ---------------------------------------------------------------------------
def test_core_breach_scenario_engages_last_line_via_real_signal(tmp_path):
    scenario = _load_scenario()
    r = scenario.run_core_breach(db_path=str(tmp_path / "t.db"), speed=0, verbose=False)

    assert r["triggered_alert"] is True
    assert r["score"] >= 55                       # aldatma motorunun yuksek tehdit esigi
    assert "Brute Force" in r["attack_classes"]
    # SQLi / path traversal olsaydi aldatma 'fake-data' secerdi, yem acilmazdi
    assert "SQL Injection" not in r["attack_classes"]
    assert "Path Traversal" not in r["attack_classes"]
    assert r["deception_action"] == "fake-success"
    assert r["core_vault_touched"] is True
    assert r["should_engage"] is True
    assert "Cekirdek yemi" in r["engage_reason"]

    st = r["fortress"]
    assert st["engaged"] is True
    assert st["summary"]["total_layers"] == 50
    assert st["summary"]["reached_real_asset"] is False
    assert st["reaction_ok"] is True


def test_core_breach_terminal_preview_does_not_notify_customer(tmp_path, monkeypatch):
    """Webhook'u panel surecindeki kale gonderir; script ikinci bildirim atmaz."""
    monkeypatch.setattr(customer_profile, "DEFAULT_PROFILE_PATH", tmp_path / "p.json")
    customer_profile.save_profile({"company_name": "ACME", "asset_name": "X",
                                   "alert_webhook_url": "https://hooks.example.com/acme"})
    sent = []
    monkeypatch.setattr(notifications, "_send", lambda url, payload: sent.append(payload))

    scenario = _load_scenario()
    r = scenario.run_core_breach(db_path=str(tmp_path / "t.db"), soar_enabled=False,
                                 speed=0, verbose=False)
    assert r["should_engage"] is True
    assert [p for p in sent if p.get("event_type") == "son_hat_devrede"] == []


# ---------------------------------------------------------------------------
# /api/fortress: gercek sinyal + yemi yutan kaynak
# ---------------------------------------------------------------------------
def test_api_fortress_engages_on_core_bait_and_reports_trigger_ip(tmp_path, monkeypatch):
    from arachne.reporting import dashboard

    db = tmp_path / "live.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    monkeypatch.setattr(dashboard, "_FORTRESS", None)
    monkeypatch.setattr(notifications, "notify_critical_event", lambda **kw: False)
    storage.init_db()
    c = dashboard.app.test_client()

    before = c.get("/api/fortress").get_json()
    assert before["engaged"] is False
    assert before["should_engage"] is False
    assert before["trigger_ip"] is None

    scenario = _load_scenario()
    scenario.run_core_breach(db_path=str(db), soar_enabled=False, speed=0, verbose=False)

    after = c.get("/api/fortress").get_json()
    assert after["engaged"] is True
    assert after["should_engage"] is True
    assert "Cekirdek yemi" in after["engage_reason"]
    assert after["trigger_ip"] == scenario.ATTACKER_IP


# ---------------------------------------------------------------------------
# bunker3d.js izleyici karari — Node.js ile (yoksa atlanir)
# ---------------------------------------------------------------------------
_NODE_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const sandbox = {
  window: {}, console, TextEncoder, setTimeout, clearTimeout, setInterval, clearInterval,
  document: { readyState: "complete", getElementById: () => null,
              querySelector: () => null, addEventListener() {} },
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), sandbox);
const d = sandbox.window.ArachneBunkerLogic.decideWatch;
const real = { engaged: true, should_engage: true };
const drillOnly = { engaged: true, should_engage: false };
const idle = { engaged: false, should_engage: false };
console.log(JSON.stringify({
  nullStatus: d(null, false, null),
  realWhileIdle: d(real, false, null),
  realDuringDrill: d(real, true, "drill"),
  realWhileReal: d(real, true, "real"),
  drillContinues: d(drillOnly, true, "drill"),
  signalGoneInReal: d(idle, true, "real"),
  serverDrillAfterReal: d(drillOnly, true, "real"),
  idleStaysIdle: d(idle, false, null),
}));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js yok")
def test_bunker_watch_decision_js():
    js = ROOT / "arachne" / "reporting" / "static" / "js" / "bunker3d.js"
    out = subprocess.run(["node", "-e", _NODE_HARNESS, str(js)],
                         capture_output=True, text=True, timeout=30, check=True)
    got = json.loads(out.stdout.strip().splitlines()[-1])
    assert got == {
        "nullStatus": "none",
        "realWhileIdle": "activate-real",
        "realDuringDrill": "promote-real",
        "realWhileReal": "none",
        "drillContinues": "none",          # tatbikat 11 sn'lik akisini surdurur
        "signalGoneInReal": "standby",
        "serverDrillAfterReal": "standby",
        "idleStaysIdle": "none",
    }
