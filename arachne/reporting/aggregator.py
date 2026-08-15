"""
Faz 20 - Birlesik durum toplayicisi.

Yeniden tasarlanan komuta merkezi (SPA) icin tum 20 fazin verisini tek,
duzenli bir sozlukte toplar. Her gorunum (tab) kendi verisini bu tek
kaynaktan alir - boylece frontend basit kalir ve veri sozlesmesi tek yerde
tanimlidir.

Tasarim ilkesi: Bu modul VERI TOPLAR, karar VERMEZ. Pahali hesaplamalar
(profilleme, saldiri grafigi) `include_intel=False` ile atlanabilir -
boylece hizli poll dongusu (canli sayaclar) ile yavas dongusu (derin
analiz) ayrilir.
"""
from .. import storage
from ..intel import risk_engine
from . import command_center


def overview(db_path=None) -> dict:
    """Genel bakis: KPI sayaclari + sistem durusu."""
    hp = storage.summary_stats(db_path=db_path)
    waf = storage.waf_summary_stats(db_path=db_path)
    mtd = storage.mtd_summary_stats(db_path=db_path)
    soar = storage.soar_summary_stats(db_path=db_path)
    mesh = storage.mesh_summary_stats(db_path=db_path)
    ad = storage.active_defense_stats(db_path=db_path)
    ht = storage.honeytoken_stats(db_path=db_path)

    try:
        from ..soar import blocklist
        active_blocks = len(blocklist.active_blocks(db_path=db_path))
    except Exception:
        active_blocks = 0

    by_sev = hp.get("by_severity", {})
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)

    if critical >= 5:
        posture, tone = "KRITIK", "critical"
    elif critical >= 1:
        posture, tone = "YUKSEK", "high"
    elif high >= 3:
        posture, tone = "ORTA-YUKSEK", "high"
    elif hp.get("total_alerts", 0) > 0:
        posture, tone = "ORTA", "medium"
    else:
        posture, tone = "SAKIN", "calm"

    return {
        "posture": posture,
        "posture_tone": tone,
        "kpis": {
            "events": hp.get("total_events", 0),
            "alerts": hp.get("total_alerts", 0),
            "critical_alerts": critical,
            "high_alerts": high,
            "waf_blocked": waf.get("blocked_requests", 0),
            "waf_total": waf.get("total_requests", 0),
            "mtd_rotations": mtd.get("total_rotations", 0),
            "soar_actions": soar.get("total_actions", 0),
            "active_blocks": active_blocks,
            "awaiting_approval": soar.get("awaiting_approval", 0),
            "sensors_online": mesh.get("online_count", 0),
            "sensors_total": mesh.get("sensor_count", 0),
            "deception_actions": ad.get("total_actions", 0),
            "honeytokens_total": ht.get("total_tokens", 0),
            "honeytokens_triggered": ht.get("triggered_tokens", 0),
        },
        "severity_distribution": by_sev,
        "alerts_timeline": storage.alerts_timeline(db_path=db_path),
    }


def defense_layers(db_path=None) -> dict:
    """Tum savunma katmanlarinin (20 faz) saglik durumu."""
    base = command_center.build_layer_health(db_path=db_path)

    # Faz 11-12: aktif savunma katmanlari
    ad = storage.active_defense_stats(db_path=db_path)
    ht = storage.honeytoken_stats(db_path=db_path)
    base["active_defense"] = {
        "label": "Aktif Savunma", "phase": "Faz 11",
        "operational": ad["total_actions"] > 0,
        "metric": ad["total_actions"], "metric_label": "aldatma eylemi",
        "detail": "Tarpit + sahte veri besleme (kendi yuzeyimizde)",
    }
    base["honeytokens"] = {
        "label": "Honeytoken Tuzaklari", "phase": "Faz 12",
        "operational": ht["total_tokens"] > 0,
        "metric": ht["triggered_tokens"], "metric_label": "tetiklenen tuzak",
        "detail": f"{ht['total_tokens']} tuzak yerlestirildi",
    }
    return base


def active_defense_view(db_path=None) -> dict:
    """SOAR + Aktif Savunma + Honeytoken gorunumu."""
    try:
        from ..soar import blocklist
        blocks = blocklist.active_blocks(db_path=db_path)
    except Exception:
        blocks = []

    return {
        "soar_actions": storage.get_soar_actions(limit=40, db_path=db_path),
        "soar_stats": storage.soar_summary_stats(db_path=db_path),
        "active_blocks": blocks,
        "active_defense_log": storage.get_active_defense(limit=40, db_path=db_path),
        "active_defense_stats": storage.active_defense_stats(db_path=db_path),
        "honeytokens": storage.get_honeytokens(db_path=db_path)[:40],
        "honeytoken_stats": storage.honeytoken_stats(db_path=db_path),
    }


def rules_and_integrity(db_path=None) -> dict:
    """Faz 14 (kural motoru) + Faz 16 (imza uretimi) + Faz 17 (butunluk)."""
    from ..detection.rule_engine import default_ruleset
    from ..integrity.audit_chain import AuditChain, tamper_report

    rs = default_ruleset()
    rules_info = [{
        "id": r.id, "name": r.name, "severity": r.severity,
        "attck": r.attck, "cwe": r.cwe,
        "string_count": len(r.strings), "condition": str(r.condition),
        "description": r.description,
    } for r in rs.rules]

    # Faz 17: SOAR denetim kayitlarindan bir butunluk zinciri kur ve dogrula.
    # Bu, "denetim kayitlarimiz kurcalanmis mi?" sorusunu kanitlanabilir kilar.
    chain = AuditChain()
    for action in reversed(storage.get_soar_actions(limit=200, db_path=db_path)):
        chain.append({
            "action": action["action"], "target": action["target"],
            "outcome": action["outcome"], "timestamp": action["timestamp"],
        })
    integrity = tamper_report(chain)

    # Faz 16: yakalanan yuklerden imza uret (kotu = alarmli IP'lerin yukleri,
    # mesru = alarm uretmemis olaylarin yukleri)
    synth = _synthesize_from_db(db_path)

    return {
        "rules": rules_info,
        "rules_loaded": len(rs.rules),
        "rules_failed": len(rs.errors),
        "integrity": integrity,
        "synthesized_signatures": synth,
    }


def _synthesize_from_db(db_path=None) -> dict:
    """Veritabanindaki olaylardan otomatik imza uretir."""
    try:
        alerts = storage.get_all_alerts(limit=200, db_path=db_path)
        alert_ips = {a["source_ip"] for a in alerts}
        events = storage.get_recent_events(since_seconds=86400, db_path=db_path)

        malicious, benign = [], []
        for e in events:
            payload = e.get("payload")
            if not payload:
                continue
            if e.get("source_ip") in alert_ips:
                malicious.append(payload)
            else:
                benign.append(payload)

        if not malicious:
            return {"candidates": [], "candidate_count": 0,
                    "note_tr": "Henuz imza uretimi icin yeterli kotu niyetli yuk yok"}

        from ..intel.signature_synth import synthesize_signatures
        return synthesize_signatures(malicious, benign, max_candidates=10)
    except Exception:
        return {"candidates": [], "candidate_count": 0, "note_tr": "hata"}


def threat_intel_view(db_path=None, top_n=25) -> dict:
    """Faz 5/6/18/19: profiller, kampanyalar, risk, saldiri grafikleri."""
    from ..ai import report_writer
    from ..intel import attack_graph, profiler
    from ..reverse.attack_analyzer import analyze_ip

    data = report_writer.situation_report(db_path=db_path)
    profiles = data.get("profiles", [])
    campaigns = data.get("campaigns", [])
    campaign_ips = {ip for c in campaigns for ip in c.get("member_ips", [])}

    # Her profile risk skoru + saldiri grafigi ekle
    enriched = []
    for p in profiles[:top_n]:
        ip = p.get("source_ip")
        events = storage.get_recent_events(source_ip=ip, db_path=db_path)
        ip_analysis = analyze_ip(ip, events)
        risk = risk_engine.compute_risk(
            attack_classes=ip_analysis.get("attack_classes", []),
            kill_chain_phase=ip_analysis.get("kill_chain", {}).get("phase", "reconnaissance"),
            automated=ip_analysis.get("automated", False),
            repeat_offender=p.get("alert_count", 0) > 1,
            in_campaign=ip in campaign_ips,
            has_reverse_shell=bool(ip_analysis.get("iocs", {}).get("reverse_shells")),
            event_count=p.get("event_count", 0),
        )
        graph = attack_graph.build_attack_graph(
            ip, ip_analysis.get("per_payload", []), events)
        enriched.append({
            "source_ip": ip,
            "threat_class": p.get("threat_class"),
            "event_count": p.get("event_count", 0),
            "alert_count": p.get("alert_count", 0),
            "primary_tool": p.get("primary_tool"),
            "attack_classes": ip_analysis.get("attack_classes", []),
            "kill_chain": ip_analysis.get("kill_chain", {}),
            "timing": p.get("timing", {}),
            "signature": p.get("signature"),
            "geo": p.get("geo", {}),
            "risk": risk,
            "attack_graph": graph,
            "in_campaign": ip in campaign_ips,
        })

    # Risk skoruna gore sirala
    enriched.sort(key=lambda x: -x["risk"]["risk_score"])

    return {
        "report": data.get("report"),
        "profiles": enriched,
        "campaigns": campaigns,
        "llm_status": data.get("llm_status"),
    }


def adaptive_view(db_path=None) -> dict:
    """Faz 21-30: adaptif savunma gorunumu - durus, D3FEND/CSF kapsam karnesi,
    aldatma agi, oyun-teorik ko-evrim, kolektif bagisiklik. Panelin 'Adaptif
    Savunma' sekmesini besler."""
    from . import command_center
    from ..adaptive import coverage, game_theory, deception_grid, collective

    # Durus + adaptif katman sayilari (kubbe ile ayni kaynaktan)
    adaptive = command_center.build_adaptive_layer_counts(db_path=db_path)

    # D3FEND & NIST CSF 2.0 kapsam karnesi
    cov = coverage.build_coverage()
    cov_dict = {
        "d3fend_covered": cov.d3fend_covered,
        "d3fend_pct": cov.d3fend_tactic_pct,
        "csf_covered": cov.csf_covered,
        "csf_pct": cov.csf_function_pct,
        "engage": cov.engage_activities,
        "summary_tr": cov.summary_tr,
        "matrix": coverage.coverage_matrix(),
    }

    # Oyun-teorik ko-evrim: statik savunma vs re-randomize eden savunma
    g = game_theory.DEFAULT_HONEYPOT_GAME
    coevo = game_theory.coevolve(g["configs"], g["attacks"], g["payoff"], rounds=8)
    stack = game_theory.stackelberg_defense(g["configs"], g["attacks"], g["payoff"])

    # Aldatma agi ornek topolojisi (kirinti yolu gorseli icin)
    grid = deception_grid.DeceptionGrid().build_default()
    grid_summary = grid.grid_summary()
    grid_summary["breadcrumbs"] = grid.plant_breadcrumbs()
    grid_summary["nodes"] = list(grid.nodes.values())
    grid_summary["edges"] = grid.edges

    # Kolektif bagisiklik: alarmli IP'leri paylasilan gostergeye cevir
    cd = collective.CollectiveDefense()
    alerts = storage.get_all_alerts(limit=200, db_path=db_path)
    sensors = storage.get_sensors(db_path=db_path)
    for s in sensors:
        cd.register_sensor(s.get("sensor_id", "sensor"))
    if not sensors:
        for sid in ("sensor-a", "sensor-b", "sensor-c"):
            cd.register_sensor(sid)
    sensor_ids = [s.get("sensor_id", "sensor") for s in sensors] or ["sensor-a", "sensor-b", "sensor-c"]
    for i, a in enumerate({a.get("source_ip") for a in alerts if a.get("source_ip")}):
        cd.share_indicator(sensor_ids[i % len(sensor_ids)],
                           {"kind": "ip", "value": a})

    return {
        "posture": adaptive["posture"],
        "posture_score": adaptive["posture_score"],
        "layer_counts": adaptive["counts"],
        "coverage": cov_dict,
        "coevolution": coevo,
        "stackelberg": stack,
        "deception_grid": grid_summary,
        "collective": {
            "immunity": cd.immunity_report(),
            "propagation": cd.propagation_savings(),
        },
    }
