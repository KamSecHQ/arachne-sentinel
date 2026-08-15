"""
AI analist raporlama arayuzu - Faz 8'in disa acilan yuzu.

Kullanicinin "yapay zekaya sistemin durumunu sor" istegi buraya duser.
Yerel analist ile opsiyonel karantina LLM'i birlestiren katman budur.

--- Birlestirme politikasi ---
Yerel analist HER ZAMAN calisir ve temel sonucu uretir. LLM etkinse
ciktisi EK BIR ALAN olarak (`llm_opinion`) eklenir - yerel sonucun
YERINE GECMEZ, YANINDA durur. Boylece:
  * LLM yaniltilsa bile deterministik sonuc bozulmaz
  * kullanici iki gorusu karsilastirabilir
  * LLM yoksa hicbir sey eksik gorunmez
"""
from .. import storage
from ..intel import profiler
from ..reverse.attack_analyzer import analyze_ip, analyze_payload
from . import analyst, llm_backend
from .sanitizer import sanitize_for_ai


def analyze_attack(payload: str, use_llm: bool = True) -> dict:
    """Tek bir saldiri yukunu tam analiz eder (deterministik + AI yorumu)."""
    technical = analyze_payload(payload)
    sanitized = sanitize_for_ai(payload)
    local = analyst.analyze_payload_locally(payload, technical, sanitized)

    result = {
        "technical_analysis": technical,
        "analyst_opinion": local,
        "sanitization": {
            "injection_attempt": sanitized["injection_attempt"],
            "injection_indicators": sanitized["injection_indicators"],
            "injection_assessment_tr": sanitized["injection_assessment_tr"],
            "truncated": sanitized["truncated"],
            "original_length": sanitized["original_length"],
        },
        "llm_opinion": None,
        "llm_status": llm_backend.status(),
    }

    if use_llm and llm_backend.is_enabled():
        context = {
            "tespit_edilen_saldiri_siniflari": technical.get("attack_classes"),
            "tespit_edilen_arac": technical.get("primary_tool"),
            "gizleme_katmani": technical.get("deobfuscation", {}).get("layers"),
            "kill_chain_asamasi": technical.get("kill_chain", {}).get("phase_tr"),
            "deterministik_tehdit_skoru": technical.get("threat_score"),
        }
        result["llm_opinion"] = llm_backend.analyze(payload, context)

    return result


def analyze_attacker(source_ip: str, db_path=None, use_llm: bool = True) -> dict:
    """Bir saldirganin tum etkinligini analiz eder."""
    events = storage.get_recent_events(source_ip=source_ip, db_path=db_path)
    alerts = [a for a in storage.get_all_alerts(limit=500, db_path=db_path)
              if a.get("source_ip") == source_ip]

    ip_analysis = analyze_ip(source_ip, events)
    profile = profiler.build_profile(source_ip, events, alerts)
    local = analyst.analyze_ip_locally(ip_analysis, profile)

    return {
        "source_ip": source_ip,
        "technical_analysis": ip_analysis,
        "profile": profile,
        "analyst_opinion": local,
        "llm_status": llm_backend.status(),
    }


def _gather_profiles(db_path=None, limit: int = 40):
    """Veritabanindaki tum saldirganlar icin profil olusturur."""
    stats = storage.summary_stats(db_path=db_path)
    all_alerts = storage.get_all_alerts(limit=500, db_path=db_path)

    alerts_by_ip = {}
    for alert in all_alerts:
        alerts_by_ip.setdefault(alert.get("source_ip"), []).append(alert)

    ips = [ip for ip, _ in stats.get("top_ips", [])][:limit]
    for ip in alerts_by_ip:
        if ip and ip not in ips:
            ips.append(ip)

    profiles = []
    for ip in ips[:limit]:
        if not ip:
            continue
        events = storage.get_recent_events(source_ip=ip, db_path=db_path)
        if not events and ip not in alerts_by_ip:
            continue
        profile = profiler.build_profile(ip, events, alerts_by_ip.get(ip, []))
        # Saldiri siniflarini profile ekle (STIX export ve raporlama icin)
        analysis = analyze_ip(ip, events)
        profile["attack_classes"] = analysis["attack_classes"]
        profile["kill_chain"] = analysis["kill_chain"]
        profiles.append(profile)

    return profiles, stats


def situation_report(db_path=None) -> dict:
    """Tum sistemin durum raporu (SITREP) - AI analistinin ana ciktisi."""
    profiles, stats = _gather_profiles(db_path=db_path)
    campaigns = profiler.correlate_campaigns(profiles)
    recent_alerts = storage.get_all_alerts(limit=20, db_path=db_path)
    mtd_stats = storage.mtd_summary_stats(db_path=db_path)

    try:
        from ..soar import blocklist
        soar_summary = storage.soar_summary_stats(db_path=db_path)
        soar_summary["active_blocks"] = len(blocklist.active_blocks())
    except Exception:
        soar_summary = {"total_actions": 0, "active_blocks": 0, "awaiting_approval": 0}

    report = analyst.build_situation_report(
        stats, profiles, campaigns, recent_alerts,
        mtd_stats=mtd_stats, soar_stats=soar_summary,
    )

    return {
        "report": report,
        "profiles": profiles,
        "campaigns": campaigns,
        "llm_status": llm_backend.status(),
    }


def generate_ai_report(output_path="data/ai_report.md", db_path=None) -> str:
    """Durum raporunu Markdown dosyasi olarak yazar.

    Markdown secildi cunku: her yerde acilir, versiyon kontrolunde
    okunabilir, ve bir yarisma basvurusuna dogrudan eklenebilir."""
    from pathlib import Path
    from datetime import datetime

    data = situation_report(db_path=db_path)
    report = data["report"]
    profiles = data["profiles"]
    campaigns = data["campaigns"]
    llm = data["llm_status"]

    lines = [
        "# Arachne Sentinel — Yapay Zeka Analist Raporu",
        "",
        f"**Olusturulma:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Analiz motoru:** {llm['mode_tr']}",
        "",
        "---",
        "",
        f"## Genel Tehdit Duzeyi: {report['posture']}",
        "",
        report["posture_reason"] + ".",
        "",
        f"**Ozet:** {report['headline']}",
        "",
        "### Rakamlar",
        "",
        "| Olcut | Deger |",
        "|---|---|",
    ]
    labels = {
        "total_events": "Toplam olay", "total_alerts": "Toplam alarm",
        "critical_alerts": "Kritik alarm", "high_alerts": "Yuksek alarm",
        "unique_attackers": "Benzersiz saldirgan", "campaigns": "Korele kampanya",
        "mtd_rotations": "MTD rotasyonu", "soar_actions": "SOAR eylemi",
    }
    for key, label in labels.items():
        lines.append(f"| {label} | {report['stats_snapshot'].get(key, 0)} |")

    lines += ["", "---", "", "## Bulgular", ""]
    if report["findings"]:
        for i, finding in enumerate(report["findings"], 1):
            lines += [f"### {i}. {finding['title']}", "", finding["detail"], ""]
    else:
        lines += ["Oncelikli bir bulgu yok.", ""]

    lines += ["---", "", "## Oneriler", ""]
    for rec in report["recommendations"]:
        lines.append(f"- {rec}")

    if campaigns:
        lines += ["", "---", "", "## Korele Kampanyalar", ""]
        for c in campaigns:
            lines += [
                f"### Kampanya `{c['campaign_id']}`", "",
                f"- **Uye IP sayisi:** {c['member_count']}",
                f"- **IP'ler:** {', '.join(c['member_ips'])}",
                f"- **Ortak araclar:** {', '.join(c['tools']) or 'tespit edilemedi'}",
                f"- **Toplam olay:** {c['total_events']}", "",
                c["assessment_tr"], "",
            ]

    if profiles:
        lines += ["", "---", "", "## Saldirgan Profilleri", "",
                  "| IP | Tehdit Sinifi | Olay | Alarm | Arac | Kill Chain |",
                  "|---|---|---|---|---|---|"]
        for p in profiles[:20]:
            lines.append(
                f"| `{p['source_ip']}` | {p.get('threat_class', '-')} | "
                f"{p.get('event_count', 0)} | {p.get('alert_count', 0)} | "
                f"{p.get('primary_tool') or '-'} | "
                f"{p.get('kill_chain', {}).get('phase_tr', '-')} |"
            )

    lines += [
        "", "---", "",
        "## Metodoloji ve Sinirlar", "",
        "Bu rapor, deterministik kural motoru + davranissal profilleme +",
        "(yapilandirildiysa) karantina altinda calisan bir dil modelinin",
        "birlesik ciktisidir.",
        "",
        "**Onemli:** Yapay zeka katmani bu sistemde YALNIZCA ZENGINLESTIRME",
        "yapar; engelleme/serbest birakma kararlari tamamen deterministik",
        "kural motorundadir. Bu, OWASP LLM06 (Excessive Agency) riskine karsi",
        "bilincli bir mimari tercihtir.",
        "",
        "Sistem izole lab ortami icin tasarlanmistir; bulgular yalnizca bu",
        "honeypot yuzeyine gelen trafigi yansitir.",
        "",
    ]

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return str(out)
