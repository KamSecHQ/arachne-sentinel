"""
Saldiri analiz orkestratoru - Faz 5'in giris kapisi.

Tek bir yuku (payload) ya da bir IP'nin tum gecmisini alir ve tam bir
"tersine muhendislik raporu" uretir:

    ham yuk
      -> katman katman kodlama cozumu (deobfuscator)
      -> saldiri sinifi tespiti (imza motoru + ML)
      -> IOC cikarimi (ioc_extractor)
      -> saldiri araci parmak izi (tool_fingerprint)
      -> MITRE ATT&CK / CWE / CAPEC eslemesi (intel.attck)
      -> kill chain asamasi ve ilerleme yuzdesi

Kritik tasarim karari: analiz SONUCLARI hicbir zaman bir engelleme kararini
TEK BASINA tetiklemez. Karar, deterministik kural motorunda (Faz 1) kalir.
Bu katman zenginlestirir, karar vermez - ayni ilke Faz 8'deki AI katmani
icin de gecerlidir (bkz. docs/ARCHITECTURE.md "Zenginlestirme vs Karar").
"""
from ..detection.rules import ATTACK_SIGNATURES
from ..intel import attck
from .deobfuscator import deobfuscate, obfuscation_score
from .ioc_extractor import extract_iocs, ioc_count, summarize_iocs
from .tool_fingerprint import fingerprint_tool

# Kodlama cozuldukten SONRA da aranan ek saldiri sinifi imzalari.
# Bunlar detection/rules.py'deki temel imzalari tamamlar - orada olmayan
# ama tersine muhendislik baglaminda anlamli olan siniflar.
EXTENDED_SIGNATURES = {
    "Web Shell": ["eval($_", "system($_", "passthru($_", "shell_exec($_",
                  "<%eval", "assert($_", "preg_replace(\"/.*/e\""],
    "Directory Brute Force": ["/admin/", "/backup/", "/.git/", "/.env",
                               "/wp-admin/", "/phpmyadmin/"],
}


def _detect_attack_classes(text: str) -> list:
    """Metinde hangi saldiri siniflarinin izini buluyoruz?

    Hem Faz 1'in temel imza sozlugunu hem de yukaridaki genisletilmis
    sozlugu kullanir. Cozulmus metin uzerinde calistigi icin, kodlanarak
    gizlenmis saldirilari da yakalar - bu, Faz 5'in en somut katkisidir."""
    lower = (text or "").lower()
    found = []
    for attack_class, signatures in ATTACK_SIGNATURES.items():
        if any(sig.lower() in lower for sig in signatures):
            found.append(attack_class)
    for attack_class, signatures in EXTENDED_SIGNATURES.items():
        if any(sig.lower() in lower for sig in signatures):
            found.append(attack_class)
    return found


def analyze_payload(payload: str) -> dict:
    """Tek bir yuk icin tam tersine muhendislik analizi.

    Donen sozluk dogrudan JSON'a cevrilebilir ve panelde/raporda gosterilir.
    """
    payload = payload or ""

    # 1) Kodlama katmanlarini ac
    deob = deobfuscate(payload)
    decoded = deob.decoded
    obf_score = obfuscation_score(deob)

    # 2) Saldiri siniflari - hem ham hem cozulmus metinde ara.
    #    Ham metinde bulunmayip cozulmus metinde bulunan bir sinif, "gizlenmis
    #    saldiri" demektir ve ayrica isaretlenir.
    classes_raw = set(_detect_attack_classes(payload))
    classes_decoded = set(_detect_attack_classes(decoded))
    all_classes = sorted(classes_raw | classes_decoded)
    hidden_classes = sorted(classes_decoded - classes_raw)

    if deob.was_obfuscated and "Obfuscation" not in all_classes:
        all_classes.append("Obfuscation")

    # 3) IOC cikarimi (cozulmus metin uzerinde - asil bilgi orada)
    iocs = extract_iocs(decoded)
    if iocs.get("reverse_shells") and "Reverse Shell" not in all_classes:
        all_classes.append("Reverse Shell")

    # 4) Arac parmak izi (ham metin uzerinde - User-Agent vb. orada)
    tools = fingerprint_tool(payload)

    # 5) Cerceve eslemesi
    mappings = [attck.map_attack_class(c) for c in all_classes]
    technique_ids = sorted({tid for m in mappings for tid in m["attck"]})
    for tool in tools:
        for tid in tool.attck_techniques:
            if tid not in technique_ids:
                technique_ids.append(tid)
    technique_ids = sorted(set(technique_ids))

    phases = [m["kill_chain_phase"] for m in mappings] or ["reconnaissance"]
    progress = attck.kill_chain_progress(phases)

    # 6) Birlesik tehdit degerlendirmesi (0-100)
    threat = _score(all_classes, obf_score, tools, iocs)

    return {
        "payload_preview": payload[:300],
        "deobfuscation": deob.to_dict(),
        "obfuscation_score": obf_score,
        "attack_classes": all_classes,
        "hidden_attack_classes": hidden_classes,
        "iocs": iocs,
        "ioc_count": ioc_count(iocs),
        "ioc_summary": summarize_iocs(iocs),
        "tools": [t.to_dict() for t in tools],
        "primary_tool": tools[0].tool if tools else None,
        "automated": bool(tools and tools[0].confidence >= 60),
        "attck_techniques": [attck.technique_info(t) for t in technique_ids],
        "framework_mappings": mappings,
        "kill_chain": progress,
        "threat_score": threat,
        "verdict": _verdict(threat),
    }


def _score(classes, obf_score, tools, iocs) -> int:
    """Analiz bulgularindan birlesik tehdit skoru (0-100).

    Agirliklar bilincli olarak aciklanabilir tutuldu: her bilesenin katkisi
    ayri ayri savunulabilir olmali. Bu bir ML ciktisi degil, seffaf bir
    toplamdir."""
    score = 0
    # Yuksek etkili saldiri siniflari
    high_impact = {"Command Injection", "Reverse Shell", "Web Shell", "SQL Injection"}
    for cls in classes:
        score += 25 if cls in high_impact else 12
    # Gizleme cabasi (kotu niyetin guclu gostergesi)
    score += obf_score // 4
    # Bilinen saldiri araci
    if tools and tools[0].confidence >= 80:
        score += 20
    elif tools:
        score += 10
    # Ters kabuk = en kritik bulgu
    if iocs.get("reverse_shells"):
        score += 30
    if iocs.get("shell_commands"):
        score += 10
    return max(0, min(100, score))


def _verdict(score: int) -> str:
    if score >= 80:
        return "kritik"
    if score >= 55:
        return "yuksek"
    if score >= 30:
        return "orta"
    if score > 0:
        return "dusuk"
    return "temiz"


def analyze_ip(source_ip: str, events: list) -> dict:
    """Bir IP'nin tum olaylarini birlestirerek saldiri zincirini yeniden kurar.

    Tek tek yukleri analiz etmek bir seydir; ayni saldirganin 40 olayini
    birlestirip "once port taradi, sonra brute-force denedi, sonra SQLi
    gonderdi" diyebilmek bambaskadir. Adli bilisimde buna 'attack chain
    reconstruction' denir ve olay mudahalesinin (incident response) temelidir."""
    analyses = []
    for event in events:
        payload = event.get("payload")
        if not payload or not payload.strip():
            continue
        result = analyze_payload(payload)
        result["timestamp"] = event.get("timestamp")
        result["service"] = event.get("service")
        result["event_id"] = event.get("id")
        analyses.append(result)

    all_classes = sorted({c for a in analyses for c in a["attack_classes"]})
    all_techniques = {}
    for a in analyses:
        for t in a["attck_techniques"]:
            all_techniques[t["id"]] = t

    tool_votes = {}
    for a in analyses:
        for t in a["tools"]:
            key = t["tool"]
            tool_votes[key] = max(tool_votes.get(key, 0), t["confidence"])
    primary_tool = max(tool_votes.items(), key=lambda kv: kv[1])[0] if tool_votes else None

    merged_iocs = {}
    for a in analyses:
        for key, values in a["iocs"].items():
            if not values:
                continue
            merged_iocs.setdefault(key, [])
            for v in values:
                if v not in merged_iocs[key]:
                    merged_iocs[key].append(v)

    phases = [attck.map_attack_class(c)["kill_chain_phase"] for c in all_classes]
    # Servis kesfi olaylari da kesif asamasi sayilir (yuk icermeseler bile)
    if not phases and events:
        phases = ["reconnaissance"]
    progress = attck.kill_chain_progress(phases)

    max_threat = max((a["threat_score"] for a in analyses), default=0)
    services = sorted({e.get("service") for e in events if e.get("service")})

    return {
        "source_ip": source_ip,
        "event_count": len(events),
        "analyzed_payloads": len(analyses),
        "attack_classes": all_classes,
        "attck_techniques": sorted(all_techniques.values(), key=lambda t: t["id"]),
        "tools_detected": sorted(tool_votes.items(), key=lambda kv: -kv[1]),
        "primary_tool": primary_tool,
        "automated": bool(primary_tool and tool_votes.get(primary_tool, 0) >= 60),
        "iocs": merged_iocs,
        "ioc_count": sum(len(v) for v in merged_iocs.values()),
        "services_touched": services,
        "kill_chain": progress,
        "max_threat_score": max_threat,
        "verdict": _verdict(max_threat),
        "per_payload": analyses[:20],
    }
