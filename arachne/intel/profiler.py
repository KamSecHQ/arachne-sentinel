"""
Saldirgan davranissal profilleme ve kampanya korelasyonu.

--- Temel fikir ---
Bir saldirganin IP'si degisebilir (VPN, proxy, botnet). Ama DAVRANISI kolay
degismez: hangi servisleri hangi sirayla yokladigi, istekler arasindaki
zamanlama ritmi, yuklerinin karakteri, kullandigi arac...

Bu modul her IP icin bir "davranissal parmak izi" (behavioral signature)
uretir ve ayni parmak izine sahip farkli IP'leri tek bir KAMPANYA altinda
birlestirir. Boylece "3 farkli IP'den 3 ayri alarm" yerine "tek bir
saldirgan 3 IP kullaniyor" diyebiliriz.

--- Neden zamanlama bu kadar ayirt edici? ---
Insan eliyle yapilan istekler duzensiz araliklarla gelir (dusunme, yazma,
karar verme suresi). Otomatik araclar ise makine hassasiyetinde duzenli
araliklarla calisir. Araliklarin STANDART SAPMASI, bu ikisini ayirmak icin
sasirtici derecede guclu ve ucuz bir olcuttur.
"""
import hashlib
import statistics
from collections import Counter
from datetime import datetime

from ..reverse.tool_fingerprint import fingerprint_tool
from . import attck
from .geo import geo_for_ip

# Otomasyon esigi: istekler arasi araliklarin standart sapmasi bu degerin
# altindaysa "makine ritmi" kabul edilir (saniye).
AUTOMATION_STDEV_THRESHOLD = 1.5
# Kampanya korelasyonu icin gereken minimum benzerlik (0-1).
CAMPAIGN_SIMILARITY_THRESHOLD = 0.75


def _parse_ts(ts: str):
    """SQLite'in 'YYYY-MM-DD HH:MM:SS' formatini datetime'a cevirir."""
    if not ts:
        return None
    try:
        return datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def _intervals(events):
    """Ardisik olaylar arasindaki saniye cinsinden araliklar."""
    times = sorted(t for t in (_parse_ts(e.get("timestamp")) for e in events) if t)
    if len(times) < 2:
        return []
    return [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]


def timing_analysis(events) -> dict:
    """Zamanlama ritmini analiz eder: insan mi, makine mi?"""
    gaps = _intervals(events)
    if not gaps:
        return {
            "sample_size": 0, "mean_gap": None, "stdev_gap": None,
            "machine_like": False, "burst_rate": None,
            "assessment_tr": "Zamanlama analizi icin yeterli olay yok",
        }

    mean_gap = statistics.fmean(gaps)
    stdev_gap = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
    machine_like = stdev_gap <= AUTOMATION_STDEV_THRESHOLD and mean_gap < 30

    total_span = sum(gaps)
    burst_rate = round(len(gaps) / total_span, 2) if total_span > 0 else None

    if machine_like:
        assessment = (
            f"Makine ritmi: istekler {mean_gap:.2f}sn araliklarla, cok dusuk "
            f"sapmayla (±{stdev_gap:.2f}sn) geldi - otomatik arac gostergesi"
        )
    elif stdev_gap > 10:
        assessment = (
            f"Duzensiz ritim (±{stdev_gap:.1f}sn sapma) - elle yapilan "
            f"etkilesim ya da kasitli yavaslatilmis tarama olabilir"
        )
    else:
        assessment = f"Orta duzenlilikte ritim (ortalama {mean_gap:.1f}sn aralik)"

    return {
        "sample_size": len(gaps),
        "mean_gap": round(mean_gap, 3),
        "stdev_gap": round(stdev_gap, 3),
        "machine_like": machine_like,
        "burst_rate": burst_rate,
        "assessment_tr": assessment,
    }


def behavioral_signature(events) -> str:
    """Davranissal parmak izi: ayni saldirgani farkli IP'lerde tanimaya yarar.

    Imzaya HANGI bilgiler giriyor:
      - dokunulan servisler (siralı kume)
      - kullanilan arac ailesi
      - zamanlama sinifi (makine/insan)
      - yuk uzunlugu buyuklugu (kaba sinif)

    Imzaya NEYIN girmedigi de en az o kadar onemli: IP adresi ve zaman
    damgasi bilincli olarak DISLANDI - cunku degisen sey tam da onlar.
    """
    services = sorted({e.get("service") for e in events if e.get("service")})
    tools = set()
    lengths = []
    for e in events:
        payload = e.get("payload") or ""
        if payload:
            lengths.append(len(payload))
            for m in fingerprint_tool(payload):
                if m.confidence >= 60:
                    tools.add(m.tool)

    timing = timing_analysis(events)
    timing_class = "machine" if timing["machine_like"] else "human"

    if not lengths:
        length_class = "none"
    else:
        avg = statistics.fmean(lengths)
        length_class = "short" if avg < 64 else ("medium" if avg < 512 else "long")

    raw = "|".join([
        "svc:" + ",".join(services),
        "tool:" + ",".join(sorted(tools)),
        "timing:" + timing_class,
        "len:" + length_class,
    ])
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return digest


def signature_components(events) -> dict:
    """Parmak izini olusturan bilesenleri ayri ayri dondurur (aciklanabilirlik).

    Hash tek basina bir juri icin anlamsizdir; bilesenleri gostermek
    "neden bu iki IP ayni saldirgan" sorusuna somut cevap verir."""
    services = sorted({e.get("service") for e in events if e.get("service")})
    tools = set()
    for e in events:
        for m in fingerprint_tool(e.get("payload") or ""):
            if m.confidence >= 60:
                tools.add(m.tool)
    timing = timing_analysis(events)
    return {
        "services": services,
        "tools": sorted(tools),
        "timing_class": "machine" if timing["machine_like"] else "human",
        "timing_detail": timing,
    }


def build_profile(source_ip: str, events: list, alerts: list = None) -> dict:
    """Bir IP icin tam davranissal profil olusturur."""
    alerts = alerts or []
    events = events or []

    services = Counter(e.get("service") for e in events if e.get("service"))
    event_types = Counter(e.get("event_type") for e in events if e.get("event_type"))
    ports = sorted({e.get("dest_port") for e in events if e.get("dest_port")})

    timing = timing_analysis(events)
    signature = behavioral_signature(events)
    components = signature_components(events)

    payloads = [e.get("payload") or "" for e in events]
    non_empty = [p for p in payloads if p.strip()]

    tool_votes = {}
    for p in non_empty:
        for m in fingerprint_tool(p):
            tool_votes[m.tool] = max(tool_votes.get(m.tool, 0), m.confidence)
    primary_tool = max(tool_votes.items(), key=lambda kv: kv[1])[0] if tool_votes else None

    times = sorted(t for t in (_parse_ts(e.get("timestamp")) for e in events) if t)
    first_seen = times[0].strftime("%Y-%m-%d %H:%M:%S") if times else None
    last_seen = times[-1].strftime("%Y-%m-%d %H:%M:%S") if times else None
    duration = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0

    severities = [a.get("severity") for a in alerts]
    max_score = max((a.get("score") or 0 for a in alerts), default=0)

    # Tehdit sinifi: hacim + siddet + otomasyon birlesimi
    threat_class, threat_reason = _classify_threat(
        len(events), max_score, timing["machine_like"], len(services), primary_tool
    )

    return {
        "source_ip": source_ip,
        "geo": geo_for_ip(source_ip),
        "signature": signature,
        "signature_components": components,
        "event_count": len(events),
        "alert_count": len(alerts),
        "max_alert_score": max_score,
        "severities": dict(Counter(severities)),
        "services_touched": dict(services),
        "event_types": dict(event_types),
        "ports_touched": ports,
        "distinct_ports": len(ports),
        "payload_count": len(non_empty),
        "timing": timing,
        "tools": sorted(tool_votes.items(), key=lambda kv: -kv[1]),
        "primary_tool": primary_tool,
        "automated": timing["machine_like"] or bool(primary_tool),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": round(duration, 1),
        "threat_class": threat_class,
        "threat_class_reason": threat_reason,
    }


def _classify_threat(event_count, max_score, machine_like, service_count, tool):
    """Saldirgani bir tehdit sinifina yerlestirir - her sinif icin GEREKCE ile.

    Siniflar bilincli olarak operasyonel: her biri farkli bir mudahale
    gerektirir (bkz. Faz 7 SOAR playbook'lari)."""
    if max_score >= 90 and service_count >= 3:
        return ("hedefli-saldirgan",
                "Yuksek skorlu alarm + coklu servis kesfi: sistematik, kararli saldirgan")
    if machine_like and event_count >= 20:
        return ("otomatik-tarayici",
                f"Makine ritmi + {event_count} olay: firsatci otomatik tarama")
    if tool:
        return ("arac-kullanan",
                f"Bilinen saldiri araci tespit edildi ({tool}): senaryo-tabanli saldiri")
    if max_score >= 60:
        return ("aktif-tehdit", "Yuksek siddetli alarm uretti ama arac imzasi yok")
    if event_count <= 3:
        return ("dusuk-etkilesim",
                "Cok az olay: yanlislikla baglanti ya da ilk yoklama olabilir")
    return ("gozlem-altinda", "Suphe uyandiran ama henuz esik asmayan davranis")


def _jaccard(a: set, b: set) -> float:
    """Iki kume arasindaki Jaccard benzerligi (kesisim / birlesim)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def profile_similarity(p1: dict, p2: dict) -> float:
    """Iki profil arasindaki benzerlik (0-1).

    Agirliklar: parmak izi tam eslesmesi cok guclu bir sinyaldir (0.5),
    geri kalani servis ortakligi (0.2), arac ortakligi (0.2) ve zamanlama
    sinifi ortakligi (0.1) uzerinden dagitilir."""
    score = 0.0
    if p1.get("signature") and p1["signature"] == p2.get("signature"):
        score += 0.5

    s1 = set(p1.get("services_touched", {}).keys())
    s2 = set(p2.get("services_touched", {}).keys())
    score += 0.2 * _jaccard(s1, s2)

    t1 = {t for t, _ in p1.get("tools", [])}
    t2 = {t for t, _ in p2.get("tools", [])}
    score += 0.2 * _jaccard(t1, t2)

    c1 = p1.get("signature_components", {}).get("timing_class")
    c2 = p2.get("signature_components", {}).get("timing_class")
    if c1 and c1 == c2:
        score += 0.1

    return round(min(1.0, score), 3)


def correlate_campaigns(profiles: list, threshold: float = None) -> list:
    """Benzer profilleri kampanyalar halinde gruplar.

    Basit ama etkili bir kume birlestirme (union-find benzeri) kullanir:
    esik ustu benzerlik gosteren her profil cifti ayni kampanyaya girer.
    Tek IP'lik gruplar kampanya sayilmaz (en az 2 IP gerekir)."""
    threshold = threshold if threshold is not None else CAMPAIGN_SIMILARITY_THRESHOLD
    n = len(profiles)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    links = []
    for i in range(n):
        for j in range(i + 1, n):
            sim = profile_similarity(profiles[i], profiles[j])
            if sim >= threshold:
                union(i, j)
                links.append((profiles[i]["source_ip"], profiles[j]["source_ip"], sim))

    groups = {}
    for idx, profile in enumerate(profiles):
        groups.setdefault(find(idx), []).append(profile)

    campaigns = []
    for members in groups.values():
        if len(members) < 2:
            continue
        ips = sorted(m["source_ip"] for m in members)
        tools = sorted({t for m in members for t, _ in m.get("tools", [])})
        services = sorted({s for m in members for s in m.get("services_touched", {})})
        total_events = sum(m.get("event_count", 0) for m in members)
        max_score = max((m.get("max_alert_score", 0) for m in members), default=0)
        campaigns.append({
            "campaign_id": hashlib.sha256("".join(ips).encode()).hexdigest()[:12],
            "member_ips": ips,
            "member_count": len(ips),
            "shared_signature": members[0].get("signature"),
            "tools": tools,
            "services": services,
            "total_events": total_events,
            "max_alert_score": max_score,
            "evidence_links": [
                {"ip_a": a, "ip_b": b, "similarity": sim}
                for a, b, sim in links
                if a in ips and b in ips
            ],
            "assessment_tr": (
                f"{len(ips)} farkli IP ayni davranissal parmak izini paylasiyor "
                f"({', '.join(tools) if tools else 'arac imzasi yok'}) - "
                f"tek bir kampanyanin parcasi olma olasiligi yuksek"
            ),
        })

    campaigns.sort(key=lambda c: (-c["member_count"], -c["total_events"]))
    return campaigns


def kill_chain_for_profile(profile: dict, attack_classes: list) -> dict:
    """Profili kill chain uzerinde konumlandirir."""
    phases = [attck.map_attack_class(c)["kill_chain_phase"] for c in attack_classes]
    if not phases:
        phases = ["reconnaissance"]
    return attck.kill_chain_progress(phases)
