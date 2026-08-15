"""
Faz 19 - Saldiri grafigi ve kill chain yol modellemesi.

Tek tek olaylar bir "nokta bulutu"dur; onlari BAGLADIGINIZDA bir HIKAYE
ortaya cikar. Bu modul, bir saldirganin olaylarindan yonlu bir graf kurar:
dugumler saldiri asamalari/teknikleri, kenarlar ise zaman icindeki gecisler.

--- Ne ise yarar? ---
  * Saldirganin kill chain boyunca izledigi YOLU gorsellestirir
     (kesif -> somuru -> kurulum...).
  * Bir sonraki muhtemel adimi tahmin eder (bu asamadan sonra genelde ne gelir?).
  * "Yatay hareket" (lateral movement) desenlerini modeller: ayni saldirgan
     bir servisten digerine gecerken.

--- Gercek dunya karsiligi ---
Kurumsal EDR/XDR urunleri (CrowdStrike, SentinelOne) tam olarak bunu yapar:
"process tree" / "attack storyline" olusturup analiste tek bir olay yerine
tum saldiri anlatisini gosterir. Biz honeypot olaylari uzerinde kucuk ama
gercek bir versiyonunu kuruyoruz.

Saf Python - graf yapisi sozluklerle, harici graf kutuphanesi yok.
"""
from collections import defaultdict
from datetime import datetime

from . import attck

# Kill chain asamasindan sonra tipik olarak gelen bir sonraki asama
# (saldirgan davranisi modeli - somut, savunulabilir bir varsayim).
_NEXT_PHASE = {
    "reconnaissance": "exploitation",
    "weaponization": "delivery",
    "delivery": "exploitation",
    "exploitation": "installation",
    "installation": "command-and-control",
    "command-and-control": "actions-on-objectives",
    "actions-on-objectives": None,
}


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def build_attack_graph(source_ip: str, per_payload_analyses: list,
                       events: list = None) -> dict:
    """Bir saldirganin analiz edilmis yuklerinden saldiri grafigi kurar.

    per_payload_analyses: reverse.analyze_ip()["per_payload"] benzeri liste;
    her biri attack_classes, kill_chain, timestamp, service icerir.
    """
    events = events or []

    # Dugumler: kill chain asamasi bazinda grupla
    nodes = {}          # phase -> {events, techniques, services, first_ts, last_ts}
    ordered = []        # zaman sirali (asama, zaman, teknik) olaylari

    for item in per_payload_analyses:
        classes = item.get("attack_classes", [])
        if not classes:
            continue
        phase = item.get("kill_chain", {}).get("phase", "reconnaissance")
        ts = _parse_ts(item.get("timestamp"))
        techniques = [t["id"] for t in item.get("attck_techniques", [])]
        service = item.get("service")

        node = nodes.setdefault(phase, {
            "phase": phase,
            "phase_tr": attck.KILL_CHAIN_TR.get(phase, phase),
            "event_count": 0, "techniques": set(),
            "services": set(), "attack_classes": set(),
            "first_ts": None, "last_ts": None,
        })
        node["event_count"] += 1
        node["techniques"].update(techniques)
        node["attack_classes"].update(classes)
        if service:
            node["services"].add(service)
        if ts:
            if node["first_ts"] is None or ts < node["first_ts"]:
                node["first_ts"] = ts
            if node["last_ts"] is None or ts > node["last_ts"]:
                node["last_ts"] = ts
        ordered.append((phase, ts, tuple(techniques)))

    # Kenarlar: kill chain sirasina gore asamalar arasi gecis
    phase_rank = attck.KILL_CHAIN_ORDER
    present = sorted(nodes.keys(), key=lambda p: phase_rank.get(p, 99))
    edges = []
    for i in range(len(present) - 1):
        edges.append({
            "from": present[i], "to": present[i + 1],
            "from_tr": attck.KILL_CHAIN_TR.get(present[i], present[i]),
            "to_tr": attck.KILL_CHAIN_TR.get(present[i + 1], present[i + 1]),
        })

    # Yatay hareket: farkli servisler arasi gecis (zamansal)
    service_transitions = _lateral_movement(events)

    # En ileri asama ve bir sonraki tahmin
    furthest = present[-1] if present else "reconnaissance"
    predicted_next = _NEXT_PHASE.get(furthest)
    progress = attck.kill_chain_progress(present or ["reconnaissance"])

    # Serilestir (set -> list)
    serial_nodes = []
    for phase in present:
        n = nodes[phase]
        serial_nodes.append({
            "phase": n["phase"], "phase_tr": n["phase_tr"],
            "event_count": n["event_count"],
            "techniques": sorted(n["techniques"]),
            "services": sorted(n["services"]),
            "attack_classes": sorted(n["attack_classes"]),
            "stage_index": phase_rank.get(phase, 0) + 1,
        })

    return {
        "source_ip": source_ip,
        "nodes": serial_nodes,
        "edges": edges,
        "node_count": len(serial_nodes),
        "furthest_phase": furthest,
        "furthest_phase_tr": attck.KILL_CHAIN_TR.get(furthest, furthest),
        "progress": progress,
        "predicted_next_phase": predicted_next,
        "predicted_next_tr": (
            attck.KILL_CHAIN_TR.get(predicted_next, predicted_next)
            if predicted_next else None
        ),
        "lateral_movement": service_transitions,
        "storyline_tr": _build_storyline(serial_nodes, service_transitions, predicted_next),
    }


def _lateral_movement(events: list) -> dict:
    """Saldirganin servisler arasi gecis desenini modeller."""
    timed = []
    for e in events:
        ts = _parse_ts(e.get("timestamp"))
        svc = e.get("service")
        if ts and svc:
            timed.append((ts, svc))
    timed.sort(key=lambda x: x[0])

    transitions = defaultdict(int)
    prev_svc = None
    for _, svc in timed:
        if prev_svc and prev_svc != svc:
            transitions[(prev_svc, svc)] += 1
        prev_svc = svc

    edges = [{"from": a, "to": b, "count": c}
             for (a, b), c in sorted(transitions.items(), key=lambda x: -x[1])]
    distinct_services = sorted({svc for _, svc in timed})
    return {
        "service_transitions": edges,
        "distinct_services": distinct_services,
        "service_count": len(distinct_services),
        "is_lateral": len(distinct_services) >= 3,
        "assessment_tr": (
            f"Yatay hareket: saldirgan {len(distinct_services)} farkli servis "
            f"arasinda gezindi ({', '.join(distinct_services)}) - sistematik "
            f"kesif/genisleme davranisi"
            if len(distinct_services) >= 3 else
            f"{len(distinct_services)} servise dokundu - sinirli hareket"
        ),
    }


def _build_storyline(nodes: list, lateral: dict, predicted_next) -> str:
    """Grafigi insan-okunabilir bir anlatiya cevirir (analist icin)."""
    if not nodes:
        return "Yeterli olay yok - saldiri anlatisi kurulamadi."

    parts = ["Saldiri anlatisi: "]
    phase_names = [n["phase_tr"] for n in nodes]
    parts.append(" -> ".join(phase_names) + ". ")

    first = nodes[0]
    parts.append(
        f"Saldirgan '{first['phase_tr']}' asamasiyla basladi "
        f"({', '.join(first['attack_classes'][:3]) or 'kesif'})"
    )
    if len(nodes) > 1:
        last = nodes[-1]
        parts.append(
            f" ve '{last['phase_tr']}' asamasina kadar ilerledi "
            f"(%{ nodes[-1]['stage_index'] * 100 // 7} tamamlanma)."
        )
    else:
        parts.append(".")

    if lateral.get("is_lateral"):
        parts.append(" " + lateral["assessment_tr"] + ".")

    if predicted_next:
        parts.append(
            f" Tahmini bir sonraki adim: '{attck.KILL_CHAIN_TR.get(predicted_next, predicted_next)}' "
            f"asamasi - bu yonde ek savunma onlemleri onerilir."
        )
    return "".join(parts)
