"""
Faz 34 - AI Korelasyon Motoru (dusuk seviyeli olaylari hikayeye baglama).

--- Fikir ---
Bir honeypot yuzlerce dusuk seviyeli olay uretir: bir port taramasi, birkac
basarisiz giris, bir dizin denemesi, bir enjeksiyon denemesi... Tek tek her
biri "gurultu"dur. Ama AYNI saldirgandan, kisa bir zaman penceresinde, artan
bir siddetle geldiklerinde bunlar TEK BIR HIKAYEDIR: hedefli bir kampanya.

Bu modul cok sayida ZAYIF sinyali birlestirerek daha ust seviye KAMPANYA ve
SALDIRI ZINCIRLERI (attack chain) uretir. "Bilinen tek saldiri imzasini
tekrar bildirmek" yerine, sinyalleri birlestirip bir zaman cizelgesi (storyline)
kurar.

--- Gercek cerceve karsiligi ---
  * SIEM/XDR korelasyon kurallari ve alarm birlestirme (alert aggregation):
    coklu dusuk-oncelikli alarmi tek bir olaya (incident) toplama.
  * MITRE ATT&CK saldiri zinciri / "attack storyline": olaylari taktik/asama
    sirasina dizme.

--- DURUSTLUK NOTU (COK ONEMLI) ---
Adindaki "AI" pazarlama degil, kavramsal bir etikettir: bu motor
DETERMINISTIK bir KURAL/HEURISTIC korelatorudur. EGITILMIS bir model, bir LLM
ya da bir sinir agi DEGILDIR. Ayni girdi her zaman ayni ciktiyi verir (test
edilebilirligin on kosulu). "Guven" (confidence) skoru ogrenilmis bir olasilik
degil, belgelenmis bir formulun ciktisidir (bkz. confidence_from_signals).

--- SAVUNMA-AMACLI ETIK NOT ---
Amac, bir savunma analistinin gurultu icinde bogulmadan gercek kampanyalari
gormesini saglamaktir. Uretilen anlati (narrative) saldiri planlamak icin
degil, savunma onceliklendirmesi ve adli inceleme icindir.

Saf Python stdlib - datetime, collections, math. Ag/dosya erisimi yoktur;
tum fonksiyonlar olay listelerini arguman olarak alan saf fonksiyonlardir.
"""
import math
from collections import Counter, defaultdict
from datetime import datetime

from . import attck

# Kampanya korelasyon penceresi disinda kalan olaylar guven skorunu dusurur
# ama kampanyayi bolmez (grafik gruplamasi IP/altyapi bazlidir).
_DEFAULT_WINDOW_SEC = 3600


def _parse_ts(ts):
    """'YYYY-MM-DD HH:MM:SS' formatini datetime'a cevirir (yoksa None)."""
    if not ts:
        return None
    try:
        return datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def _subnet_24(ip):
    """IPv4 /24 blogu (ornek: '1.2.3.7' -> '1.2.3'); IPv4 degilse None."""
    if not ip:
        return None
    parts = str(ip).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3])
    return None


def _default_technique_fn(payload):
    """Payload -> ATT&CK teknik ID listesi (intel.attck uzerinden)."""
    from ..reverse.attack_analyzer import _detect_attack_classes
    tids = []
    for cls in _detect_attack_classes(payload or ""):
        for tid in attck.map_attack_class(cls)["attck"]:
            if tid not in tids:
                tids.append(tid)
    return tids


def _primary_tool(payloads):
    """Yuklerden baskin arac parmak izi (yoksa None)."""
    from ..reverse.tool_fingerprint import fingerprint_tool
    best, best_conf = None, -1
    for payload in payloads:
        for match in fingerprint_tool(payload or ""):
            if match.confidence > best_conf:
                best_conf, best = match.confidence, match.tool
    return best


def _chain_stages(events):
    """Olaylardan gozlemlenen sirada (storyline) kill chain asama listesi uretir.

    Her olayin payload'undan ATT&CK teknikleri, oradan kill chain asamasi
    turetilir. Asamalar ILK GORULDUKLERI zamana gore siralanir ve tekrarlar
    ilk gorunumleri korunarak silinir - boylece 'kesif -> somuru -> kurulum'
    gibi bir anlati ortaya cikar."""
    seen = []
    ordered = sorted(events, key=lambda e: (_parse_ts(e.get("timestamp"))
                                            or datetime.min))
    for event in ordered:
        for tid in _default_technique_fn(event.get("payload")):
            phase = attck.technique_info(tid)["kill_chain_phase"]
            phase_tr = attck.KILL_CHAIN_TR.get(phase, phase)
            if phase_tr not in seen:
                seen.append(phase_tr)
    return seen


def confidence_from_signals(signal_count: int, distinct_services: int,
                            time_span_sec: float, repeat: bool) -> float:
    """Bir korelasyonun guven skorunu (0..1) belgelenmis bir formulle uretir.

    Bu skor OGRENILMIS bir olasilik DEGILDIR (bkz. modul basi DURUSTLUK notu);
    dort gozlemlenebilir sinyali agirlikli olarak birlestiren deterministik
    bir gostergedir:

      * hacim   (0.40): min(1, signal_count / 8)
                Ne kadar cok olay, o kadar guclu korelasyon (8'de doyar).
      * cesitlilik (0.25): min(1, distinct_services / 4)
                Birden fazla servisi yoklamak hedefli davranisa isaret eder.
      * kararlilik (0.25): min(1, time_span_sec / _DEFAULT_WINDOW_SEC)
                Zamana yayilan israrli etkinlik tek seferlik gurultuden ayrilir.
      * tekrar   (0.10): tekrar eden desen varsa bonus (True/False).

    Toplam 0..1 araligina kirpilir ve 3 ondaliga yuvarlanir. Tek bir zayif
    olay dusuk skor alir; birden cok zayif sinyal birlesince skor yukselir -
    modulun asil fikri budur."""
    volume = min(1.0, max(0, signal_count) / 8.0)
    diversity = min(1.0, max(0, distinct_services) / 4.0)
    persistence = min(1.0, max(0.0, time_span_sec) / _DEFAULT_WINDOW_SEC)
    repeat_bonus = 0.10 if repeat else 0.0
    score = 0.40 * volume + 0.25 * diversity + 0.25 * persistence + repeat_bonus
    return round(min(1.0, score), 3)


def merge_low_level(events: list) -> dict:
    """Tek bir saldirgana ait N dusuk seviyeli olayi TEK bir olaya (incident) birlestirir.

    Zayif sinyallerin nasil birlestigini gosterir: 5 ayri "kucuk" olay, tek
    basina onemsizken, birlikte hedefli bir kampanyaya isaret edebilir.

    Donus: {attacker, event_count, distinct_services, distinct_payload_types,
            severity_estimate, narrative_tr}."""
    events = events or []
    if not events:
        return {
            "attacker": None, "event_count": 0, "distinct_services": 0,
            "distinct_payload_types": 0, "severity_estimate": "low",
            "narrative_tr": "Olay yok - birlestirilecek sinyal bulunamadi.",
        }

    ips = Counter(e.get("source_ip") for e in events if e.get("source_ip"))
    attacker = ips.most_common(1)[0][0] if ips else None
    services = sorted({e.get("service") for e in events if e.get("service")})
    payload_types = sorted({e.get("event_type") for e in events
                            if e.get("event_type")})
    techniques = set()
    for event in events:
        techniques.update(_default_technique_fn(event.get("payload")))

    # Siddet tahmini: hacim + servis cesitliligi + teknik varligi.
    score = len(events) + 2 * len(services) + len(techniques) * 2
    if score >= 16:
        severity = "critical"
    elif score >= 10:
        severity = "high"
    elif score >= 5:
        severity = "medium"
    else:
        severity = "low"

    narrative_tr = (
        f"{len(events)} dusuk seviyeli olay tek bir saldirgana ({attacker}) "
        f"ait; {len(services)} farkli servis ve {len(payload_types)} farkli "
        f"olay turu iceriyor. Tek tek zayif olan bu sinyaller birlesince "
        f"'{severity}' seviyesinde hedefli bir etkinlige isaret ediyor."
    )
    return {
        "attacker": attacker,
        "event_count": len(events),
        "distinct_services": len(services),
        "distinct_payload_types": len(payload_types),
        "severity_estimate": severity,
        "techniques": sorted(techniques),
        "narrative_tr": narrative_tr,
    }


def _group_campaigns(events, window_sec):
    """Olaylari saldirgana ve kampanyaya (ortak /24 ya da ortak arac) gruplar.

    Once IP bazinda toplar, sonra ayni /24'u ya da ayni baskin araci paylasan
    IP'leri tek bir kampanya altinda birlestirir (union-find)."""
    by_ip = defaultdict(list)
    for event in events:
        ip = event.get("source_ip")
        if ip:
            by_ip[ip].append(event)

    ips = sorted(by_ip)
    parent = {ip: ip for ip in ips}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(b)] = find(a)

    by_subnet = defaultdict(list)
    by_tool = defaultdict(list)
    tool_of = {}
    for ip in ips:
        subnet = _subnet_24(ip)
        tool = _primary_tool([e.get("payload") for e in by_ip[ip]])
        tool_of[ip] = tool
        if subnet:
            by_subnet[subnet].append(ip)
        if tool:
            by_tool[tool].append(ip)
    for group in list(by_subnet.values()) + list(by_tool.values()):
        for other in group[1:]:
            union(group[0], other)

    groups = defaultdict(list)
    for ip in ips:
        groups[find(ip)].append(ip)
    return by_ip, tool_of, groups


def correlate_events(events: list, window_sec: int = _DEFAULT_WINDOW_SEC,
                     clock=None) -> dict:
    """Dusuk seviyeli olaylari kampanyalara ve saldiri zincirlerine korele eder.

    Olaylari saldirgan (IP) ve kampanya (ortak /24 ya da ortak arac parmak izi)
    bazinda gruplar; her grup icinde olaylari zaman sirasina dizip bir SALDIRI
    ZINCIRI (sirali kill chain asamalari) turetir.

    `clock` enjekte edilebilir bir saattir (deterministik test icin); rapora
    'generated_at' epoch damgasi eklemek disinda korelasyon sonucunu
    ETKILEMEZ - grup icerigi yalnizca olaylardan turetilir.

    Donus: {"campaigns": [...], "incidents": [...], "summary_tr"}."""
    events = events or []
    window_sec = window_sec or _DEFAULT_WINDOW_SEC
    by_ip, tool_of, groups = _group_campaigns(events, window_sec)

    campaigns = []
    for root, members in groups.items():
        members = sorted(members)
        camp_events = [e for ip in members for e in by_ip[ip]]
        timestamps = [t for t in (_parse_ts(e.get("timestamp"))
                                  for e in camp_events) if t]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        span = ((last_seen - first_seen).total_seconds()
                if first_seen and last_seen else 0.0)

        services = Counter(e.get("service") for e in camp_events
                           if e.get("service"))
        primary_service = (sorted(services.items(),
                                  key=lambda kv: (-kv[1], kv[0]))[0][0]
                           if services else None)
        event_types = {e.get("event_type") for e in camp_events
                       if e.get("event_type")}
        chain = _chain_stages(camp_events)

        # Tekrar: ayni olay turu birden cok kez ya da birden cok IP -> tekrar.
        type_counts = Counter(e.get("event_type") for e in camp_events)
        repeat = len(members) > 1 or any(c > 1 for c in type_counts.values())
        confidence = confidence_from_signals(
            signal_count=len(camp_events),
            distinct_services=len(services),
            time_span_sec=span,
            repeat=repeat,
        )
        tools = sorted({tool_of[ip] for ip in members if tool_of[ip]})

        narrative_tr = (
            f"{len(camp_events)} olay {len(members)} IP'den geldi"
            + (f" (ortak arac: {', '.join(tools)})" if tools else "")
            + f"; birincil hedef '{primary_service}'. "
            + (f"Gozlemlenen asama zinciri: {' -> '.join(chain)}. "
               if chain else "Belirgin bir teknik zinciri yok. ")
            + f"Zayif sinyaller birlesti; korelasyon guveni {confidence:.0%}."
        )

        campaigns.append({
            "id": f"campaign:{members[0]}",
            "member_ips": members,
            "event_count": len(camp_events),
            "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S")
            if first_seen else None,
            "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S")
            if last_seen else None,
            "primary_service": primary_service,
            "distinct_services": len(services),
            "distinct_event_types": len(event_types),
            "tools": tools,
            "chain": chain,
            "confidence": confidence,
            "narrative_tr": narrative_tr,
        })

    campaigns.sort(key=lambda c: (-c["confidence"], c["id"]))

    # Incident'lar: her saldirgan icin zayif sinyallerin tek olaya birlesimi.
    incidents = [merge_low_level(by_ip[ip]) for ip in sorted(by_ip)]
    incidents.sort(key=lambda i: (-i["event_count"], i["attacker"] or ""))

    multi = [c for c in campaigns if len(c["member_ips"]) > 1]
    summary_tr = (
        f"{len(events)} ham olay, {len(by_ip)} saldirgan ve "
        f"{len(campaigns)} kampanya olarak korele edildi "
        f"({len(multi)} kampanya birden cok IP iceriyor). "
        f"Bu korelasyon DETERMINISTIK kurallara dayanir, egitilmis bir "
        f"model degildir."
    )

    result = {
        "campaigns": campaigns,
        "incidents": incidents,
        "summary_tr": summary_tr,
    }
    if clock is not None:
        result["generated_at"] = clock()
    return result
