"""
Faz 33 - IOC Korelasyon Grafigi (analistin pivot grafi).

--- Fikir ---
Tek tek olaylar bir "nokta bulutu"dur; bir SOC analisti asil degeri onlari
BAGLADIGINDA elde eder: "bu IOC hangi olayda gorundu? o olayi kim yapti? o
saldirgan hangi ATT&CK teknigini kullandi? ayni kampanyadaki diger IP'ler
kimler? neyi hedefliyorlar?" Bu modul ham olaylari tipli, yonlu bir korelasyon
grafina cevirir:

    IOC -> olay -> saldirgan -> ATT&CK teknigi -> kampanya -> hedef

Analist herhangi bir dugume tiklayip komsularini acabilir (pivot). Bu, ticari
tehdit istihbarati platformlarindaki (Maltego, ThreatConnect, MISP) "link
analysis" grafinin honeypot olaylari uzerinde kucuk ama gercek bir surumudur.

--- Gercek cerceve karsiligi ---
  * STIX 2.1 iliski modeli: dugumler SDO benzeri (indicator, attack-pattern,
    identity, campaign), kenarlar SRO benzeri (observed-in, attributed-to,
    uses, targets, part-of).
  * MITRE ATT&CK: teknik dugumleri intel.attck katalogundan T-ID'lerle beslenir.

--- DURUSTLUK NOTU ---
Bu bir OTOMATIK atif (attribution) araci DEGILDIR. "attacker" dugumu sadece
gozlemlenen kaynak IP'dir; gercek bir tehdit aktoru kimligi iddia etmez. IP
sahtelenebilir/proxy'lenebilir; graf yalnizca gozlemlenen iliskileri gosterir,
kesin bir "kim" cevabi degil. Kampanya gruplamasi da bir HEURISTIC'tir (/24 ya
da ayni arac parmak izi), kesin bir kanit degil.

--- SAVUNMA-AMACLI ETIK NOT ---
Grafin tek amaci, izole honeypot ortaminda toplanan olaylari bir analistin
anlayabilecegi bir hikayeye donusturmektir (savunma/adli inceleme). Saldiri
planlamak icin hicbir sey uretmez.

Saf Python - graf sozluklerle modellenir, harici graf kutuphanesi yoktur.
"""
import ipaddress
from collections import Counter, defaultdict

from . import attck

# IOC extractor sozluk anahtari -> graf uzerindeki kisa IOC turu etiketi.
# (Cok kalabalik olmamasi icin path/komut gibi genis kategoriler de dahil,
#  ama her biri ayri kisa bir "kind" ile isaretlenir.)
_IOC_KIND_MAP = {
    "ipv4": "ip",
    "ipv6": "ip",
    "domains": "domain",
    "urls": "url",
    "emails": "email",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "bitcoin_addresses": "btc",
    "shell_commands": "cmd",
    "reverse_shells": "revshell",
    "unix_paths": "path",
    "windows_paths": "path",
}


# --- Varsayilan enjekte edilebilir fonksiyonlar ----------------------------

def _default_extract_fn(text: str) -> dict:
    """Varsayilan IOC cikarici (reverse.ioc_extractor.extract_iocs)."""
    from ..reverse.ioc_extractor import extract_iocs
    return extract_iocs(text or "")


def _default_technique_fn(payload: str) -> list:
    """Varsayilan payload -> ATT&CK teknik ID listesi eslemesi.

    Once payload icindeki saldiri siniflarini tespit eder (reverse katmaninin
    imza motoru), sonra intel.attck ile her sinifi kanonik T-ID'lere esler.
    Boylece graf, projenin geri kalaniyla ayni ATT&CK dilini konusur."""
    from ..reverse.attack_analyzer import _detect_attack_classes
    classes = _detect_attack_classes(payload or "")
    tids = []
    for cls in classes:
        for tid in attck.map_attack_class(cls)["attck"]:
            if tid not in tids:
                tids.append(tid)
    return tids


# --- Yardimcilar ------------------------------------------------------------

def _subnet_24(ip: str):
    """Bir IPv4 adresinin /24 blogunu dondurur (yoksa None)."""
    try:
        addr = ipaddress.IPv4Address(str(ip))
    except (ValueError, ipaddress.AddressValueError):
        return None
    net = ipaddress.IPv4Network((int(addr) & 0xFFFFFF00, 24))
    return str(net)


def _primary_tool(payloads: list):
    """Bir saldirganin yuklerinden baskin arac parmak izini dondurur (yoksa None)."""
    from ..reverse.tool_fingerprint import fingerprint_tool
    best = None
    best_conf = -1
    for payload in payloads:
        for match in fingerprint_tool(payload or ""):
            if match.confidence > best_conf:
                best_conf = match.confidence
                best = match.tool
    return best


class _UnionFind:
    """Kampanya gruplamasi icin basit birlesim-bulma (union-find)."""

    def __init__(self, items):
        self.parent = {x: x for x in items}

    def find(self, x):
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def groups(self):
        out = defaultdict(list)
        for x in self.parent:
            out[self.find(x)].append(x)
        return list(out.values())


# --- Ana API ----------------------------------------------------------------

def build_correlation_graph(events: list, alerts: list = None,
                            extract_fn=None, technique_fn=None) -> dict:
    """Ham olaylardan tipli, yonlu bir korelasyon grafi kurar.

    Donen sozluk:
        {"nodes": [{id, type, label, meta}], "edges": [{"from","to","rel"}],
         "stats": {tur -> adet}}

    Dugum turleri: ioc, event, attacker, technique, campaign, target.
    Dugum ID'leri deterministiktir (ornek: 'attacker:1.2.3.4',
    'ioc:domain:evil.com', 'technique:T1190', 'target:ssh').

    Parametreler:
      extract_fn(text)->dict : payload'lardan IOC cikarir (varsayilan:
                               ioc_extractor.extract_iocs).
      technique_fn(payload)->list : payload'i ATT&CK T-ID listesine esler
                               (varsayilan: intel.attck uzerinden).
    """
    events = events or []
    extract_fn = extract_fn or _default_extract_fn
    technique_fn = technique_fn or _default_technique_fn

    # Alarm bilgisini IP bazinda indeksle (saldirgan dugumunu zenginlestirir).
    alert_by_ip = {}
    for alert in (alerts or []):
        ip = alert.get("source_ip")
        if ip:
            alert_by_ip[ip] = alert

    nodes = {}          # id -> node dict
    edges = set()       # (from, to, rel) - dedup icin
    attacker_payloads = defaultdict(list)
    attacker_services = defaultdict(Counter)
    attacker_events = defaultdict(int)
    attacker_techniques = defaultdict(set)
    service_attackers = defaultdict(set)
    service_events = defaultdict(int)

    def add_node(node_id, ntype, label, meta):
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": ntype,
                              "label": label, "meta": meta}
        return nodes[node_id]

    def add_edge(src, dst, rel):
        edges.add((src, dst, rel))

    for event in events:
        ip = event.get("source_ip")
        service = event.get("service")
        payload = event.get("payload") or ""
        ev_id = event.get("id")
        if ev_id is None:
            # ID yoksa deterministik bir tanimlayici uret.
            ev_id = f"{ip}-{event.get('timestamp')}-{service}"
        event_node_id = f"event:{ev_id}"

        # 1) Olay dugumu
        add_node(event_node_id, "event", f"Olay {ev_id}", {
            "timestamp": event.get("timestamp"),
            "service": service,
            "event_type": event.get("event_type"),
            "dest_port": event.get("dest_port"),
            "source_ip": ip,
        })

        # 2) Saldirgan (kaynak IP) dugumu
        if ip:
            attacker_id = f"attacker:{ip}"
            attacker_events[ip] += 1
            attacker_payloads[ip].append(payload)
            if service:
                attacker_services[ip][service] += 1
            # olay -> saldirgan (STIX: attributed-to)
            add_edge(event_node_id, attacker_id, "attributed-to")

        # 3) Hedef (servis) dugumu
        if service:
            target_id = f"target:{service}"
            service_events[service] += 1
            if ip:
                service_attackers[service].add(ip)
            add_node(target_id, "target", f"Hedef: {service}",
                     {"service": service})
            add_edge(event_node_id, target_id, "targets")
            if ip:
                add_edge(f"attacker:{ip}", target_id, "targets")

        # 4) IOC dugumleri (payload'dan cikarilir)
        iocs = extract_fn(payload)
        for key, kind in _IOC_KIND_MAP.items():
            for value in iocs.get(key, []) or []:
                ioc_id = f"ioc:{kind}:{value}"
                add_node(ioc_id, "ioc", f"{kind}: {value}",
                         {"kind": kind, "value": value})
                # IOC -> olay (STIX: observed-in)
                add_edge(ioc_id, event_node_id, "observed-in")

        # 5) ATT&CK teknik dugumleri (payload'dan)
        for tid in technique_fn(payload):
            info = attck.technique_info(tid)
            tech_id = f"technique:{tid}"
            add_node(tech_id, "technique", f"{tid} {info['name']}", {
                "technique_id": tid,
                "name": info["name"],
                "tactic": info["tactic"],
                "tactic_tr": info["tactic_tr"],
                "kill_chain_phase": info["kill_chain_phase"],
            })
            add_edge(event_node_id, tech_id, "exhibits")
            if ip:
                attacker_techniques[ip].add(tid)
                add_edge(f"attacker:{ip}", tech_id, "uses")

    # Saldirgan dugumlerini (topladigimiz ozetlerle) olustur.
    attacker_meta = {}
    for ip, count in attacker_events.items():
        attacker_id = f"attacker:{ip}"
        subnet = _subnet_24(ip)
        tool = _primary_tool(attacker_payloads[ip])
        meta = {
            "ip": ip,
            "event_count": count,
            "services": dict(attacker_services[ip]),
            "subnet": subnet,
            "primary_tool": tool,
            "technique_count": len(attacker_techniques[ip]),
        }
        if ip in alert_by_ip:
            meta["score"] = alert_by_ip[ip].get("score")
            meta["severity"] = alert_by_ip[ip].get("severity")
        attacker_meta[ip] = meta
        add_node(attacker_id, "attacker", f"Saldirgan {ip}", meta)

    # Hedef dugum meta bilgisini zenginlestir (saldirgan sayisi vb.).
    for service in service_events:
        node = nodes.get(f"target:{service}")
        if node:
            node["meta"]["event_count"] = service_events[service]
            node["meta"]["attacker_count"] = len(service_attackers[service])

    # 6) Kampanya dugumleri: /24 ya da ayni baskin araci paylasan saldirganlar.
    campaign_nodes = _build_campaigns(attacker_meta)
    for camp in campaign_nodes:
        add_node(camp["id"], "campaign", camp["label"], camp["meta"])
        for ip in camp["meta"]["member_ips"]:
            add_edge(f"attacker:{ip}", camp["id"], "part-of")

    node_list = sorted(nodes.values(), key=lambda n: (n["type"], n["id"]))
    edge_list = [{"from": s, "to": d, "rel": r} for (s, d, r) in
                 sorted(edges)]

    by_type = Counter(n["type"] for n in node_list)
    return {
        "nodes": node_list,
        "edges": edge_list,
        "stats": {"by_type": dict(by_type),
                  "node_count": len(node_list),
                  "edge_count": len(edge_list)},
    }


def _build_campaigns(attacker_meta: dict) -> list:
    """Saldirgan IP'lerini /24 ya da ayni arac parmak izine gore gruplar.

    Yalnizca 2+ uyesi olan gruplar bir kampanya dugumu olur (tek bir IP bir
    "kampanya" degildir - kampanya en az iki gozlemin korelasyonudur)."""
    ips = sorted(attacker_meta.keys())
    if not ips:
        return []

    uf = _UnionFind(ips)
    by_subnet = defaultdict(list)
    by_tool = defaultdict(list)
    for ip in ips:
        subnet = attacker_meta[ip]["subnet"]
        tool = attacker_meta[ip]["primary_tool"]
        if subnet:
            by_subnet[subnet].append(ip)
        if tool:
            by_tool[tool].append(ip)
    for group in list(by_subnet.values()) + list(by_tool.values()):
        for other in group[1:]:
            uf.union(group[0], other)

    campaigns = []
    for members in uf.groups():
        if len(members) < 2:
            continue
        members = sorted(members)
        subnets = sorted({attacker_meta[ip]["subnet"] for ip in members
                          if attacker_meta[ip]["subnet"]})
        tools = sorted({attacker_meta[ip]["primary_tool"] for ip in members
                        if attacker_meta[ip]["primary_tool"]})
        basis = []
        if len(subnets) == 1 and len(members) > 1:
            basis.append(f"ortak /24 ({subnets[0]})")
        if len(tools) == 1 and tools:
            basis.append(f"ortak arac ({tools[0]})")
        if not basis:
            basis.append("ortak altyapi")
        camp_id = f"campaign:{members[0]}"
        campaigns.append({
            "id": camp_id,
            "label": f"Kampanya [{', '.join(basis)}]",
            "meta": {
                "member_ips": members,
                "size": len(members),
                "basis": basis,
                "subnets": subnets,
                "tools": tools,
                "event_count": sum(attacker_meta[ip]["event_count"]
                                   for ip in members),
            },
        })
    return sorted(campaigns, key=lambda c: c["id"])


def node_neighbors(graph: dict, node_id: str) -> dict:
    """Bir dugumun komsuluklarini dondurur (genisletilebilir arayuz icin).

    Analist bir dugume tikladiginda: gelen (incoming) ve giden (outgoing)
    tum iliskileri gorur. Donus:
        {"node": <dugum ya da None>,
         "incoming": [{"node": <komsu>, "rel": ...}],
         "outgoing": [{"node": <komsu>, "rel": ...}]}
    """
    index = {n["id"]: n for n in graph.get("nodes", [])}
    incoming = []
    outgoing = []
    for edge in graph.get("edges", []):
        if edge["to"] == node_id:
            incoming.append({"node": index.get(edge["from"]),
                             "rel": edge["rel"]})
        if edge["from"] == node_id:
            outgoing.append({"node": index.get(edge["to"]),
                             "rel": edge["rel"]})
    return {"node": index.get(node_id),
            "incoming": incoming, "outgoing": outgoing}


def graph_summary(graph: dict) -> dict:
    """Graf hakkinda insan-okunabilir bir ozet (panel/rapor icin).

    Donus: {node_count, edge_count, by_type, top_attackers, campaigns,
            summary_tr}."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    by_type = dict(Counter(n["type"] for n in nodes))

    attackers = [n for n in nodes if n["type"] == "attacker"]
    attackers.sort(key=lambda n: (-n["meta"].get("event_count", 0), n["id"]))
    top_attackers = [{
        "ip": n["meta"].get("ip"),
        "event_count": n["meta"].get("event_count", 0),
        "primary_tool": n["meta"].get("primary_tool"),
        "severity": n["meta"].get("severity"),
    } for n in attackers[:5]]

    campaigns = [{
        "id": n["id"],
        "member_ips": n["meta"].get("member_ips", []),
        "size": n["meta"].get("size", 0),
        "basis": n["meta"].get("basis", []),
    } for n in nodes if n["type"] == "campaign"]

    summary_tr = (
        f"{len(nodes)} dugum ve {len(edges)} kenar; "
        f"{by_type.get('attacker', 0)} saldirgan, "
        f"{by_type.get('campaign', 0)} kampanya, "
        f"{by_type.get('technique', 0)} ATT&CK teknigi, "
        f"{by_type.get('ioc', 0)} IOC, "
        f"{by_type.get('target', 0)} hedef servis korelasyonu."
    )
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "by_type": by_type,
        "top_attackers": top_attackers,
        "campaigns": campaigns,
        "summary_tr": summary_tr,
    }
