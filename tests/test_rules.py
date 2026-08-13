from arachne.detection import rules


def _event(service, event_type="connect", dest_port=22, payload=None):
    return {"service": service, "event_type": event_type, "dest_port": dest_port,
            "payload": payload}


def test_rule_port_scan_triggers_on_enough_distinct_ports():
    events = [_event("ssh", dest_port=p) for p in (21, 22, 23, 3306)]
    triggered, reason, weight = rules.rule_port_scan(events)
    assert triggered is True
    assert weight == 30
    assert "Port tarama" in reason


def test_rule_port_scan_does_not_trigger_with_few_ports():
    events = [_event("ssh", dest_port=22)]
    triggered, _, _ = rules.rule_port_scan(events)
    assert triggered is False


def test_rule_brute_force_triggers_on_repeated_connects_same_service():
    events = [_event("ssh") for _ in range(5)]
    triggered, reason, weight = rules.rule_brute_force(events)
    assert triggered is True
    assert weight == 40


def test_rule_known_signature_detects_sql_injection():
    events = [_event("http-admin", event_type="data",
                      payload="user=admin' OR '1'='1&pass=x")]
    triggered, reason, weight = rules.rule_known_signature(events)
    assert triggered is True
    assert "SQL Injection" in reason


def test_rule_known_signature_ignores_benign_payload():
    events = [_event("http-admin", event_type="data", payload="user=emir&pass=normalPass123")]
    triggered, _, _ = rules.rule_known_signature(events)
    assert triggered is False


def test_rule_multi_service_probe_triggers_across_services():
    events = [_event("ssh"), _event("ftp"), _event("http-admin")]
    triggered, reason, weight = rules.rule_multi_service_probe(events)
    assert triggered is True
    assert weight == 25


def test_rule_repeated_offender_reflects_prior_alert_flag():
    triggered, _, weight = rules.rule_repeated_offender([], has_prior_alert=True)
    assert triggered is True
    assert weight == 20
    triggered, _, _ = rules.rule_repeated_offender([], has_prior_alert=False)
    assert triggered is False
