"""Faz 14 - Imza kural motoru testleri."""
import pytest

from arachne.detection import rule_engine as re_mod
from arachne.detection.rule_engine import (
    RuleCompileError, RuleSet, compile_rule, scan_payload,
)


def test_compile_valid_rule():
    rule = compile_rule({
        "id": "test", "name": "Test", "severity": "high",
        "condition": "any",
        "strings": [{"id": "s1", "type": "contains", "value": "attack"}],
    })
    assert rule.id == "test"
    assert len(rule.strings) == 1


def test_compile_rejects_missing_field():
    with pytest.raises(RuleCompileError):
        compile_rule({"id": "x", "name": "y"})   # strings eksik


def test_compile_rejects_bad_regex():
    with pytest.raises(RuleCompileError):
        compile_rule({
            "id": "x", "name": "y",
            "strings": [{"id": "s", "type": "regex", "value": "([unclosed"}],
        })


def test_compile_rejects_bad_severity():
    with pytest.raises(RuleCompileError):
        compile_rule({
            "id": "x", "name": "y", "severity": "apocalyptic",
            "strings": [{"id": "s", "type": "contains", "value": "a"}],
        })


def test_compile_rejects_n_of_exceeding_strings():
    with pytest.raises(RuleCompileError):
        compile_rule({
            "id": "x", "name": "y", "condition": 5,
            "strings": [{"id": "s", "type": "contains", "value": "a"}],
        })


def test_condition_all_requires_every_string():
    rule = compile_rule({
        "id": "t", "name": "T", "condition": "all",
        "strings": [
            {"id": "s1", "type": "icontains", "value": "union"},
            {"id": "s2", "type": "icontains", "value": "select"},
        ],
    })
    assert rule.evaluate("union select")["fired"] is True
    assert rule.evaluate("union only")["fired"] is False


def test_condition_any_requires_one():
    rule = compile_rule({
        "id": "t", "name": "T", "condition": "any",
        "strings": [
            {"id": "s1", "type": "icontains", "value": "sleep("},
            {"id": "s2", "type": "icontains", "value": "benchmark("},
        ],
    })
    assert rule.evaluate("1 AND sleep(5)")["fired"] is True


def test_condition_n_of():
    rule = compile_rule({
        "id": "t", "name": "T", "condition": 2,
        "strings": [
            {"id": "s1", "type": "icontains", "value": ";"},
            {"id": "s2", "type": "icontains", "value": "cat"},
            {"id": "s3", "type": "icontains", "value": "/etc/passwd"},
        ],
    })
    # 2 of 3
    assert rule.evaluate("; cat file")["fired"] is True
    assert rule.evaluate("just cat")["fired"] is False


def test_entropy_above_condition():
    rule = compile_rule({
        "id": "t", "name": "T", "condition": "all",
        "strings": [{"id": "s", "type": "entropy_above", "value": 5.0}],
    })
    import base64
    high = base64.b64encode(bytes(range(200))).decode()
    assert rule.evaluate(high)["fired"] is True
    assert rule.evaluate("aaaa")["fired"] is False


def test_length_above_condition():
    rule = compile_rule({
        "id": "t", "name": "T", "condition": "all",
        "strings": [{"id": "s", "type": "length_above", "value": 10}],
    })
    assert rule.evaluate("x" * 20)["fired"] is True
    assert rule.evaluate("short")["fired"] is False


def test_evaluate_reports_matched_strings():
    """Aciklanabilirlik: hangi string'lerin eslestigi dondurulmeli."""
    rule = compile_rule({
        "id": "t", "name": "T", "condition": "any",
        "strings": [
            {"id": "a", "type": "icontains", "value": "union"},
            {"id": "b", "type": "icontains", "value": "xyz"},
        ],
    })
    result = rule.evaluate("union select")
    assert "a" in result["matched_strings"]
    assert "b" not in result["matched_strings"]


def test_builtin_ruleset_loads_without_errors():
    rs = RuleSet()
    assert len(rs.rules) > 0
    assert rs.errors == []      # yerlesik kurallarin hicbiri bozuk olmamali


def test_builtin_detects_union_sqli():
    result = scan_payload("id=1 UNION SELECT username,password FROM users")
    assert result["match_count"] >= 1
    assert any(m["rule_id"] == "sqli-union-based" for m in result["matched_rules"])


def test_builtin_detects_rce():
    result = scan_payload("cmd=; cat /etc/passwd")
    assert any(m["rule_id"] == "rce-shell-chain" for m in result["matched_rules"])
    assert result["highest_severity"] == "critical"


def test_builtin_detects_webshell():
    result = scan_payload("data=eval($_POST['x'])")
    assert any(m["rule_id"] == "webshell-upload" for m in result["matched_rules"])


def test_builtin_no_false_positive_on_benign():
    result = scan_payload("GET /products?category=shoes&page=2 HTTP/1.1")
    assert result["match_count"] == 0


def test_scan_summary_sorts_by_severity():
    rs = RuleSet()
    # Hem kritik hem orta tetikleyen bir yuk
    result = rs.scan("; cat /etc/passwd UNION SELECT 1")
    if len(result) >= 2:
        severities = [m["severity"] for m in result]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert severities == sorted(severities, key=lambda s: order[s])


def test_custom_ruleset_with_broken_rule_records_error():
    rs = RuleSet([
        {"id": "good", "name": "G", "strings": [{"id": "s", "type": "contains", "value": "a"}]},
        {"id": "bad", "name": "B", "strings": [{"id": "s", "type": "regex", "value": "["}]},
    ])
    assert len(rs.rules) == 1
    assert len(rs.errors) == 1
