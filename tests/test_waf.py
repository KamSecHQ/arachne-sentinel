from arachne.waf import rules


def test_scan_text_detects_sql_injection():
    hits = rules.scan_text("name=' OR '1'='1")
    categories = [c for c, _ in hits]
    assert "SQL Injection" in categories


def test_scan_text_detects_xss():
    hits = rules.scan_text("<script>alert(1)</script>")
    categories = [c for c, _ in hits]
    assert "XSS" in categories


def test_scan_text_ignores_benign_input():
    hits = rules.scan_text("name=emirhan&age=25")
    assert hits == []


def test_scan_text_detects_path_traversal():
    hits = rules.scan_text("../../../etc/passwd")
    categories = [c for c, _ in hits]
    assert "Path Traversal" in categories
