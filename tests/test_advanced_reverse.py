"""Faz 13 - Gelismis kodlama cozucu ve entropi testleri."""
import base64
import gzip

from arachne.reverse import advanced_decoder as ad
from arachne.reverse.attack_analyzer import analyze_payload


def test_entropy_low_for_repetitive():
    assert ad.shannon_entropy("aaaaaaaa") < 1.0


def test_entropy_high_for_random_base64():
    data = base64.b64encode(bytes(range(256))).decode()
    assert ad.shannon_entropy(data) > 5.0


def test_entropy_empty_string():
    assert ad.shannon_entropy("") == 0.0


def test_decode_sql_char_chain():
    # CHAR(39)+CHAR(79)+CHAR(82) = "'OR"
    result = ad.advanced_decode("CHAR(39)+CHAR(79)+CHAR(82)")
    assert "'OR" in result.decoded
    assert any(s.method == "sql-char" for s in result.steps)


def test_decode_js_fromcharcode():
    result = ad.advanced_decode("String.fromCharCode(97,108,101,114,116)")
    assert "alert" in result.decoded


def test_decode_decimal_entities():
    result = ad.advanced_decode("&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;")
    assert "<script>" in result.decoded


def test_decode_gzip_base64():
    original = "'; DROP TABLE users; --"
    packed = base64.b64encode(gzip.compress(original.encode())).decode()
    result = ad.advanced_decode(packed)
    assert original in result.decoded
    assert any(s.method == "gzip-base64" for s in result.steps)


def test_decode_rot13_only_on_meaningful():
    # ROT13 of "select" is "fryrpg"; rot13 back should give select
    result = ad.advanced_decode("fryrpg * sebz")
    assert "select" in result.decoded.lower()


def test_decode_sql_comment_strip():
    result = ad.advanced_decode("union/**/select/**/password")
    assert "/*" not in result.decoded
    assert "union" in result.decoded


def test_plain_text_not_transformed():
    result = ad.advanced_decode("merhaba dunya normal metin")
    assert not result.was_transformed


def test_polyglot_detection():
    # Hem SQL hem XSS iceren yuk
    poly = ad.is_polyglot("' OR 1=1-- <script>alert(1)</script>")
    assert poly["is_polyglot"] is True
    assert "SQL" in poly["contexts"]
    assert "HTML/JS" in poly["contexts"]


def test_polyglot_single_context():
    poly = ad.is_polyglot("' OR 1=1--")
    assert poly["is_polyglot"] is False


def test_analyze_payload_includes_advanced_fields():
    result = analyze_payload("CHAR(39)+CHAR(79)+CHAR(82)+CHAR(32)+CHAR(49)+CHAR(61)+CHAR(49)")
    assert "advanced_decoding" in result
    assert "entropy" in result
    assert "polyglot" in result


def test_analyze_payload_polyglot_raises_threat():
    poly_payload = "' OR 1=1-- <script>alert(document.cookie)</script>"
    result = analyze_payload(poly_payload)
    assert result["polyglot"]["is_polyglot"] is True
    assert result["threat_score"] > 0
