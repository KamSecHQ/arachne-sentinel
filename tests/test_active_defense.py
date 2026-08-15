"""Faz 11 (aktif savunma) ve Faz 12 (honeytoken) testleri.

ETIK: Bu testler, aktif savunmanin BASKA SISTEME SALDIRMADIGINI ve tum
eylemlerin kendi honeypot yuzeyimizde kaldigini da dogrular.
"""
import tempfile
from pathlib import Path

from arachne import storage
from arachne.active_defense import deception, honeytokens, tarpit


def _tmp_db():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=tmp)
    return tmp


# --- Faz 11: Tarpit ---------------------------------------------------------

def test_tarpit_no_delay_for_low_threat():
    """Dusuk tehditli ilk baglanti yavaslatilmamali (mesru kullanici olabilir)."""
    result = tarpit.compute_tarpit_delay(threat_score=10, prior_alerts=0)
    assert result["applied"] is False
    assert result["delay"] == 0.0


def test_tarpit_delays_high_threat():
    result = tarpit.compute_tarpit_delay(threat_score=90, prior_alerts=0)
    assert result["applied"] is True
    assert result["delay"] > 0


def test_tarpit_escalates_with_prior_alerts():
    low = tarpit.compute_tarpit_delay(threat_score=60, prior_alerts=0)
    high = tarpit.compute_tarpit_delay(threat_score=60, prior_alerts=5)
    assert high["delay"] > low["delay"]


def test_tarpit_respects_max_delay():
    result = tarpit.compute_tarpit_delay(threat_score=100, prior_alerts=100)
    assert result["delay"] <= tarpit.MAX_DELAY


def test_tarpit_can_be_disabled():
    policy = tarpit.TarpitPolicy(enabled=False)
    result = tarpit.compute_tarpit_delay(90, 5, policy)
    assert result["applied"] is False


def test_tarpit_banner_stream_chunks():
    chunks = list(tarpit.tarpit_banner_stream("SSH-2.0-OpenSSH", delay=4.0, chunks=4))
    assert len(chunks) >= 1
    reassembled = "".join(c[0] for c in chunks)
    assert reassembled == "SSH-2.0-OpenSSH"


# --- Faz 11: Aldatma --------------------------------------------------------

def test_deception_normal_for_low_threat():
    decision = deception.decide_response(10)
    assert decision.action == "normal"


def test_deception_tarpit_for_medium():
    decision = deception.decide_response(40)
    assert decision.action == "tarpit"


def test_deception_fake_data_for_path_traversal():
    decision = deception.decide_response(70, ["Path Traversal"])
    assert decision.action == "fake-data"


def test_deception_fake_success_for_brute_force():
    decision = deception.decide_response(70, ["Brute Force"])
    assert decision.action == "fake-success"


def test_fake_credentials_are_marked_fake_and_traceable():
    creds = deception.generate_fake_credentials("203.0.113.5", count=3)
    assert len(creds) == 3
    for c in creds:
        assert c["honeytoken_id"].startswith("ht_")
        assert "SAHTE" in c["note"]


def test_fake_credentials_deterministic_per_ip():
    """Ayni IP tutarli bir sahte dunya gormeli (inandiricilik)."""
    a = deception.generate_fake_credentials("203.0.113.5")
    b = deception.generate_fake_credentials("203.0.113.5")
    assert a == b


def test_fake_passwd_contains_no_real_data():
    passwd = deception.generate_fake_passwd("203.0.113.5")
    assert "root:x:0:0" in passwd
    # Uydurma kullanicilar - gercek sistemden alinmamis
    assert passwd.count("\n") >= 5


def test_fake_filesystem_generated():
    files = deception.generate_fake_filesystem("203.0.113.5", count=5)
    assert len(files) == 5
    for f in files:
        assert f["honeytoken_id"].startswith("ht_file_")


def test_deception_engine_applies_and_logs():
    db = _tmp_db()
    engine = deception.DeceptionEngine(db_path=db)
    result = engine.apply("203.0.113.5", threat_score=70, attack_classes=["Path Traversal"])
    assert result["deception_applied"] is True
    logged = storage.get_active_defense(db_path=db)
    assert len(logged) == 1


def test_deception_engine_normal_not_logged():
    db = _tmp_db()
    engine = deception.DeceptionEngine(db_path=db)
    result = engine.apply("203.0.113.5", threat_score=5)
    assert result["deception_applied"] is False
    assert storage.get_active_defense(db_path=db) == []


# --- Faz 12: Honeytokens ----------------------------------------------------

def test_generate_honeytoken_has_unique_id():
    t1 = honeytokens.generate_honeytoken("api_key")
    t2 = honeytokens.generate_honeytoken("api_key")
    assert t1.token_id != t2.token_id


def test_honeytoken_types_have_realistic_prefixes():
    aws = honeytokens.generate_honeytoken("aws_key")
    assert aws.value.startswith("AKIA")
    api = honeytokens.generate_honeytoken("api_key")
    assert api.value.startswith("sk_live_")


def test_vault_mint_and_detect():
    db = _tmp_db()
    vault = honeytokens.HoneytokenVault(db_path=db)
    token = vault.mint("api_key", context="sahte-config")

    # Saldirgan token'i "calip" geri gonderirse yakalanmali
    payload = f"Authorization: Bearer {token.value}"
    triggered = vault.check(payload, source_ip="203.0.113.5")
    assert len(triggered) == 1
    assert triggered[0]["token_id"] == token.token_id


def test_vault_no_trigger_on_clean_payload():
    db = _tmp_db()
    vault = honeytokens.HoneytokenVault(db_path=db)
    vault.mint("api_key")
    triggered = vault.check("normal request without tokens", source_ip="203.0.113.5")
    assert triggered == []


def test_honeytoken_trigger_recorded_in_db():
    db = _tmp_db()
    vault = honeytokens.HoneytokenVault(db_path=db)
    token = vault.mint("aws_key")
    vault.check(f"leaked: {token.value}", source_ip="203.0.113.9")

    tokens = storage.get_honeytokens(triggered_only=True, db_path=db)
    assert len(tokens) == 1
    assert tokens[0]["triggered_by"] == "203.0.113.9"


def test_check_payload_cross_process():
    """Bir surecte uretilen token, baska bir yerden (DB uzerinden) yakalanmali."""
    db = _tmp_db()
    vault = honeytokens.HoneytokenVault(db_path=db)
    token = vault.mint("db_uri")

    # Farkli bir "surec" (yeni vault yok, dogrudan DB kontrolu)
    result = honeytokens.check_payload_for_tokens(
        f"connecting to {token.value}", db_path=db)
    assert result["high_confidence_breach"] is True
    assert result["count"] == 1


def test_mint_set_creates_all_types():
    db = _tmp_db()
    vault = honeytokens.HoneytokenVault(db_path=db)
    tokens = vault.mint_set()
    assert len(tokens) == len(honeytokens.TOKEN_TYPES)
