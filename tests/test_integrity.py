"""Faz 17 - Kurcalama-kaniti denetim zinciri testleri."""
from arachne.integrity import audit_chain
from arachne.integrity.audit_chain import AuditChain, merkle_root, verify_chain


def test_empty_chain_is_valid():
    chain = AuditChain()
    valid, idx = chain.verify()
    assert valid is True
    assert idx is None


def test_append_and_verify():
    chain = AuditChain()
    chain.append({"action": "block", "ip": "203.0.113.5"})
    chain.append({"action": "unblock", "ip": "203.0.113.5"})
    valid, idx = chain.verify()
    assert valid is True
    assert len(chain) == 2


def test_each_record_links_to_previous():
    chain = AuditChain()
    r1 = chain.append({"x": 1})
    r2 = chain.append({"x": 2})
    assert r2["prev_hash"] == r1["hash"]
    assert r1["prev_hash"] == audit_chain.GENESIS_HASH


def test_tampering_is_detected():
    """Kurcalama-kaniti temel testi: bir kaydi degistir, zincir bozulsun."""
    chain = AuditChain()
    chain.append({"action": "block", "ip": "203.0.113.5"})
    chain.append({"action": "block", "ip": "203.0.113.6"})
    chain.append({"action": "block", "ip": "203.0.113.7"})

    # Ortadaki kaydin verisini kurcala
    chain.records[1]["data"]["ip"] = "10.0.0.1"

    valid, idx = chain.verify()
    assert valid is False
    assert idx == 1


def test_tampering_hash_directly_detected():
    chain = AuditChain()
    chain.append({"a": 1})
    chain.append({"a": 2})
    chain.records[0]["hash"] = "f" * 64
    valid, idx = chain.verify()
    assert valid is False


def test_verify_chain_standalone():
    chain = AuditChain()
    chain.append({"a": 1})
    chain.append({"a": 2})
    records = chain.to_list()
    valid, idx = verify_chain(records)
    assert valid is True


def test_verify_chain_detects_serialized_tampering():
    chain = AuditChain()
    chain.append({"a": 1})
    chain.append({"a": 2})
    records = chain.to_list()
    records[0]["data"]["a"] = 999
    valid, idx = verify_chain(records)
    assert valid is False
    assert idx == 0


def test_merkle_root_empty():
    assert merkle_root([]) == audit_chain.GENESIS_HASH


def test_merkle_root_deterministic():
    hashes = ["a" * 64, "b" * 64, "c" * 64]
    assert merkle_root(hashes) == merkle_root(hashes)


def test_merkle_root_changes_with_input():
    r1 = merkle_root(["a" * 64, "b" * 64])
    r2 = merkle_root(["a" * 64, "c" * 64])
    assert r1 != r2


def test_merkle_root_odd_count():
    # Tek sayida hash - son eleman kendisiyle eslenir, cokmez
    root = merkle_root(["a" * 64, "b" * 64, "c" * 64])
    assert len(root) == 64


def test_tamper_report():
    chain = AuditChain()
    chain.append({"a": 1})
    report = audit_chain.tamper_report(chain)
    assert report["chain_valid"] is True
    assert report["record_count"] == 1
    assert "SAGLAM" in report["assessment_tr"]

    chain.records[0]["data"]["a"] = 2
    report2 = audit_chain.tamper_report(chain)
    assert report2["chain_valid"] is False
    assert "KURCALAMA" in report2["assessment_tr"]
