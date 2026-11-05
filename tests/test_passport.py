"""Tests for the agent passport (P3) — portable, registry-anchored identity."""

from __future__ import annotations

import copy

import pytest

pytest.importorskip("cryptography")

from raucle.audit import Ed25519Signer  # noqa: E402
from raucle.passport import (  # noqa: E402
    PASSPORT_VERSION,
    AgentPassport,
    issue_passport,
    verify_passport,
)
from raucle.provenance import AgentIdentity  # noqa: E402
from raucle.trust_registry import TrustRegistry  # noqa: E402


@pytest.fixture
def issued(tmp_path):
    """An org publishes its issuer key and issues a passport for its agent."""
    org_signer = Ed25519Signer.generate()
    reg = TrustRegistry(tmp_path / "reg.jsonl", operator_signer=Ed25519Signer.generate())
    reg.publish(org_signer.public_key_pem().decode(), issuer="Org X")
    agent = AgentIdentity.generate(
        agent_id="agent:billing.bot",
        allowed_models=["claude-sonnet-4-6"],
        allowed_tools=["lookup_invoice", "send_email"],
    )
    passport = issue_passport(
        agent.statement, issuer_signer=org_signer, issuer="Org X", ttl_seconds=3600
    )
    return reg, org_signer, agent, passport


def test_valid_passport_verifies_via_registry(issued):
    reg, _signer, _agent, passport = issued
    v = verify_passport(passport.to_dict(), registry=reg)
    assert v.valid
    assert v.agent_id == "agent:billing.bot"
    assert v.allowed_tools == ["lookup_invoice", "send_email"]
    assert v.issuer == "Org X"


def test_passport_round_trip(tmp_path, issued):
    reg, _signer, _agent, passport = issued
    path = tmp_path / "agent.passport.json"
    passport.save(path)
    reloaded = AgentPassport.load(path)
    assert verify_passport(reloaded.to_dict(), registry=reg).valid
    assert reloaded.body()["version"] == PASSPORT_VERSION


def test_revoked_issuer_rejected(issued):
    reg, _signer, _agent, passport = issued
    reg.revoke(passport.issuer_key_id, reason="org key rotated")
    v = verify_passport(passport.to_dict(), registry=reg)
    assert not v.valid
    assert "revoked" in v.reason


def test_unknown_issuer_rejected(tmp_path, issued):
    _reg, _signer, _agent, passport = issued
    other = TrustRegistry(tmp_path / "other.jsonl")
    other.publish(Ed25519Signer.generate().public_key_pem().decode(), issuer="someone else")
    v = verify_passport(passport.to_dict(), registry=other)
    assert not v.valid
    assert "unknown" in v.reason


def test_tampered_statement_rejected(tmp_path, issued):
    reg, _signer, _agent, passport = issued
    bad = copy.deepcopy(passport.to_dict())
    bad["statement"]["allowed_tools"].append("transfer_funds")  # privilege escalation attempt
    assert not verify_passport(bad, registry=reg).valid


def test_expired_passport_rejected(tmp_path):
    org_signer = Ed25519Signer.generate()
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    reg.publish(org_signer.public_key_pem().decode(), issuer="Org X")
    agent = AgentIdentity.generate(agent_id="agent:x")
    passport = issue_passport(
        agent.statement, issuer_signer=org_signer, issuer="Org X", ttl_seconds=1
    )
    v = verify_passport(passport.to_dict(), registry=reg, now=passport.expires_at + 5)
    assert not v.valid
    assert "expired" in v.reason


def test_unknown_version_rejected(issued):
    reg, _signer, _agent, passport = issued
    d = passport.to_dict()
    d["version"] = "agent-passport/v99"
    assert not verify_passport(d, registry=reg).valid


def test_no_expiry_passport_is_long_lived(tmp_path):
    org_signer = Ed25519Signer.generate()
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    reg.publish(org_signer.public_key_pem().decode(), issuer="Org X")
    agent = AgentIdentity.generate(agent_id="agent:x")
    passport = issue_passport(agent.statement, issuer_signer=org_signer, issuer="Org X")
    assert passport.expires_at is None
    assert verify_passport(passport.to_dict(), registry=reg, now=10**12).valid


class TestCLI:
    def test_issue_then_verify(self, tmp_path):
        import json

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from raucle.cli import main

        # Org signer key on disk
        k = Ed25519PrivateKey.generate()
        signer_pem = tmp_path / "org.key.pem"
        signer_pem.write_bytes(
            k.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pub_pem = (
            k.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        # Registry with the org's issuer key published
        reg = TrustRegistry(tmp_path / "reg.jsonl")
        reg.publish(pub_pem, issuer="Org X")

        # Agent statement on disk
        agent = AgentIdentity.generate(agent_id="agent:cli.bot", allowed_tools=["t1"])
        stmt = tmp_path / "stmt.json"
        stmt.write_text(json.dumps(agent.statement.to_dict()))

        out = tmp_path / "agent.passport.json"
        rc = main(
            [
                "passport",
                "issue",
                str(stmt),
                "--issuer-key",
                str(signer_pem),
                "--issuer",
                "Org X",
                "--out",
                str(out),
            ]
        )
        assert rc == 0
        assert out.exists()

        rc2 = main(["passport", "verify", str(out), "--registry", str(tmp_path / "reg.jsonl")])
        assert rc2 == 0

    def test_verify_unknown_issuer_fails(self, tmp_path):
        import json

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from raucle.cli import main

        k = Ed25519PrivateKey.generate()
        signer_pem = tmp_path / "org.key.pem"
        signer_pem.write_bytes(
            k.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        agent = AgentIdentity.generate(agent_id="agent:x")
        stmt = tmp_path / "stmt.json"
        stmt.write_text(json.dumps(agent.statement.to_dict()))
        out = tmp_path / "p.json"
        main(
            [
                "passport",
                "issue",
                str(stmt),
                "--issuer-key",
                str(signer_pem),
                "--issuer",
                "X",
                "--out",
                str(out),
            ]
        )

        # Registry WITHOUT the org's key
        empty = TrustRegistry(tmp_path / "reg.jsonl")
        empty.publish(
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode(),
            issuer="other",
        )
        rc = main(["passport", "verify", str(out), "--registry", str(tmp_path / "reg.jsonl")])
        assert rc == 1  # invalid passport -> nonzero


def test_issuer_impersonation_rejected(tmp_path):
    """A registered org cannot sign a passport claiming a DIFFERENT issuer name
    than the registry's authoritative record (codex #2)."""
    org_signer = Ed25519Signer.generate()
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    reg.publish(org_signer.public_key_pem().decode(), issuer="bank-a")  # registry: bank-a
    agent = AgentIdentity.generate(agent_id="agent:x")
    # Same key, but passport claims to be "evil-corp" pretending... actually claims
    # to be a bank it is not: issue with issuer="Megabank" while registry says bank-a.
    passport = issue_passport(agent.statement, issuer_signer=org_signer, issuer="Megabank")
    v = verify_passport(passport.to_dict(), registry=reg)
    assert not v.valid
    assert "issuer mismatch" in v.reason


def test_malformed_passport_fails_closed(tmp_path):
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    reg.publish(Ed25519Signer.generate().public_key_pem().decode(), issuer="X")
    for bad in [
        {},
        {"statement": "not-a-dict", "issuer_key_id": "x"},
        {"issuer_key_id": 123},
        "nonsense",
    ]:
        v = verify_passport(bad, registry=reg)
        assert not v.valid  # never raises


def test_string_expiry_fails_closed_not_crash(tmp_path):
    """A registry-valid issuer signing a passport whose expires_at is a numeric
    STRING must yield an invalid verdict, not a TypeError at the ts comparison
    (codex r9): fail-closed includes weird-but-signed inputs."""
    org_signer = Ed25519Signer.generate()
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    reg.publish(org_signer.public_key_pem().decode(), issuer="Org X")
    agent = AgentIdentity.generate(agent_id="agent:x")
    passport = issue_passport(agent.statement, issuer_signer=org_signer, issuer="Org X")
    # Re-sign a body with a string expiry — a hostile-but-registered issuer.
    from raucle.audit import _canonical_json
    from raucle.passport import _b64

    passport.expires_at = "9999999999"
    passport.issuer_signature = _b64(org_signer.sign(_canonical_json(passport.body())))
    v = verify_passport(passport.to_dict(), registry=reg, now=2)
    assert not v.valid
    assert "expires_at" in v.reason  # never raises # never raises
