"""Tests for the Agent Trust Registry (P1) — the cross-org trust-anchor layer."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from raucle.audit import Ed25519Signer  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.trust_registry import (  # noqa: E402
    REGISTRY_VERSION,
    RegistryIntegrityError,
    TrustRegistry,
)


def _issuer(name: str) -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer=name)


class TestPublishResolve:
    def test_publish_returns_canonical_key_id(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        assert kid == iss.key_id  # matches cap:v1 key_id derivation

    def test_resolve_active_key(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        rec = reg.resolve(kid)
        assert rec is not None and rec.issuer == "Org A" and not rec.revoked
        assert reg.public_key(kid) == iss.public_key_pem

    def test_unknown_key_is_none_fail_closed(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        assert reg.public_key("deadbeefdeadbeef") is None
        assert reg.resolve("deadbeefdeadbeef") is None


class TestRevocation:
    def test_revoke_fails_closed(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        reg.revoke(kid, reason="compromised")
        assert reg.public_key(kid) is None  # fail-closed
        assert reg.is_revoked(kid)
        # history preserved: the record is still resolvable, marked revoked
        rec = reg.resolve(kid)
        assert rec.revoked and rec.revoked_reason == "compromised"

    def test_republish_reactivates(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        reg.revoke(kid)
        assert reg.public_key(kid) is None
        reg.publish(iss.public_key_pem, issuer="Org A")  # re-register
        assert reg.public_key(kid) == iss.public_key_pem


class TestCrossOrgVerification:
    """The network-effect path: org B verifies org A's token via a shared registry,
    with no prior key exchange between A and B."""

    def test_gate_built_from_registry_verifies_foreign_token(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss_a = _issuer("org-a")
        iss_b = _issuer("org-b")
        reg.publish(iss_a.public_key_pem, issuer="Org A")
        kb = reg.publish(iss_b.public_key_pem, issuer="Org B")

        token_a = iss_a.mint(agent_id="agent:a", tool="t", constraints={})
        gate_b = CapabilityGate(trusted_issuers=reg.as_issuer_map())
        assert gate_b.check(token_a, tool="t", args={}).allowed
        assert kb in reg.as_issuer_map()  # both orgs present

    def test_revoked_issuer_drops_from_issuer_map(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss_a = _issuer("org-a")
        ka = reg.publish(iss_a.public_key_pem, issuer="Org A")
        reg.publish(_issuer("org-b").public_key_pem, issuer="Org B")
        reg.revoke(ka)
        assert ka not in reg.as_issuer_map()
        assert len(reg.as_issuer_map()) == 1


class TestIntegrity:
    def test_signed_registry_authenticates(self, tmp_path):
        op = Ed25519Signer.generate()
        reg = TrustRegistry(tmp_path / "r.jsonl", operator_signer=op)
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        loaded = TrustRegistry.load(tmp_path / "r.jsonl")
        assert loaded.verify_integrity(operator_public_pem=op.public_key_pem())

    def test_header_records_version_and_signed_flag(self, tmp_path):
        op = Ed25519Signer.generate()
        reg = TrustRegistry(tmp_path / "r.jsonl", operator_signer=op)
        assert reg._entries[0]["version"] == REGISTRY_VERSION
        assert reg._entries[0]["signed"] is True

    def test_tampered_chain_detected(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        lines = (tmp_path / "r.jsonl").read_text().splitlines()
        lines[1] = lines[1].replace('"A"', '"EVIL"')
        (tmp_path / "t.jsonl").write_text("\n".join(lines) + "\n")
        with pytest.raises(RegistryIntegrityError):
            TrustRegistry.load(tmp_path / "t.jsonl")

    def test_wrong_operator_key_rejected(self, tmp_path):
        op = Ed25519Signer.generate()
        reg = TrustRegistry(tmp_path / "r.jsonl", operator_signer=op)
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        loaded = TrustRegistry.load(tmp_path / "r.jsonl")
        foreign_pem = Ed25519Signer.generate().public_key_pem()
        with pytest.raises(RegistryIntegrityError):
            loaded.verify_integrity(operator_public_pem=foreign_pem)

    def test_unsigned_registry_chain_only(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")  # no operator signer
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        assert TrustRegistry.load(tmp_path / "r.jsonl").verify_integrity()


class TestPersistenceRoundTrip:
    def test_jsonl_round_trip(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("a")
        kid = reg.publish(iss.public_key_pem, issuer="A", metadata={"org": "acme"})
        text = (tmp_path / "r.jsonl").read_text()
        reg2 = TrustRegistry.from_jsonl(text)
        rec = reg2.resolve(kid)
        assert rec.public_key_pem == iss.public_key_pem
        assert rec.metadata == {"org": "acme"}

    def test_append_persists_across_instances(self, tmp_path):
        path = tmp_path / "r.jsonl"
        reg = TrustRegistry(path)
        k1 = reg.publish(_issuer("a").public_key_pem, issuer="A")
        reg2 = TrustRegistry(path)  # reopen
        k2 = reg2.publish(_issuer("b").public_key_pem, issuer="B")
        reg3 = TrustRegistry(path)
        assert reg3.public_key(k1) and reg3.public_key(k2)


def test_duplicate_issuer_name_rejected(tmp_path):
    """Two different keys cannot hold the same active issuer name (codex re-review
    #3): the issuer string is the identity verifiers match on."""
    reg = TrustRegistry(tmp_path / "r.jsonl")
    reg.publish(_issuer("a").public_key_pem, issuer="Acme Bank")
    dup_pem = _issuer("b").public_key_pem
    with pytest.raises(ValueError, match="collides with an active key"):
        reg.publish(dup_pem, issuer="Acme Bank")  # different key, same name
    # Re-publishing the SAME key under its name is fine.
    same = _issuer("c")
    reg.publish(same.public_key_pem, issuer="Other")
    reg.publish(same.public_key_pem, issuer="Other")  # no raise


def test_issuer_name_reusable_after_revoke(tmp_path):
    reg = TrustRegistry(tmp_path / "r.jsonl")
    k1 = reg.publish(_issuer("a").public_key_pem, issuer="Acme Bank")
    reg.revoke(k1)
    # After revocation the name is free for a new key.
    reg.publish(_issuer("b").public_key_pem, issuer="Acme Bank")  # no raise


def test_duplicate_active_issuer_name_rejected_on_load(tmp_path):
    """A hand-crafted (even operator-signed) registry with duplicate active issuer
    names must be REJECTED on load, not just at publish (codex r3 #1)."""
    op = Ed25519Signer.generate()
    reg = TrustRegistry(tmp_path / "r.jsonl", operator_signer=op)
    reg.publish(_issuer("a").public_key_pem, issuer="Acme Bank")
    # Forge a second active register entry with the SAME name, different key
    # (one issuer instance so key_id matches its own PEM — isolates the
    # uniqueness check from the key_id-invariant check).
    b = _issuer("b")
    reg._write_entry(
        {
            "type": "register",
            "key_id": b.key_id,
            "public_key_pem": b.public_key_pem,
            "issuer": "Acme Bank",
            "created_at": 0,
            "metadata": {},
        }
    )
    with pytest.raises(RegistryIntegrityError, match="duplicate active issuer name"):
        TrustRegistry.load(tmp_path / "r.jsonl")


def test_confusable_issuer_names_rejected(tmp_path):
    """Case/whitespace-confusable names cannot both be active (codex r3 #2)."""
    reg = TrustRegistry(tmp_path / "r.jsonl")
    reg.publish(_issuer("a").public_key_pem, issuer="Acme Bank")
    confusable_pem = _issuer("b").public_key_pem
    with pytest.raises(ValueError, match="collides"):
        reg.publish(confusable_pem, issuer="acme bank ")  # casefold+strip collide


def test_blank_issuer_rejected(tmp_path):
    """A blank/whitespace issuer name is refused (codex r5): an empty identity
    must not be registrable."""
    reg = TrustRegistry(tmp_path / "r.jsonl")
    blank_pub = _issuer("x").public_key_pem
    for bad in ("", "   ", "\t"):
        with pytest.raises(ValueError, match="non-empty"):
            reg.publish(blank_pub, issuer=bad)


def _stale_rollback_fixture(tmp_path):
    """Builds the stale-rollback scenario: operator op publishes issuer 'a',
    a genuine signed pre-revocation snapshot is captured, the key is revoked,
    and the attacker serves the genuine older prefix (codex r7/r8)."""
    op = Ed25519Signer.generate()
    path = tmp_path / "r.jsonl"
    reg = TrustRegistry(path, operator_signer=op)
    kid = reg.publish(_issuer("a").public_key_pem, issuer="org-a")
    stale_text = path.read_text()  # genuine signed snapshot BEFORE revocation
    reg.revoke(kid)
    fresh_head = reg.head()
    stale = TrustRegistry.from_jsonl(stale_text)
    return op, kid, stale, fresh_head


def test_stale_snapshot_detected_via_expected_head(tmp_path):
    """A REAL stale signed prefix — chain-valid, operator-signed, but rolled
    back to before a revocation — is caught when the consumer pins the fresh
    head hash as the freshness anchor (codex r7, hardened per codex r8)."""
    op, kid, stale, fresh_head = _stale_rollback_fixture(tmp_path)
    assert stale.public_key(kid) is not None  # revoked key still resolvable in stale view

    op_pem = op.public_key_pem()
    with pytest.raises(RegistryIntegrityError, match="stale"):
        stale.verify_integrity(operator_public_pem=op_pem, expected_head_hash=fresh_head["hash"])


def test_stale_snapshot_detected_via_min_index(tmp_path):
    """min_index at the fresh head is rejected for the rolled-back prefix."""
    _op, _kid, stale, fresh_head = _stale_rollback_fixture(tmp_path)
    with pytest.raises(RegistryIntegrityError, match="stale"):
        stale.verify_integrity(min_index=fresh_head["index"])


def test_stale_snapshot_detected_via_max_age(tmp_path):
    """max_age rejects an old (pre-revocation) head."""
    _op, _kid, stale, fresh_head = _stale_rollback_fixture(tmp_path)
    with pytest.raises(RegistryIntegrityError, match="stale"):
        stale.verify_integrity(max_age_seconds=1, now=fresh_head["ts"] + 10_000)


def test_stale_snapshot_verifies_without_anchor(tmp_path):
    """Without any freshness anchor it verifies fine — that's the gap the
    anchor exists to stop (the original exploit is preserved as evidence)."""
    op, kid, stale, _fresh_head = _stale_rollback_fixture(tmp_path)
    # And the revoked key is still resolvable in the stale view — the exploit.
    assert stale.public_key(kid) is not None
    assert stale.verify_integrity(operator_public_pem=op.public_key_pem())


def _unverified_snapshot(tmp_path):
    """A freshly published signed registry loaded without any verification."""
    op = Ed25519Signer.generate()
    path = tmp_path / "r.jsonl"
    reg = TrustRegistry(path, operator_signer=op)
    reg.publish(_issuer("a").public_key_pem, issuer="org-a")
    loaded = TrustRegistry.load(path)
    return reg, loaded


def test_freshness_head_hash_enforced_without_operator_key(tmp_path):
    """expected_head_hash must bite even without the operator key
    (codex r8 MEDIUM): the early unauthenticated return used to skip it."""
    _reg, loaded = _unverified_snapshot(tmp_path)
    with pytest.raises(RegistryIntegrityError, match="stale"):
        loaded.verify_integrity(expected_head_hash="f" * 64)  # no operator key


def test_freshness_min_index_enforced_without_operator_key(tmp_path):
    """min_index must bite even without the operator key (codex r8 MEDIUM)."""
    _reg, loaded = _unverified_snapshot(tmp_path)
    with pytest.raises(RegistryIntegrityError, match="stale"):
        loaded.verify_integrity(min_index=999)


def test_freshness_max_age_enforced_without_operator_key(tmp_path):
    """max_age must bite even without the operator key (codex r8 MEDIUM)."""
    reg, loaded = _unverified_snapshot(tmp_path)
    old_head = reg.head()["ts"]
    with pytest.raises(RegistryIntegrityError, match="stale"):
        loaded.verify_integrity(max_age_seconds=1, now=old_head + 10_000)


def test_future_dated_head_rejected(tmp_path):
    """A head timestamped in the future must not count as eternally fresh
    (codex r8 LOW): ref - ts would be negative and never exceed max_age."""
    op = Ed25519Signer.generate()
    path = tmp_path / "r.jsonl"
    reg = TrustRegistry(path, operator_signer=op)
    reg.publish(_issuer("a").public_key_pem, issuer="org-a")
    head_ts = reg.head()["ts"]
    op_pem = op.public_key_pem()
    with pytest.raises(RegistryIntegrityError, match="future"):
        reg.verify_integrity(
            operator_public_pem=op_pem,
            max_age_seconds=3600,
            now=head_ts - 10_000,  # head is 10000s in this verifier's future
        )
