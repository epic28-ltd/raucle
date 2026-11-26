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
        assert rec is not None
        assert rec.issuer == "Org A"
        assert not rec.revoked
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
        assert rec.revoked
        assert rec.revoked_reason == "compromised"

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
        assert reg3.public_key(k1)
        assert reg3.public_key(k2)


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


class TestRetirement:
    """X3 slice 3: key retirement, the registry's rotation transition state.

    A RETIRED key is not revoked: revocation is the trust cut (fail-closed,
    the key stops resolving); retirement only ends the key's tenure as the
    ACTIVE holder of its issuer name, so receipts the retired key signed
    keep verifying through the registry. The dual-key window a rotation
    needs (retired + active under one issuer) is exactly this state.
    """

    def test_retire_keeps_key_verifiable_and_marks_record(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")

        reg.retire(kid, reason="operator key rotation")

        # Retired is NOT revoked: the key still resolves so the receipts it
        # signed keep verifying. The trust cut (revoke) is a separate act.
        assert reg.public_key(kid) == iss.public_key_pem
        assert reg.is_retired(kid)
        assert not reg.is_revoked(kid)
        rec = reg.resolve(kid)
        assert rec is not None
        assert rec.retired
        assert rec.retired_reason == "operator key rotation"
        assert not rec.revoked

    def test_retired_key_stays_in_issuer_map_for_verification(self, tmp_path):
        """Old tokens/receipts keep verifying: retirement does not remove
        the key from the verifier's issuer map (revocation does)."""
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss_old = _issuer("org-a")
        old_kid = reg.publish(iss_old.public_key_pem, issuer="Org A")
        iss_new = _issuer("org-a")
        new_kid = reg.publish(iss_new.public_key_pem, issuer="Org A v2")

        reg.retire(old_kid, reason="rotation")

        assert old_kid in reg.as_issuer_map()
        assert new_kid in reg.as_issuer_map()

    def test_retire_unknown_key_refuses(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        with pytest.raises(ValueError, match="not registered"):
            reg.retire("deadbeefdeadbeef", reason="nothing to retire")

    def test_publish_new_key_under_freed_name_after_retire(self, tmp_path):
        """Rotation's re-registration: retire the old key, then publish the
        successor under the SAME issuer name. The retired key no longer
        competes for the name (that is the transition), and the registry
        holds BOTH keys: retired + active."""
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss_old = _issuer("org-a")
        old_kid = reg.publish(iss_old.public_key_pem, issuer="raucle-gateway")
        reg.retire(old_kid, reason="rotation")

        iss_new = _issuer("org-a")
        new_kid = reg.publish(iss_new.public_key_pem, issuer="raucle-gateway")

        assert new_kid != old_kid
        # The dual-key window: both resolve, only the successor is active.
        assert reg.public_key(old_kid) == iss_old.public_key_pem
        assert reg.public_key(new_kid) == iss_new.public_key_pem
        assert reg.is_retired(old_kid)
        assert not reg.is_retired(new_kid)
        active = [r for r in reg.records() if not r.retired and not r.revoked]
        assert [r.key_id for r in active] == [new_kid]
        assert active[0].issuer == "raucle-gateway"

    def test_publish_under_a_name_held_active_still_refuses(self, tmp_path):
        """Retirement is the ONLY way a second key takes an issuer name:
        while the old key is still active, the impersonation control holds."""
        reg = TrustRegistry(tmp_path / "r.jsonl")
        reg.publish(_issuer("org-a").public_key_pem, issuer="Org A")
        with pytest.raises(ValueError, match="collides"):
            reg.publish(_issuer("org-a").public_key_pem, issuer="org a")

    def test_registry_with_retired_and_active_reloads_and_verifies(self, tmp_path):
        """The post-rotation registry is loadable: issuer-name uniqueness
        counts only ACTIVE keys, and the whole log verifies."""
        path = tmp_path / "r.jsonl"
        op = Ed25519Signer.generate()
        reg = TrustRegistry(path, operator_signer=op)
        old_kid = reg.publish(_issuer("org-a").public_key_pem, issuer="raucle-gateway")
        reg.retire(old_kid, reason="rotation")
        new_kid = reg.publish(_issuer("org-b").public_key_pem, issuer="raucle-gateway")

        loaded = TrustRegistry.load(path)
        loaded.verify_integrity(operator_public_pem=op.public_key_pem())
        assert loaded.is_retired(old_kid)
        assert not loaded.is_retired(new_kid)
        assert loaded.public_key(old_kid) is not None

    def test_retire_is_append_only_history_preserved(self, tmp_path):
        path = tmp_path / "r.jsonl"
        reg = TrustRegistry(path)
        kid = reg.publish(_issuer("org-a").public_key_pem, issuer="Org A")
        before = (path.read_text(encoding="utf-8")).splitlines()

        reg.retire(kid, reason="rotation")

        after = path.read_text(encoding="utf-8").splitlines()
        assert len(after) == len(before) + 1
        import json as _json

        entry = _json.loads(after[-1])
        assert entry["type"] == "retire"
        assert entry["key_id"] == kid
        assert entry["reason"] == "rotation"

    def test_republish_after_retire_reactivates(self, tmp_path):
        """Symmetric with revocation: a fresh register entry supersedes the
        retirement (auditable in history)."""
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        reg.retire(kid, reason="rotation")
        assert reg.is_retired(kid)
        reg.publish(iss.public_key_pem, issuer="Org A")
        assert not reg.is_retired(kid)

    def test_retire_then_revoke_fails_closed(self, tmp_path):
        """The separate acts compose: retirement keeps the retired key
        verifiable; a LATER revocation cuts it (old receipts stop verifying)."""
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        reg.retire(kid, reason="rotation")
        assert reg.public_key(kid) is not None

        reg.revoke(kid, reason="compromised after rotation")

        assert reg.public_key(kid) is None
        rec = reg.resolve(kid)
        assert rec is not None
        assert rec.retired and rec.revoked


def _read_entries(path) -> list[dict]:
    import json as _json

    return [
        _json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _write_entries(path, entries: list[dict]) -> None:
    import json as _json

    path.write_text(
        "\n".join(_json.dumps(e, ensure_ascii=False, separators=(",", ":")) for e in entries)
        + "\n",
        encoding="utf-8",
    )


def _key_id_of(public_pem: bytes) -> str:
    """The canonical key_id for a public key PEM (first 16 hex of SHA-256)."""
    import hashlib as _hl

    return _hl.sha256(public_pem).hexdigest()[:16]


def _rechain(entries: list[dict], from_position: int) -> None:
    """Recompute index, prev_hash and hash forward from a position: exactly
    what a tamperer CAN do with the public algorithm (no secret needed),
    short of the operator signature that a signed registry carries."""
    from raucle.audit import _canonical_json, _sha256_hex

    prev = entries[from_position - 1]["hash"]
    for i in range(from_position, len(entries)):
        e = entries[i]
        e["index"] = i
        e["prev_hash"] = prev
        body = {
            k: v
            for k, v in e.items()
            if k not in ("hash", "operator_sig", "operator_pq_key_id", "operator_pq_sig")
        }
        e["hash"] = _sha256_hex(_canonical_json(body))
        prev = e["hash"]


class TestConstructorVerifiesIntegrity:
    """Q10 (a second external review of the main branch, P0): the
    CONSTRUCTOR path verifies integrity by default.

    The gateway boot builds the caller issuer map by constructing the
    registry DIRECTLY from its path, so a parseable-but-tampered history
    (reordered entries, swapped key material) loaded unverified; only
    ``load()`` and ``from_jsonl()`` checked. The constructor now refuses
    with the same named error, and the operator-key-registry boot guard
    refuses the tampered-history class too.
    """

    def _signed_registry(self, tmp_path):
        op = Ed25519Signer.generate()
        path = tmp_path / "r.jsonl"
        reg = TrustRegistry(path, operator_signer=op)
        iss_a = _issuer("org-a")
        iss_b = _issuer("org-b")
        reg.publish(iss_a.public_key_pem, issuer="Org A")
        reg.publish(iss_b.public_key_pem, issuer="Org B")
        return path, op, iss_a, iss_b

    def test_constructor_refuses_reordered_entries(self, tmp_path):
        """Reordering two signed entries breaks the index/prev_hash chain:
        the constructor refuses with the named error and the exact mechanism."""
        path, _op, _iss_a, _iss_b = self._signed_registry(tmp_path)
        entries = _read_entries(path)
        entries[1], entries[2] = entries[2], entries[1]
        _write_entries(path, entries)

        with pytest.raises(RegistryIntegrityError) as excinfo:
            TrustRegistry(path)
        assert "index mismatch" in str(excinfo.value)
        with pytest.raises(RegistryIntegrityError):
            TrustRegistry.load(path)

    def test_constructor_refuses_swapped_key_material_despite_rechained_hashes(self, tmp_path):
        """The attacker-grade swap: new key material, a re-derived key_id, and
        the whole chain recomputed (all doable without a secret). The operator
        signature is over the ORIGINAL entry hash, so a deployment whose
        authorisation surface holds the operator key refuses it (a signed
        registry without the operator key is the documented integrity-only
        model)."""
        path, op, iss_a, _iss_b = self._signed_registry(tmp_path)
        entries = _read_entries(path)
        attacker = Ed25519Signer.generate()
        entries[1]["public_key_pem"] = attacker.public_key_pem().decode()
        entries[1]["key_id"] = _key_id_of(attacker.public_key_pem())
        _rechain(entries, from_position=1)
        _write_entries(path, entries)

        with pytest.raises(RegistryIntegrityError) as excinfo:
            TrustRegistry(path, operator_signer=op)
        assert "operator signature invalid" in str(excinfo.value)
        # A SIGNED registry built WITHOUT the operator key stays on the
        # documented integrity-only model: construction passes, the chain
        # verifies, but the source is not authenticated (the operator key
        # is what authenticates a local file).
        assert TrustRegistry(path).verify_integrity()
        # The honest key never resolved from the tampered file.
        reg_ok = TrustRegistry(tmp_path / "clean.jsonl")
        reg_ok.publish(iss_a.public_key_pem, issuer="Org A")
        assert reg_ok.resolve(iss_a.key_id) is not None

    def test_constructor_refuses_swapped_key_material_unsigned(self, tmp_path):
        """Unsigned registry, tampered entry WITHOUT rechain: the entry hash
        no longer matches its content (the base tamper-evidence class)."""
        path, _op, _iss_a, _iss_b = self._signed_registry(tmp_path)
        entries = _read_entries(path)
        for e in entries:
            e.pop("operator_sig", None)
            e.pop("operator_pq_key_id", None)
            e.pop("operator_pq_sig", None)
        entries[1]["public_key_pem"] = Ed25519Signer.generate().public_key_pem().decode()
        _write_entries(path, entries)

        with pytest.raises(RegistryIntegrityError) as excinfo:
            TrustRegistry(path)
        assert "hash mismatch" in str(excinfo.value)

    def test_unsigned_rechained_swap_caught_by_key_id_binding(self, tmp_path):
        """Unsigned registry WITH recomputed hashes: the codex #6 binding
        (key_id is the digest of its own published PEM) still refuses the
        swapped key material - the resolution surface cannot be forked."""
        path, _op, _iss_a, _iss_b = self._signed_registry(tmp_path)
        entries = _read_entries(path)
        for e in entries:
            e.pop("operator_sig", None)
        entries[1]["public_key_pem"] = Ed25519Signer.generate().public_key_pem().decode()
        _rechain(entries, from_position=1)
        _write_entries(path, entries)

        with pytest.raises(RegistryIntegrityError) as excinfo:
            TrustRegistry(path)
        assert "key_id does not match" in str(excinfo.value)

    def test_constructor_loads_the_honest_clean_registry(self, tmp_path):
        path, _op, iss_a, iss_b = self._signed_registry(tmp_path)
        reg = TrustRegistry(path)
        assert reg.public_key(iss_a.key_id) == iss_a.public_key_pem
        assert reg.public_key(iss_b.key_id) == iss_b.public_key_pem
        assert set(reg.as_issuer_map()) == {iss_a.key_id, iss_b.key_id}

    def test_verify_false_is_the_named_escape_hatch(self, tmp_path):
        """The one escape hatch is explicit and named (verify=False) for
        authoring/repair tooling only: it constructs the tampered file and
        leaves the refusal one verify_integrity() call away."""
        path, _op, _iss_a, _iss_b = self._signed_registry(tmp_path)
        entries = _read_entries(path)
        entries[1]["public_key_pem"] = Ed25519Signer.generate().public_key_pem().decode()
        _write_entries(path, entries)

        reg = TrustRegistry(path, verify=False)
        with pytest.raises(RegistryIntegrityError):
            reg.verify_integrity()


class TestGatewayIssuerMapConstructionSite:
    """Q10 item (5): every construction site is verified. The gateway boot
    issuer-map path (gateway._ensure_caller_gate constructing the registry
    DIRECTLY from its path) refuses a tampered registry into fail-closed
    fallback instead of folding attacker-issued keys into caller auth."""

    def _config(self, tmp_path, *, registry_path):
        from raucle.gateway import GatewayConfig

        return GatewayConfig(
            host="127.0.0.1",
            signer_backend="local",
            policy_file="",
            signer_key_path=str(tmp_path / "gateway-signing-key.pem"),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            receipt_store_dir="",
            audit_chain=str(tmp_path / "audit.jsonl"),
            audit_persist=True,
            audit_log_file=str(tmp_path / "gateway-audit.jsonl"),
            registry_path=str(registry_path),
            operator_key_registry="",
        )

    def test_tampered_registry_never_reaches_the_issuer_map(self, tmp_path):
        """A registry whose register entry carries ATTACKER key material (the
        entry hash left stale by the swap) is refused at the constructor: the
        caller gate falls back to the gateway's own issuer and the attacker's
        token does not verify."""
        from raucle.capability import CapabilityIssuer
        from raucle.gateway import RaucleGateway

        path = tmp_path / "caller-registry.jsonl"
        org_a = _issuer("org-a")
        TrustRegistry(path).publish(org_a.public_key_pem, issuer="Org A")

        attacker = CapabilityIssuer.generate(issuer="Org A")
        entries = _read_entries(path)
        entries[1]["public_key_pem"] = attacker.public_key_pem
        entries[1]["key_id"] = attacker.key_id
        _write_entries(path, entries)  # NO rechain: the hash is left stale

        config = self._config(tmp_path, registry_path=path)
        gate = RaucleGateway(config)._ensure_caller_gate()

        attacker_token = attacker.mint(
            agent_id="agent:evil.bot", tool="transfer_funds", constraints={}
        )
        decision = gate.check(
            attacker_token, tool="transfer_funds", args={}, agent_id="agent:evil.bot"
        )
        assert not decision.allowed

    def test_honest_registry_still_supplies_the_issuer_map(self, tmp_path):
        """The clean path keeps working end to end: a published org's token
        verifies through the boot issuer map after constructor verification."""
        from raucle.gateway import RaucleGateway

        path = tmp_path / "caller-registry.jsonl"
        reg = TrustRegistry(path)
        org_a = _issuer("org-a")
        reg.publish(org_a.public_key_pem, issuer="Org A")

        config = self._config(tmp_path, registry_path=path)
        gate = RaucleGateway(config)._ensure_caller_gate()
        token = org_a.mint(agent_id="agent:a", tool="t", constraints={})
        assert gate.check(token, tool="t", args={}, agent_id="agent:a").allowed


def test_append_write_failure_rolls_back_file_and_memory(tmp_path, monkeypatch):
    """A partial append failure must not advance the in-memory trust head."""
    import builtins

    path = tmp_path / "r.jsonl"
    reg = TrustRegistry(path)
    before_bytes = path.read_bytes()
    before_entries = list(reg._entries)
    before_head = reg.head()
    real_open = builtins.open

    class PartialWriter:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.handle.close()

        def write(self, data):
            self.handle.write(data[: max(1, len(data) // 2)])
            self.handle.flush()
            raise OSError("simulated disk full")

        def __getattr__(self, name):
            return getattr(self.handle, name)

    def failing_open(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if mode == "a+b":
            return PartialWriter(handle)
        return handle

    monkeypatch.setattr(builtins, "open", failing_open)
    with pytest.raises(OSError, match="simulated disk full"):
        reg.publish(_issuer("failed").public_key_pem, issuer="Failed")

    assert path.read_bytes() == before_bytes
    assert reg._entries == before_entries
    assert reg.head() == before_head

    monkeypatch.setattr(builtins, "open", real_open)
    kid = reg.publish(_issuer("recovered").public_key_pem, issuer="Recovered")
    assert reg.public_key(kid) is not None
    assert TrustRegistry(path).public_key(kid) is not None


def test_append_fsync_failure_rolls_back_file_and_memory(tmp_path, monkeypatch):
    """A failed durability barrier must be treated as a failed append."""
    import raucle.trust_registry as trust_registry_module

    path = tmp_path / "r.jsonl"
    reg = TrustRegistry(path)
    before_bytes = path.read_bytes()
    before_entries = list(reg._entries)
    before_head = reg.head()
    real_fsync = trust_registry_module.os.fsync
    calls = 0

    def fail_first_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(trust_registry_module.os, "fsync", fail_first_fsync)
    with pytest.raises(OSError, match="simulated fsync failure"):
        reg.publish(_issuer("failed-fsync").public_key_pem, issuer="Failed Fsync")

    assert calls == 2
    assert path.read_bytes() == before_bytes
    assert reg._entries == before_entries
    assert reg.head() == before_head
