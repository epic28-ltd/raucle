"""Tests for capability-based agent permissions (v0.10.0)."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("cryptography")

from raucle.capability import (
    Capability,
    CapabilityGate,
    CapabilityIssuer,
)


def _issuer(name: str = "platform.example") -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer=name)


def _gate(issuer: CapabilityIssuer) -> CapabilityGate:
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


# ---------------------------------------------------------------------------
# Minting + verification
# ---------------------------------------------------------------------------


def test_mint_produces_valid_token():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    assert cap.token_id.startswith("cap:")
    assert cap.signature
    assert cap.expires_at > cap.issued_at


def test_gate_allows_call_satisfying_constraints():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    decision = _gate(iss).check(
        cap, tool="transfer_funds", args={"to": "alice@example", "amount": 50}
    )
    assert decision.allowed, decision.reason


def test_gate_denies_call_violating_max_value():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    decision = _gate(iss).check(cap, tool="transfer_funds", args={"amount": 500})
    assert decision.denied
    assert "max_value" in decision.reason


def test_gate_denies_forbidden_recipient():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="send_email",
        constraints={"forbidden_values": {"to": ["attacker@evil.example"]}},
    )
    decision = _gate(iss).check(
        cap, tool="send_email", args={"to": "attacker@evil.example", "body": "hi"}
    )
    assert decision.denied


def test_gate_denies_wrong_tool():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:billing", tool="transfer_funds")
    decision = _gate(iss).check(cap, tool="delete_user", args={})
    assert decision.denied
    assert "tool" in decision.reason


def test_gate_denies_expired_token():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t", ttl_seconds=1)
    time.sleep(1.1)
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.denied
    assert "expired" in decision.reason


def test_gate_denies_not_yet_valid_token():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t", not_before_offset=120)
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.denied
    assert "not yet valid" in decision.reason


def test_gate_denies_unknown_issuer():
    iss_a = _issuer("a.example")
    iss_b = _issuer("b.example")
    cap = iss_a.mint(agent_id="agent:x", tool="t")
    gate = CapabilityGate(trusted_issuers={iss_b.key_id: iss_b.public_key_pem})
    decision = gate.check(cap, tool="t", args={})
    assert decision.denied
    assert "unknown key_id" in decision.reason


def test_gate_denies_tampered_signature():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t", constraints={"max_value": {"amount": 100}})
    # Mutate the constraints after signing.
    cap.constraints = {"max_value": {"amount": 999_999}}
    decision = _gate(iss).check(cap, tool="t", args={"amount": 500})
    assert decision.denied


def test_gate_denies_tampered_token_id():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t")
    cap.token_id = "cap:" + "f" * 24
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.denied


# ---------------------------------------------------------------------------
# Attenuation
# ---------------------------------------------------------------------------


def test_attenuation_narrows_max_value():
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 1000}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 50}})
    assert child.parent_id == parent.token_id
    assert child.constraints["max_value"]["amount"] == 50
    # Parent's bound stays intact on the original token.
    assert parent.constraints["max_value"]["amount"] == 1000


def test_attenuation_cannot_broaden_max_value():
    """Asking for a higher bound silently keeps the tighter parent bound."""
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:x",
        tool="t",
        constraints={"max_value": {"amount": 100}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 1000}})
    # Merge picks the smaller bound — broadening is impossible.
    assert child.constraints["max_value"]["amount"] == 100


def test_attenuation_cannot_outlive_parent():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:x", tool="t", ttl_seconds=10)
    with pytest.raises(ValueError, match="outlive"):
        iss.attenuate(parent, narrower_ttl_seconds=10_000)


def test_attenuation_narrower_agent_id_must_be_subscope():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:billing", tool="t")
    # Valid sub-scope:
    child = iss.attenuate(parent, narrower_agent_id="agent:billing.invoice")
    assert child.agent_id == "agent:billing.invoice"
    # Invalid (sibling, not sub-scope):
    with pytest.raises(ValueError, match="sub-scope"):
        iss.attenuate(parent, narrower_agent_id="agent:auth")


def test_attenuated_child_gate_check_inherits_parent_constraints():
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:x",
        tool="transfer_funds",
        constraints={"forbidden_values": {"to": ["attacker@evil.example"]}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 100}})
    decision = _gate(iss).check(
        child,
        tool="transfer_funds",
        args={"to": "attacker@evil.example", "amount": 50},
    )
    assert decision.denied
    assert "forbidden_values" in decision.reason


def test_attenuation_intersects_allowed_values():
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:x",
        tool="t",
        constraints={"allowed_values": {"currency": ["USD", "EUR", "GBP"]}},
    )
    child = iss.attenuate(
        parent, extra_constraints={"allowed_values": {"currency": ["EUR", "JPY"]}}
    )
    # Intersection only — JPY drops out, USD/GBP drop out.
    assert child.constraints["allowed_values"]["currency"] == ["EUR"]


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


def test_gate_verifies_full_chain_when_resolver_supplied():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:x", tool="t")
    child = iss.attenuate(parent)

    by_id = {parent.token_id: parent, child.token_id: child}
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        parent_resolver=by_id.get,
    )
    decision = gate.check(child, tool="t", args={})
    assert decision.allowed
    assert parent.token_id in decision.chain


def test_chain_verification_rejects_missing_parent():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:x", tool="t")
    child = iss.attenuate(parent)
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        parent_resolver=lambda _id: None,
    )
    decision = gate.check(child, tool="t", args={})
    assert decision.denied
    assert "unresolved parent" in decision.reason


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_token_roundtrips_through_disk(tmp_path):
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:x",
        tool="t",
        constraints={"forbidden_values": {"to": ["bad@example"]}},
    )
    path = tmp_path / "tok.json"
    cap.save(path)
    loaded = Capability.load(path)
    assert loaded.token_id == cap.token_id
    assert loaded.signature == cap.signature
    decision = _gate(iss).check(loaded, tool="t", args={"to": "good@example"})
    assert decision.allowed


def test_policy_proof_hash_round_trips():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:x",
        tool="t",
        policy_proof_hash="sha256:" + "a" * 64,
    )
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.allowed
    assert cap.policy_proof_hash == "sha256:" + "a" * 64


# ---------------------------------------------------------------------------
# FIX 2 — Strict proof-enforced mint mode
# ---------------------------------------------------------------------------


pytest.importorskip("z3", reason="strict-mint tests need the [proof] extra")


def _proven_proof(
    grammar_hash: str = "sha256:" + "g" * 64,
    policy_hash: str = "sha256:" + "p" * 64,
):
    from raucle.prove import ProofResult

    return ProofResult(
        status="PROVEN",
        prover="raucle.json-schema/v1",
        prover_version="0.9.0",
        grammar_hash=grammar_hash,
        policy_hash=policy_hash,
    )


def _undecided_proof():
    from raucle.prove import ProofResult

    return ProofResult(
        status="UNDECIDED",
        prover="raucle.json-schema/v1",
        prover_version="0.9.0",
        grammar_hash="sha256:" + "g" * 64,
        policy_hash="sha256:" + "p" * 64,
        notes=["solver timeout"],
    )


def _refuted_proof():
    from raucle.prove import ProofResult

    return ProofResult(
        status="REFUTED",
        prover="raucle.json-schema/v1",
        prover_version="0.9.0",
        grammar_hash="sha256:" + "g" * 64,
        policy_hash="sha256:" + "p" * 64,
        counterexample={"amount": 99999},
    )


def test_default_mode_unchanged():
    """``require_proof=False`` (default) preserves existing behaviour:
    mint with no proof_result still succeeds."""
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t")
    assert cap.signature
    assert cap.policy_proof_hash is None
    assert cap.grammar_hash is None
    assert cap.policy_hash is None


def test_strict_mint_refuses_without_proof():
    from raucle.errors import PolicyUnproven

    iss = CapabilityIssuer.generate(issuer="p.x", require_proof=True)
    assert iss.require_proof is True
    with pytest.raises(PolicyUnproven, match="requires a ProofResult"):
        iss.mint(agent_id="agent:x", tool="t")


def test_strict_mint_refuses_undecided():
    from raucle.errors import PolicyUnproven

    iss = CapabilityIssuer.generate(issuer="p.x", require_proof=True)
    proof = _undecided_proof()
    with pytest.raises(PolicyUnproven, match="PROVEN.*UNDECIDED"):
        iss.mint(agent_id="agent:x", tool="t", proof_result=proof)


def test_strict_mint_refuses_refuted():
    from raucle.errors import PolicyUnproven

    iss = CapabilityIssuer.generate(issuer="p.x", require_proof=True)
    proof = _refuted_proof()
    with pytest.raises(PolicyUnproven, match="PROVEN.*REFUTED"):
        iss.mint(agent_id="agent:x", tool="t", proof_result=proof)


def test_strict_mint_binds_proven_hashes_into_token():
    """The cited proof's content-address, grammar_hash, and policy_hash
    all end up bound in the capability's signed body — visible to any
    downstream verifier."""
    iss = CapabilityIssuer.generate(issuer="p.x", require_proof=True)
    proof = _proven_proof()
    cap = iss.mint(agent_id="agent:x", tool="t", proof_result=proof)
    assert cap.policy_proof_hash == proof.hash
    assert cap.grammar_hash == proof.grammar_hash
    assert cap.policy_hash == proof.policy_hash
    # Token round-trips through dict (grammar/policy hashes preserved).
    rebuilt = Capability.from_dict(cap.to_dict())
    assert rebuilt.policy_proof_hash == proof.hash
    assert rebuilt.grammar_hash == proof.grammar_hash
    assert rebuilt.policy_hash == proof.policy_hash


def test_mint_rejects_conflicting_policy_proof_hash_and_proof_result():
    iss = _issuer()
    proof = _proven_proof()
    with pytest.raises(ValueError, match="conflicts"):
        iss.mint(
            agent_id="agent:x",
            tool="t",
            proof_result=proof,
            policy_proof_hash="sha256:" + "z" * 64,
        )


def test_mint_rejects_grammar_hash_mismatch_against_proof():
    from raucle.errors import PolicyUnproven

    iss = _issuer()
    proof = _proven_proof()
    with pytest.raises(PolicyUnproven, match="grammar_hash"):
        iss.mint(
            agent_id="agent:x",
            tool="t",
            proof_result=proof,
            grammar_hash="sha256:" + "x" * 64,
        )


def test_env_var_enables_strict_mode(monkeypatch):
    """``RAUCLE_REQUIRE_PROOF=1`` enables strict mode without changing
    construction sites."""
    from raucle.errors import PolicyUnproven

    monkeypatch.setenv("RAUCLE_REQUIRE_PROOF", "1")
    iss = CapabilityIssuer.generate(issuer="p.env")
    assert iss.require_proof is True
    with pytest.raises(PolicyUnproven):
        iss.mint(agent_id="agent:x", tool="t")


# ---------------------------------------------------------------------------
# Gate-time proof enforcement (FIX 2 / D2)
# ---------------------------------------------------------------------------


def test_gate_proof_mode_off_is_noop():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t")
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        proof_enforcement_mode="off",
    )
    assert gate.check(cap, tool="t", args={}).allowed


def test_gate_proof_mode_lenient_warns_on_missing_cache(caplog):
    import logging

    iss = _issuer()
    proof = _proven_proof()
    cap = iss.mint(agent_id="agent:x", tool="t", proof_result=proof)
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        proof_enforcement_mode="lenient",
        trusted_proofs={},  # empty — proof not present
    )
    with caplog.at_level(logging.WARNING):
        decision = gate.check(cap, tool="t", args={})
    assert decision.allowed
    assert "lenient" in caplog.text


def test_gate_proof_mode_strict_denies_missing_cache():
    iss = _issuer()
    proof = _proven_proof()
    cap = iss.mint(agent_id="agent:x", tool="t", proof_result=proof)
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        proof_enforcement_mode="strict",
        trusted_proofs={},
    )
    d = gate.check(cap, tool="t", args={})
    assert d.allowed is False
    assert "not in trusted_proofs" in d.reason


def test_gate_proof_mode_strict_denies_token_with_no_proof_hash():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t")  # no proof
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        proof_enforcement_mode="strict",
    )
    d = gate.check(cap, tool="t", args={})
    assert d.allowed is False
    assert "no policy_proof_hash" in d.reason


def test_gate_proof_mode_strict_allows_matching_proof():
    """Strict mode allows only when the proof is bound to the ENFORCED constraints (H3)."""
    from raucle.prove import JSONSchemaProver

    iss = _issuer()
    schema = {
        "type": "object",
        "properties": {"amount": {"type": "integer", "minimum": 0, "maximum": 100}},
        "required": ["amount"],
    }
    policy = {"max_value": {"amount": 100}}
    proof = JSONSchemaProver().prove(schema, policy)
    assert proof.status == "PROVEN"
    cap = iss.mint(agent_id="agent:x", tool="t", constraints=policy, proof_result=proof)
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        proof_enforcement_mode="strict",
        trusted_proofs={proof.hash: proof},
    )
    assert gate.check(cap, tool="t", args={"amount": 50}).allowed


def test_gate_proof_mode_strict_denies_proof_unbound_to_constraints():
    """H3: a token citing a valid proof but enforcing DIFFERENT constraints is denied."""
    from raucle.prove import JSONSchemaProver

    iss = _issuer()
    schema = {
        "type": "object",
        "properties": {"amount": {"type": "integer", "minimum": 0, "maximum": 100}},
        "required": ["amount"],
    }
    policy = {"max_value": {"amount": 100}}
    proof = JSONSchemaProver().prove(schema, policy)
    cap = iss.mint(
        agent_id="agent:x",
        tool="t",
        constraints={"max_value": {"amount": 1_000_000}},
        policy_proof_hash=proof.hash,
        grammar_hash=proof.grammar_hash,
        policy_hash=proof.policy_hash,
    )
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        proof_enforcement_mode="strict",
        trusted_proofs={proof.hash: proof},
    )
    d = gate.check(cap, tool="t", args={"amount": 999_999})
    assert not d.allowed
    assert "not bound" in d.reason


def test_unknown_constraint_key_raises_not_silently_dropped():
    """A mis-cased/typo'd constraint key must error, not be silently ignored.

    Regression: `cap mint --constraints` previously dropped unknown keys
    (e.g. camelCase `allowedValues`), minting a token enforcing less than
    intended. The normaliser now rejects unknown keys loudly.
    """
    import pytest

    from raucle.capability import _normalise_constraints

    with pytest.raises(ValueError, match="unknown constraint key"):
        _normalise_constraints({"allowedValues": {"invoice": ["4471"]}})

    # Correct snake_case is accepted unchanged.
    ok = _normalise_constraints({"allowed_values": {"invoice": ["4471"]}})
    assert ok == {"allowed_values": {"invoice": ["4471"]}}


def test_starts_with_constraint_allows_and_denies():
    """`starts_with` (the README hero example) enforces a string prefix."""
    from raucle.capability import CapabilityGate, CapabilityIssuer

    issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    tok = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={"starts_with": {"customer_id": "C-"}},
        ttl_seconds=300,
    )
    assert tok.constraints == {"starts_with": {"customer_id": "C-"}}
    assert gate.check(tok, tool="lookup_customer", args={"customer_id": "C-123"}).allowed
    bad = gate.check(tok, tool="lookup_customer", args={"customer_id": "X-9"})
    assert not bad.allowed
    assert "does not start with" in bad.reason
    # non-string value also fails the prefix check
    assert not gate.check(tok, tool="lookup_customer", args={"customer_id": 42}).allowed


def test_starts_with_attenuation_narrows_not_broadens():
    from raucle.capability import CapabilityIssuer

    issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
    parent = issuer.mint(
        agent_id="agent:kyc",
        tool="lookup_customer",
        constraints={"starts_with": {"customer_id": "C-"}},
        ttl_seconds=300,
    )
    child = issuer.attenuate(parent, extra_constraints={"starts_with": {"customer_id": "C-9"}})
    assert child.constraints["starts_with"]["customer_id"] == "C-9"

    import pytest

    with pytest.raises(ValueError, match="cannot broaden"):
        issuer.attenuate(parent, extra_constraints={"starts_with": {"customer_id": "C"}})


def test_package_version_matches_metadata():
    """__version__ must match the installed package metadata (regression: was 0.7.0)."""
    import importlib.metadata

    import raucle

    assert raucle.__version__ == importlib.metadata.version("raucle")


def test_revocation_denylist_refuses_token_and_children():
    """A revoked token (and children citing it as parent) is DENY'd before expiry."""
    from raucle.capability import CapabilityGate, CapabilityIssuer

    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    tok = issuer.mint(agent_id="agent:ops", tool="lookup_customer", ttl_seconds=300)
    child = issuer.attenuate(tok, narrower_agent_id="agent:ops.sub")
    # Revocation depth requires a parent_resolver; a token citing a parent_id is
    # otherwise DENY'd because the chain cannot be verified (fail-closed, §8.7).
    store = {tok.token_id: tok, child.token_id: child}
    gate = CapabilityGate(
        trusted_issuers={issuer.key_id: issuer.public_key_pem},
        parent_resolver=store.get,
    )

    # Valid before revocation.
    assert gate.check(tok, tool="lookup_customer").allowed
    assert gate.check(child, tool="lookup_customer", agent_id="agent:ops.sub").allowed

    # Revoke the parent → both parent and child are refused.
    gate.revoke(tok.token_id)
    d_parent = gate.check(tok, tool="lookup_customer")
    assert not d_parent.allowed
    assert "revoked" in d_parent.reason
    d_child = gate.check(child, tool="lookup_customer", agent_id="agent:ops.sub")
    assert not d_child.allowed
    assert "revoked" in d_child.reason


def test_revocation_via_constructor():
    from raucle.capability import CapabilityGate, CapabilityIssuer

    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    tok = issuer.mint(agent_id="agent:ops", tool="lookup_customer", ttl_seconds=300)
    gate = CapabilityGate(
        trusted_issuers={issuer.key_id: issuer.public_key_pem},
        revoked_token_ids={tok.token_id},
    )
    assert not gate.check(tok, tool="lookup_customer").allowed


# ── Security regressions (pre-launch audit 2026-06-01) ──────────────────


def _issuer_gate():
    from raucle.capability import CapabilityGate, CapabilityIssuer

    i = CapabilityIssuer.generate(issuer="acme.bank")
    g = CapabilityGate(trusted_issuers={i.key_id: i.public_key_pem})
    return i, g


def test_sec_c1_agent_prefix_requires_delimiter():
    """A token for agent:billing must NOT authorise agent:billing-evil."""
    i, g = _issuer_gate()
    t = i.mint(agent_id="agent:billing", tool="x", ttl_seconds=300)
    assert not g.check(t, tool="x", agent_id="agent:billing-evil").allowed
    assert not g.check(t, tool="x", agent_id="agent:billingsomething").allowed
    assert g.check(t, tool="x", agent_id="agent:billing").allowed
    assert g.check(t, tool="x", agent_id="agent:billing.invoice").allowed


def test_sec_c1_attenuate_prefix_requires_delimiter():
    import pytest

    i, _ = _issuer_gate()
    parent = i.mint(agent_id="agent:billing", tool="x", ttl_seconds=300)
    # broadening / sibling is refused
    with pytest.raises(ValueError):
        i.attenuate(parent, narrower_agent_id="agent:billing-evil")
    # genuine descendant is fine
    child = i.attenuate(parent, narrower_agent_id="agent:billing.invoice")
    assert child.agent_id == "agent:billing.invoice"


def test_sec_c2_value_constraints_fail_closed_on_absent_field():
    """allowed_values / starts_with / max/min deny when the field is omitted."""
    i, g = _issuer_gate()
    t = i.mint(
        agent_id="agent:b",
        tool="transfer",
        constraints={"forbidden_values": {"to": ["attacker"]}, "max_value": {"amount": 100}},
        ttl_seconds=300,
    )
    # renamed args must NOT bypass the bound
    assert not g.check(t, tool="transfer", args={"recipient": "attacker", "value": 10**9}).allowed
    # legitimate call still allowed
    assert g.check(t, tool="transfer", args={"to": "alice", "amount": 50}).allowed
    # whitelist + prefix also fail closed on absence
    t2 = i.mint(
        agent_id="agent:b", tool="r", constraints={"allowed_values": {"id": ["A"]}}, ttl_seconds=300
    )
    assert not g.check(t2, tool="r", args={}).allowed
    t3 = i.mint(
        agent_id="agent:b", tool="r", constraints={"starts_with": {"id": "C-"}}, ttl_seconds=300
    )
    assert not g.check(t3, tool="r", args={}).allowed


def test_sec_c3_type_confusion_denies_not_raises():
    """Non-numeric / bool args on a numeric bound DENY, never raise.

    Per §8.6 (FORALL_NUMERIC): a collection is evaluated element-wise — every
    contained scalar must be a finite non-bool number satisfying the bound. A
    string-number, bool, None, or a dict (whose flattened key is a string) all
    contain a non-number → DENY.
    """
    i, g = _issuer_gate()
    t = i.mint(
        agent_id="agent:b", tool="t", constraints={"max_value": {"amount": 100}}, ttl_seconds=300
    )
    for bad in ["99999999", True, None, {"x": 1}, [1, "2"], []]:
        d = g.check(t, tool="t", args={"amount": bad})
        assert not d.allowed, f"expected deny for {bad!r}"  # no exception, explicit deny


def test_sec_c3_numeric_collection_semantics():
    """§8.6 for-all numeric: a list of in-bound numbers is ALLOWED; one
    out-of-bound element DENIES the whole call."""
    i, g = _issuer_gate()
    t = i.mint(
        agent_id="agent:b", tool="t", constraints={"max_value": {"amount": 100}}, ttl_seconds=300
    )
    assert g.check(t, tool="t", args={"amount": [1, 2, 100]}).allowed
    assert not g.check(t, tool="t", args={"amount": [1, 2, 101]}).allowed


def test_canonical_json_rejects_nan_infinity():
    """NaN/Infinity are not valid JSON — canonicalisation must raise, not emit."""
    import pytest

    from raucle.capability import _canonical_json

    for bad in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError):
            _canonical_json({"x": bad})


def test_canonical_json_rejects_lone_surrogates_explicitly():
    """Profile R8: a lone UTF-16 surrogate is rejected at sign time with a clean
    ValueError naming the surrogate — not incidentally via UnicodeEncodeError
    from a later .encode('utf-8'). Covers both value and key position."""
    import pytest

    from raucle.capability import _canonical_json

    lone = "tok\ud83d"  # unpaired high surrogate U+D83D
    for obj in ({"x": lone}, {lone: 1}, {"nested": [{"y": lone}]}):
        with pytest.raises(ValueError) as exc:
            _canonical_json(obj)
        assert "lone surrogate" in str(exc.value)

    # The constraint-normalisation pre-sort runs the UTF-16 sort-key helpers
    # BEFORE _canonical_json's explicit rejector; those helpers must also raise
    # the clean R8 ValueError (not an incidental UnicodeEncodeError from encode).
    from raucle._canon import utf16_key, value_sort_key

    for fn in (utf16_key, value_sort_key):
        with pytest.raises(ValueError) as exc:
            fn(lone)
        assert "lone surrogate" in str(exc.value)


def test_standalone_cap_verifier_rejects_lone_surrogates():
    """The standalone OWASP cap_verifier (no package import) must enforce R8 with
    the same clean ValueError, so it rejects the same cross-language-unstable
    material as the package signer."""
    import importlib.util
    import pathlib

    import pytest

    path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "standards"
        / "cap-verifier"
        / "cap_verifier.py"
    )
    spec = importlib.util.spec_from_file_location("cap_verifier_under_test", path)
    cv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cv)

    lone = "tok\ud83d"
    for obj in ({"x": lone}, {lone: 1}):
        with pytest.raises(ValueError) as exc:
            cv.canonical_json(obj)
        assert "lone surrogate" in str(exc.value)


def test_cli_errors_are_clean_not_tracebacks(capsys):
    """CLI prints 'error: ...' for expected user errors, never a raw traceback."""
    from raucle.cli import main

    rc = main(
        [
            "cap",
            "check",
            "/no/such.json",
            "--pubkey",
            "/no/such.pem",
            "--tool",
            "x",
            "--args",
            "/no/such.json",
        ]
    )
    out = capsys.readouterr()
    assert rc == 1
    assert "Traceback" not in (out.out + out.err)
    assert "error:" in out.err.lower()
