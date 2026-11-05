"""Tests for the cross-org agent handshake (P2) — trust resolved from the registry."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from raucle.audit import Ed25519Signer  # noqa: E402
from raucle.capability import CapabilityIssuer  # noqa: E402
from raucle.handshake import (  # noqa: E402
    HANDSHAKE_VERSION,
    HandshakeRequest,
    accept_call,
    build_request,
    verify_ack,
)
from raucle.trust_registry import TrustRegistry  # noqa: E402


@pytest.fixture
def two_orgs(tmp_path):
    """A shared registry with org A (an issuer) and org B (a responder),
    with NO prior key exchange between them."""
    reg = TrustRegistry(tmp_path / "reg.jsonl", operator_signer=Ed25519Signer.generate())
    iss_a = CapabilityIssuer.generate(issuer="org-a.bank")
    resp_b = Ed25519Signer.generate()
    reg.publish(iss_a.public_key_pem, issuer=iss_a.issuer)
    reg.publish(resp_b.public_key_pem().decode(), issuer="org-b.gateway")
    token = iss_a.mint(
        agent_id="agent:a.payments",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}, "allowed_values": {"to": ["acct:b-co"]}},
        ttl_seconds=300,
    )
    return reg, iss_a, resp_b, token


def test_accept_authorised_call(two_orgs):
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(
        token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50}, nonce="n1"
    )
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    assert res.accepted
    assert res.ack_receipt["body"]["decision"] == "ACCEPT"
    assert res.ack_receipt["body"]["version"] == HANDSHAKE_VERSION


def test_initiator_verifies_responder_ack_via_registry(two_orgs):
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(
        token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50}, nonce="n1"
    )
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    ok, reason = verify_ack(res.ack_receipt, registry=reg, expected_nonce="n1")
    assert ok
    assert "ACCEPT" in reason


def test_injected_call_denied(two_orgs):
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(
        token, tool="transfer_funds", args={"to": "acct:attacker", "amount": 9900}, nonce="n2"
    )
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    assert not res.accepted
    assert res.ack_receipt["body"]["decision"] == "REJECT"
    # The denial ack is itself signed and verifiable.
    assert verify_ack(res.ack_receipt, registry=reg, require_binding=False)[0]


def test_revoked_initiator_rejected_before_gate(two_orgs):
    reg, iss_a, resp_b, token = two_orgs
    reg.revoke(iss_a.key_id, reason="compromised")
    req = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50})
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    assert not res.accepted
    assert "revoked" in res.reason


def test_unknown_initiator_rejected(tmp_path):
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    resp_b = Ed25519Signer.generate()
    reg.publish(resp_b.public_key_pem().decode(), issuer="org-b.gateway")
    # Org A's issuer was NEVER published to this registry.
    iss_a = CapabilityIssuer.generate(issuer="org-a")
    token = iss_a.mint(agent_id="agent:a", tool="t", constraints={})
    req = build_request(token, tool="t", args={})
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b")
    assert not res.accepted
    assert "not in the registry" in res.reason


def test_ack_nonce_replay_rejected(two_orgs):
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(
        token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50}, nonce="n1"
    )
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    ok, reason = verify_ack(res.ack_receipt, registry=reg, expected_nonce="DIFFERENT")
    assert not ok
    assert "nonce" in reason


def test_tampered_ack_signature_rejected(two_orgs):
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50})
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    # Attacker flips the decision REJECT->ACCEPT in the body; signature no longer matches.
    res.ack_receipt["body"]["decision"] = "ACCEPT"
    res.ack_receipt["body"]["reason"] = "tampered"
    ok, _ = verify_ack(res.ack_receipt, registry=reg)
    assert not ok


def test_malformed_token_rejected(two_orgs):
    reg, _iss_a, resp_b, _token = two_orgs
    req = HandshakeRequest(
        capability_token={"not": "a token"}, tool="t", args={}, caller_agent_id="x"
    )
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b")
    assert not res.accepted
    assert "malformed" in res.reason


def test_request_round_trip():
    reg_iss = CapabilityIssuer.generate(issuer="a")
    token = reg_iss.mint(agent_id="agent:a", tool="t", constraints={})
    req = build_request(token, tool="t", args={"x": 1}, nonce="n")
    rebuilt = HandshakeRequest.from_dict(req.to_dict())
    assert rebuilt.tool == "t"
    assert rebuilt.nonce == "n"
    assert rebuilt.args == {"x": 1}


def test_demo_script_passes_self_check():
    import pathlib
    import subprocess
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, str(root / "examples" / "cross_org_demo" / "demo.py")],
        capture_output=True,
        text=True,
        cwd=root,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ACCEPT" in proc.stdout
    assert "REJECT" in proc.stdout
    assert "revoked" in proc.stdout


def test_issuer_impersonation_rejected(tmp_path):
    """A registered org cannot present a token claiming to be a DIFFERENT org
    (codex #2): the token's issuer must match the registry's record."""
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    evil = CapabilityIssuer.generate(issuer="evil-corp")
    resp_b = Ed25519Signer.generate()
    # Evil registers under its OWN name, then mints a token... but the token's
    # issuer is evil-corp; registry record says evil-corp -> they match, gate runs.
    # The attack is registering evil's key but claiming bank's NAME: we publish
    # evil's key under the WRONG (bank) name only the operator could do, so here
    # we simulate the mismatch the verifier must catch.
    reg.publish(evil.public_key_pem, issuer="bank-a")  # registry says bank-a
    resp_kid = reg.publish(resp_b.public_key_pem().decode(), issuer="org-b")
    assert resp_kid
    token = evil.mint(agent_id="agent:evil", tool="t", constraints={})  # token.issuer = evil-corp
    req = build_request(token, tool="t", args={})
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b")
    assert not res.accepted
    assert "issuer mismatch" in res.reason


def test_ack_bound_to_token_and_request(two_orgs):
    """The ack binds token_id + request_hash, so it cannot be accepted for a
    different capability/request (codex #3)."""
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50})
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    # Correct bindings verify.
    ok, _ = verify_ack(
        res.ack_receipt,
        registry=reg,
        expected_token_id=token.token_id,
        expected_request=req,
        expected_decision="ACCEPT",
    )
    assert ok
    # A different token_id is rejected (replay into another capability context).
    ok2, why2 = verify_ack(res.ack_receipt, registry=reg, expected_token_id="cap:" + "0" * 24)
    assert not ok2
    assert "token_id" in why2
    # A different request is rejected.
    other = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 99})
    ok3, why3 = verify_ack(res.ack_receipt, registry=reg, expected_request=other)
    assert not ok3
    assert "request_hash" in why3


def test_default_nonce_is_random(two_orgs):
    _reg, _iss_a, _resp_b, token = two_orgs
    r1 = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 1})
    r2 = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 1})
    assert r1.nonce
    assert r2.nonce
    assert r1.nonce != r2.nonce


def test_responder_identity_impersonation_rejected(tmp_path):
    """An attacker's registered key cannot sign an ack claiming to be a DIFFERENT
    responder org (codex round 4 — symmetric to the initiator check)."""
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    initiator = CapabilityIssuer.generate(issuer="org-a.bank")
    attacker = Ed25519Signer.generate()
    reg.publish(initiator.public_key_pem, issuer="org-a.bank")
    reg.publish(attacker.public_key_pem().decode(), issuer="evil.gateway")
    token = initiator.mint(agent_id="agent:a", tool="transfer", constraints={}, ttl_seconds=300)
    req = build_request(token, tool="transfer", args={}, nonce="n1")
    # Attacker signs an ACCEPT but lies that it is org-b.gateway.
    res = accept_call(req, registry=reg, responder_signer=attacker, responder_id="org-b.gateway")
    ok, why = verify_ack(res.ack_receipt, registry=reg, require_binding=False)
    assert not ok
    assert "responder identity mismatch" in why
    # Honest case: the responder_id matches the registry record -> verifies.
    res2 = accept_call(req, registry=reg, responder_signer=attacker, responder_id="evil.gateway")
    ok2, _ = verify_ack(res2.ack_receipt, registry=reg, require_binding=False)
    assert ok2  # signed name now matches the registry record


def test_verify_ack_requires_binding_by_default(two_orgs):
    """Without an anti-replay binding, verify_ack refuses to return ok (codex r5)."""
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50})
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    ok, why = verify_ack(res.ack_receipt, registry=reg)  # no binding
    assert not ok
    assert "anti-replay binding" in why
    # With a binding it verifies.
    assert verify_ack(res.ack_receipt, registry=reg, expected_request=req)[0]


def test_responder_rejects_replayed_request(two_orgs):
    """The responder, given a persistent seen-set, rejects a replayed request
    (codex r6)."""
    reg, _iss_a, resp_b, token = two_orgs
    seen: set[str] = set()
    req = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50})
    first = accept_call(
        req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway", seen=seen
    )
    assert first.accepted
    # Replaying the SAME request is now rejected.
    replay = accept_call(
        req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway", seen=seen
    )
    assert not replay.accepted
    assert "replay" in replay.reason
    # A fresh request (new nonce) is accepted.
    req2 = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50})
    assert accept_call(
        req2, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway", seen=seen
    ).accepted


def test_verify_ack_malformed_toplevel_fails_closed(tmp_path):
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    reg.publish(Ed25519Signer.generate().public_key_pem().decode(), issuer="x")
    for bad in (None, [], "nonsense", 42):
        ok, _ = verify_ack(bad, registry=reg, require_binding=False)
        assert not ok  # never raises


def test_token_id_alone_is_not_replay_binding(two_orgs):
    """expected_token_id alone is insufficient (the token is reusable) — a
    per-handshake binding is required (codex r7)."""
    reg, _iss_a, resp_b, token = two_orgs
    req = build_request(token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50})
    res = accept_call(req, registry=reg, responder_signer=resp_b, responder_id="org-b.gateway")
    ok, why = verify_ack(
        res.ack_receipt, registry=reg, expected_token_id=token.token_id, expected_decision="ACCEPT"
    )
    assert not ok
    assert "anti-replay binding" in why
    # request binding makes it valid.
    assert verify_ack(res.ack_receipt, registry=reg, expected_request=req)[0]
