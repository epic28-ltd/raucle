"""Raucle ⇄ A2A binding: signed, offline-verifiable per-skill authorisation."""

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from raucle import a2a
from raucle.provenance import AgentIdentity

ISS = "https://acme.example/raucle"
CAP = "sha256:" + "ab" * 32
ROOT = "sha256:" + "00" * 32  # A's task-root receipt id (handoff is non-root)
INPUT = {"amount": 100}


def _cards(skill_caps=None):
    payments = AgentIdentity.generate(agent_id="agent:acme-payments")
    orch = AgentIdentity.generate(agent_id="agent:acme-orchestrator")
    callee = {
        "url": "https://agents.acme.example/pay",
        "skills": [{"id": "transfer"}],
        "metadata": a2a.card_metadata(
            iss=ISS,
            key_id=payments.key_id,
            public_key_b64=a2a.issuer_public_b64(payments.public_key_pem()),
            skill_capabilities=skill_caps,
        ),
    }
    caller = {
        "url": "https://agents.acme.example/orchestrator",
        "metadata": a2a.card_metadata(
            iss=ISS,
            key_id=orch.key_id,
            public_key_b64=a2a.issuer_public_b64(orch.public_key_pem()),
        ),
    }
    return orch, caller, callee


def _handoff(orch, callee, *, skill="transfer", cap=CAP, target=None, skill_input=INPUT):
    jws, rid = a2a.emit_handoff(
        orch,
        iss=ISS,
        skill=skill,
        target_url=target or callee["url"],
        skill_input=skill_input,
        parents=[ROOT],
        issued_at=1_700_000_000,
        capability_proof_hash=cap,
    )
    return jws


def test_valid_handoff_verifies_offline():
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    jws = _handoff(orch, callee)
    v = a2a.verify_handoff(jws, caller, callee)
    assert v.ok, v.reason
    assert v.skill == "transfer"
    assert v.receipt_id.startswith("sha256:")
    assert v.payload["operation"] == "agent_handoff"


def test_attach_to_message_lists_extension_and_receipt():
    orch, _caller, callee = _cards()
    jws = _handoff(orch, callee)
    msg = a2a.attach_to_message({"messageId": "m", "parts": []}, jws)
    assert a2a.RAUCLE_A2A_EXTENSION_URI in msg["extensions"]
    assert msg["metadata"][a2a.RAUCLE_A2A_EXTENSION_URI]["receipt"] == jws


def test_rejects_unadvertised_skill():
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    jws = _handoff(orch, callee, skill="drain_account")
    v = a2a.verify_handoff(jws, caller, callee)
    assert not v.ok
    assert "not advertised" in v.reason


def test_rejects_missing_capability_when_required():
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    jws = _handoff(orch, callee, cap=None)  # required by the callee, not cited
    v = a2a.verify_handoff(jws, caller, callee)
    assert not v.ok
    assert "capability" in v.reason


def test_rejects_wrong_capability_hash():
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    jws = _handoff(orch, callee, cap="sha256:" + "cd" * 32)
    v = a2a.verify_handoff(jws, caller, callee)
    assert not v.ok
    assert "capability" in v.reason


def test_rejects_wrong_target_agent():
    orch, caller, callee = _cards()
    jws = _handoff(orch, callee, target="https://evil.example/pay")
    v = a2a.verify_handoff(jws, caller, callee)
    assert not v.ok
    assert "target" in v.reason


def test_rejects_signature_from_key_not_in_caller_card():
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    evil = AgentIdentity.generate(agent_id="agent:attacker")
    jws = _handoff(evil, callee)  # signed by a key NOT published in caller_card
    v = a2a.verify_handoff(jws, caller, callee)
    assert not v.ok
    assert "signature" in v.reason


def test_rejects_non_canonical_payload():
    """§6: a receipt whose payload is re-encoded non-canonically (here, a
    tampered but still base64url-decodable blob) must be rejected even if the
    signature were to match — the canonical byte-equality check catches it."""
    orch, caller, callee = _cards()
    jws = _handoff(orch, callee)
    header_b64, payload_b64, sig_b64 = jws.split(".")
    # Inject a non-canonical payload (leading space → not canonical JSON).
    bad_payload = base64.urlsafe_b64encode(b' {"operation":"agent_handoff"}').rstrip(b"=").decode()
    tampered = f"{header_b64}.{bad_payload}.{sig_b64}"
    v = a2a.verify_handoff(tampered, caller, callee)
    assert not v.ok  # fails on signature or canonical check — never accepts


def test_emit_requires_a_parent():
    """agent_handoff is non-root: a parentless receipt is not wire-valid."""
    orch, _caller, callee = _cards()
    with pytest.raises(ValueError, match="non-root"):
        a2a.emit_handoff(
            orch,
            iss=ISS,
            skill="transfer",
            target_url=callee["url"],
            skill_input=INPUT,
            parents=[],
            issued_at=1,
        )


def test_rejects_input_substitution():
    """High: a receipt signed for one input must not verify against another."""
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    jws = _handoff(orch, callee, skill_input={"amount": 100})
    ok = a2a.verify_handoff(jws, caller, callee, expected_input={"amount": 100})
    assert ok.ok
    bad = a2a.verify_handoff(jws, caller, callee, expected_input={"amount": 999999})
    assert not bad.ok
    assert "input" in bad.reason


def test_rejects_replay_of_seen_receipt():
    """High: with a persisted seen-set, the same receipt verifies once, not twice."""
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    jws = _handoff(orch, callee)
    seen: set[str] = set()
    assert a2a.verify_handoff(jws, caller, callee, seen_receipt_ids=seen).ok
    replay = a2a.verify_handoff(jws, caller, callee, seen_receipt_ids=seen)
    assert not replay.ok
    assert "replay" in replay.reason


def test_rejects_tampered_header_kid():
    """Medium: header.kid must bind payload.agent_key_id; a swapped (but
    re-signed) header with a different kid must be rejected."""
    import base64 as _b64
    import json as _json

    orch, caller, callee = _cards()
    jws = _handoff(orch, callee)
    header_b64, payload_b64, sig_b64 = jws.split(".")
    header = _json.loads(a2a._b64url_decode(header_b64))
    header["kid"] = "deadbeefdeadbeef"  # no longer == agent_key_id
    new_header_b64 = _b64.urlsafe_b64encode(a2a._canonical_json(header)).rstrip(b"=").decode()
    tampered = f"{new_header_b64}.{payload_b64}.{sig_b64}"
    v = a2a.verify_handoff(tampered, caller, callee)
    assert not v.ok  # fails on signature (header changed) or kid binding


def _sign_custom(identity, payload, *, extra_header=None):
    """Build a signed handoff JWS bypassing emit_handoff's guards, to test the
    verifier's own enforcement (parents, exact header)."""
    header = {
        "alg": "EdDSA",
        "typ": "provenance-receipt/v1",
        "kid": identity.key_id,
        "crit": ["raucle/v1"],
        "raucle/v1": "provenance",
        **(extra_header or {}),
    }
    si = (
        a2a._b64url_encode(a2a._canonical_json(header))
        + "."
        + a2a._b64url_encode(a2a._canonical_json(payload))
    ).encode("ascii")
    return si.decode("ascii") + "." + a2a._b64url_encode(identity.sign(si))


def _base_payload(orch, callee, **over):
    p = {
        "iss": ISS,
        "iat": 1,
        "agent_id": orch.agent_id,
        "agent_key_id": orch.key_id,
        "operation": "agent_handoff",
        "parents": [ROOT],
        "input_hash": a2a._sha256_hex(a2a._canonical_json(INPUT)),
        "output_hash": a2a._sha256_hex(a2a._canonical_json(INPUT)),
        "taint": ["untrusted_user"],
        "x_a2a_skill": "transfer",
        "x_a2a_target": callee["url"],
        "x_capability_proof_hash": CAP,
    }
    p.update(over)
    return p


def test_verifier_rejects_parentless_handoff(monkeypatch):
    """Codex Medium: a signed-but-parentless agent_handoff (crafted outside
    emit_handoff) must be rejected by the verifier, not only at emit."""
    orch, caller, callee = _cards(skill_caps={"transfer": CAP})
    # Re-key caller card to the orch we control here.
    jws = _sign_custom(orch, _base_payload(orch, callee, parents=[]))
    # Publish orch's key in the caller card so the signature verifies.
    caller["metadata"] = a2a.card_metadata(
        iss=ISS,
        key_id=orch.key_id,
        public_key_b64=a2a.issuer_public_b64(orch.public_key_pem()),
    )
    v = a2a.verify_handoff(jws, caller, callee)
    assert not v.ok
    assert "parent" in v.reason


def test_verifier_rejects_extra_header_member():
    """Codex Medium: header must be exactly the profile members; an extra
    protected header member (even with a valid signature) is rejected."""
    orch, _caller, callee = _cards(skill_caps={"transfer": CAP})
    caller = {
        "url": "https://agents.acme.example/orchestrator",
        "metadata": a2a.card_metadata(
            iss=ISS,
            key_id=orch.key_id,
            public_key_b64=a2a.issuer_public_b64(orch.public_key_pem()),
        ),
    }
    jws = _sign_custom(orch, _base_payload(orch, callee), extra_header={"x_extra": "smuggled"})
    v = a2a.verify_handoff(jws, caller, callee)
    assert not v.ok
    assert "header" in v.reason


def test_demo_runs_and_exits_zero(tmp_path):
    demo = Path(__file__).resolve().parent.parent / "examples" / "a2a_handoff" / "demo.py"
    repo = demo.parent.parent.parent
    proc = subprocess.run(
        [sys.executable, str(demo)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(repo), "PATH": ""},
    )
    assert proc.returncode == 0, proc.stderr
    assert "RESULT: AUTHORISED" in proc.stdout
    assert proc.stdout.count("✗ REJECTED") == 5
    assert "AUTHZ BROKEN" not in proc.stdout
