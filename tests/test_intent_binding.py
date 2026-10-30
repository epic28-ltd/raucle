"""A1: receipts v1.2 - task-intent binding.

The intent binds at mint (the capability token carries the approved task
statement plus structured constraints), enforces at the gate
(deterministically, no model involvement, fail-closed), mirrors into the
receipt (x_gate.intent + a bounded x_gate.intent_check disclosure), and
re-checks at the verifier: a chain-valid ALLOW receipt whose action
violates its own intent is rejected with a named reason. DENY receipts are
the enforcement, so they are exempt from the re-check.

Fixtures from the ticket: the calendar-vs-archive case (a "check today's
calendar" intent cannot mint an ALLOW receipt for a 5-year export) and
the recipient-allowlist case.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.gateway import GateReceiptContext, GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier
from raucle.trust_registry import TrustRegistry

CALENDAR_INTENT = {
    "statement": "Check today's calendar and report conflicts",
    "tools": ["calendar_read"],
    "constraints": {"allowed_values": {"window": ["today"]}},
}


def _gate(issuer):
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


def test_intent_token_mints_and_gate_enforces_scope():
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    token = issuer.mint(
        agent_id="agent:svc",
        tool="calendar_read",
        constraints={"required_present": ["window"]},
        intent=CALENDAR_INTENT,
        ttl_seconds=600,
    )
    assert token.intent == CALENDAR_INTENT
    # byte-compat: intent=None mints a body without the field
    plain = issuer.mint(agent_id="agent:svc", tool="calendar_read", ttl_seconds=600)
    assert "intent" not in plain.body()
    assert plain.intent is None

    gate = _gate(issuer)
    ok = gate.check(token, tool="calendar_read", args={"window": "today"})
    assert ok.allowed, ok.reason

    # intent scope: a token bound to a tool the approved task does not cover
    # (the tool-binding stage passes; the intent refuses - the approved
    # purpose cannot be widened by minting a tool outside its scope)
    off_purpose = issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        intent=CALENDAR_INTENT,
        ttl_seconds=600,
    )
    wrong_tool = gate.check(off_purpose, tool="lookup_balance", args={"query": "x"})
    assert not wrong_tool.allowed
    assert wrong_tool.attributable
    assert "intent scope" in wrong_tool.reason, wrong_tool.reason

    # a tool the token is not even bound to denies at the binding stage first
    unbound = gate.check(token, tool="archive_export", args={"years": 5})
    assert not unbound.allowed
    assert unbound.attributable

    # out-of-intent args: the window is bound to "today"
    wrong_args = gate.check(token, tool="calendar_read", args={"window": "2019"})
    assert not wrong_args.allowed
    assert wrong_args.attributable
    assert "intent constraint violated" in wrong_args.reason, wrong_args.reason


def test_attenuate_narrows_intent_never_widens():
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    parent = issuer.mint(
        agent_id="agent:svc",
        tool="calendar_read",
        intent={
            "statement": "Calendar duties",
            "tools": ["calendar_read", "calendar_write"],
            "constraints": {"allowed_values": {"window": ["today", "tomorrow"]}},
        },
        ttl_seconds=600,
    )
    child = issuer.attenuate(
        parent,
        extra_constraints={"allowed_values": {"window": ["today"]}},
    )
    # the child inherits the parent's intent unchanged
    assert child.intent == parent.intent

    # a child that narrows the intent is fine
    narrowed = issuer.attenuate(
        parent,
        intent={
            "statement": "Read-only calendar check",
            "tools": ["calendar_read"],
            "constraints": {"allowed_values": {"window": ["today"]}},
        },
    )
    assert set(narrowed.intent["tools"]) <= set(parent.intent["tools"])

    # a child that WIDENS the intent is refused
    with pytest.raises(ValueError):
        issuer.attenuate(
            parent,
            intent={
                "statement": "Everything",
                "tools": ["calendar_read", "archive_export", "email_send"],
                "constraints": {},
            },
        )


def _receipt_payload(envelope):
    seg = envelope["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def test_gateway_receipt_carries_intent_block(tmp_path):
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(
        """
version: 1
issuer: test.bank
policies:
  - tool: calendar_read
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        window: ["today", "tomorrow"]
"""
    )
    config.gate_auth = "token"

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    token = issuer.mint(
        agent_id="agent:svc",
        tool="calendar_read",
        intent=CALENDAR_INTENT,
        ttl_seconds=600,
    )
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    resp = client.post(
        "/gate",
        json={"tool": "calendar_read", "args": {"window": "today"}, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )
    assert resp.json()["decision"] == "allow", resp.json()

    envelope = json.loads((tmp_path / "receipts.jsonl").read_text().strip().splitlines()[-1])
    payload = _receipt_payload(envelope)
    x_gate = payload["x_gate"]
    assert x_gate["intent"]["statement"] == CALENDAR_INTENT["statement"]
    assert x_gate["intent_check"]["tool"] == "calendar_read"
    # bounded disclosure: only fields the intent constrains
    assert x_gate["intent_check"]["satisfied_fields"] == {"window": "today"}


def test_verifier_rejects_allow_receipt_violating_intent(tmp_path):
    """Defence-in-depth: a gate that failed to enforce (or a tampered
    deployment) mints an ALLOW receipt whose action violates the intent.
    The verifier re-checks deterministically and rejects with a named
    reason - the calendar-vs-archive case."""
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    gw = RaucleGateway(config)  # emitter only; the gate decision is simulated

    # Simulate enforcement failure: an ALLOW receipt for a 5-year export
    # under a "check today's calendar" intent.
    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="allow",
            reason="ok",
            tool="archive_export",
            agent_id="agent:svc",
            args={"years": 5},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="archive",
            trace_id="trace-1",
            intent_block={
                "intent": CALENDAR_INTENT,
                "intent_check": {"tool": "archive_export", "satisfied_fields": {}},
            },
        )
    )

    pem = gw._gate_identity.public_key_pem()
    verifier = ProvenanceVerifier(public_keys={gw._gate_identity.key_id: pem})
    report = verifier.verify_chain(tmp_path / "receipts.jsonl")
    assert not report.valid
    assert any("outside intent scope" in e for e in report.errors), report.errors


def test_verifier_rejects_allow_receipt_violating_intent_constraints(tmp_path):
    """The recipient-allowlist case: the intent allows mail to two
    recipients; an ALLOW receipt disclosing a third recipient is invalid."""
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    gw = RaucleGateway(config)
    intent = {
        "statement": "Email the weekly digest to the named recipients",
        "tools": ["send_email"],
        "constraints": {"allowed_values": {"to": ["alice@corp.example", "bob@corp.example"]}},
    }
    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="allow",
            reason="ok",
            tool="send_email",
            agent_id="agent:svc",
            args={"to": "eve@evil.example"},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="smtp",
            trace_id="trace-2",
            intent_block={
                "intent": intent,
                "intent_check": {
                    "tool": "send_email",
                    "satisfied_fields": {"to": "eve@evil.example"},
                },
            },
        )
    )

    pem = gw._gate_identity.public_key_pem()
    verifier = ProvenanceVerifier(public_keys={gw._gate_identity.key_id: pem})
    report = verifier.verify_chain(tmp_path / "receipts.jsonl")
    assert not report.valid
    assert any("violates intent constraint" in e for e in report.errors), report.errors


def test_verifier_accepts_honest_intent_receipt(tmp_path):
    """The in-intent ALLOW receipt verifies clean; and a DENY receipt for an
    out-of-intent attempt is the enforcement working, not a violation."""
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    gw = RaucleGateway(config)
    intent_block = {
        "intent": CALENDAR_INTENT,
        "intent_check": {"tool": "calendar_read", "satisfied_fields": {"window": "today"}},
    }
    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="allow",
            reason="ok",
            tool="calendar_read",
            agent_id="agent:svc",
            args={"window": "today"},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="calendar",
            trace_id="t-ok",
            intent_block=intent_block,
        )
    )
    # the DENY for the out-of-intent export: enforcement, not violation
    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="deny",
            reason="delegated authority: intent scope",
            tool="archive_export",
            agent_id="agent:svc",
            args={"years": 5},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="archive",
            trace_id="t-deny",
            intent_block={
                "intent": CALENDAR_INTENT,
                "intent_check": {"tool": "archive_export", "satisfied_fields": {}},
            },
        )
    )

    pem = gw._gate_identity.public_key_pem()
    verifier = ProvenanceVerifier(public_keys={gw._gate_identity.key_id: pem})
    report = verifier.verify_chain(tmp_path / "receipts.jsonl")
    assert report.valid, report.errors
    assert report.receipt_count == 2
