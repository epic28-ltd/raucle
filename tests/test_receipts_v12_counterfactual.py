"""Receipts v1.2 (lane K3): counterfactual evidence on intent receipts.

Spec: docs/spec/provenance/v1.2/counterfactual-evidence.md. An intent
receipt MAY carry the optional versioned counterfactual block: the
NOT-TAKEN decision under a named alternative ruleset, evaluated at
decision time by the same deterministic gate machinery that produced
the enforced decision. The block is evidence about a hypothetical,
never about enforcement. Receipts without it stay byte-identical to
their v1.1 shape; the verifier re-checks every block structurally,
refuses unknown versions with a named error, and reports the replay
re-check honestly (not re-run when it holds neither the alternative
ruleset nor the stored input). No message claims proof: the
counterfactual reports what the machinery recorded, never what it
proves.
"""

import base64
import hashlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier
from raucle.trust_registry import TrustRegistry

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: calendar_read
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      require: [window]
"""

INTENT = {
    "statement": "Read today's calendar entries",
    "tools": ["calendar_read"],
}

# The alternative ruleset: a stricter window bound (policy rule) plus a
# repeated-deny storm session rule. Parsed with the same PolicyFile
# machinery the enforced policy uses, so the counterfactual evaluates
# under the same deterministic vocabulary.
ALTERNATIVE = """
version: 1
issuer: test.bank
policies:
  - id: cf-window-today
    tool: calendar_read
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        window: ["today"]
session_rules:
  - id: cf-storm
    kind: repeated_deny_storm
    window_seconds: 300
    threshold: 2
"""


def _setup(tmp_path, ruleset: "str | None" = ALTERNATIVE):
    """An intent-receipting gateway in token mode, optionally with the
    alternative ruleset configured."""
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
    config.policy_file.write_text(POLICY)
    config.gate_auth = "token"
    if ruleset is not None:
        ruleset_path = tmp_path / "counterfactual.yaml"
        ruleset_path.write_text(ruleset)
        config.counterfactual_ruleset_file = str(ruleset_path)

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    token = issuer.mint(
        agent_id="agent:svc",
        tool="calendar_read",
        constraints={"required_present": ["window"]},
        intent=INTENT,
        ttl_seconds=600,
    )
    ledger.register(token, "agent:svc", verifying_key=issuer)
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, token, tmp_path


def _gate(client, token, args, session_id=""):
    body = {"tool": "calendar_read", "args": args, "agent_id": "agent:svc"}
    if session_id:
        body["session_id"] = session_id
    return client.post(
        "/gate",
        json=body,
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )


def _payload_of(envelope):
    seg = envelope["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def _last_payload(tmp_path):
    line = (tmp_path / "receipts.jsonl").read_text().strip().splitlines()[-1]
    return _payload_of(json.loads(line))


def _verify(gw, tmp_path):
    return ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")


def _no_proof_claim(report):
    """The CAN/CANNOT conclusions are enforced by what the verifier
    reports: no message in the report claims proof."""
    texts = list(report.errors) + [
        row.get("note", "") for row in getattr(report, "counterfactual_evidence", [])
    ]
    for text in texts:
        assert not re.search(r"\bprov(es|en|ing|e)\b", str(text), re.IGNORECASE), text


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------


def test_intent_receipt_carries_counterfactual_allow(tmp_path):
    """The enforced decision allows; the alternative ruleset (window
    bound: today only) also allows. The block records the not-taken
    decision with no rule fields (nothing fired)."""
    gw, client, token, tmp = _setup(tmp_path)
    assert _gate(client, token, {"window": "today"}).json()["decision"] == "allow"

    payload = _last_payload(tmp)
    cf = payload["x_gate"]["counterfactual"]
    assert cf["version"] == "counterfactual/v1"
    assert cf["decision"] == "allow"
    assert "rule_id" not in cf
    assert "rule_kind" not in cf
    assert "session" not in cf
    assert cf["evaluated_at"] <= payload["iat"]
    # the ruleset is named by digest over the file bytes: a third party
    # holding the same bytes hashes them and confirms it
    expected = "sha256:" + hashlib.sha256(
        (tmp / "counterfactual.yaml").read_bytes()
    ).hexdigest()
    assert cf["ruleset_hash"] == expected


def test_counterfactual_policy_rule_deny(tmp_path):
    """The enforced decision allows tomorrow's read; the alternative
    window bound would have denied it. The block records deny, the
    firing rule id and the closed rule kind."""
    gw, client, token, tmp = _setup(tmp_path)
    assert _gate(client, token, {"window": "tomorrow"}).json()["decision"] == "allow"

    cf = _last_payload(tmp)["x_gate"]["counterfactual"]
    assert cf["decision"] == "deny"
    assert cf["rule_id"] == "cf-window-today"
    assert cf["rule_kind"] == "policy_rule"
    assert "session" not in cf


def test_no_ruleset_configured_leaves_v11_shape(tmp_path):
    """Backwards compatibility: without the alternative ruleset the
    receipt carries no counterfactual block at all, byte-identical to
    its v1.1 shape."""
    gw, client, token, tmp = _setup(tmp_path, ruleset=None)
    assert _gate(client, token, {"window": "today"}).json()["decision"] == "allow"

    x_gate = _last_payload(tmp)["x_gate"]
    assert "counterfactual" not in x_gate


def test_counterfactual_rides_intent_receipts_only(tmp_path):
    """The block rides the intent receipt decision path: a receipt
    without an intent carries none, configured ruleset or not."""
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
    ruleset_path = tmp_path / "counterfactual.yaml"
    ruleset_path.write_text(ALTERNATIVE)
    config.counterfactual_ruleset_file = str(ruleset_path)
    gw = RaucleGateway(config)
    from raucle.gateway import GateReceiptContext

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
            trace_id="trace-1",
        )
    )
    assert "counterfactual" not in _last_payload(tmp_path)["x_gate"]


def test_counterfactual_session_rule_with_window_evidence(tmp_path):
    """A session-rule alternative fires over the receipt's own session
    window: the block carries the session block with the exact two-key
    window_evidence shape (counters first, tools always present)."""
    gw, client, token, tmp = _setup(tmp_path)
    # seed the session window with two receipted denies (constraint
    # violations are attributable and receipted), then an allowed call
    for _ in range(2):
        denied = _gate(client, token, {}, session_id="session:sess-1")
        assert denied.json()["decision"] == "deny"
    allowed = _gate(client, token, {"window": "today"}, session_id="session:sess-1")
    assert allowed.json()["decision"] == "allow"

    cf = _last_payload(tmp)["x_gate"]["counterfactual"]
    assert cf["decision"] == "deny"
    assert cf["rule_id"] == "cf-storm"
    assert cf["rule_kind"] == "repeated_deny_storm"
    session = cf["session"]
    assert session["session_id"] == "session:sess-1"
    assert session["window_seconds"] == 300
    assert session["participant"] == "tool_call"
    evidence = session["window_evidence"]
    assert set(evidence) == {"counters", "tools"}
    assert all(
        isinstance(v, int) and not isinstance(v, bool) and v >= 0
        for v in evidence["counters"].values()
    )
    assert evidence["counters"]["denied_calls"] == 2
    assert evidence["tools"] == ["calendar_read"]
    assert cf["evaluated_at"] <= _last_payload(tmp)["iat"]


def test_counterfactual_ruleset_file_from_env(monkeypatch, tmp_path):
    """Config wiring round-trip: the env var lands on the field."""
    monkeypatch.setenv("RAUCLE_COUNTERFACTUAL_RULESET_FILE", str(tmp_path / "cf.yaml"))
    assert (
        GatewayConfig.from_env().counterfactual_ruleset_file == str(tmp_path / "cf.yaml")
    )


def test_malformed_ruleset_mints_no_block(tmp_path):
    """A ruleset that cannot be parsed mints no counterfactual
    evidence: the block is optional, never fabricated. The calls still
    decide (enforcement never depends on the evidence surface)."""
    gw, client, token, tmp = _setup(tmp_path, ruleset="version: 1\npolicies: [")
    resp = _gate(client, token, {"window": "today"})
    assert resp.json()["decision"] == "allow"
    assert "counterfactual" not in _last_payload(tmp)["x_gate"]


# ---------------------------------------------------------------------------
# Verifier (forged blocks via the emitter seam, DLP-test pattern)
# ---------------------------------------------------------------------------


def _forge(tmp_path, monkeypatch, block, session_id="", intent_block=None):
    """Mint one signed intent receipt carrying an arbitrary
    counterfactual block, then verify the chain."""
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
    from raucle.gateway import GateReceiptContext

    monkeypatch.setattr(gw, "_counterfactual_block", lambda ctx: block)
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
            trace_id="trace-1",
            session_id=session_id,
            intent_block=intent_block
            or {"intent": INTENT, "intent_check": {"tool": "calendar_read"}},
        )
    )
    report = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")
    return gw, report


def _valid_block(**overrides):
    base = {
        "version": "counterfactual/v1",
        "ruleset_hash": "sha256:" + "ab" * 32,
        "decision": "allow",
        "evaluated_at": 1,
    }
    base.update(overrides)
    for key, value in list(overrides.items()):
        if value is None:
            base.pop(key)
    return base


def test_valid_counterfactual_verifies_and_reports_not_rerun(tmp_path, monkeypatch):
    """The acceptance: a structurally valid block verifies offline; the
    chain verifier holds neither the alternative ruleset nor the stored
    input, so it names the counterfactual as not re-run and the chain
    stays valid."""
    gw, report = _forge(
        tmp_path,
        monkeypatch,
        _valid_block(),
        session_id="session:sess-1",
    )
    assert report.valid, report.errors
    rows = report.counterfactual_evidence
    assert len(rows) == 1
    assert rows[0]["re_run"] is False
    assert "not re-run" in rows[0]["note"]
    _no_proof_claim(report)


def test_unknown_counterfactual_version_refuses(tmp_path, monkeypatch):
    """Version gate: an unknown version refuses the receipt with a
    named error, never a skip."""
    gw, report = _forge(
        tmp_path,
        monkeypatch,
        _valid_block(version="counterfactual/v2"),
    )
    assert not report.valid
    assert any("counterfactual" in e and "version" in e for e in report.errors), report.errors
    assert any("counterfactual/v2" in e for e in report.errors)
    _no_proof_claim(report)


def test_evaluated_at_after_iat_fails(tmp_path, monkeypatch):
    """A post-dated block is editorial, not evidence: evaluated_at
    later than the receipt's own iat fails with a named error."""
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
    from raucle.gateway import GateReceiptContext

    gw = RaucleGateway(config)
    monkeypatch.setattr(
        gw,
        "_counterfactual_block",
        lambda ctx: _valid_block(
            evaluated_at=int(__import__("time").time()) + 60,
        ),
    )
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
            trace_id="trace-1",
            intent_block={"intent": INTENT, "intent_check": {"tool": "calendar_read"}},
        )
    )
    report = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")
    assert not report.valid
    assert any("evaluated_at" in e for e in report.errors), report.errors


def test_session_id_mismatch_fails(tmp_path, monkeypatch):
    """Session coherence: a session block citing a session id other
    than the receipt's own is incoherent and fails with a named
    error."""
    block = _valid_block(
        decision="deny",
        rule_id="cf-storm",
        rule_kind="repeated_deny_storm",
        session={
            "session_id": "session:other",
            "window_seconds": 300,
            "participant": "tool_call",
            "window_evidence": {"counters": {"denied_calls": 2}, "tools": ["calendar_read"]},
        },
    )
    gw, report = _forge(tmp_path, monkeypatch, block, session_id="session:sess-1")
    assert not report.valid
    assert any("session" in e and "own" in e for e in report.errors), report.errors


@pytest.mark.parametrize(
    "evidence",
    [
        {"counters": {"denied_calls": 2}},
        {"tools": ["calendar_read"]},
        {
            "counters": {"denied_calls": 2},
            "tools": ["calendar_read"],
            "args_text": "account=ACC-999",
        },
        {"counters": {"denied_calls": "2"}, "tools": ["calendar_read"]},
        {"counters": {"denied_calls": -1}, "tools": ["calendar_read"]},
        {"counters": {"denied_calls": 2}, "tools": ["calendar_read", 7]},
    ],
)
def test_window_evidence_two_key_shape_enforced(tmp_path, monkeypatch, evidence):
    """window_evidence is exactly the closed two-key shape: a missing
    key, an extra key or a content-like value inside it fails with a
    named error."""
    block = _valid_block(
        decision="deny",
        rule_id="cf-storm",
        rule_kind="repeated_deny_storm",
        session={
            "session_id": "session:sess-1",
            "window_seconds": 300,
            "participant": "tool_call",
            "window_evidence": evidence,
        },
    )
    gw, report = _forge(tmp_path, monkeypatch, block, session_id="session:sess-1")
    assert not report.valid
    assert any("window_evidence" in e for e in report.errors), report.errors


def test_rule_kind_vocabulary_enforced(tmp_path, monkeypatch):
    """No other rule kind may back a counterfactual: a classifier
    verdict kind is advisory detection and fails the closed
    vocabulary."""
    block = _valid_block(decision="deny", rule_id="cf-1", rule_kind="classifier_verdict")
    gw, report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("rule_kind" in e for e in report.errors), report.errors


def test_allow_with_rule_fields_fails(tmp_path, monkeypatch):
    """rule_id is present if and only if the decision is deny."""
    block = _valid_block(rule_id="cf-window-today")
    gw, report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("rule_id" in e for e in report.errors), report.errors


def test_deny_without_rule_id_fails(tmp_path, monkeypatch):
    block = _valid_block(decision="deny", rule_kind="policy_rule")
    gw, report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("rule_id" in e for e in report.errors), report.errors


def test_session_block_presence_tracks_rule_kind(tmp_path, monkeypatch):
    """session is present if and only if the firing alternative rule is
    a session rule."""
    good_session = {
        "session_id": "session:sess-1",
        "window_seconds": 300,
        "participant": "tool_call",
        "window_evidence": {"counters": {"denied_calls": 2}, "tools": ["calendar_read"]},
    }
    # a policy rule with a session block
    block = _valid_block(
        decision="deny",
        rule_id="cf-window-today",
        rule_kind="policy_rule",
        session=good_session,
    )
    gw, report = _forge(tmp_path, monkeypatch, block, session_id="session:sess-1")
    assert not report.valid
    assert any("session" in e for e in report.errors), report.errors

    # a session rule without a session block
    block = _valid_block(
        decision="deny", rule_id="cf-storm", rule_kind="repeated_deny_storm"
    )
    gw, report = _forge(tmp_path, monkeypatch, block, session_id="session:sess-1")
    assert not report.valid
    assert any("session" in e for e in report.errors), report.errors


def test_forbidden_field_in_counterfactual_fails(tmp_path, monkeypatch):
    """Bounded disclosure: a content-like field anywhere in the block
    fails with a named error, so a leaky emitter cannot hide argument
    values inside signed evidence."""
    block = _valid_block(args={"window": "today"})
    gw, report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("content-like" in e for e in report.errors), report.errors


def test_ruleset_hash_digest_shape(tmp_path, monkeypatch):
    block = _valid_block(ruleset_hash="md5:deadbeef")
    gw, report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("ruleset_hash" in e for e in report.errors), report.errors


def test_unknown_counterfactual_decision_fails(tmp_path, monkeypatch):
    block = _valid_block(decision="block")
    gw, report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("decision" in e for e in report.errors), report.errors
