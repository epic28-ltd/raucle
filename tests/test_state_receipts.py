"""EPIC W, lane W1: state-verified write receipts (x_state).

Evidence-at-mint: the adapter/runtime executes the paired read after a
receipted write, hashes the raw response bytes (sha256) and submits
digest, handle and field names through the gateway mint path. The
verifier re-checks offline with no runtime present: structure, the
literal absent sentinel, the closed field set, the forbidden-field
sweep, pairing-registry linkage and pairing coverage. A covered write
receipt carrying neither evidence nor the sentinel marks INVALID with
a named reason: that is the paper's false-success class, checkable.
"""

import base64 as _b64
import hashlib
import json

import pytest

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.middleware import RaucleMiddleware
from raucle.provenance import ProvenanceVerifier
from raucle.tool_schema import (
    SchemaPolicyLoadError,
    StatePairingRegistry,
    ToolSchemaRegistry,
)
from raucle.trust_registry import TrustRegistry

MANIFEST = [
    {
        "name": "create_event",
        "inputSchema": {
            "type": "object",
            "properties": {"title": {"type": "string"}},
            "required": ["title"],
        },
    },
    {
        "name": "get_event",
        "inputSchema": {
            "type": "object",
            "properties": {"event_id": {"type": "string"}},
            "required": ["event_id"],
        },
    },
]

POLICY = """
version: 1
issuer: test.bank
state_pairings:
  - write_tool: create_event
    read_tool: get_event
    id_pointer: event_id
    require_field_classes:
      - status
policies:
  - tool: create_event
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        title: ["Launch"]
"""

POLICY_WITHOUT_PAIRINGS = """
version: 1
issuer: test.bank
policies:
  - tool: create_event
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        title: ["Launch"]
"""

READ_BACK = b'{"event_id": "evt-1", "status": "confirmed", "title": "Launch"}'


def _read_digest(payload: bytes = READ_BACK) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _gateway(tmp_path, policy_text=POLICY):
    tmp_path.mkdir(parents=True, exist_ok=True)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(policy_text)
    config.tool_schema_manifest = str(tmp_path / "tools.json")
    (tmp_path / "tools.json").write_text(json.dumps(MANIFEST))
    config.gate_auth = "token"

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    root = issuer.mint(
        agent_id="agent:svc",
        tool="create_event",
        constraints={"allowed_values": {"title": ["Launch"]}},
        ttl_seconds=600,
    )
    ledger.register(root, "agent:svc", verifying_key=issuer)
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")
    config.registry_path = str(tmp_path / "registry.jsonl")
    config.delegations_file = str(tmp_path / "delegations.jsonl")

    from fastapi.testclient import TestClient

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, root


def _run(client, token, args):
    resp = client.post(
        "/gate",
        json={"tool": "create_event", "args": args, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )
    return resp.json()


def _verify(tmp_path, gw, pairings="default"):
    rows = gw.state_pairings() if pairings == "default" else pairings
    report = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()},
        state_pairings=rows,
    ).verify_chain(tmp_path / "receipts.jsonl")
    return report


def _chain_payloads(tmp_path):
    out = []
    for line in (tmp_path / "receipts.jsonl").read_text().splitlines():
        seg = line.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        out.append(json.loads(_b64.urlsafe_b64decode(seg)))
    return out


def _x_state(**overrides):
    """A structurally valid x_state evidence block, overridable to
    produce deliberate violations in the structural tests."""
    base = {
        "version": "state-evidence/v1",
        "pairing_id": "create_event:get_event",
        "read_tool": "get_event",
        "evidence_digest": _read_digest(),
        "handle": "evt-1",
        "field_classes": ["event_id", "status", "title"],
        "cited_receipt": "sha256:" + "ab" * 32,
    }
    base.update(overrides)
    for key, value in list(overrides.items()):
        if value is None:
            base.pop(key)
    return base


def _emit_x_state(gw, block, verdict="state_verified"):
    return gw._emit_authority_receipt(
        verdict=verdict,
        extension_key="x_state",
        extension=block,
    )


def _receipted_write(client, token):
    allowed = _run(client, token, {"title": "Launch"})
    assert allowed["decision"] == "allow", allowed
    return allowed["receipt_id"]


def _submit_evidence(gw, write_id, payload: bytes = READ_BACK):
    return gw.emit_state_evidence(
        cited_receipt=write_id,
        pairing_id="create_event:get_event",
        read_tool="get_event",
        evidence_digest=_read_digest(payload),
        handle="evt-1",
        field_classes=["event_id", "status", "title"],
    )


# -- pairing registry: load-time fail-closed ------------------------------


def _schema_registry():
    reg = ToolSchemaRegistry()
    reg.register_from_mcp_tools(MANIFEST)
    return reg


def test_pairing_validation_fail_closed_at_load():
    """The spec sentence, as written: a pairing referencing an unknown
    tool or an undeclared id field raises a SchemaPolicyLoadError-class
    error at config load, never at call time."""
    reg = StatePairingRegistry(_schema_registry())
    pairing = reg.register(
        {"write_tool": "create_event", "read_tool": "get_event", "id_pointer": "event_id"}
    )
    assert pairing.pairing_id == "create_event:get_event"
    with pytest.raises(SchemaPolicyLoadError, match="unknown write tool"):
        reg.register(
            {"write_tool": "ghost_write", "read_tool": "get_event", "id_pointer": "event_id"}
        )
    with pytest.raises(SchemaPolicyLoadError, match="unknown read tool"):
        reg.register(
            {"write_tool": "create_event", "read_tool": "ghost_read", "id_pointer": "event_id"}
        )
    with pytest.raises(SchemaPolicyLoadError, match="id field"):
        reg.register(
            {"write_tool": "create_event", "read_tool": "get_event", "id_pointer": "undeclared"}
        )
    with pytest.raises(SchemaPolicyLoadError, match="already paired"):
        reg.register(
            {"write_tool": "create_event", "read_tool": "get_event", "id_pointer": "event_id"}
        )


def test_gateway_boots_pairings_and_refuses_unknown_tool(tmp_path):
    """The policy-file section rides the tool schema manifest: unknown
    tools refuse the boot, valid entries expose bounded rows."""
    gw, _client, _token = _gateway(tmp_path)
    rows = gw.state_pairings()
    assert rows["create_event:get_event"]["write_tool"] == "create_event"
    assert rows["create_event:get_event"]["read_tool"] == "get_event"
    assert rows["create_event:get_event"]["id_pointer"] == "event_id"

    bad = POLICY.replace("read_tool: get_event", "read_tool: ghost_read")
    with pytest.raises(SchemaPolicyLoadError, match="unknown read tool"):
        _gateway(tmp_path / "second", policy_text=bad)


def test_malformed_pairing_section_refuses_config(tmp_path):
    bad = POLICY.replace("    id_pointer: event_id\n", "")
    with pytest.raises(ValueError, match="state_pairings"):
        _gateway(tmp_path, policy_text=bad)


# -- the acceptance: evidence verifies, coverage refuses silence ----------


def test_valid_x_state_evidence_verifies_offline(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _submit_evidence(gw, write_id)
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors

    payloads = _chain_payloads(tmp_path)
    assert any("x_state" in p for p in payloads)
    gate = next(p for p in payloads if "x_gate" in p)
    assert "x_state" not in gate


def test_covered_write_without_evidence_marks_invalid(tmp_path):
    """The lane acceptance: a pairing-covered write receipt carrying
    neither evidence nor the absent sentinel marks INVALID with a
    named reason at verify."""
    gw, client, token = _gateway(tmp_path)
    _receipted_write(client, token)
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("state evidence missing" in e for e in report.errors), report.errors


def test_covered_write_with_absent_sentinel_verifies(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    gw.emit_state_evidence(cited_receipt=write_id)
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors


def test_denied_write_needs_no_state_evidence(tmp_path):
    gw, client, token = _gateway(tmp_path)
    denied = _run(client, token, {"title": "Offroad"})
    assert denied["decision"] != "allow", denied
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors


def test_absent_sentinel_literal_never_a_fake_digest(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(
        gw,
        {
            "version": "state-evidence/v1",
            "pairing_id": "create_event:get_event",
            "read_tool": "get_event",
            "state_evidence": "absent",
            "evidence_digest": _read_digest(),
            "cited_receipt": write_id,
        },
    )
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("never carries evidence" in e for e in report.errors), report.errors


def test_block_with_neither_evidence_nor_sentinel_fails(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(
        gw,
        {
            "version": "state-evidence/v1",
            "pairing_id": "create_event:get_event",
            "read_tool": "get_event",
            "cited_receipt": write_id,
        },
    )
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("neither evidence nor the absent sentinel" in e for e in report.errors), (
        report.errors
    )


def test_evidence_without_digest_or_handle_fails(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    # No digest and no sentinel: the block states nothing.
    _emit_x_state(gw, _x_state(cited_receipt=write_id, evidence_digest=None))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("neither evidence nor the absent sentinel" in e for e in report.errors), (
        report.errors
    )

    gw2, client2, token2 = _gateway(tmp_path / "second")
    write_id2 = _receipted_write(client2, token2)
    _emit_x_state(gw2, _x_state(cited_receipt=write_id2, handle=None))
    report2 = _verify(tmp_path / "second", gw2)
    assert not report2.valid
    assert any("missing field" in e for e in report2.errors), report2.errors


# -- structural verifier discipline ----------------------------------------


def test_unknown_version_refuses(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(gw, _x_state(cited_receipt=write_id, version="state-evidence/v2"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("version" in e and "unknown" in e for e in report.errors), report.errors


def test_unknown_field_refuses_closed_set(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(gw, _x_state(cited_receipt=write_id, response_text="evt-1 confirmed"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("unknown field" in e for e in report.errors), report.errors


def test_content_like_field_swept_from_x_state(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(gw, _x_state(cited_receipt=write_id, content="evt-1 confirmed"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("content-like" in e for e in report.errors), report.errors


def test_bad_digest_shape_fails(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(gw, _x_state(cited_receipt=write_id, evidence_digest="md5:deadbeef"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("digest" in e for e in report.errors), report.errors


def test_citation_of_a_missing_receipt_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_state(gw, _x_state(cited_receipt="sha256:" + "cd" * 32))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("cites receipt" in e for e in report.errors), report.errors


def test_pairing_linkage_rechecks_registry_and_tools(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)

    # Unknown pairing id: evidence must be registry-bound.
    _emit_x_state(gw, _x_state(cited_receipt=write_id, pairing_id="ghost:pairing"))
    rows = gw.state_pairings()
    report = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()},
        state_pairings=rows,
    ).verify_chain(tmp_path / "receipts.jsonl")
    assert not report.valid
    assert any("not in the pairing registry" in e for e in report.errors), report.errors


def test_pairing_read_tool_mismatch_fails(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(gw, _x_state(cited_receipt=write_id, read_tool="ghost_read"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("read tool" in e for e in report.errors), report.errors


def test_require_field_classes_presence_rechecked(tmp_path):
    """The deliberately dumb v1 depth: presence by name only, never a
    semantic expectation on read outputs."""
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    _emit_x_state(gw, _x_state(cited_receipt=write_id, field_classes=["event_id", "title"]))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("field_classes" in e for e in report.errors), report.errors


# -- v1.0 byte-shape preservation and digest stability --------------------


def test_v10_chain_byte_shape_preserved(tmp_path):
    """Omit-when-absent for non-W1 chains: a pre-W1 config mints gate
    receipts with no x_state key anywhere, and the chain verifies with
    and without a pairing-aware verifier."""
    gw, client, token = _gateway(tmp_path, policy_text=POLICY_WITHOUT_PAIRINGS)
    _receipted_write(client, token)
    report = _verify(tmp_path, gw, pairings={"create_event:get_event": {}})
    assert report.valid, report.errors
    for payload in _chain_payloads(tmp_path):
        assert "x_state" not in payload
    # A pairing-covered write still verifies for a verifier constructed
    # without the registry (the off-deployment residual, structural only).
    report_plain = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")
    assert report_plain.valid, report_plain.errors


def test_evidence_digest_stable_over_identical_reads(tmp_path):
    gw, client, token = _gateway(tmp_path)
    first = _receipted_write(client, token)
    _submit_evidence(gw, first)
    second = _receipted_write(client, token)
    _submit_evidence(gw, second)
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors

    states = [p["x_state"] for p in _chain_payloads(tmp_path) if "x_state" in p]
    assert len(states) == 2
    assert states[0]["evidence_digest"] == states[1]["evidence_digest"]
    assert states[0]["evidence_digest"] == _read_digest()
    assert states[0]["handle"] == "evt-1"
    assert states[0]["cited_receipt"] == first
    assert states[1]["cited_receipt"] == second


# -- definition-drift interplay (W2 + W1, no conflict) --------------------


def test_definition_drift_and_state_evidence_coexist(tmp_path):
    """A changed tool definition receipted as a definition_changed
    finding and pairing evidence for the same write land as both
    findings, no conflict: the verifier pins both families."""
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    gw.emit_finding(
        harness="tool-schema",
        test_id="definition_changed",
        verdict="confirmed",
        cited_receipt=write_id,
        expected_decision="allow",
        actual_decision="allow",
        tool="create_event",
        args_digest="sha256:" + "33" * 32,
        note="definition drift: old and new digests only",
    )
    _submit_evidence(gw, write_id)
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors

    payloads = _chain_payloads(tmp_path)
    finding = next(
        p for p in payloads if p.get("x_finding", {}).get("test_id") == "definition_changed"
    )
    assert finding["x_finding"]["harness"] == "tool-schema"
    assert any("x_state" in p for p in payloads)


# -- gateway mint path: fail-closed where the middleware is fail-open -----


def test_emit_state_evidence_refuses_unknown_pairing(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    digest = _read_digest()
    with pytest.raises(ValueError, match="pairing"):
        gw.emit_state_evidence(
            cited_receipt=write_id,
            pairing_id="ghost:pairing",
            read_tool="get_event",
            evidence_digest=digest,
            handle="evt-1",
            field_classes=["event_id"],
        )
    with pytest.raises(ValueError, match="digest"):
        gw.emit_state_evidence(
            cited_receipt=write_id,
            pairing_id="create_event:get_event",
            read_tool="get_event",
            handle="evt-1",
            field_classes=["event_id"],
        )
    with pytest.raises(ValueError, match="cited_receipt"):
        gw.emit_state_evidence(cited_receipt="not-a-hash")


def test_emit_state_evidence_refuses_without_registry(tmp_path):
    gw, client, token = _gateway(tmp_path, policy_text=POLICY_WITHOUT_PAIRINGS)
    write_id = _receipted_write(client, token)
    digest = _read_digest()
    with pytest.raises(ValueError, match="no state pairings"):
        gw.emit_state_evidence(
            cited_receipt=write_id,
            pairing_id="create_event:get_event",
            read_tool="get_event",
            evidence_digest=digest,
            handle="evt-1",
            field_classes=["event_id"],
        )
    # The honest absent path still mints for an uncovered deployment.
    receipt = gw.emit_state_evidence(cited_receipt=write_id)
    assert receipt


# -- the adapter evidence lane (middleware) --------------------------------


def _chain_lines(tmp_path):
    return len((tmp_path / "receipts.jsonl").read_text().splitlines())


def test_middleware_submits_evidence_post_write(tmp_path):
    """The mint-time path: the runtime hashes the read-back (raw bytes
    sha256), carries handle + pairing_id; the middleware is the seam."""
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    mw = RaucleMiddleware(gateway=gw)
    mw.record_trace_receipt("t1", write_id, "allow")
    mw.submit_state_evidence("create_event", read_response=READ_BACK, trace_id="t1")

    report = _verify(tmp_path, gw)
    assert report.valid, report.errors
    state = next(p["x_state"] for p in _chain_payloads(tmp_path) if "x_state" in p)
    assert state["evidence_digest"] == _read_digest()
    assert state["handle"] == "evt-1"
    assert state["pairing_id"] == "create_event:get_event"
    assert state["cited_receipt"] == write_id


def test_middleware_missing_read_mints_absent_and_finding(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    before = _chain_lines(tmp_path)
    mw = RaucleMiddleware(gateway=gw)
    mw.record_trace_receipt("t1", write_id, "allow")
    mw.submit_state_evidence("create_event", read_response=None, trace_id="t1")

    report = _verify(tmp_path, gw)
    assert report.valid, report.errors
    assert _chain_lines(tmp_path) == before + 2  # absent receipt + advisory finding

    payloads = _chain_payloads(tmp_path)
    state = next(p["x_state"] for p in payloads if "x_state" in p)
    assert state["state_evidence"] == "absent"
    finding = next(
        p["x_finding"]
        for p in payloads
        if p.get("x_finding", {}).get("test_id") == "state_evidence_missing"
    )
    assert finding["harness"] == "state-verification"
    assert finding["cited_receipt"] == write_id


def test_middleware_unparseable_response_falls_back_to_absent(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    mw = RaucleMiddleware(gateway=gw)
    mw.record_trace_receipt("t1", write_id, "allow")
    mw.submit_state_evidence("create_event", read_response=b"not json", trace_id="t1")

    report = _verify(tmp_path, gw)
    assert report.valid, report.errors
    state = next(p["x_state"] for p in _chain_payloads(tmp_path) if "x_state" in p)
    assert state["state_evidence"] == "absent"


def test_middleware_uncovered_tool_absent_without_pairing_id(tmp_path):
    gw, client, token = _gateway(tmp_path)
    write_id = _receipted_write(client, token)
    mw = RaucleMiddleware(gateway=gw)
    mw.record_trace_receipt("t1", write_id, "allow")
    mw.submit_state_evidence("ghost_tool", read_response=READ_BACK, trace_id="t1")

    report = _verify(tmp_path, gw)
    assert report.valid, report.errors
    state = next(p["x_state"] for p in _chain_payloads(tmp_path) if "x_state" in p)
    assert state["state_evidence"] == "absent"
    assert "pairing_id" not in state


def test_middleware_uncited_trace_mints_nothing(tmp_path):
    gw, client, token = _gateway(tmp_path)
    _receipted_write(client, token)
    before = _chain_lines(tmp_path)
    mw = RaucleMiddleware(gateway=gw)
    mw.submit_state_evidence("create_event", read_response=READ_BACK, trace_id="unbound")
    assert _chain_lines(tmp_path) == before
