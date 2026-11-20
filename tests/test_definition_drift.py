"""EPIC W, lane W2: definition drift as replay-verifiable evidence.

Spec: docs/spec/provenance/v1.2/definition-drift.md. The gate binds a
definition digest over each registered tool schema at load time (X1's
ToolSchemaRegistry); every gate receipt for a schema-registered tool
carries the digest in a versioned ``x_gate.tool_definition`` block, so a
third party holding the same manifest re-derives WHICH definition the
decision was made against. A manifest reload that observes a changed
digest emits a receipted ``definition_changed`` finding (old and new
digests only, never schema content). The verifier re-checks every block
structurally, refuses unknown versions and vantages with named errors,
and re-computes the LATEST block's digest per tool against the on-disk
manifest (the deployment's registry state); historical blocks may carry
superseded digests, because that is the drift evidence itself. Receipts
without the block stay byte-identical to their pre-W2 shape.
"""

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GateReceiptContext, GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app, create_gateway_app
from raucle.provenance import ProvenanceVerifier
from raucle.tool_schema import (
    SchemaPolicyLoadError,
    ToolSchemaRegistry,
    _definition_digest,
)
from raucle.trust_registry import TrustRegistry

ADMIN_KEY = "admin-key-for-tests-0123456789"

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""

SCHEMA_V1 = {
    "type": "object",
    "properties": {
        "account": {"type": "string"},
        "rows": {"type": "number"},
    },
}

SCHEMA_V2 = {
    "type": "object",
    "properties": {
        "account": {"type": "string"},
        "rows": {"type": "number"},
        "format": {"type": "string"},
    },
}


def _manifest(tmp_path, schema=SCHEMA_V1, name="tools-manifest.json"):
    path = tmp_path / name
    path.write_text(json.dumps([{"name": "export_records", "inputSchema": schema}]))
    return path


def _config(tmp_path):
    return GatewayConfig(
        host="127.0.0.1",
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )


def _setup(tmp_path, schema=SCHEMA_V1):
    """A token-mode gateway whose tool schema manifest is loaded at boot."""
    config = _config(tmp_path)
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(POLICY)
    config.gate_auth = "token"
    config.tool_schema_manifest = str(_manifest(tmp_path, schema))

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    root = issuer.mint(
        agent_id="agent:svc",
        tool="export_records",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
        ttl_seconds=600,
    )
    ledger.register(root, "agent:svc", verifying_key=issuer)
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")
    config.delegations_file = str(tmp_path / "delegations.jsonl")

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, root


def _gate(client, token, args):
    return client.post(
        "/gate",
        json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )


def _payload_of(envelope):
    seg = envelope["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def _envelopes(tmp_path):
    store = tmp_path / "receipts.jsonl"
    if not store.exists():
        # No receipt was ever minted: an honest empty chain, never a
        # fabricated one.
        return []
    lines = store.read_text().strip().splitlines()
    return [json.loads(ln) for ln in lines]


def _payloads(tmp_path):
    return [_payload_of(env) for env in _envelopes(tmp_path)]


def _verify(gw, tmp_path):
    return ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")


# ---------------------------------------------------------------------------
# Registry: the digest bound at registration (bind time)
# ---------------------------------------------------------------------------


def test_definition_digest_stable_across_registry_instances():
    """The digest is a function of the schema content, not the process:
    two fresh registries (a restart) bind the same definition digest."""
    a = ToolSchemaRegistry()
    b = ToolSchemaRegistry()
    a.register("export_records", dict(SCHEMA_V1))
    b.register("export_records", dict(SCHEMA_V1))
    assert a.definition_digest("export_records") == b.definition_digest("export_records")
    assert a.definition_manifest("export_records") == ""


def test_definition_digest_is_canonical_over_key_order():
    """Two manifests whose properties appear in a different file order
    parse to the same content and bind the same digest: the digest names
    the definition, never the file's byte layout."""
    reordered = {
        "properties": {"rows": {"type": "number"}, "account": {"type": "string"}},
        "type": "object",
    }
    a = ToolSchemaRegistry()
    b = ToolSchemaRegistry()
    a.register("t", dict(SCHEMA_V1))
    b.register("t", reordered)
    assert a.definition_digest("t") == b.definition_digest("t")


def test_definition_digest_tracks_the_manifest_source():
    """The registry records which manifest each definition came from, so
    receipts can name the pin the verifier recomputes against."""
    reg = ToolSchemaRegistry()
    reg.register_from_mcp_tools(
        [{"name": "export_records", "inputSchema": dict(SCHEMA_V1)}],
        manifest="/etc/raucle/tools.json",
    )
    assert reg.definition_manifest("export_records") == "/etc/raucle/tools.json"
    assert reg.has_schema("export_records")


def test_reload_observes_changed_digest_and_supersedes():
    """The reload path recomputes digests: a changed definition is
    superseded in the registry and the drift record carries old and new
    digests only (never schema content)."""
    reg = ToolSchemaRegistry()
    reg.register("export_records", dict(SCHEMA_V1), manifest="m.json")
    first = reg.definition_digest("export_records")
    drift = reg.reload_from_mcp_tools(
        [{"name": "export_records", "inputSchema": dict(SCHEMA_V2)}], manifest="m.json"
    )
    assert reg.definition_digest("export_records") != first
    assert len(drift) == 1
    assert drift[0]["tool"] == "export_records"
    assert drift[0]["old_definition_digest"] == first
    assert drift[0]["new_definition_digest"] == reg.definition_digest("export_records")
    assert drift[0]["manifest"] == "m.json"


def test_reload_without_change_emits_no_drift():
    reg = ToolSchemaRegistry()
    reg.register("export_records", dict(SCHEMA_V1), manifest="m.json")
    drift = reg.reload_from_mcp_tools(
        [{"name": "export_records", "inputSchema": dict(SCHEMA_V1)}], manifest="m.json"
    )
    assert drift == []


def test_register_changed_schema_load_path_still_refuses():
    """X1 unchanged (extend, do not fork): the load-time bind path
    refuses a conflicting schema with the named error; only the explicit
    reload path observes drift."""
    reg = ToolSchemaRegistry()
    reg.register("export_records", dict(SCHEMA_V1))
    with pytest.raises(SchemaPolicyLoadError):
        reg.register("export_records", dict(SCHEMA_V2))


# ---------------------------------------------------------------------------
# Emitter: the block rides x_gate (v1.2), absent when unregistered
# ---------------------------------------------------------------------------


def test_receipt_carries_tool_definition_block(tmp_path):
    """The acceptance: a gate decision for a schema-registered tool binds
    the versioned definition block - digest, manifest path, honest
    vantage none - and the digest re-derives from the on-disk manifest."""
    gw, client, token = _setup(tmp_path)
    assert _gate(client, token, {"account": "ACC-001"}).json()["decision"] == "allow"

    payload = _payloads(tmp_path)[0]
    block = payload["x_gate"]["tool_definition"]
    assert block["version"] == "tool-definition/v1"
    assert block["definition_manifest"] == gw.config.tool_schema_manifest
    assert block["definition_vantage"] == "none"
    manifest = json.loads(Path(gw.config.tool_schema_manifest).read_text())
    assert block["definition_digest"] == _definition_digest(manifest[0]["inputSchema"])
    report = _verify(gw, tmp_path)
    assert report.valid, report.errors


def test_receipt_without_registered_schema_omits_block(tmp_path):
    """v1.0 byte-shape preservation: a tool with no registered schema
    mints a receipt whose x_gate carries no tool_definition key at all
    (additive extension, historical shape untouched)."""
    gw, client, token = _setup(tmp_path)
    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="deny",
            reason="test",
            tool="unregistered_tool",
            agent_id="agent:svc",
            args={},
            policy=None,
            latency_us=1,
            source="agent:svc",
            destination="test",
            trace_id="trace-1",
        )
    )
    payload = _payloads(tmp_path)[-1]
    assert "tool_definition" not in payload["x_gate"]
    report = _verify(gw, tmp_path)
    assert report.valid, report.errors


def test_malformed_manifest_refuses_boot(tmp_path):
    """Fail-closed load (X1 doctrine): a manifest the deployment cannot
    interpret is a named load-time error, never a silently empty
    registry."""
    bad = tmp_path / "tools.json"
    bad.write_text("{not json")
    config = _config(tmp_path)
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(POLICY)
    config.tool_schema_manifest = str(bad)
    with pytest.raises(SchemaPolicyLoadError):
        RaucleGateway(config)


# ---------------------------------------------------------------------------
# Reload-drift findings (receipted, cited, no content)
# ---------------------------------------------------------------------------


def test_reload_changed_schema_emits_receipted_finding(tmp_path):
    """The W2 acceptance: a manifest reload that changes a registered
    tool's schema emits a receipted definition_changed finding citing the
    last gate receipt for that tool; receipts before and after the reload
    carry different digests; the chain verifies offline with the finding
    in it."""
    gw, client, token = _setup(tmp_path)
    assert _gate(client, token, {"account": "ACC-001"}).json()["decision"] == "allow"
    first_digest = _payloads(tmp_path)[0]["x_gate"]["tool_definition"]["definition_digest"]
    first_hash = _envelopes(tmp_path)[0]["receipt_hash"]

    _manifest(tmp_path, SCHEMA_V2)  # the operator rewrites the manifest
    result = gw.reload_tool_schemas()
    assert result["status"] == "ok"
    assert len(result["drift"]) == 1
    drift = result["drift"][0]
    assert drift["tool"] == "export_records"
    assert drift["old_definition_digest"] == first_digest

    assert _gate(client, token, {"account": "ACC-001"}).json()["decision"] == "allow"
    payloads = _payloads(tmp_path)
    second_digest = payloads[-1]["x_gate"]["tool_definition"]["definition_digest"]
    assert second_digest != first_digest

    findings = [p for p in payloads if "x_finding" in p]
    assert len(findings) == 1
    finding = findings[0]["x_finding"]
    assert finding["harness"] == "tool-schema"
    assert finding["test_id"] == "definition_changed"
    assert finding["verdict"] == "confirmed"
    assert finding["cited_receipt"] == first_hash
    # Bounded disclosure: old and new digests only, never schema content.
    assert first_digest in finding["note"]
    assert second_digest in finding["note"]
    assert drift["finding"] == _envelopes(tmp_path)[1]["receipt_hash"]

    report = _verify(gw, tmp_path)
    assert report.valid, report.errors


def test_reload_drift_without_prior_receipt_skips_finding_honestly(tmp_path):
    """No prior gate receipt means no citation: the x_finding contract
    forbids ghost citations, so the drift is recorded in the reload
    result and no finding is minted, never a fabricated citation."""
    gw, client, token = _setup(tmp_path)
    _manifest(tmp_path, SCHEMA_V2)
    result = gw.reload_tool_schemas()
    assert result["status"] == "ok"
    assert len(result["drift"]) == 1
    assert result["drift"][0]["finding"] == "skipped_no_prior_receipt"
    # Nothing was minted at all: no gate receipt, no finding, the store
    # file was never created (a finding without evidence is a ghost).
    assert not (tmp_path / "receipts.jsonl").exists()
    assert not [p for p in _payloads(tmp_path) if "x_finding" in p]


def test_reload_without_manifest_configured_is_a_named_error(tmp_path):
    config = _config(tmp_path)
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(POLICY)
    gw = RaucleGateway(config)
    result = gw.reload_tool_schemas()
    assert result["status"] == "error"
    assert "no tool schema manifest configured" in result["message"]


def test_tool_schema_manifest_from_env(monkeypatch, tmp_path):
    """Config wiring round-trip: the env var lands on the field."""
    monkeypatch.setenv("RAUCLE_TOOL_SCHEMA_MANIFEST", str(tmp_path / "tools.json"))
    assert GatewayConfig.from_env().tool_schema_manifest == str(tmp_path / "tools.json")


# ---------------------------------------------------------------------------
# Verifier (forged blocks via the emitter seam, K3/DLP test pattern)
# ---------------------------------------------------------------------------


def _valid_block(manifest, **overrides):
    """A structurally valid tool_definition block pinned to a real
    manifest, with fields overridable to produce deliberate violations."""
    digest = _definition_digest(SCHEMA_V1)
    base = {
        "version": "tool-definition/v1",
        "definition_digest": digest,
        "definition_manifest": str(manifest),
        "definition_vantage": "none",
    }
    base.update(overrides)
    for key, value in list(overrides.items()):
        if value is None:
            base.pop(key)
    return base


def _forge(tmp_path, monkeypatch, *blocks, schema=SCHEMA_V1):
    """Mint one signed gate receipt per ``tool_definition`` block, then
    verify the chain. The manifest on disk is written from *schema*: the
    emitter is patched, so only the verifier's recompute reads it."""
    config = _config(tmp_path)
    config.tool_schema_manifest = str(_manifest(tmp_path, schema))
    gw = RaucleGateway(config)
    pending = iter(blocks)
    monkeypatch.setattr(gw, "_tool_definition_block", lambda tool: next(pending))
    for _ in blocks:
        gw._emit_gate_receipt(
            GateReceiptContext(
                decision="allow",
                reason="ok",
                tool="export_records",
                agent_id="agent:svc",
                args={},
                policy=None,
                latency_us=1,
                source="agent:svc",
                destination="test",
                trace_id="trace-1",
            )
        )
    return ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")


def test_valid_block_over_real_manifest_verifies(tmp_path, monkeypatch):
    report = _forge(tmp_path, monkeypatch, _valid_block(_manifest(tmp_path)))
    assert report.valid, report.errors


def test_unknown_tool_definition_version_refuses(tmp_path, monkeypatch):
    """Version gate: an unknown version refuses the receipt with a named
    error, never a skip."""
    report = _forge(
        tmp_path, monkeypatch, _valid_block(_manifest(tmp_path), version="tool-definition/v2")
    )
    assert not report.valid
    assert any("tool-definition/v2" in e and "version" in e for e in report.errors), report.errors


def test_unknown_vantage_refuses(tmp_path, monkeypatch):
    """The vantage vocabulary is closed: 'none' is the only honest value
    until the in-path MCP gateway exists; a served vantage is refused."""
    report = _forge(
        tmp_path, monkeypatch, _valid_block(_manifest(tmp_path), definition_vantage="served")
    )
    assert not report.valid
    assert any("vantage" in e for e in report.errors), report.errors


def test_missing_required_field_fails(tmp_path, monkeypatch):
    report = _forge(
        tmp_path, monkeypatch, _valid_block(_manifest(tmp_path), definition_digest=None)
    )
    assert not report.valid
    assert any("missing field" in e and "definition_digest" in e for e in report.errors)


def test_unknown_field_fails_closed_set(tmp_path, monkeypatch):
    block = _valid_block(_manifest(tmp_path))
    block["ruleset_hash"] = "sha256:" + "ab" * 32
    report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("unknown field" in e for e in report.errors), report.errors


def test_content_like_field_is_swept(tmp_path, monkeypatch):
    """The shared forbidden-field sweep: a leaky emitter cannot hide
    schema content inside the block."""
    block = _valid_block(_manifest(tmp_path))
    block["content"] = {"properties": {"account": {"type": "string"}}}
    report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("content-like field" in e for e in report.errors), report.errors


def test_digest_not_rederiving_from_manifest_fails(tmp_path, monkeypatch):
    """Pin discipline: when the manifest is readable the digest MUST
    re-derive from the tool's registered inputSchema inside it."""
    block = _valid_block(_manifest(tmp_path))
    block["definition_digest"] = _definition_digest(SCHEMA_V2)
    report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("does not re-derive" in e for e in report.errors), report.errors


def test_manifest_without_the_receipts_tool_fails(tmp_path, monkeypatch):
    """A receipt claiming a definition a readable manifest does not
    carry is drift evidence, and fails with a named error."""
    other = _manifest(tmp_path, SCHEMA_V1, name="other.json")
    other.write_text(json.dumps([{"name": "other_tool", "inputSchema": dict(SCHEMA_V1)}]))
    block = _valid_block(other)
    report = _forge(tmp_path, monkeypatch, block)
    assert not report.valid
    assert any("does not declare the receipt's tool" in e for e in report.errors), report.errors


def test_unreadable_manifest_leaves_the_block_structural(tmp_path, monkeypatch):
    """Off-deployment verification (documented residual): the manifest
    file absent from the verifier's host means no recompute; the block's
    structure still fully re-checks and the chain stays valid."""
    block = _valid_block(tmp_path / "absent.json")
    report = _forge(tmp_path, monkeypatch, block)
    assert report.valid, report.errors


def test_historical_digest_passes_when_latest_matches(tmp_path, monkeypatch):
    """Drift is the point: an older receipt may carry a superseded digest
    (that IS the drift evidence); the pin discipline binds the LATEST
    block per tool to the on-disk manifest, so a before/after-drift chain
    verifies offline."""
    manifest = _manifest(tmp_path, SCHEMA_V2)
    report = _forge(
        tmp_path,
        monkeypatch,
        _valid_block(manifest),  # the pre-drift definition (superseded)
        _valid_block(manifest, definition_digest=_definition_digest(SCHEMA_V2)),
        schema=SCHEMA_V2,
    )
    assert report.valid, report.errors


def test_latest_digest_mismatch_names_the_latest_line(tmp_path, monkeypatch):
    """The pin binds the newest block: a latest digest that does not
    re-derive from the readable manifest fails with the line of the
    LATEST block, the chain's final decision being the one the
    deployment's registry state must answer for."""
    manifest = _manifest(tmp_path, SCHEMA_V1)
    report = _forge(
        tmp_path,
        monkeypatch,
        _valid_block(manifest),
        _valid_block(manifest, definition_digest=_definition_digest(SCHEMA_V2)),
    )
    assert not report.valid
    assert any("line 2" in e and "does not re-derive" in e for e in report.errors), report.errors


# ---------------------------------------------------------------------------
# Operability: the admin reload route and the split-brain guard
# ---------------------------------------------------------------------------


def test_reload_with_post_boot_manifest_names_restart(tmp_path):
    """Split-brain guard: a manifest configured AFTER construction cannot
    be bound by a reload (the CapabilityGate holds the registry bound at
    construction, and rebinding would split receipts from the enforcement
    path), so the reload names the restart instead."""
    config = _config(tmp_path)
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(POLICY)
    config.policy_file = policy_path
    gw = RaucleGateway(config)
    _manifest(tmp_path)  # the manifest appears after boot
    gw.config.tool_schema_manifest = str(tmp_path / "tools-manifest.json")
    result = gw.reload_tool_schemas()
    assert result["status"] == "error"
    assert "restart" in result["message"]


def test_admin_reload_route_receipts_the_drift(tmp_path):
    """The operable path: POST /api/tool-schemas/reload re-reads the
    configured manifest through the admin app and the drift finding lands
    in the chain, citable and verifiable offline."""
    gw, client, token = _setup(tmp_path)
    assert _gate(client, token, {"account": "ACC-001"}).json()["decision"] == "allow"
    _manifest(tmp_path, SCHEMA_V2)  # the operator rewrites the manifest
    users = UserManager()
    users.add_user(ADMIN_KEY, "admin", "Admin")
    admin = TestClient(create_admin_app(gw, users))
    resp = admin.post("/api/tool-schemas/reload", headers={"Authorization": ADMIN_KEY})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert len(body["drift"]) == 1
    assert body["drift"][0]["finding"].startswith("sha256:")
    report = _verify(gw, tmp_path)
    assert report.valid, report.errors
