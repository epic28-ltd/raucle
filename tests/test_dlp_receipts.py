"""EPIC Q, lane Q-7a: content DLP receipts (x_dlp) as replay-verifiable evidence.

An in-path content scanner (the enterprise LLM endpoint proxy, a client of
the gateway) reports each scan decision as a signed receipt carrying an
x_dlp extension: digests, class names and counts only, never content. The
verifier re-checks the receipt offline with no scanner present: structure,
bounded class vocabulary, digest shape, action/redaction consistency and
chain membership. A payload carrying a content-like field fails, so a
leaky emitter cannot hide matched values inside signed evidence.
"""

import base64 as _b64
import hashlib
import json

import pytest

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier
from raucle.trust_registry import TrustRegistry

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


def _gateway(tmp_path):
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
    config.policy_file.write_text(POLICY)
    config.gate_auth = "token"

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
    config.registry_path = str(tmp_path / "registry.jsonl")
    config.delegations_file = str(tmp_path / "delegations.jsonl")

    from fastapi.testclient import TestClient

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, root


def _run(client, token, args):
    resp = client.post(
        "/gate",
        json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )
    return resp.json()


def _verify(tmp_path, gw):
    report = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")
    return report


def _dlp(**overrides):
    """A structurally valid x_dlp extension, with fields overridable to
    produce deliberate violations in the structural tests."""
    base = {
        "action": "allowed_with_findings",
        "scan_id": "scan:" + "ab" * 16,
        "route": {"source": "agent:svc", "destination": "llm:endpoint-1"},
        "direction": "egress_to_model",
        "content_sha256": "sha256:" + "11" * 32,
        "matched_classes": ["pii_email"],
        "span_counts": {"pii_email": 2},
        "rule_id": "dlp-default",
    }
    base.update(overrides)
    for key, value in list(overrides.items()):
        if value is None:
            base.pop(key)
    return base


def _emit_x_dlp(gw, extension, cited_receipt=None, verdict=None):
    cited = cited_receipt if cited_receipt is not None else ""
    if cited:
        extension = dict(extension, cited_receipt=cited)
    return gw._emit_authority_receipt(
        verdict=verdict or extension["action"],
        extension_key="x_dlp",
        extension=extension,
    )


def test_valid_x_dlp_with_cited_decision_receipt_verifies(tmp_path):
    """The acceptance: a valid x_dlp receipt citing a real decision
    receipt verifies offline through ProvenanceVerifier, and the
    extension lives INSIDE the signed payload."""
    gw, client, token = _gateway(tmp_path)
    allowed = _run(client, token, {"account": "ACC-001"})
    assert allowed["decision"] == "allow"

    _emit_x_dlp(gw, _dlp(), cited_receipt=allowed["receipt_id"])
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors

    line = (tmp_path / "receipts.jsonl").read_text().splitlines()[-1]
    seg = line.split(".")[1]
    seg += "=" * (-len(seg) % 4)
    payload = json.loads(_b64.urlsafe_b64decode(seg))
    assert "x_dlp" in payload


def test_content_like_field_fails_with_named_error(tmp_path):
    gw, client, token = _gateway(tmp_path)
    _run(client, token, {"account": "ACC-001"})
    _emit_x_dlp(gw, _dlp(matched_value="4111111111111111"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("content-like" in e for e in report.errors), report.errors


def test_missing_required_field_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(gw, _dlp(content_sha256=None))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("missing field" in e for e in report.errors), report.errors


def test_bad_digest_shape_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(gw, _dlp(content_sha256="md5:deadbeef"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("digest" in e for e in report.errors), report.errors


def test_unknown_matched_class_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(gw, _dlp(matched_classes=["pii_favourite_colour"], span_counts={}))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("unknown class" in e for e in report.errors), report.errors


def test_negative_span_count_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(gw, _dlp(span_counts={"pii_email": -1}))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("span_counts" in e for e in report.errors), report.errors


def test_span_count_without_matching_class_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(
        gw,
        _dlp(matched_classes=[], span_counts={"pii_email": 2}),
    )
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("span_counts" in e for e in report.errors), report.errors


def test_redaction_without_post_redaction_digest_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(gw, _dlp(action="redacted"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("redacted_content_sha256" in e for e in report.errors), report.errors


def test_digest_on_non_redaction_action_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(
        gw,
        _dlp(action="blocked", redacted_content_sha256="sha256:" + "22" * 32),
    )
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("redacted_content_sha256" in e for e in report.errors), report.errors


def test_unknown_direction_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(gw, _dlp(direction="sideways"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("direction" in e for e in report.errors), report.errors


def test_unknown_action_fails(tmp_path):
    gw, _client, _token = _gateway(tmp_path)
    _emit_x_dlp(gw, _dlp(action="squinted"))
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("action" in e for e in report.errors), report.errors


def test_citation_of_a_missing_receipt_fails(tmp_path):
    gw, client, token = _gateway(tmp_path)
    _run(client, token, {"account": "ACC-001"})
    _emit_x_dlp(gw, _dlp(), cited_receipt="sha256:" + "ff" * 32)
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("not in the chain" in e for e in report.errors), report.errors


def test_legacy_chain_without_x_dlp_verifies_unchanged(tmp_path):
    """Byte-compat: a chain with no x_dlp extension verifies exactly as
    before; the x_dlp re-check is additive."""
    gw, client, token = _gateway(tmp_path)
    allowed = _run(client, token, {"account": "ACC-001"})
    assert allowed["decision"] == "allow"
    gw.emit_finding(
        harness="qm",
        test_id="baseline:no-dlp",
        verdict="expected_pass",
        cited_receipt=allowed["receipt_id"],
        expected_decision="allow",
        actual_decision="allow",
        tool="export_records",
        args_digest=allowed["args_hash"],
    )
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors


def test_tampered_x_dlp_payload_fails(tmp_path):
    gw, client, token = _gateway(tmp_path)
    allowed = _run(client, token, {"account": "ACC-001"})
    _emit_x_dlp(gw, _dlp(), cited_receipt=allowed["receipt_id"])

    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    dlp_line = lines[-1]
    header, seg, sig = dlp_line.split(".")
    from raucle.provenance import _b64url_encode, _canonical_json

    payload = json.loads(_b64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    payload["x_dlp"]["span_counts"] = {"pii_card": 99}
    seg2 = _b64url_encode(_canonical_json(payload))
    lines[-1] = f"{header}.{seg2}.{sig}"
    (tmp_path / "receipts.jsonl").write_text("\n".join(lines) + "\n")

    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("x_dlp" in e for e in report.errors) or any(
        "signature" in e.lower() for e in report.errors
    ), report.errors


def test_emit_dlp_finding_public_surface(tmp_path):
    """emit_dlp_finding is the public emitter the proxy uses: it mints an
    x_dlp authority receipt (verdict naming the action, ruleset hash bound
    to the extension), refuses out-of-vocabulary inputs, and binds
    content_sha256 to the digest of the fixture payload supplied
    separately."""
    gw, _client, _token = _gateway(tmp_path)
    payload = b"invoice total 42.00 reply to finance@corp.example"
    expected_digest = "sha256:" + hashlib.sha256(payload).hexdigest()

    receipt_id = gw.emit_dlp_finding(
        scan_id="scan:" + "cd" * 16,
        route={"source": "agent:svc", "destination": "llm:endpoint-1"},
        direction="egress_to_model",
        content_sha256=expected_digest,
        matched_classes=["pii_email"],
        span_counts={"pii_email": 1},
        action="redacted",
        redacted_content_sha256="sha256:" + "33" * 32,
        rule_id="dlp-default",
    )
    assert receipt_id

    line = (tmp_path / "receipts.jsonl").read_text().splitlines()[-1]
    envelope = json.loads(line)
    assert envelope["receipt_hash"] == receipt_id
    receipt_jws = json.loads(line)["jws"] if line.startswith("{") else line
    seg = receipt_jws.split(".")[1]
    decoded = json.loads(_b64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    x_dlp = decoded["x_dlp"]
    assert x_dlp["content_sha256"] == expected_digest
    assert decoded["guardrail_verdict"] == "redacted"
    assert decoded["ruleset_hash"] == decoded["input_hash"]

    # closed vocabularies at emission
    with pytest.raises(ValueError):
        gw.emit_dlp_finding(
            scan_id="scan:" + "ee" * 16,
            route={"source": "a", "destination": "b"},
            direction="egress_to_model",
            content_sha256="sha256:" + "44" * 32,
            matched_classes=["pii_favourite_colour"],
            span_counts={},
            action="allowed_with_findings",
            rule_id="r",
        )
    with pytest.raises(ValueError):
        gw.emit_dlp_finding(
            scan_id="scan:" + "ee" * 16,
            route={"source": "a", "destination": "b"},
            direction="egress_to_model",
            content_sha256="sha256:" + "44" * 32,
            matched_classes=[],
            span_counts={},
            action="shredded",
            rule_id="r",
        )
