"""RED-013 / RED-017 regression gates (raucle-agent-red corpora findings).

The red-team corpora found two escape classes through the gate:

- RED-013 ``http-oversize-accepted``: an oversized ``/gate`` payload was
  processed to a full verdict with no size bound. Now the gate rejects
  it pre-gate with HTTP 413 before any policy processing.
- RED-017 ``mcp-uri-traversal-allowed`` (x3): a ``file://`` resource URI
  escaping a ``starts_with`` prefix policy was allowed, because the
  prefix operator matches the literal string while the URI layer resolves
  dot segments / percent-encoding the policy text never sees. The gate
  now canonicalises file:// URIs before the prefix match, so every
  documented escape variant lands as an attributable DENIED verdict.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app

# The three documented RED-017 escape payloads plus the in-scope control.
RED_017_ESCAPES = [
    "file:///ledger/coversheets/../../etc/passwd",
    "file:///ledger/coversheets/././..",
    "file:///ledger/coversheets/%2e%2e/%2e%2e/secrets",
]
RED_017_INSCOPE = "file:///ledger/coversheets/x"

_PREFIX_POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: read_resource
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      starts_with:
        uri: 'file:///ledger/coversheets/'
  - tool: unbounded_tool
    agent_id: agent:big
    ttl_seconds: 300
    constraints:
      starts_with:
        marker: 'ok'
"""


@pytest.fixture
def gate(tmp_path) -> tuple[TestClient, Any]:
    policy = tmp_path / "policies.yaml"
    policy.write_text(_PREFIX_POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_backend="local",
    )
    return TestClient(create_gateway_app(RaucleGateway(config))), tmp_path


def _post_gate(client, tool: str, args: dict, agent_id: str):
    return client.post(
        "/gate",
        json={"tool": tool, "args": args, "agent_id": agent_id},
    )


# ---------------------------------------------------------------------------
# RED-013: oversized payloads are rejected, never processed to a verdict
# ---------------------------------------------------------------------------


def test_red013_oversized_payload_rejected_413(gate):
    client, _ = gate
    resp = _post_gate(
        client, "unbounded_tool", {"marker": "ok", "blob": "A" * 2_100_000}, "agent:big"
    )
    assert resp.status_code == 413
    assert "size bound" in resp.text


def test_red013_normal_payload_still_processes(gate):
    client, _ = gate
    resp = _post_gate(client, "unbounded_tool", {"marker": "ok", "blob": "A" * 1000}, "agent:big")
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"


def test_red013_limit_is_env_configurable(gate, monkeypatch):
    client, _ = gate
    monkeypatch.setenv("RAUCLE_GATE_MAX_PAYLOAD_CHARS", "500")
    resp = _post_gate(client, "unbounded_tool", {"marker": "ok", "blob": "B" * 600}, "agent:big")
    assert resp.status_code == 413
    resp = _post_gate(client, "unbounded_tool", {"marker": "ok", "blob": "A" * 10}, "agent:big")
    assert resp.status_code == 200


def test_red013_overbound_request_writes_no_receipt(gate):
    """Nothing about the rejected payload reaches the gate receipt trail."""
    client, _ = gate
    resp = _post_gate(client, "unbounded_tool", {"blob": "A" * 1_500_000}, "agent:big")
    assert resp.status_code == 413
    assert "decision" not in resp.json()


# ---------------------------------------------------------------------------
# RED-017 (x3): file:// prefix escapes deny with the documented outcome
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("uri", RED_017_ESCAPES, ids=["dots-parent", "dot-slash-dots", "encoded"])
def test_red017_file_uri_escapes_are_denied(gate, uri):
    client, _ = gate
    resp = _post_gate(client, "read_resource", {"uri": uri}, "agent:svc")
    assert resp.status_code == 200
    body = resp.json()
    # The documented audit outcome: an ATTRIBUTABLE denial — decision deny,
    # reason naming the constraint violation, receipt present.
    assert body["decision"] == "deny"
    assert "does not start with" in body["reason"]
    assert body["receipt_id"] is not None


def test_red017_inscope_resource_still_allowed(gate):
    client, _ = gate
    resp = _post_gate(client, "read_resource", {"uri": RED_017_INSCOPE}, "agent:svc")
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"


def test_red017_canonical_match_ignores_harmless_dot_segments(gate):
    """`./` inside the prefix is resolved, not denied: canonical compare."""
    client, _ = gate
    resp = _post_gate(
        client, "read_resource", {"uri": "file:///ledger/coversheets/./x"}, "agent:svc"
    )
    assert resp.json()["decision"] == "allow"


def test_red017_denial_reason_carries_resolved_uri(gate):
    """Bounded disclosure: the deny reason shows the RESOLVED escape."""
    client, _ = gate
    uri = "file:///ledger/coversheets/%2e%2e/%2e%2e/secrets"
    resp = _post_gate(client, "read_resource", {"uri": uri}, "agent:svc")
    assert "/secrets" in resp.json()["reason"]


def test_red017_non_file_prefixes_unchanged(gate):
    """The literal-prefix contract for non-file:// values is untouched."""
    client, _ = gate
    resp = _post_gate(client, "unbounded_tool", {"marker": "ok-prefix"}, "agent:big")
    assert resp.json()["decision"] == "allow"
    resp = _post_gate(client, "unbounded_tool", {"marker": "nope-prefix"}, "agent:big")
    assert resp.json()["decision"] == "deny"


def test_red017_unit_canonicalisation_contract():
    from raucle.capability import _canonical_file_uri, _check_starts_with

    assert (
        _canonical_file_uri("file:///ledger/coversheets/../../etc/passwd") == "file:///etc/passwd"
    )
    assert _canonical_file_uri("file:///ledger/coversheets/%2e%2e/x") == "file:///ledger/x"
    assert _canonical_file_uri("https://example.com/x") is None
    assert _canonical_file_uri("file:///ledger/out/../in") == "file:///ledger/in"
    c = {"starts_with": {"uri": "file:///ledger/coversheets/"}}
    assert _check_starts_with(c, {"uri": "file:///ledger/coversheets/deep/x"}) is None
    denial = _check_starts_with(c, {"uri": RED_017_ESCAPES[0]})
    assert denial is not None
    assert "does not start with" in denial


def test_red017_denials_bind_a_receipt_their_peer_allows_miss(gate):
    """End-to-end: the denies are recorded in the gate's receipt trail."""
    client, tmp_path = gate
    for uri in RED_017_ESCAPES:
        resp = _post_gate(client, "read_resource", {"uri": uri}, "agent:svc")
        assert resp.json()["decision"] == "deny"
    resp = _post_gate(client, "read_resource", {"uri": RED_017_INSCOPE}, "agent:svc")
    assert resp.json()["decision"] == "allow"
    receipts = tmp_path / "receipts.jsonl"
    assert receipts.exists()
    parsed = [json.loads(line) for line in receipts.read_text().splitlines() if line.strip()]
    assert parsed
