"""O2 deny-retry guidance: deterministic, additive, honest absence.

Unit leg: the derivation from a capability token dict, the additive
attach contract (verdict bytes untouched), the schema conformance and
the honest-absence cases. Live leg: the real raucle-gate deployment
artifact against a real gate socket - deny out-of-whitelist, read the
retry_guidance shape, retry within the declared alternatives, allowed by
the SAME authority with no policy loosening.
"""

import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.integrations.qm import QmHarnessBridge
from raucle.integrations.retry_guidance import (
    RETRY_GUIDANCE_SCHEMA,
    SCHEMA_NAME,
    attach_retry_guidance,
    retry_guidance,
)
from raucle.trust_registry import TrustRegistry

_SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "qm"
    / "tools"
    / "raucle-gate"
    / "raucle-gate"
)
assert _SCRIPT.exists(), _SCRIPT

_TOKEN = {
    "tool": "lookup_balance",
    "constraints": {
        "allowed_values": {"account": ["ACC-001", "ACC-002"]},
        "required_present": ["account"],
        "forbidden_values": {"memo": ["gift"]},
        "max_value": {"amount": 5000},
        "min_value": {"amount": 0},
    },
}

_EXPECTED = {
    "schema": SCHEMA_NAME,
    "permitted_actions": [
        {
            "tool": "lookup_balance",
            "criteria": {
                "allowed_values": {"account": ["ACC-001", "ACC-002"]},
                "required_present": ["account"],
                "bounds": {"amount": {"min": 0, "max": 5000}},
            },
        }
    ],
}


def _check(obj: object, schema: dict, path: str = "$") -> list[str]:
    """Minimal validator for exactly the keywords the v1 schema uses."""
    errs: list[str] = []
    if "const" in schema and obj != schema["const"]:
        errs.append(f"{path}: const mismatch")
    types = schema.get("type")
    if types:
        kinds = [types] if isinstance(types, str) else types
        kind_map = {
            "object": dict,
            "array": list,
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
        }
        if not any(
            (k == "integer" and isinstance(obj, int) and not isinstance(obj, bool))
            or (k != "integer" and isinstance(obj, kind_map[k]))
            for k in kinds
        ):
            errs.append(f"{path}: type {type(obj).__name__} not in {kinds}")
            return errs
    if isinstance(obj, dict) and schema.get("type") == "object":
        for key in schema.get("required", []):
            if key not in obj:
                errs.append(f"{path}: missing required {key!r}")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in obj:
                if key not in props:
                    errs.append(f"{path}: additional property {key!r}")
        for key in set(obj) & set(props):
            errs.extend(_check(obj[key], props[key], f"{path}.{key}"))
        addon = schema.get("additionalProperties")
        if isinstance(addon, dict):
            for key, value in obj.items():
                if key not in props:
                    errs.extend(_check(value, addon, f"{path}.{key}"))
        if "minProperties" in schema and len(obj) < schema["minProperties"]:
            errs.append(f"{path}: too few properties")
    if isinstance(obj, list) and schema.get("type") == "array":
        if "minItems" in schema and len(obj) < schema["minItems"]:
            errs.append(f"{path}: too few items")
        item = schema.get("items")
        if isinstance(item, dict):
            for i, entry in enumerate(obj):
                errs.extend(_check(entry, item, f"{path}[{i}]"))
    return errs


def test_derivation_is_deterministic_and_matches_the_schema():
    assert retry_guidance(_TOKEN) == _EXPECTED
    # Same inputs, same shape - byte-identical, no inference involved.
    assert retry_guidance(dict(_TOKEN, intent=None)) == _EXPECTED
    guidance = attach_retry_guidance({"decision": "deny"}, _TOKEN)
    assert json.dumps(guidance, sort_keys=True) == json.dumps(
        {"decision": "deny", "retry_guidance": _EXPECTED}, sort_keys=True
    )
    assert _check(_EXPECTED, RETRY_GUIDANCE_SCHEMA) == []
    assert RETRY_GUIDANCE_SCHEMA["properties"]["schema"]["const"] == SCHEMA_NAME


def test_honest_absence_on_non_derivable_authority():
    # Denylist-only authority: forbidden_values says what NOT to send, it
    # never determines what WOULD be allowed - absent, not null.
    denylist_only = {
        "tool": "lookup_balance",
        "constraints": {"forbidden_values": {"memo": ["gift"]}},
    }
    assert retry_guidance(denylist_only) is None
    deny = {"decision": "deny", "reason": "constraint violated"}
    out = attach_retry_guidance(deny, denylist_only)
    assert out == deny
    assert "retry_guidance" not in out
    # Rate-limit class: no positive constraint to derive from either.
    rate = {"tool": "t", "constraints": {"forbidden_field_combinations": [["a", "b"]]}}
    assert retry_guidance(rate) is None
    assert retry_guidance({"constraints": {"allowed_values": {}}}) is None
    assert retry_guidance({}) is None
    assert retry_guidance(None) is None  # type: ignore[arg-type]


def test_intent_narrows_the_derived_alternatives():
    token = dict(
        _TOKEN,
        intent={
            "tools": ["lookup_balance"],
            "constraints": {"allowed_values": {"account": ["ACC-001"]}},
        },
    )
    guidance = retry_guidance(token)
    assert guidance is not None
    criteria = guidance["permitted_actions"][0]["criteria"]
    # Intersection, never widening: only ACC-001 covers BOTH constraint sets.
    assert criteria["allowed_values"] == {"account": ["ACC-001"]}

    outside = dict(_TOKEN, intent={"tools": ["other_tool"], "constraints": {}})
    assert retry_guidance(outside) is None
    # Empty intersection = this authority permits nothing: honest absence.
    empty = dict(
        _TOKEN,
        intent={
            "tools": ["lookup_balance"],
            "constraints": {"allowed_values": {"account": ["OTHER"]}},
        },
    )
    assert retry_guidance(empty) is None


def test_attach_is_additive_and_verdict_bytes_untouched():
    # Allow and escalate responses pass through byte-identical - the key
    # is never added to them.
    allow = {"decision": "allow", "receipt_id": "r1"}
    assert attach_retry_guidance(allow, _TOKEN) == allow
    escalate = {"decision": "escalate", "reason": "needs approval"}
    assert attach_retry_guidance(escalate, _TOKEN) == escalate

    deny = {
        "decision": "deny",
        "reason": "constraint violated: account ACC-999",
        "receipt_id": "r2",
    }
    with_guidance = attach_retry_guidance(deny, _TOKEN)
    # Every pre-existing field byte-identical; the guidance is the only delta.
    base = {k: v for k, v in with_guidance.items() if k != "retry_guidance"}
    assert json.dumps(base, sort_keys=True) == json.dumps(deny, sort_keys=True)
    assert with_guidance["decision"] == "deny"


def test_bridge_exposes_feedback_and_schema():
    assert QmHarnessBridge.deny_feedback(_TOKEN) == _EXPECTED
    assert QmHarnessBridge.deny_feedback({"constraints": {}}) is None
    schema = QmHarnessBridge.retry_guidance_schema()
    assert schema["$id"] == SCHEMA_NAME


POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def live_gate(tmp_path):
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    bridge = QmHarnessBridge(issuer, ledger, gateway_url="http://raucle-gateway:8080")
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")
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
    config.delegations_file = str(tmp_path / "delegations.jsonl")
    gateway = RaucleGateway(config)
    app = create_gateway_app(gateway)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    yield f"http://127.0.0.1:{port}", bridge, gateway, tmp_path
    server.should_exit = True
    thread.join(timeout=10)


def _run_gate(url: str, token: dict, tool: str, args: dict) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "RAUCLE_GATEWAY_URL": url,
        "RAUCLE_CAPABILITY_TOKEN": json.dumps(token),
    }
    return subprocess.run(
        [sys.executable, str(_SCRIPT), tool, json.dumps(args)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_live_deny_retry_within_the_alternative_succeeds(live_gate):
    url, bridge, _gateway, tmp = live_gate
    # The chain: mint the authority ONCE, then deny -> guidance -> retry.
    root_tok = bridge.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        constraints={"allowed_values": {"account": ["ACC-001", "ACC-002"]}},
    )
    child_tok = bridge.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        parent=bridge.ledger.resolver()(root_tok["token_id"]),
        constraints={"max_calls_per_hour": 50},
    )

    # A simulated agent goes out of the whitelist; the authority denies.
    denied = _run_gate(url, child_tok, "lookup_balance", {"account": "ACC-999"})
    assert denied.returncode == 1, denied.stdout + denied.stderr
    deny_body = json.loads(denied.stdout)
    assert deny_body["decision"] == "deny", deny_body

    # The deny now carries the machine-readable fix: the SAME token's
    # whitelist, deterministically. The retry loop parses it - it decides
    # the retry itself, and the field never changes the verdict.
    guidance = deny_body["retry_guidance"]
    assert _check(guidance, RETRY_GUIDANCE_SCHEMA) == []
    allowed_accounts = guidance["permitted_actions"][0]["criteria"]["allowed_values"]["account"]
    assert set(allowed_accounts) == {"ACC-001", "ACC-002"}
    assert deny_body["decision"] == "deny"  # additive: still a deny

    # The agent (simulated retry) picks a value from the declared
    # alternatives - no minting, no policy change, the SAME token.
    retry = _run_gate(url, child_tok, "lookup_balance", {"account": allowed_accounts[0]})
    assert retry.returncode == 0, retry.stdout + retry.stderr
    retry_body = json.loads(retry.stdout)
    assert retry_body["decision"] == "allow", retry_body
    assert "receipt_id" in retry_body and "retry_guidance" not in retry_body


def test_live_verdict_bytes_are_guidance_free_and_stable(live_gate):
    url, bridge, _gateway, tmp = live_gate
    # A token whose constraints are denylist-only: the gate denies the
    # denylisted argument, and the artifact adds NO guidance key -
    # absence is byte-visible, not a null.
    token = bridge.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        constraints={"forbidden_values": {"memo": ["gift"]}},
    )
    denied = _run_gate(url, token, "lookup_balance", {"account": "ACC-001", "memo": "gift"})
    assert denied.returncode == 1, denied.stdout + denied.stderr
    body = json.loads(denied.stdout)
    assert body["decision"] == "deny", body
    assert "retry_guidance" not in body

    # Determinism: a second identical call produces the same verdict
    # fields (guidance presence never perturbs the decision; only the
    # per-call bookkeeping - timestamp, receipt id - differs).
    again = _run_gate(url, token, "lookup_balance", {"account": "ACC-001", "memo": "gift"})
    again_body = json.loads(again.stdout)
    for key in ("decision", "reason", "tool", "agent_id", "policy"):
        assert again_body[key] == body[key]

    # The gate endpoint itself NEVER emits the field: it is an
    # adapter-layer additive presentation, not part of the verdict.
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        url.rstrip("/") + "/gate",
        data=json.dumps(
            {
                "tool": "lookup_balance",
                "args": {"account": "ACC-003"},
                "agent_id": token["agent_id"],
            }
        ).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-Capability-Token": json.dumps(token)},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            gate_body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        gate_body = json.loads(exc.read())
    assert gate_body["decision"] == "deny", gate_body
    assert "retry_guidance" not in gate_body

    # And the receipt for the deny verifies offline, unmodified by guidance.
    lines = (tmp / "receipts.jsonl").read_text().strip().splitlines()
    last_env = json.loads(lines[-1])
    seg = last_env["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    payload = json.loads(base64.urlsafe_b64decode(seg))
    assert payload["x_gate"]["decision"] == "deny"
    assert "retry_guidance" not in json.dumps(payload)
