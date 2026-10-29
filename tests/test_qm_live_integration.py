"""Live QM integration test: the deployment-directory artifact against a real gate.

This is Move 3's live leg. The unit tests (test_harness_qm.py) prove the bridge
against an in-process TestClient. This test proves the actual artifact a QM
deployment installs - the tool.json fragment and the /usr/local/bin/raucle-gate
script QM's deployment-layer sync converges into every sandbox - against a
raucle gateway bound to a real socket.

The chain exercised is exactly the one the wiring() bundle describes:

    QM task hand-off -> mint_for_task (root, attenuated child; ledger-registered)
    -> per-tool-call: the raucle-gate script POSTs /gate with X-Capability-Token
    -> the gate decides and writes a v1.1 receipt binding the delegation chain
    -> a third party verifies the whole chain offline with the public verifier.
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
from raucle.provenance import ProvenanceVerifier
from raucle.trust_registry import TrustRegistry

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

_SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "qm"
    / "tools"
    / "raucle-gate"
    / "raucle-gate"
)
assert _SCRIPT.exists(), _SCRIPT


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
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


def test_qm_live_end_to_end(live_gate):
    """The installed script, the real socket, the v1.1 chain, offline verify."""
    url, bridge, gateway, tmp = live_gate

    # QM hands the task off: the principal mints root, then attenuates
    root_tok = bridge.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
    )
    child_tok = bridge.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        parent=bridge.ledger.resolver()(root_tok["token_id"]),
        constraints={"max_calls_per_hour": 50},
    )
    assert child_tok["parent_id"] == root_tok["token_id"]

    # The sandbox runs the installed tool: in-scope call is allowed
    ok = _run_gate(url, child_tok, "lookup_balance", {"account": "ACC-001"})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    body = json.loads(ok.stdout)
    assert body["decision"] == "allow", body
    assert body.get("receipt_id"), body

    # Out-of-scope call (violates the attenuated chain's narrowing) is an
    # ATTRIBUTABLE denial: the token is validly signed and chain-verified,
    # the delegated authority simply refuses the call. Denied WITH a
    # receipt binding the chain - who tried what is evidence. Fail-closed
    # either way: the wrapped action does not proceed.
    denied = _run_gate(url, child_tok, "lookup_balance", {"account": "ACC-999"})
    assert denied.returncode == 1, denied.stdout + denied.stderr
    denied_body = json.loads(denied.stdout)
    assert denied_body["decision"] == "deny", denied_body
    assert "constraint violated" in denied_body["reason"], denied_body
    assert denied_body.get("receipt_id"), denied_body

    # No token, no call: the script fails closed
    import subprocess as sp

    env = {k: v for k, v in os.environ.items() if k != "RAUCLE_CAPABILITY_TOKEN"}
    env["RAUCLE_GATEWAY_URL"] = url
    no_token = sp.run(
        [sys.executable, str(_SCRIPT), "lookup_balance", '{"account": "ACC-001"}'],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert no_token.returncode == 3

    # Both decisions persist and bind the delegated-authority chain (v1.1):
    # the allow AND the attributable deny. Unauthenticated callers stay
    # pre-gate (no trustworthy chain to bind), but the no-token call above
    # never reached the gate.
    receipt_lines = (tmp / "receipts.jsonl").read_text().strip().splitlines()
    assert len(receipt_lines) >= 2
    last = json.loads(receipt_lines[-1])
    seg = last["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    payload = json.loads(base64.urlsafe_b64decode(seg))
    auth = payload["x_gate"]["authorization"]
    assert auth["capability_id"] == child_tok["token_id"]
    assert auth["attenuated"] is True
    assert auth["parent_id"] == root_tok["token_id"]
    assert payload["x_gate"]["decision"] == "deny", "last receipt = the attributable denial"

    # A third party verifies the whole chain offline with the public verifier
    verifier = ProvenanceVerifier(
        public_keys={gateway._gate_identity.key_id: gateway._gate_identity.public_key_pem()}
    )
    report = verifier.verify_chain(tmp / "receipts.jsonl")
    assert report.valid, report.errors
    assert report.receipt_count >= 1
    assert report.signature_failures == 0
    assert report.parent_link_failures == 0

    # The deployment fragment is conforming: QM's own validation invariants
    tool_json = json.loads((_SCRIPT.parent / "tool.json").read_text(encoding="utf-8"))
    assert tool_json["id"] == "raucle-gate"
    install = tool_json["install"]
    assert install["binary"] == "raucle-gate"
    for entry in install["files"]:
        assert entry["from"] != "tool.json"
        assert entry["to"] == "/usr/local/bin/raucle-gate"
        assert entry["mode"] == "0755"
