"""K2 (X6 slice 2): the panel tab's data sources, swept for disclosure.

The simulate tab renders exactly what these surfaces emit, so the panel's
content discipline is pinned at its sources:

- content-absence sweep (the ACC-999 class): a candidate that flips the
  incident account's decision must be renderable without the account
  VALUE ever entering the outcome the panel draws rows from;
- 422 rows: malformed bodies refuse with FastAPI validation rows, and
  the demo plane refuses a body without a preset by name;
- auth rows: unauthenticated calls refuse 401 on both planes, and the
  auditor-role key (the demo key's role) is refused named on the
  operator plane, which is the honest unavailable state the tab renders.
"""

from __future__ import annotations

import dataclasses
import json

from fastapi.testclient import TestClient

from raucle.demo_policy_sim import run_demo_policy_sim
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app, create_gateway_app
from raucle.replay import InputStore

ORIGINAL_POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-999"]
"""

#: The candidate that flips the incident account (ACC-999) from allow to
#: deny: exactly the decision the tab's flippable-diff table must show
#: WITHOUT the account value that caused it.
CANDIDATE_POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""


def _config(tmp_path):
    return GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "creds.jsonl"),
    )


def _window(tmp_path, config):
    """Serve two exports under the original policy (ACC-001, ACC-999)."""
    policy = tmp_path / "policies.yaml"
    policy.write_text(ORIGINAL_POLICY)
    config.policy_file = str(policy)
    config.gate_auth = "apikey"
    gateway = RaucleGateway(config)
    serve_key = gateway._agent_creds.issue(agent_id="agent:svc")

    client = TestClient(create_gateway_app(gateway))
    store_path = tmp_path / "inputs.jsonl"
    with InputStore(store_path) as store:
        for account in ("ACC-001", "ACC-999"):
            args = {"account": account}
            resp = client.post(
                "/gate",
                json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
                headers={"X-Api-Key": serve_key},
            )
            assert resp.status_code == 200
            assert resp.json()["decision"] == "allow"
            from raucle.provenance import _canonical_json

            store.add(_canonical_json(args).decode("utf-8"))
    return tmp_path / "receipts.jsonl", store_path


def _sim_env(tmp_path):
    config = _config(tmp_path)
    chain, store = _window(tmp_path, config)
    # the operator-plane gateway keeps its OWN receipt store: a
    # simulation never appends into the window it replays
    sim_config = dataclasses.replace(config, receipt_store=str(tmp_path / "sim-receipts.jsonl"))
    gateway = RaucleGateway(sim_config)
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    users.add_user("auditor-key", "auditor", "Auditor")
    client = TestClient(create_admin_app(gateway, users))
    return {"client": client, "chain": chain, "store": store}


def _simulate(client, *, key="admin-key", body=None):
    payload = {"candidate_policy_yaml": CANDIDATE_POLICY}
    if body is not None:
        payload = body
    return client.post(
        "/api/policy/simulate",
        json=payload,
        headers={"Authorization": key},
    )


# ---------------------------------------------------------------------------
# Content-absence sweep (the ACC-999 class)
# ---------------------------------------------------------------------------


def test_operator_result_carries_no_argument_values(tmp_path):
    """The candidate flips ACC-999 from allow to deny; the signed outcome
    the panel renders rows from carries the flip, never the account
    value, and never a denial reason."""
    env = _sim_env(tmp_path)
    resp = _simulate(
        env["client"],
        body={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(env["chain"]),
            "input_store_ref": str(env["store"]),
        },
    )
    assert resp.status_code == 200
    text = json.dumps(resp.json())
    assert "ACC-999" not in text, "the incident account value leaked into the simulate result"
    assert "ACC-001" not in text, "any account value leaked into the simulate result"
    result = resp.json()["result"]
    gate = result["gate"]
    assert gate["actions_replayed"] == 2
    assert gate["changed_decisions"], "the flip the tab must show is missing"
    row = gate["changed_decisions"][0]
    assert set(row) == {
        "receipt_hash",
        "tool",
        "agent_id",
        "current_decision",
        "candidate_decision",
        "evidence_depth",
    }, "changed-decision rows carry fields beyond the bounded disclosure set"
    # the receipt metadata the tab renders beside the diff
    assert result["candidate_policy_hash"].startswith("sha256:")
    assert result["window_hash"].startswith("sha256:")
    assert resp.json()["receipt_hash"].startswith("sha256:")
    assert resp.json()["jws"]


def test_demo_outcome_carries_no_argument_values():
    """The preset outcome (the demo plane's response shape) is value-free
    in its result rows: the preset LABEL names the tweak as demo copy,
    the OUTCOME never carries the account value."""
    out = run_demo_policy_sim("narrow-export")
    outcome_text = json.dumps(out["outcome"])
    assert "ACC-999" not in outcome_text, "the account value leaked into the demo outcome"
    assert "ACC-001" not in outcome_text
    # the flip row the tab renders is present and bounded
    assert out["outcome"]["changed_decisions"]
    row = out["outcome"]["changed_decisions"][0]
    assert set(row) == {
        "receipt_hash",
        "tool",
        "agent_id",
        "current_decision",
        "candidate_decision",
        "evidence_depth",
    }
    # the label is demo copy and may name the tweak; the outcome may not
    assert "ACC-999" in out["label"]


# ---------------------------------------------------------------------------
# 422 rows
# ---------------------------------------------------------------------------


def test_malformed_operator_body_refuses_with_422_rows(tmp_path):
    """A body that is not a request model refuses with FastAPI's
    validation rows; the panel renders those rows as named text."""
    env = _sim_env(tmp_path)
    resp = env["client"].post(
        "/api/policy/simulate",
        content="[1, 2, 3]",
        headers={"Authorization": "admin-key", "Content-Type": "application/json"},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert isinstance(detail, list), "the 422 refusal must be rows, not a bare string"
    assert all(isinstance(row, dict) and "msg" in row for row in detail)


def test_demo_run_without_a_preset_refuses_422_named(tmp_path, monkeypatch):
    """The demo plane's 422 is a named string, the operator plane's is a
    row list: the tab's renderer must accept both shapes."""
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
    config = _config(tmp_path)
    gateway = RaucleGateway(config)
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    client = TestClient(create_admin_app(gateway, users))
    resp = client.post(
        "/api/demo/policy-simulate",
        json={},
        headers={"Authorization": "admin-key"},
    )
    assert resp.status_code == 422
    assert "preset" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Auth rows
# ---------------------------------------------------------------------------


def test_unauthenticated_calls_refuse_401_on_both_planes(tmp_path):
    env = _sim_env(tmp_path)
    assert (
        env["client"].post("/api/policy/simulate", json={"candidate_policy_yaml": "x"}).status_code
        == 401
    )
    assert env["client"].get("/api/demo/policy-simulate/presets").status_code == 401
    assert (
        env["client"].post("/api/demo/policy-simulate", json={"preset": "no-change"}).status_code
        == 401
    )


def test_auditor_key_gets_the_named_role_refusal(tmp_path):
    """The demo key's role is auditor: the operator simulate plane
    refuses it named, which is the honest unavailable state the tab
    renders for the paste path in the demo view."""
    env = _sim_env(tmp_path)
    resp = _simulate(env["client"], key="auditor-key")
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "auditor" in detail
    assert "policies" in detail
