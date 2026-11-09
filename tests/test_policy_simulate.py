"""X6 SLICE 1: policy simulation API - deterministic, signed, flippable.

Six pinned behaviours:
1. simulate on fixture traffic (counterfactual + replay over a served window)
2. determinism: same inputs -> byte-identical signed result
3. schema-invalid candidate refuses named
4. agent-plane key refuses (deny-by-default, named)
5. flip round-trip: signed result applies through the named sim_apply path
6. SIEM event emitted
"""

from __future__ import annotations

import json

import pytest
import yaml
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app, create_gateway_app
from raucle.policy_simulate import (  # noqa: F401
    SimulateError,
    simulate_policy,
    verify_simulation_receipt,
)
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

CANDIDATE_POLICY_CANONICAL = yaml.dump(
    yaml.safe_load(CANDIDATE_POLICY), default_flow_style=False, sort_keys=False
)


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
    """Serve two exports under the ORIGINAL policy; return (gateway, chain, store).

    Both calls' args are recorded in the input store under the same digest
    the receipts bind (canonical JSON form), exactly as the I1 demo does.
    """
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
    return gateway, tmp_path / "receipts.jsonl", store_path


@pytest.fixture
def sim_env(tmp_path):
    config = _config(tmp_path)
    _serve_gw, chain, store = _window(tmp_path, config)
    import dataclasses

    # the operator-plane gateway keeps its OWN receipt store: a
    # simulation must never append into the window it is replaying,
    # otherwise the second identical call sees a different window.
    sim_config = dataclasses.replace(config, receipt_store=str(tmp_path / "sim-receipts.jsonl"))
    gateway = RaucleGateway(sim_config)
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    users.add_user("operator-key", "operator", "Operator")
    agent_key = gateway._agent_creds.issue(agent_id="agent:pay")
    client = TestClient(create_admin_app(gateway, users))
    return {
        "gateway": gateway,
        "users": users,
        "admin": client,
        "chain": chain,
        "store": store,
        "agent_key": agent_key,
        "tmp_path": tmp_path,
        "config": sim_config,
    }


# ---------------------------------------------------------------------------
# 1. simulate on fixture traffic
# ---------------------------------------------------------------------------


def test_simulate_on_fixture_traffic(sim_env):
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(sim_env["chain"]),
            "input_store_ref": str(sim_env["store"]),
        },
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    result = body["result"]
    gate = result["gate"]
    assert gate["current"] == {"allow": 2, "deny": 0}
    assert gate["candidate"] == {"allow": 1, "deny": 1}
    assert len(gate["changed_decisions"]) == 1
    changed = gate["changed_decisions"][0]
    assert changed["current_decision"] == "allow"
    assert changed["candidate_decision"] == "deny"
    assert gate["actions_replayed"] == 2
    assert gate["actions_unreplayable"] == 0
    # bounded disclosure: no arg values, no denial reasons
    assert "ACC-999" not in json.dumps(body)
    # the receipt is verifiable and binds the result
    sim = verify_simulation_receipt(sim_env["gateway"], body["jws"])
    assert sim["candidate_policy_hash"] == result["candidate_policy_hash"]
    import hashlib

    assert (
        body["receipt_hash"] == "sha256:" + hashlib.sha256(body["jws"].encode("ascii")).hexdigest()
    )


# ---------------------------------------------------------------------------
# 2. determinism: same inputs => byte-identical signed result
# ---------------------------------------------------------------------------


def test_same_inputs_byte_identical_signed_result(sim_env):
    payload = {
        "candidate_policy_yaml": CANDIDATE_POLICY,
        "window_ref": str(sim_env["chain"]),
        "input_store_ref": str(sim_env["store"]),
    }
    first = (
        sim_env["admin"]
        .post(
            "/api/policy/simulate",
            json=payload,
            headers={"Authorization": "Bearer operator-key"},
        )
        .json()
    )
    second = (
        sim_env["admin"]
        .post(
            "/api/policy/simulate",
            json=payload,
            headers={"Authorization": "Bearer admin-key"},
        )
        .json()
    )
    # byte-identical signed result: result AND signature, different caller
    assert first["result"] == second["result"]
    assert first["jws"] == second["jws"]
    assert first["receipt_hash"] == second["receipt_hash"]


def test_determinism_uses_no_wall_clock(sim_env):
    """The receipt payload carries iat 0; the JWS is a pure function."""
    body = (
        sim_env["admin"]
        .post(
            "/api/policy/simulate",
            json={
                "candidate_policy_yaml": CANDIDATE_POLICY,
                "window_ref": str(sim_env["chain"]),
                "input_store_ref": str(sim_env["store"]),
            },
            headers={"Authorization": "Bearer operator-key"},
        )
        .json()
    )
    import base64

    payload_b64 = body["jws"].split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==" * (-len(payload_b64) % 4)))
    assert payload["iat"] == 0


# ---------------------------------------------------------------------------
# 3. schema-invalid candidate refuses named
# ---------------------------------------------------------------------------


def test_schema_invalid_candidate_refuses_named(sim_env):
    bad = "version: 1\nissuer: demo.bank\npolicies:\n  - nope: true\n"
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={"candidate_policy_yaml": bad, "window_ref": str(sim_env["chain"])},
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 400
    assert "invalid_candidate_policy" in resp.json()["detail"]


def test_missing_candidate_source_refuses_named(sim_env):
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={"window_ref": str(sim_env["chain"])},
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 400
    assert "candidate_policy_required" in resp.json()["detail"]


def test_unknown_window_refuses_named(sim_env):
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(sim_env["tmp_path"] / "absent.jsonl"),
        },
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 400
    assert "unknown_window" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 4. agent-plane key denies by default, named
# ---------------------------------------------------------------------------


def test_agent_plane_key_denied_by_default_named(sim_env):
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(sim_env["chain"]),
        },
        headers={"Authorization": f"Bearer {sim_env['agent_key']}"},
    )
    assert resp.status_code == 403
    assert "agent_plane_key_denied" in resp.json()["detail"]


def test_agent_plane_key_denied_on_apply_too(sim_env):
    resp = sim_env["admin"].post(
        "/api/policy/simulate/apply",
        json={"simulation_receipt": "not.a.jws", "candidate_policy_yaml": CANDIDATE_POLICY},
        headers={"Authorization": f"Bearer {sim_env['agent_key']}"},
    )
    assert resp.status_code == 403
    assert "agent_plane_key_denied" in resp.json()["detail"]


def test_auditor_role_cannot_simulate(sim_env):
    users = sim_env["users"]
    users.add_user("aud-key", "auditor", "Aud")
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(sim_env["chain"]),
        },
        headers={"Authorization": "Bearer aud-key"},
    )
    assert resp.status_code == 403


def test_unknown_operator_key_refused(sim_env):
    """An operator-plane key stays operator-plane: gate plane unchanged."""
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(sim_env["chain"]),
        },
        headers={"Authorization": "Bearer no-such-key"},
    )
    assert resp.status_code == 403
    assert "Invalid API key" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 5. flip round-trip through the named sim_apply path
# ---------------------------------------------------------------------------


def test_flip_round_trip(sim_env):
    body = (
        sim_env["admin"]
        .post(
            "/api/policy/simulate",
            json={
                "candidate_policy_yaml": CANDIDATE_POLICY,
                "window_ref": str(sim_env["chain"]),
                "input_store_ref": str(sim_env["store"]),
            },
            headers={"Authorization": "Bearer operator-key"},
        )
        .json()
    )
    sim_hash_before = body["result"]["candidate_policy_hash"]

    resp = sim_env["admin"].post(
        "/api/policy/simulate/apply",
        json={
            "simulation_receipt": body["jws"],
            "candidate_policy_yaml": CANDIDATE_POLICY,
        },
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 200, resp.text
    applied = resp.json()
    assert applied["applied"] is True
    assert applied["candidate_policy_hash"] == sim_hash_before
    assert applied["simulation_receipt"] == body["receipt_hash"]
    assert applied["receipt_id"]  # the apply path has its OWN receipt

    # the candidate is live: the gate now denies the incident account
    gate_key = sim_env["gateway"]._agent_creds.issue(agent_id="agent:svc")
    gate = TestClient(create_gateway_app(sim_env["gateway"]))
    resp2 = gate.post(
        "/gate",
        json={"tool": "export_records", "args": {"account": "ACC-999"}, "agent_id": "agent:svc"},
        headers={"X-Api-Key": gate_key},
    )
    assert resp2.json()["decision"] == "deny"

    # the apply receipt exists in the store and carries x_sim_apply
    receipts = sim_env["gateway"].config.receipt_store
    import base64

    found = False
    with open(receipts, encoding="utf-8") as fh:
        receipts_text = fh.read()
    for line in receipts_text.splitlines():
        if not line.strip():
            continue
        env = json.loads(line)
        seg = env["jws"].split(".")[1]
        pl = json.loads(base64.urlsafe_b64decode(seg + "==" * (-len(seg) % 4)))
        if "x_sim_apply" in pl:
            assert pl["x_sim_apply"]["simulation_receipt"] == body["receipt_hash"]
            found = True
    assert found


def test_flip_refuses_mismatched_candidate(sim_env):
    body = (
        sim_env["admin"]
        .post(
            "/api/policy/simulate",
            json={
                "candidate_policy_yaml": CANDIDATE_POLICY,
                "window_ref": str(sim_env["chain"]),
                "input_store_ref": str(sim_env["store"]),
            },
            headers={"Authorization": "Bearer operator-key"},
        )
        .json()
    )
    resp = sim_env["admin"].post(
        "/api/policy/simulate/apply",
        json={
            "simulation_receipt": body["jws"],
            "candidate_policy_yaml": ORIGINAL_POLICY,
        },
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 400
    assert "candidate_hash_mismatch" in resp.json()["detail"]


def test_flip_refuses_tampered_receipt(sim_env):
    body = (
        sim_env["admin"]
        .post(
            "/api/policy/simulate",
            json={
                "candidate_policy_yaml": CANDIDATE_POLICY,
                "window_ref": str(sim_env["chain"]),
            },
            headers={"Authorization": "Bearer operator-key"},
        )
        .json()
    )
    # flip a payload byte: signature must fail
    h, p, s = body["jws"].split(".")
    import base64

    pad = "==" * (-len(p) % 4)
    payload = json.loads(base64.urlsafe_b64decode(p + pad))
    tampered = h + "." + p + "." + s
    assert tampered == body["jws"]
    payload["x_sim"]["gate"]["verdict"] = "all clear"
    p2 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .decode()
        .rstrip("=")
    )
    resp = sim_env["admin"].post(
        "/api/policy/simulate/apply",
        json={
            "simulation_receipt": f"{h}.{p2}.{s}",
            "candidate_policy_yaml": CANDIDATE_POLICY,
        },
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "invalid_simulation_receipt" in detail or "candidate_hash_mismatch" in detail


# ---------------------------------------------------------------------------
# 7. caller-supplied refs are confined to the allow roots
# ---------------------------------------------------------------------------


def test_traversal_refs_refused_named(sim_env):
    """A window/input-store/policy_ref outside the allow roots is refused."""
    client = sim_env["admin"]
    headers = {"Authorization": "Bearer operator-key"}
    secret = sim_env["tmp_path"].parent / "outside-secret.yaml"
    secret.write_text("version: 1\nissuer: x\npolicies: []\n")
    try:
        for ref_key, ref_value in (
            ("window_ref", str(secret)),
            ("input_store_ref", str(secret)),
            ("policy_ref", str(secret)),
        ):
            payload = {ref_key: ref_value}
            if ref_key != "policy_ref":
                payload["candidate_policy_yaml"] = CANDIDATE_POLICY
            resp = client.post("/api/policy/simulate", json=payload, headers=headers)
            assert resp.status_code == 400, (ref_key, resp.text)
            assert "outside the allowed roots" in resp.json()["detail"], ref_key
    finally:
        secret.unlink(missing_ok=True)


def test_traversal_escapes_refused_named(sim_env):
    """../ from an allowed root lands outside and is refused."""
    resp = sim_env["admin"].post(
        "/api/policy/simulate",
        json={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(sim_env["tmp_path"].resolve().parent / "escape.jsonl"),
        },
        headers={"Authorization": "Bearer operator-key"},
    )
    assert resp.status_code == 400
    assert "outside the allowed roots" in resp.json()["detail"]


def test_relative_ref_resolves_inside_roots(sim_env):
    """A relative ref inside an allowed root resolves and simulates."""
    gw = sim_env["gateway"]

    body = simulate_policy(
        gw,
        candidate_policy_yaml=CANDIDATE_POLICY,
        window_ref=sim_env["chain"].name,
        input_store_ref=sim_env["store"].name,
        ref_roots=[sim_env["tmp_path"]],
    )
    assert body["result"]["gate"]["actions_replayed"] == 2


def test_simulate_ref_roots_config_extension(sim_env):
    """Operator-configured extras widen the allow set."""
    from dataclasses import replace

    cfg = replace(
        sim_env["config"],
        simulate_ref_roots=(str(sim_env["tmp_path"].parent),),
    )
    from raucle.gateway_app import _sim_ref_roots

    gw = type(sim_env["gateway"])(cfg)
    roots = _sim_ref_roots(gw)
    assert any(str(r).endswith(str(sim_env["tmp_path"].parent)) for r in roots)
    body = simulate_policy(
        gw,
        candidate_policy_yaml=CANDIDATE_POLICY,
        window_ref=str(sim_env["chain"]),
        input_store_ref=str(sim_env["store"]),
        ref_roots=roots,
    )
    assert body["result"]["gate"]["actions_replayed"] == 2


# ---------------------------------------------------------------------------
# 8. SIEM event emitted
# ---------------------------------------------------------------------------


def test_siem_event_emitted(sim_env):
    sim_env["admin"].post(
        "/api/policy/simulate",
        json={
            "candidate_policy_yaml": CANDIDATE_POLICY,
            "window_ref": str(sim_env["chain"]),
            "input_store_ref": str(sim_env["store"]),
        },
        headers={"Authorization": "Bearer operator-key"},
    )
    buffered = sim_env["gateway"].siem.buffered_events()
    assert any(isinstance(e, dict) and e.get("event") == "policy_simulate" for e in buffered), (
        buffered
    )
