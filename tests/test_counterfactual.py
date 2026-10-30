"""I1: counterfactual replay - the incident review question, answered
deterministically from the receipts.

The demo scenario the backlog names: rerun an incident chain under a
narrowed policy, show the deny that did not happen.
"""

import json

from raucle.counterfactual import replay_counterfactual
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import _canonical_json
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

# the stricter policy: ACC-999 (the incident account) is no longer allowed
ALTERNATIVE_POLICY = """
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


def _incident(tmp_path):
    """Run the incident: two exports under the original (too-loose)
    policy, with every call's args recorded in the input store."""
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
    config.policy_file.write_text(ORIGINAL_POLICY)
    config.gate_auth = "off"

    gateway = RaucleGateway(config)
    from fastapi.testclient import TestClient

    client = TestClient(create_gateway_app(gateway))

    store_path = tmp_path / "inputs.jsonl"
    with InputStore(store_path) as store:
        for account in ("ACC-001", "ACC-999"):  # ACC-999 is the incident
            args = {"account": account}
            resp = client.post(
                "/gate",
                json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
            )
            assert resp.status_code == 200 and resp.json()["decision"] == "allow"
            # record the args in the store under the SAME digest the
            # receipt binds (canonical json form)
            store.add(_canonical_json(args).decode("utf-8"))
    return tmp_path / "receipts.jsonl", store_path


def test_counterfactual_shows_the_deny_that_did_not_happen(tmp_path):
    chain, store = _incident(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_POLICY)

    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )

    # both incident actions replay (both have stored inputs)
    assert report["actions_replayed"] == 2
    assert report["actions_unreplayable"] == 0
    # one action the original allowed, the alternative prevents
    assert report["prevented_by_alternative"] == 1
    assert report["still_allowed_by_alternative"] == 1

    prevented = [r for r in report["actions"] if r["prevented"]]
    assert len(prevented) == 1
    assert prevented[0]["original_decision"] == "allow"
    assert prevented[0]["counterfactual_decision"] == "deny"
    assert "ACC-999" not in json.dumps(report)  # bounded: no arg values leak

    assert report["verdict"].startswith("the alternative policy would have prevented 1 of 2")


def test_receipt_without_stored_input_is_unreplayable_not_guessed(tmp_path):
    chain, store = _incident(tmp_path)
    # wipe one stored input: the replay must mark it unreplayable
    lines = store.read_text().splitlines()
    store.write_text("\n".join(lines[:-1]) + "\n")

    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_POLICY)
    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )
    assert report["actions_unreplayable"] == 1
    assert report["actions_replayed"] == 1


def test_the_replay_never_writes_to_the_incident_chain(tmp_path):
    """The counterfactual must not touch the evidence it examines."""
    chain, store = _incident(tmp_path)
    before = chain.read_text()
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_POLICY)
    replay_counterfactual(chain, input_store_path=store, alternative_policy_path=alt_policy)
    assert chain.read_text() == before
