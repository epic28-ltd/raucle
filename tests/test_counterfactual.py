"""I1: counterfactual replay - the incident review question, answered
deterministically from the receipts.

The demo scenario the backlog names: rerun an incident chain under a
narrowed policy, show the deny that did not happen.
"""

import json

import pytest

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


# ---------------------------------------------------------------------------
# The z3 leg: PROVEN / REFUTED / UNDECIDED per prevented action
# ---------------------------------------------------------------------------

# the stricter policy is a denylist: the incident value is refused outright
ALTERNATIVE_DENYLIST_POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      deny:
        account: ["ACC-999"]
"""

# the stricter policy bans the field combination the incident call used: every
# call carrying both fields is denied, whatever their values
ALTERNATIVE_COMBINATION_POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      forbidden_combinations: [["account", "reason"]]
"""

# a realistic mix: an allowlist plus the combination ban. The allowlist kind is
# gate-enforced but not prover-modelled, so the whole policy is honestly
# UNDECIDED even though the combination ban alone would have proven exclusion
ALTERNATIVE_MIXED_POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
      forbidden_combinations: [["account", "reason"]]
"""

# a policy with no rule for the tool at all: denials come from the absence of
# a grant, not from constraints
ALTERNATIVE_NO_RULE_POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: unrelated_tool
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        thing: ["ok"]
"""


def _incident_two_field(tmp_path):
    """An incident whose recorded call carries two fields, both recorded in
    the input store."""
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
        args = {"account": "ACC-999", "reason": "audit export"}
        resp = client.post(
            "/gate",
            json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
        )
        assert resp.status_code == 200 and resp.json()["decision"] == "allow"
        store.add(_canonical_json(args).decode("utf-8"))
    return tmp_path / "receipts.jsonl", store_path


_PROOF_KEYS = {
    "status",
    "prover",
    "prover_version",
    "grammar_hash",
    "policy_hash",
    "counterexample_fields",
    "notes",
}


def _proofs(report):
    return [r["proof"] for r in report["actions"] if r.get("prevented")]


def _assert_proof_bounded(report):
    """Bounded disclosure, pinned: proofs carry field NAMES only - no recorded
    values, no constraint values, no counterexample values."""
    blob = json.dumps(report)
    assert "ACC-999" not in blob
    assert "ACC-001" not in blob
    for proof in _proofs(report):
        assert set(proof) <= _PROOF_KEYS
        assert proof["status"] in {"PROVEN", "REFUTED", "UNDECIDED"}
        assert "counterexample" not in set(proof)  # values never, fields only
        for name in proof.get("counterexample_fields", []):
            assert isinstance(name, str)


def test_prevented_action_proven_when_alt_policy_excludes_the_class(tmp_path):
    """The combination ban denies EVERY call of the recorded shape, whatever
    the values: the exclusion is structural and the prover certifies it."""
    pytest.importorskip("z3")
    chain, store = _incident_two_field(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_COMBINATION_POLICY)

    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )

    assert report["prevented_by_alternative"] == 1
    proofs = _proofs(report)
    assert len(proofs) == 1
    assert proofs[0]["status"] == "PROVEN"
    assert "counterexample_fields" not in proofs[0]
    assert proofs[0]["prover"] == "JSONSchemaProver"
    assert proofs[0]["grammar_hash"].startswith("sha256:")
    assert proofs[0]["policy_hash"].startswith("sha256:")
    assert report["prevented_proven"] == 1
    assert report["prevented_refuted"] == 0
    assert report["prevented_undecided"] == 0
    # the verdict states the proof, not the replay alone
    assert "proven to exclude the recorded argument class" in report["verdict"]
    _assert_proof_bounded(report)


def test_mixed_policy_with_unmodelled_kind_is_honestly_undecided(tmp_path):
    """A realistic alternative policy mixes an allowlist with the combination
    ban. The allowlist kind is not prover-modelled, so the report cannot
    certify the exclusion the combination ban alone would have proven:
    UNDECIDED naming the unmodelled kind, never upgraded."""
    pytest.importorskip("z3")
    chain, store = _incident_two_field(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_MIXED_POLICY)

    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )

    assert report["prevented_by_alternative"] == 1
    proofs = _proofs(report)
    assert len(proofs) == 1
    assert proofs[0]["status"] == "UNDECIDED"
    assert any("allowed_values" in n for n in proofs[0]["notes"])
    assert report["prevented_undecided"] == 1
    assert report["prevented_proven"] == 0
    _assert_proof_bounded(report)


def test_prevented_action_refuted_when_the_deny_is_value_specific(tmp_path):
    """A denylist refuses the incident value but not the whole class: the
    prover refutes the exclusion and names the escaping FIELD, never a value."""
    pytest.importorskip("z3")
    chain, store = _incident(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_DENYLIST_POLICY)

    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )

    assert report["prevented_by_alternative"] == 1
    proofs = _proofs(report)
    assert len(proofs) == 1
    assert proofs[0]["status"] == "REFUTED"
    # the escaping field is NAMED; the counterexample value never leaves the prover
    assert proofs[0]["counterexample_fields"] == ["account"]
    assert report["prevented_refuted"] == 1
    assert report["prevented_proven"] == 0
    assert "proven to exclude" not in report["verdict"]
    _assert_proof_bounded(report)


def test_prevented_action_undecided_when_alt_constraints_unmodelled(tmp_path):
    """The flagship demo: an allowlist (allowed_values) is gate-enforced but
    not prover-modelled. The report says UNDECIDED honestly and never
    upgrades: the replay verdict stands alone."""
    pytest.importorskip("z3")
    chain, store = _incident(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_POLICY)

    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )

    assert report["prevented_by_alternative"] == 1
    proofs = _proofs(report)
    assert len(proofs) == 1
    assert proofs[0]["status"] == "UNDECIDED"
    assert any("allowed_values" in n for n in proofs[0]["notes"])
    assert report["prevented_undecided"] == 1
    assert report["prevented_proven"] == 0
    # never upgraded: the verdict is the replay's alone
    assert report["verdict"].startswith("the alternative policy would have prevented 1 of 2")
    assert "proven to exclude" not in report["verdict"]
    _assert_proof_bounded(report)


def test_proof_leg_reports_undecided_without_z3(tmp_path, monkeypatch):
    """Without the [proof] extra the replay still answers; every proof row
    says UNDECIDED with the honest reason. Never a silent absence."""
    from raucle.prove import JSONSchemaProver

    def _no_z3(self, schema, policy):
        raise ImportError("raucle.prove requires the [proof] extra")

    monkeypatch.setattr(JSONSchemaProver, "prove_exclusion", _no_z3)

    chain, store = _incident_two_field(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_COMBINATION_POLICY)
    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )

    assert report["prevented_by_alternative"] == 1
    proofs = _proofs(report)
    assert len(proofs) == 1
    assert proofs[0]["status"] == "UNDECIDED"
    assert any("[proof]" in n for n in proofs[0]["notes"])
    assert report["prevented_undecided"] == 1
    _assert_proof_bounded(report)


def test_prevented_by_absence_of_grant_is_undecided_not_proven(tmp_path):
    """When the alternative policy has no rule for the tool, the deny comes
    from the absence of a grant - outside the constraint prover's question.
    Honest UNDECIDED with the reason; never a PROVEN."""
    pytest.importorskip("z3")
    chain, store = _incident(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_NO_RULE_POLICY)
    report = replay_counterfactual(
        chain, input_store_path=store, alternative_policy_path=alt_policy
    )

    assert report["prevented_by_alternative"] == 2
    proofs = _proofs(report)
    assert len(proofs) == 2
    for proof in proofs:
        assert proof["status"] == "UNDECIDED"
        assert any("absence of grant" in n for n in proof["notes"])
    assert report["prevented_undecided"] == 2
    _assert_proof_bounded(report)
