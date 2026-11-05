"""Verification demo (P1.4V): P1.4c admission refusals made live.

Acceptance criterion: a tampered-manifest refusal is demonstrated live
through the admission path with a verifiable receipt record, and the
agent registry and chain reconstruction (P1.1a) resolve against each
other for at least one enrolled agent. The demo itself is exercised via
``run_demo`` so the printed VERIFIED claims correspond to real computed
values.
"""

import json

from raucle.agent_registry import AgentRegistry
from raucle.provenance import ProvenanceVerifier
from scripts.demo_p1_4v import run_demo


def _receipts(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_tampered_enrolment_refused_and_receipted(tmp_path):
    r = run_demo(tmp_path)
    assert r["tampered_refused"]
    assert "verification failed" in r["tampered_reason"]
    assert r["deny_receipt"]
    assert r["deny_receipt_in_store"]
    assert r["deny_verdict"] == "deny"
    ext = r["deny_extension"]
    assert ext.get("decision_source") == "admission"
    assert ext.get("reason") == r["tampered_reason"]


def test_refusal_receipt_verifies_with_provenance_verifier(tmp_path):
    r = run_demo(tmp_path)
    verifier = ProvenanceVerifier(public_keys=r["gate_public_keys"])
    report = verifier.verify_chain(str(tmp_path / "receipts.jsonl"))
    assert report.valid, report.errors
    assert r["store_verified"]
    assert report.errors == []


def test_registry_refuses_tampered_record_without_appending(tmp_path):
    r = run_demo(tmp_path)
    assert r["registry_refused"]
    assert r["registry_unchanged"]
    assert "admission refused" in r["registry_error"]
    # the store file holds exactly the enrolled agent, nothing else
    reg = AgentRegistry(path=tmp_path / "agents.jsonl")
    assert reg.agent_ids() == ["agent:demo"]


def test_registry_and_chain_graph_resolve_against_each_other(tmp_path):
    r = run_demo(tmp_path)
    assert r["enrol_allowed"]
    assert r["graph_node_signature"] == "verified"
    assert r["identity_match"], (
        f"agent_id mismatch: registry={r['registry_agent_id']} extension={r['extension_agent_id']}"
    )
    assert r["digest_match"], (
        f"digest mismatch: registry={r['registry_digest']} receipt={r['extension_digest']}"
    )
    assert r["cross_check"]
