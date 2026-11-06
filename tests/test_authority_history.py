"""N5: authority-history replay - recompute decisions from evidence ALONE.

The operator is trusted for NOTHING: every gate decision in a chain is
recomputed from the retained evidence (stored args bound by digests, the
policy of record resolved BY DIGEST, the receipt's own decision) and the
comparison table is asserted here. Scenario vectors live in
tests/authority_history_vectors.json; each test below realises one vector
against a LIVE fixture chain (a real gateway run, not synthetic records).
"""

import base64
import hashlib
import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from raucle.authority_history import (
    ARGS_STORE_MISSING,
    POLICY_ARTIFACT_MISSING,
    POLICY_DIGEST_MISMATCH,
    deterministic_bytes,
    replay_authority_history,
)
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import _b64url_encode, _canonical_json
from raucle.replay import InputStore

VECTORS = json.loads(
    (Path(__file__).parent / "authority_history_vectors.json").read_text(encoding="utf-8")
)

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

NO_POLICY_POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: other_tool
    agent_id: agent:svc
    ttl_seconds: 60
"""

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


def _fixture(tmp_path, *, store_all: bool = False):
    """A real incident chain: two allowed exports (ACC-001, ACC-999),
    one denied unstored call (ACC-777), one tool with no policy rule.
    Returns (chain, store_path, policy_dir, alt_policy, gateway)."""
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(ORIGINAL_POLICY)
    config.gate_auth = "off"
    gateway = RaucleGateway(config)
    client = TestClient(create_gateway_app(gateway))

    store_path = tmp_path / "inputs.jsonl"
    with InputStore(store_path) as store:
        for account in ("ACC-001", "ACC-999"):
            args = {"account": account}
            resp = client.post(
                "/gate",
                json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
            )
            assert resp.status_code == 200 and resp.json()["decision"] == "allow"
            store.add(_canonical_json(args).decode("utf-8"))
        if store_all:
            args = {"account": "ACC-777", "purpose": "audit"}
            resp = client.post(
                "/gate",
                json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
            )
            assert resp.status_code == 200 and resp.json()["decision"] == "deny"
            store.add(_canonical_json(args).decode("utf-8"))
        else:
            client.post(
                "/gate",
                json={
                    "tool": "export_records",
                    "args": {"account": "ACC-777", "purpose": "audit"},
                    "agent_id": "agent:svc",
                },
            )
        # a tool the policy does not cover: no-policy digest path
        resp = client.post(
            "/gate",
            json={"tool": "unmodelled_tool", "args": {"x": 1}, "agent_id": "agent:svc"},
        )
        assert resp.status_code == 200 and resp.json()["decision"] == "deny"
        if store_all:
            # store_all means EVERYTHING stored: also the unmodelled call's
            # args, so the no-policy digest row is honestly resolvable
            # (see vector no_policy_digest_honestly_resolvable).
            store.add(_canonical_json({"x": 1}).decode("utf-8"))

    policy_dir = tmp_path / "retained-policies"
    policy_dir.mkdir()
    (policy_dir / "policies.yaml").write_text(ORIGINAL_POLICY)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_POLICY)

    def replay(**kwargs):
        return replay_authority_history(
            tmp_path / "receipts.jsonl",
            input_store_path=store_path,
            policy_dir=policy_dir,
            **kwargs,
        )

    return replay, store_path, policy_dir, alt_policy, gateway, tmp_path / "receipts.jsonl"


def _by_hash(report):
    return {row["receipt_hash"]: row for row in report["items"]}


def _first_status(report, status):
    return [r for r in report["items"] if r["status"] == status]


# --- vector: honest_full_replay -------------------------------------------


def test_honest_full_replay():
    replay, store_path, policy_dir, alt_policy, *_ = _fixture(
        Path(tempfile.mkdtemp(prefix="n5-honest-"))
    )
    report = replay(counterfactual_policy_path=alt_policy)
    # FOUR gate decisions reach the chain, not three: the two allowed
    # exports, the denied unstored call, AND the unmodelled tool's deny -
    # all four are receipts the replay must audit (chain holds 4 real
    # gate-decided envelopes; verified by replay-count).
    assert report["gate_decisions"] == 4
    assert report["verified"] == 2
    assert report["divergent"] == 0
    assert report["unverified"] == 2
    # both the unstored denied call and the unstored unmodelled call are
    # named missing-evidence, never guessed
    assert report["missing_evidence"] == {ARGS_STORE_MISSING: 2}
    assert report["verdict"].startswith("INCOMPLETE EVIDENCE:")
    # the unstored calls: receipted deny stays receipted, never guessed
    for unver in _first_status(report, "unverified"):
        assert unver["receipted_decision"] == "deny"
        assert unver["recomputed_decision"] is None


def test_honest_full_replay_everything_stored():
    replay, store_path, policy_dir, alt_policy, *_ = _fixture(
        Path(tempfile.mkdtemp(prefix="n5-full-")), store_all=True
    )
    report = replay(counterfactual_policy_path=alt_policy)
    # all four decisions now replay from evidence: the two allowed
    # exports, the stored denied call, AND the stored unmodelled call -
    # whose no-policy digest is honestly resolvable by the retained
    # empty-policy semantics (the deny recomputes exactly).
    assert report["gate_decisions"] == 4
    assert report["verified"] == 4
    assert report["unverified"] == 0
    assert report["verdict"].startswith("4/4 decisions")


# --- vector: deterministic_output_bytes -----------------------------------


def test_deterministic_output_bytes():
    replay, _, policy_dir, alt_policy, *_ = _fixture(Path(tempfile.mkdtemp(prefix="n5-det-")))
    r1 = replay(counterfactual_policy_path=alt_policy)
    r2 = replay(counterfactual_policy_path=alt_policy)
    assert deterministic_bytes(r1) == deterministic_bytes(r2)
    # canonical form: sorted keys, no whitespace
    raw = deterministic_bytes(r1)
    assert raw == json.dumps(r1, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# --- vector: tampered stored args ----------------------------------------


def _tamper_store(store_path, index, new_args):
    """Rewrite one stored record's text AND its store hash field, so the
    store itself accepts the tampered record - only the RECEIPT's digest
    binding can catch it."""
    lines = store_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[index])
    rec["text"] = _canonical_json(new_args).decode("utf-8")
    rec["hash"] = "sha256:" + hashlib.sha256(rec["text"].encode("utf-8")).hexdigest()
    lines[index] = json.dumps(rec)
    store_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_tampered_stored_args_rebinds_to_receipt_digest():
    replay, store_path, *_ = _fixture(Path(tempfile.mkdtemp(prefix="n5-tam1-")))
    _tamper_store(store_path, 0, {"account": "ACC-888"})
    report = replay()
    tampered = _first_status(report, "unverified")
    # The tampered record is rewritten text-AND-hash, so the store itself
    # accepts it - but re-keyed under its NEW self-consistent digest, and
    # the receipt binds the ORIGINAL digest. The receipt's digest binding
    # surfaces as a lookup MISS (stored_args_missing): the row is named,
    # unverified, never silently reused. (args_hash_mismatch remains the
    # guard for text still retrievable under the receipt's digest without
    # reproducing the canonical binding.)
    assert any(r["missing_evidence"] == ARGS_STORE_MISSING for r in tampered)
    # the honest second row still verifies; nothing passes silently
    assert report["verified"] == 1
    assert report["divergent"] == 0
    # the tampered row still binds by receipt: the first export's receipt
    # (receipted allow) is the tampered one
    trow = [r for r in tampered if r["receipted_decision"] == "allow"][0]
    assert trow["tool"] == "export_records"
    assert trow["recomputed_decision"] is None


def test_tampered_store_record_reads_as_missing():
    replay, store_path, policy_dir, alt_policy, *_ = _fixture(
        Path(tempfile.mkdtemp(prefix="n5-tam2-"))
    )
    lines = store_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["text"] = "tampered"
    lines[0] = json.dumps(rec)
    store_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = (
        replay(counterfactual_policy_path=None)
        if alt_policy is None
        else replay(counterfactual_policy_path=alt_policy)
    )
    assert any(r["missing_evidence"] == ARGS_STORE_MISSING for r in report["items"])
    assert report["verified"] == 1


# --- vector: missing policy artifact + digest mismatch --------------------


def test_missing_policy_artifact():
    replay, _, policy_dir, alt_policy, *_ = _fixture(Path(tempfile.mkdtemp(prefix="n5-nopol-")))
    # empty the retained policy directory
    for f in policy_dir.iterdir():
        f.unlink()
    report = replay()
    assert report["verified"] == 0 and report["divergent"] == 0
    # four receipts, none recomputable: the two stored args rows lose
    # their policy of record (artifact missing), the two unstored rows
    # are named at the args stage before the policy is even consulted
    assert report["missing_evidence"] == {
        POLICY_ARTIFACT_MISSING: 2,
        ARGS_STORE_MISSING: 2,
    }


def test_policy_digest_mismatch():
    replay, _, policy_dir, alt_policy, *_ = _fixture(Path(tempfile.mkdtemp(prefix="n5-dig2-")))
    (policy_dir / "policies.yaml").write_text(ALTERNATIVE_POLICY)
    report = replay()
    assert report["missing_evidence"].get(POLICY_DIGEST_MISMATCH) == 2
    assert report["verified"] == 0


# --- vector: forged receipt divergence -----------------------------------


def _forge_decision(chain_path, gateway, index=0):
    """Decode receipt *index*, flip its decision to deny, re-sign with
    the gate key, and rewrite the chain line: a forged receipt the
    recompute must catch as DIVERGENT (not merely unverifiable)."""
    lines = chain_path.read_text(encoding="utf-8").splitlines()
    envelope = json.loads(lines[index])
    header_b64, payload_b64, _ = envelope["jws"].split(".")
    # Each JWS segment carries its own modulo-4 remainder: pad each one
    # independently (padding the header with the payload's remainder
    # raises "Incorrect padding" whenever the header length mod 4 differs).
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    payload["x_gate"]["decision"] = "deny"
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    sig = gateway._gate_identity.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64url_encode(sig)
    new_hash = "sha256:" + hashlib.sha256(jws.encode("ascii")).hexdigest()
    lines[index] = json.dumps({"receipt_hash": new_hash, "jws": jws}, ensure_ascii=False)
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return new_hash


def test_forged_receipt_decision_diverges():
    replay, _, policy_dir, alt_policy, gateway, chain = _fixture(
        Path(tempfile.mkdtemp(prefix="n5-forg-"))
    )
    forged_hash = _forge_decision(chain, gateway, index=0)
    report = replay()
    by_hash = _by_hash(report)
    assert forged_hash in by_hash
    row = by_hash[forged_hash]
    assert row["status"] == "divergent"
    assert row["receipted_decision"] == "deny"
    assert row["recomputed_decision"] == "allow"
    assert report["verdict"].startswith("EVIDENCE DIVERGENCE:")
    assert report["divergent"] == 1 and report["verified"] == 1


# --- vector: counterfactual join + bounded disclosure --------------------


def test_counterfactual_variant_joined_by_receipt():
    replay, _, _, alt_policy, *_ = _fixture(Path(tempfile.mkdtemp(prefix="n5-cf-")))
    report = replay(counterfactual_policy_path=alt_policy)
    cf = [r["counterfactual_decision"] for r in report["items"]]
    assert cf.count("deny") == 1  # ACC-999 the alternative prevents
    assert cf.count("allow") == 1  # the unstored denial is unreplayable there
    assert None in cf
    assert report["counterfactual_note"]
    # the receipted column and the counterfactual column never overwrite
    # each other: the receipted deny of the unmodelled tool stays listed
    assert all("receipted_decision" in r for r in report["items"])


def test_bounded_disclosure():
    replay, _, _, alt_policy, *_ = _fixture(Path(tempfile.mkdtemp(prefix="n5-bd-")))
    report = replay(counterfactual_policy_path=alt_policy)
    dump = json.dumps(report)
    assert "ACC-" not in dump  # no argument VALUES anywhere in the table
    for field in VECTORS["vectors"][8]["expected"]["fields_present"]:
        assert all(field in r for r in report["items"])


# --- vector: no-policy digest honestly resolvable ------------------------


def test_no_policy_digest_honestly_resolvable():
    replay, store_path, policy_dir, alt_policy, gateway, chain = _fixture(
        Path(tempfile.mkdtemp(prefix="n5-npd-")), store_all=True
    )
    report = replay()
    rows = [
        r
        for r in report["items"]
        if r["tool"] == "unmodelled_tool" and r["missing_evidence"] is None
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == "verified"
    assert rows[0]["recomputed_decision"] == "deny"


# --- vectors file integrity ----------------------------------------------


def test_vectors_file_loads_and_names_the_draft():
    assert VECTORS["spec"] == "draft-rampertab-audit-agent-authority-history-00"
    names = {v["name"] for v in VECTORS["vectors"]}
    assert {
        "honest_full_replay",
        "deterministic_output_bytes",
        "tampered_stored_args_rebinds_to_receipt_digest",
        "missing_policy_artifact",
        "policy_digest_mismatch",
        "forged_receipt_decision_diverges",
        "counterfactual_variant_joined_by_receipt",
        "bounded_disclosure",
        "no_policy_digest_honestly_resolvable",
    } <= names
