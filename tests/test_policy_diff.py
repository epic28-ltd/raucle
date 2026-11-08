"""S2 (EPIC S2): the receipt-bound bilateral policy diff.

Contract: the counterfactual replay's report becomes a signed document
binding chain head + both policy digests; the counterparty verifies it
OFFLINE (public key + referenced material only) and a tampered document,
a wrong key, a swapped chain or an edited policy file all fail with NAMED
errors — never a partial pass.
"""

import base64
import json

from raucle.policy_diff import (
    POLICY_DIFF_TYP,
    sign_policy_diff_document,
    verify_policy_diff_document,
)
from raucle.provenance import AgentIdentity, _canonical_json
from tests.test_counterfactual import ALTERNATIVE_POLICY, _incident


def _report(chain, store, alt_policy):
    from raucle.counterfactual import replay_counterfactual

    return replay_counterfactual(chain, input_store_path=store, alternative_policy_path=alt_policy)


def _material(tmp_path, agent):
    chain, store = _incident(tmp_path)
    alt_policy = tmp_path / "alt.yaml"
    alt_policy.write_text(ALTERNATIVE_POLICY)
    report = _report(chain, store, alt_policy)
    envelope = sign_policy_diff_document(
        agent,
        key_id=agent.key_id,
        report=report,
        chain_path=str(chain),
        original_policy_path=str(tmp_path / "policies.yaml"),
        alternative_policy_path=str(alt_policy),
        generated_at=1700000000,
    )
    return envelope, chain, store, alt_policy, tmp_path / "policies.yaml"


def test_roundtrip_verifies_offline(tmp_path):
    """Sign once, verify with ONLY the public key + material."""
    agent = AgentIdentity.generate(agent_id="agent:reviewer", allowed_tools=[])
    envelope, chain, store, alt_policy, orig_policy = _material(tmp_path, agent)
    ok, errors = verify_policy_diff_document(
        envelope,
        public_key_pem=agent.public_key_pem(),
        chain_path=str(chain),
        original_policy_path=str(orig_policy),
        alternative_policy_path=str(alt_policy),
        input_store_path=str(store),
    )
    assert ok, errors
    assert errors == []
    # envelope shape matches the receipt-chain outer shape (archivable beside it)
    assert envelope["receipt_hash"].startswith("sha256:")
    assert envelope["typ"] == POLICY_DIFF_TYP


def test_tampered_summary_and_wrong_key_fail_named(tmp_path):
    agent = AgentIdentity.generate(agent_id="agent:reviewer", allowed_tools=[])
    envelope, chain, store, alt_policy, orig_policy = _material(tmp_path, agent)
    pub = agent.public_key_pem()

    # 1: a retyped summary (the dishonesty this feature exists to prevent)
    head, payload_b64, sig = envelope["jws"].split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    payload["document"]["summary"]["prevented_by_alternative"] = 99
    new_payload = base64.urlsafe_b64encode(_canonical_json(payload)).decode().rstrip("=")
    tampered = {"jws": f"{head}.{new_payload}.{sig}"}
    ok, errors = verify_policy_diff_document(
        tampered,
        public_key_pem=pub,
        chain_path=str(chain),
        original_policy_path=str(orig_policy),
        alternative_policy_path=str(alt_policy),
        input_store_path=str(store),
    )
    assert not ok
    assert any("signature does not verify" in e for e in errors)

    # 2: an honest document verified under the WRONG public key
    outsider = AgentIdentity.generate(agent_id="agent:outsider", allowed_tools=[])
    ok, errors = verify_policy_diff_document(
        envelope,
        public_key_pem=outsider.public_key_pem(),
        chain_path=str(chain),
        original_policy_path=str(orig_policy),
        alternative_policy_path=str(alt_policy),
        input_store_path=str(store),
    )
    assert not ok
    assert any("signature does not verify" in e for e in errors)


def test_binding_drift_fails_with_named_errors(tmp_path):
    agent = AgentIdentity.generate(agent_id="agent:reviewer", allowed_tools=[])
    envelope, chain, store, alt_policy, orig_policy = _material(tmp_path, agent)
    pub = agent.public_key_pem()

    # swap in a DIFFERENT chain: the chain_head binding must flag it
    lines = chain.read_text().splitlines()
    chain2 = tmp_path / "chain2.jsonl"
    chain2.write_text(
        json.dumps(json.loads(lines[0])) + "\n" + json.dumps(json.loads(lines[0])) + "\n"
    )
    ok, errors = verify_policy_diff_document(
        envelope,
        public_key_pem=pub,
        chain_path=str(chain2),
        original_policy_path=str(orig_policy),
        alternative_policy_path=str(alt_policy),
        input_store_path=str(store),
    )
    assert not ok
    assert any("chain_head" in e for e in errors)

    # edit the alternative policy after signing: the digest binding flags it
    alt2 = tmp_path / "alt2.yaml"
    alt2.write_text(ALTERNATIVE_POLICY + "\n  - tool: other_tool\n")
    ok, errors = verify_policy_diff_document(
        envelope,
        public_key_pem=pub,
        chain_path=str(chain),
        original_policy_path=str(orig_policy),
        alternative_policy_path=str(alt2),
        input_store_path=str(store),
    )
    assert not ok
    assert any("alternative_policy_sha256" in e for e in errors)

    # edit the incident chain's bound evidence (wipe a stored input):
    # the replay re-run diverges and the verification fails
    lines = store.read_text().splitlines()
    store.write_text("\n".join(lines[:-1]) + "\n")
    ok, errors = verify_policy_diff_document(
        envelope,
        public_key_pem=pub,
        chain_path=str(chain),
        original_policy_path=str(orig_policy),
        alternative_policy_path=str(alt_policy),
        input_store_path=str(store),
    )
    assert not ok
    assert any("does not match the document" in e for e in errors)


def test_bounded_disclosure_holds_in_the_document(tmp_path):
    agent = AgentIdentity.generate(agent_id="agent:reviewer", allowed_tools=[])
    envelope, chain, store, alt_policy, _orig = _material(tmp_path, agent)
    _head, payload_b64, _sig = envelope["jws"].split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    text = json.dumps(payload)
    # the incident's arg VALUES never enter the signed document
    assert "ACC-001" not in text
    assert "ACC-999" not in text
