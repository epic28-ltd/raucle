"""Admission policy hooks (P1.4c): refuse unattested agents at the gate.

Acceptance criterion: an attempt to run an enrolment with a tampered
manifest is refused and the refusal is receipted. The refusal rides the
EXISTING receipt machinery: gate denies reuse _emit_gate_receipt and
enrolment/activation refusals reuse _emit_authority_receipt, both
verifiable offline with ProvenanceVerifier.
"""

import base64
import json

import pytest

from raucle.admission import admission_check
from raucle.agent_registry import (
    AgentRegistry,
    Attestation,
    DelegationCeilings,
    DescriptorError,
    issue_descriptor,
)
from raucle.audit import Ed25519Signer
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.provenance import ProvenanceVerifier

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


def _attest() -> Attestation:
    return Attestation(
        attested_manifest_hash="sha256:" + "a" * 64,
        attested_manifest_kind="manifest",
        framework="testfw",
        framework_version="1.0",
    )


@pytest.fixture()
def operator():
    return Ed25519Signer.generate()


@pytest.fixture()
def operator_pem(operator):
    return operator.public_key_pem().decode("ascii")


def _signed_record(operator) -> dict:
    return issue_descriptor(
        "agent:svc",
        operator="ops",
        operator_binding="rak:ops",
        status="enrolled",
        attestation=_attest(),
        ceilings=DelegationCeilings(),
        signer=operator,
    ).to_dict()


def _tampered_record(operator) -> dict:
    """A valid signed record with the attested manifest hash swapped after
    signing: the manifest is tampered, the signature no longer covers it."""
    record = _signed_record(operator)
    record["attested_manifest_hash"] = "sha256:" + "b" * 64
    return record


# -- admission_check ---------------------------------------------------------


class TestAdmissionCheck:
    def test_valid_descriptor_admitted(self, operator, operator_pem):
        verdict = admission_check(_signed_record(operator), operator_pem)
        assert verdict.allowed
        assert verdict.descriptor is not None
        assert verdict.descriptor.agent_id == "agent:svc"

    def test_tampered_manifest_refused(self, operator, operator_pem):
        verdict = admission_check(_tampered_record(operator), operator_pem)
        assert not verdict.allowed
        assert "verification failed" in verdict.reason

    def test_bad_signature_refused(self, operator, operator_pem, other):
        """A record signed by a different key than the operator's fails."""
        record = issue_descriptor(
            "agent:svc",
            operator="ops",
            operator_binding="rak:ops",
            status="enrolled",
            attestation=_attest(),
            ceilings=DelegationCeilings(),
            signer=other,
        ).to_dict()
        verdict = admission_check(record, operator_pem)
        assert not verdict.allowed

    @pytest.fixture()
    def other(self):
        return Ed25519Signer.generate()

    def test_unknown_version_refused(self, operator, operator_pem):
        record = _signed_record(operator)
        record["version"] = "agent-descriptor/v9"
        verdict = admission_check(record, operator_pem)
        assert not verdict.allowed
        assert "verification failed" in verdict.reason

    def test_retired_descriptor_refused(self, operator, operator_pem):
        record = issue_descriptor(
            "agent:svc",
            operator="ops",
            operator_binding="rak:ops",
            status="retired",
            attestation=_attest(),
            ceilings=DelegationCeilings(),
            signer=operator,
        ).to_dict()
        verdict = admission_check(record, operator_pem)
        assert not verdict.allowed
        assert "retired" in verdict.reason

    def test_unexpected_failure_fails_closed(self, operator, operator_pem):
        """A broken key input is a refusal, never an allow."""
        verdict = admission_check(_signed_record(operator), "not a pem")
        assert not verdict.allowed


# -- AgentRegistry.enrol_from_descriptor -------------------------------------


class TestEnrolFromDescriptor:
    def test_valid_descriptor_enrols(self, operator, operator_pem, tmp_path):
        reg = AgentRegistry(path=tmp_path / "agents.jsonl")
        rec = reg.enrol_from_descriptor(_signed_record(operator), operator_pem)
        assert rec["agent_id"] == "agent:svc"

    def test_tampered_manifest_enrolment_refused_and_not_appended(
        self, operator, operator_pem, tmp_path
    ):
        """The AC: an enrolment attempt with a tampered manifest is refused
        and nothing lands in the registry."""
        path = tmp_path / "agents.jsonl"
        reg = AgentRegistry(path=path)
        with pytest.raises(DescriptorError, match="admission refused"):
            reg.enrol_from_descriptor(_tampered_record(operator), operator_pem)
        assert not path.exists()
        assert reg.agent_ids() == []
        # a re-opened store has nothing to fold either
        assert AgentRegistry(path=path).agent_ids() == []


# -- Gateway receipting ------------------------------------------------------


@pytest.fixture()
def gw(tmp_path, operator_pem):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_registry_public_key=operator_pem,
        emit_receipts=True,
    )
    return RaucleGateway(config)


def _decode_payload(receipt: dict) -> dict:
    part = receipt["jws"].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _read_receipts(gw) -> list[dict]:
    with open(gw.config.receipt_store, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class TestEnrolmentReceipting:
    def test_tampered_enrolment_refused_and_receipted(self, gw, operator, operator_pem):
        verdict, receipt_id = gw.admit_enrolment(_tampered_record(operator), operator_pem)
        assert not verdict.allowed
        assert receipt_id
        receipts = _read_receipts(gw)
        found = [r for r in receipts if r["receipt_hash"] == receipt_id]
        assert len(found) == 1
        payload = _decode_payload(found[0])
        assert payload["guardrail_verdict"] == "deny"
        assert payload["x_admission"]["decision_source"] == "admission"
        assert payload["x_admission"]["descriptor_hash"]
        assert payload["x_admission"]["reason"]

    def test_admission_receipts_verify_with_provenance_verifier(self, gw, operator, operator_pem):
        _, receipt_id = gw.admit_enrolment(_tampered_record(operator), operator_pem)
        verifier = ProvenanceVerifier(
            public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
        )
        report = verifier.verify_chain(gw.config.receipt_store)
        assert report.valid, report.errors
        hashes = [r["receipt_hash"] for r in _read_receipts(gw)]
        assert receipt_id in hashes

    def test_valid_enrolment_receipted_allow(self, gw, operator, operator_pem):
        verdict, receipt_id = gw.admit_enrolment(_signed_record(operator), operator_pem)
        assert verdict.allowed
        assert receipt_id
        payload = _decode_payload(
            next(r for r in _read_receipts(gw) if r["receipt_hash"] == receipt_id)
        )
        assert payload["guardrail_verdict"] == "allow"
        assert payload["x_admission"]["agent_id"] == "agent:svc"


# -- Gate enforcement --------------------------------------------------------


@pytest.fixture()
def enforced_gw(tmp_path, operator, operator_pem):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    agents = tmp_path / "agents.jsonl"
    registry = AgentRegistry(path=agents)
    registry.enrol_from_descriptor(_signed_record(operator), operator_pem)
    # a retired agent too
    registry.retire(
        "agent:gone", operator="ops", operator_binding="rak:ops", signer=operator
    )
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_registry_file=str(agents),
        agent_registry_public_key=operator_pem,
        admission_enforce=True,
        emit_receipts=True,
    )
    return RaucleGateway(config)


class TestGateAdmission:
    def test_enrolled_agent_reaches_policy(self, enforced_gw):
        result = enforced_gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc"
        )
        assert result["decision"] == "allow"
        assert not result["reason"].startswith("admission refused")

    def test_unenrolled_agent_refused_at_gate(self, enforced_gw):
        result = enforced_gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:nobody"
        )
        assert result["decision"] == "deny"
        assert result["reason"] == "admission refused: no descriptor enrolled for agent"
        assert result["receipt_id"].startswith("sha256:")

    def test_retired_agent_refused_at_gate(self, enforced_gw):
        result = enforced_gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:gone"
        )
        assert result["decision"] == "deny"
        assert "retired" in result["reason"]
        assert result["receipt_id"].startswith("sha256:")

    def test_gate_refusal_is_receipted_and_verifiable(self, enforced_gw):
        result = enforced_gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:nobody"
        )
        verifier = ProvenanceVerifier(
            public_keys={
                enforced_gw.gate_identity.key_id: enforced_gw.gate_identity.public_key_pem()
            }
        )
        report = verifier.verify_chain(enforced_gw.config.receipt_store)
        assert report.valid, report.errors
        hashes = [r["receipt_hash"] for r in _read_receipts(enforced_gw)]
        assert result["receipt_id"] in hashes

    def test_tampered_store_record_refused_at_gate(self, enforced_gw, operator):
        """A tampered descriptor appended directly to the store file fails
        admission at the gate (fail-closed over store contents)."""
        record = _signed_record(operator)
        record["attested_manifest_hash"] = "sha256:" + "c" * 64
        record["agent_id"] = "agent:tampered"
        with open(enforced_gw.config.agent_registry_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        result = enforced_gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:tampered"
        )
        assert result["decision"] == "deny"
        assert "admission refused" in result["reason"]
        assert result["receipt_id"].startswith("sha256:")

    def test_hook_unconfigured_leaves_gate_behaviour_unchanged(self, gw):
        """Without admission configured, calls behave exactly as before."""
        result = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc"
        )
        assert result["decision"] == "allow"
