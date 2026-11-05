"""P1.4a: agent registry schema and signed descriptor."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from raucle.agent_credentials import AgentCredentialStore
from raucle.agent_registry import (
    DESCRIPTOR_VERSION,
    AgentRegistry,
    Attestation,
    DelegationCeilings,
    DescriptorError,
    issue_descriptor,
    parse_descriptor,
    verify_descriptor,
)
from raucle.audit import Ed25519Signer

ATT = Attestation(
    attested_manifest_hash="sha256:" + hashlib.sha256(b"agent-card-bytes").hexdigest(),
    attested_manifest_kind="agent-card",
    framework="langgraph",
    framework_version="0.2.9",
)
CEIL = DelegationCeilings(max_hops=3, max_scope=4, lease_ceilings={"max_ttl_seconds": 600})


@pytest.fixture
def signer():
    return Ed25519Signer.generate()


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_descriptor_verifies_offline(signer, tmp_path):
    d = issue_descriptor(
        "agent:svc",
        operator="Org X",
        operator_binding="rak-key:ops",
        status="enrolled",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
    )
    path = tmp_path / "descriptor.json"
    d.save(path)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    verdict = verify_descriptor(loaded, signer.public_key_pem())
    assert verdict.valid
    assert verdict.valid and verdict.descriptor
    assert verdict.descriptor.agent_id == "agent:svc"
    assert verdict.descriptor.version == DESCRIPTOR_VERSION
    assert verdict.descriptor.ceilings.max_hops == 3


def test_tampered_field_fails_verification(signer):
    d = issue_descriptor(
        "agent:svc",
        operator="Org X",
        operator_binding="rak-key:ops",
        status="enrolled",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
    )
    body = d.to_dict()
    body["attested_manifest_hash"] = _sha(b"tampered-manifest")
    assert not verify_descriptor(body, signer.public_key_pem()).valid
    body2 = d.to_dict()
    body2["delegation_ceilings"] = {**body2["delegation_ceilings"], "max_hops": 99}
    assert not verify_descriptor(body2, signer.public_key_pem()).valid
    foreign = Ed25519Signer.generate()
    assert not verify_descriptor(d.to_dict(), foreign.public_key_pem).valid


def test_unknown_version_and_unknown_field_fail_closed(signer):
    d = issue_descriptor(
        "agent:svc",
        operator="Org X",
        operator_binding="rak-key:ops",
        status="enrolled",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
    )
    body = d.to_dict()
    body["version"] = "agent-descriptor/v99"
    assert not verify_descriptor(body, signer.public_key_pem()).valid
    body2 = d.to_dict()
    body2["sneaky"] = "x"
    with pytest.raises(DescriptorError):
        parse_descriptor(body2)


def test_attestation_and_ceiling_validation(signer):
    bad = Attestation(
        attested_manifest_hash="not-a-hash",
        attested_manifest_kind="agent-card",
        framework="f",
        framework_version="1",
    )
    with pytest.raises(DescriptorError):
        bad.validate()
    with pytest.raises(DescriptorError):
        Attestation(
            attested_manifest_hash=_sha(b"x"),
            attested_manifest_kind="nope",
            framework="f",
            framework_version="1",
        ).validate()
    with pytest.raises(DescriptorError):
        DelegationCeilings(lease_ceilings={"max_turtle": 1}).validate()
    with pytest.raises(DescriptorError):
        issue_descriptor(
            "agent:svc",
            operator="O",
            operator_binding="b",
            status="enrolled",
            attestation=ATT,
            ceilings=DelegationCeilings(max_hops=-1),
            signer=signer,
        )


def test_registry_enrol_update_retire_append_only(signer, tmp_path):
    reg_path = tmp_path / "agents.jsonl"
    reg = AgentRegistry(reg_path)
    reg.enrol(
        "agent:a",
        operator="Org X",
        operator_binding="k1",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
    )
    newer = Attestation(
        attested_manifest_hash=_sha(b"rotated-card"),
        attested_manifest_kind="agent-card",
        framework="langgraph",
        framework_version="0.3.0",
    )
    reg.update(
        "agent:a",
        operator="Org X",
        operator_binding="k1",
        attestation=newer,
        ceilings=CEIL,
        signer=signer,
    )
    reg.retire("agent:a", operator="Org X", operator_binding="k1", signer=signer)
    assert len(reg._entries) == 3  # append-only: nothing rewritten
    assert [rec.status for rec in reg.history("agent:a")] == ["enrolled", "enrolled", "retired"]
    current = reg.resolve("agent:a")
    assert current is not None
    assert current.status == "retired"
    # Fail-closed: a retired agent is NOT reported active.
    assert current.attestation.attested_manifest_hash == "sha256:" + "0" * 64
    reloaded = AgentRegistry(reg_path)
    current2 = reloaded.resolve("agent:a")
    assert current2 is not None and current2.status == "retired"
    assert len(reloaded.agent_ids()) == 1


def test_registry_entries_verify_offline_after_reload(signer, tmp_path):
    reg_path = tmp_path / "agents.jsonl"
    reg = AgentRegistry(reg_path)
    reg.enrol(
        "agent:b",
        operator="Org X",
        operator_binding="k1",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
    )
    reg.retire("agent:b", operator="Org X", operator_binding="k1", signer=signer)
    reloaded = AgentRegistry(reg_path)
    verdicts = reloaded.verify_all(signer.public_key_pem())
    assert [v.valid for v in verdicts] == [True, True]
    reg_path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(DescriptorError):
        AgentRegistry(reg_path)


def test_credential_store_integration(signer, tmp_path):
    creds = AgentCredentialStore(tmp_path / "creds.jsonl")
    reg = AgentRegistry(tmp_path / "agents.jsonl")
    record, key = reg.enrol(
        "agent:new",
        operator="Org X",
        operator_binding="k1",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
        credential_store=creds,
    )
    assert record["status"] == "enrolled"
    assert key is not None and key.startswith("rak_")
    assert creds.verify(key) == "agent:new"
    # Second enrolment rotates nothing: the agent already holds a key.
    record2, key2 = reg.enrol(
        "agent:new",
        operator="Org X",
        operator_binding="k1",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
        credential_store=creds,
    )
    assert key2 is None
    assert creds.verify(key) == "agent:new"
    # Unknown agent without a store binding is still enrolable (the
    # operator_binding is free-form so external operators enrol too).
    record3, _ = reg.enrol(
        "agent:ext",
        operator="External",
        operator_binding="k2",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
    )
    assert record3["status"] == "enrolled"


def test_duplicate_json_keys_rejected(signer):
    d = issue_descriptor(
        "agent:svc",
        operator="O",
        operator_binding="b",
        status="enrolled",
        attestation=ATT,
        ceilings=CEIL,
        signer=signer,
    )
    doc = json.dumps(d.to_dict())
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.json"
        p.write_text(doc, encoding="utf-8")
        assert verify_descriptor(json.loads(doc), signer.public_key_pem()).valid
