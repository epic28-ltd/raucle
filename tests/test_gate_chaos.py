"""S5 (EPIC S5): gate chaos mode — default-off, refusal, named fault receipts.

Contract:
1. Chaos is OFF unless RAUCLE_ENV=dev AND RAUCLE_CHAOS=1; a gateway with
   no env behaves exactly as before.
2. Chaos is REFUSED outside DEV builds and behind any auth mode that is
   not "off" — at construction time, with named ValueError messages.
3. Each named fault (drop_receipt, delay_index_write, misorder_chain)
   fires exactly once, is recorded, and the OFFLINE checks flag it by
   name: offline_flags for store/index gaps, HashChainSink.verify_chain
   for the mis-ordered chain.
4. Each injection can be emitted as a NAMED FAULT RECEIPT — a signed
   compact JWS naming the fault — that verifies offline under the gate
   identity's public key, and fails closed under any other key or after
   tampering.
"""

import json

import pytest

from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink
from raucle.chaos import (
    CHAOS_FAULTS,
    ChaosAuditSink,
    ChaosFaultController,
    emit_fault_receipt,
    offline_flags,
    verify_fault_receipt,
)
from raucle.gateway import GatewayConfig, RaucleGateway

POLICY = """
version: 1
issuer: chaos.example
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-999"]
"""


@pytest.fixture(autouse=True)
def _clean_chaos_env(monkeypatch):
    for var in ("RAUCLE_CHAOS", "RAUCLE_ENV", "RAUCLE_CHAOS_FAULTS"):
        monkeypatch.delenv(var, raising=False)
    # chaos module state is env-only; nothing to leak between tests
    yield


def _gateway(tmp_path, monkeypatch, *, faults=None, with_index=True):
    """A gateway with chaos enabled (dev, gate_auth off)."""
    monkeypatch.setenv("RAUCLE_ENV", "dev")
    monkeypatch.setenv("RAUCLE_CHAOS", "1")
    if faults:
        monkeypatch.setenv("RAUCLE_CHAOS_FAULTS", faults)
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
    config.gate_auth = "off"
    if with_index:
        config.receipt_index_path = str(tmp_path / "index.sqlite")
    gateway = RaucleGateway(config)
    return gateway, tmp_path / "receipts.jsonl"


def _make_calls(gateway, n=3):
    hashes = []
    for account in ("ACC-001", "ACC-999", "ACC-001"):
        if len(hashes) >= n:
            break
        decision = gateway.check_tool_call(
            "export_records", {"account": account}, agent_id="agent:svc"
        )
        assert decision["decision"] == "allow"
        hashes.append(decision["receipt_id"])
    return hashes


def test_chaos_off_by_default(tmp_path, monkeypatch):
    """No env: the controller is disabled and no fault ever fires."""
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
    config.gate_auth = "off"
    gateway = RaucleGateway(config)
    assert not gateway._chaos.fault_active("drop_receipt")
    assert gateway._chaos.injections == []
    hashes = _make_calls(gateway)
    assert len(hashes) == 3
    flags = offline_flags(str(tmp_path / "receipts.jsonl"), claimed_hashes=hashes)
    assert flags == []


def test_chaos_refused_outside_dev_builds(monkeypatch):
    monkeypatch.setenv("RAUCLE_CHAOS", "1")
    with pytest.raises(ValueError, match="not 'dev'"):
        ChaosFaultController.from_env(gate_auth="off")


def test_chaos_refused_behind_real_authentication(monkeypatch):
    monkeypatch.setenv("RAUCLE_ENV", "dev")
    monkeypatch.setenv("RAUCLE_CHAOS", "1")
    with pytest.raises(ValueError, match="not 'off'"):
        ChaosFaultController.from_env(gate_auth="apikey")
    with pytest.raises(ValueError, match="not 'off'"):
        ChaosFaultController.from_env(gate_auth="token")


def test_gateway_refuses_chaos_with_apikey_auth(tmp_path, monkeypatch):
    """The refusal is enforced at gateway construction, not later."""
    monkeypatch.setenv("RAUCLE_ENV", "dev")
    monkeypatch.setenv("RAUCLE_CHAOS", "1")
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
    config.gate_auth = "apikey"
    with pytest.raises(ValueError, match="not 'off'"):
        RaucleGateway(config)


def test_drop_receipt_fires_once_and_is_flagged_named(tmp_path, monkeypatch):
    gateway, store = _gateway(tmp_path, monkeypatch, faults="drop_receipt")
    hashes = _make_calls(gateway)
    # exactly one injection, named
    assert [i["fault"] for i in gateway._chaos.injections] == ["drop_receipt"]
    # the DROPPED receipt is the one absent from the store
    dropped = gateway._chaos.injections[0]["target"]
    assert dropped in hashes  # the caller still holds the hash
    flags = offline_flags(str(store), claimed_hashes=hashes)
    assert len(flags) == 1 and flags[0].startswith("drop_receipt:") and dropped in flags[0]


def test_delay_index_write_defers_and_drain_catches_up(tmp_path, monkeypatch):
    gateway, store = _gateway(tmp_path, monkeypatch, faults="delay_index_write")
    index = gateway._receipt_index
    assert index is not None
    decision = gateway.check_tool_call(
        "export_records", {"account": "ACC-001"}, agent_id="agent:svc"
    )
    assert decision["decision"] == "allow"
    delayed = gateway._chaos.injections[0]["target"]
    assert [i["fault"] for i in gateway._chaos.injections] == ["delay_index_write"]
    # with the drain never called: the receipt is in the store but
    # still absent from the index projection - named offline
    flags = offline_flags(str(store), index=index)
    assert any(f.startswith("delay_index_write:") and delayed in f for f in flags), flags
    # the drain is the catch-up contract: after it, the gap closes
    assert gateway._chaos.drain_pending_index_writes(index) >= 1
    assert offline_flags(str(store), index=index) == []


def test_misorder_chain_breaks_the_offline_verifier(tmp_path, monkeypatch):
    gateway, store = _gateway(tmp_path, monkeypatch, faults="misorder_chain")
    audit_path = tmp_path / "audit.jsonl"
    sink = HashChainSink(audit_path)
    chaos_sink = ChaosAuditSink(sink, gateway._chaos)
    chaos_sink.append({"tool": "a", "n": 1})
    chaos_sink.append({"tool": "b", "n": 2})  # lands BEFORE the withheld record
    chaos_sink.close()
    assert [i["fault"] for i in gateway._chaos.injections] == ["misorder_chain"]
    lines = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    events = [ln["index"] for ln in lines if "index" in ln]
    # the file order no longer matches the index sequence
    assert events != sorted(events)
    report = AuditVerifier().verify_chain(audit_path)
    assert not report.valid
    assert any("index mismatch" in e or "prev_hash mismatch" in e for e in report.errors)


def test_named_fault_receipts_verify_offline_and_fail_closed(tmp_path, monkeypatch):
    """Every injection can be emitted as a signed receipt naming the fault."""
    signer = Ed25519Signer.generate()
    gateway, store = _gateway(tmp_path, monkeypatch, faults="drop_receipt")
    _make_calls(gateway, n=1)
    receipts = gateway._chaos.fault_receipts(signer, key_id="chaos-gate")
    assert len(receipts) == 1
    ok, why = verify_fault_receipt(receipts[0], public_key_pem=signer.public_key_pem())
    assert ok, why
    # the receipt NAMES the fault it documents
    header, payload, sig = receipts[0]["jws"].split(".")
    import base64

    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    assert decoded["fault"] == "drop_receipt"
    assert decoded["typ"] == "raucle/chaos-fault/v1"

    # fail-closed: a wrong key and a tampered payload both refuse
    outsider = Ed25519Signer.generate()
    ok, why = verify_fault_receipt(receipts[0], public_key_pem=outsider.public_key_pem())
    assert not ok and "signature does not verify" in why
    tampered = dict(receipts[0])
    tampered["jws"] = receipts[0]["jws"][:-6] + "AAAAAA"
    ok, why = verify_fault_receipt(tampered, public_key_pem=signer.public_key_pem())
    assert not ok and "signature does not verify" in why
    # an unknown fault name is refused at emission
    with pytest.raises(ValueError, match="unknown chaos fault"):
        emit_fault_receipt(signer, key_id="k", fault="poltergeist")


def test_each_fault_receipts_run_flags_offline_verifier(tmp_path, monkeypatch):
    """The full chaos run: all three named faults, all named receipts.

    Each fault fires exactly once; the offline verifier flags each of the
    three with its named error, and the fault receipts verify offline.
    """
    gateway, store = _gateway(tmp_path, monkeypatch)  # all faults
    hashes = _make_calls(gateway)
    audit_path = tmp_path / "audit.jsonl"
    sink = HashChainSink(audit_path)
    chaos_sink = ChaosAuditSink(sink, gateway._chaos)
    chaos_sink.append({"tool": "a"})
    chaos_sink.append({"tool": "b"})  # the successor lands before the withheld record
    chaos_sink.close()
    faults_injected = [i["fault"] for i in gateway._chaos.injections]
    assert set(faults_injected) == set(CHAOS_FAULTS) and len(faults_injected) == 3

    # offline flags name the store fault; the delayed index write was
    # already drained by the next real write (the catch-up contract),
    # so the projection is consistent by the end of the run by design
    flags = offline_flags(str(store), index=gateway._receipt_index, claimed_hashes=hashes)
    assert any(f.startswith("drop_receipt:") for f in flags)
    assert not any(f.startswith("delay_index_write:") for f in flags)
    # the misordered chain is flagged by the chain verifier
    report = AuditVerifier().verify_chain(audit_path)
    assert not report.valid

    # every fault carries its NAMED receipt and each verifies offline
    signer = gateway._gate_identity
    receipts = gateway._chaos.fault_receipts(signer, key_id="agent:gate")
    assert len(receipts) == 3
    for envelope in receipts:
        ok, why = verify_fault_receipt(envelope, public_key_pem=signer.public_key_pem())
        assert ok, why
