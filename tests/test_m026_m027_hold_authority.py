# SPDX-License-Identifier: Apache-2.0
"""M-026 / M-027: round-3 bypass remediation regression tests (RED-026/027).

M-026 (RED-026 / AV-02): an agent/chain hold snapshots token ids when
applied; a chain re-minted into the SAME ledger during the hold escaped
the per-call deny set. DelegationLedger.register now consults active
containment holds (published as control rows in the ledger by the
containment manager) at mint/registration time: new authority entering a
held scope is refused into the live deny set (named ``hold_active``), or
the registration is refused outright when no revocations surface exists.

M-027 (RED-027 / AV-10): the resume digest check was integrity-only - a
state writer could re-stamp ``original_bytes_b64`` + ``original_sha256``
together and commit attacker bytes silently. Resume now binds the
snapshot to the RECEIPTED hold: a state whose snapshot digest/scope does
not match the hold receipt is refused named (``snapshot_restamped``),
receipted, and the halt stays applied.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.containment import (
    VERDICT_RESUME,
    VERDICT_RESUME_REFUSED,
    ContainmentConfig,
    ContainmentError,
    ContainmentManager,
)


def _receipts_payloads(path) -> list[dict]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        part = row["jws"].split(".")[1]
        out.append(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))))
    return out


def _revocation_ids(path) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return {
        json.loads(line)["token_id"]
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


@pytest.fixture
def env(tmp_path):
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger_path = tmp_path / "delegations.jsonl"
    ledger_path.touch()
    cfg = ContainmentConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        revocations_file=str(tmp_path / "revocations.jsonl"),
        delegations_file=str(ledger_path),
        receipts_path=str(tmp_path / "receipts.jsonl"),
        state_dir=str(tmp_path / "containment"),
        actor="op",
        global_min_approvers=1,
    )
    return issuer, ledger_path, cfg


def test_remit_during_agent_hold_is_covered(env):
    """RED-026: authority re-minted during a hold lands in the deny set."""
    issuer, ledger_path, cfg = env
    ledger = DelegationLedger(ledger_path)
    root = issuer.mint(agent_id="agent:svc", tool="lookup", ttl_seconds=600)
    ledger.register(root, "agent:svc", verifying_key=issuer)

    mgr = ContainmentManager(cfg)
    mgr.hold(scope="agent", scope_id="agent:svc", reason="incident")

    reminted = issuer.mint(agent_id="agent:svc", tool="lookup", ttl_seconds=900)
    if reminted.token_id == root.token_id:
        reminted = issuer.mint(agent_id="agent:svc", tool="other", ttl_seconds=900)
    ledger.register(reminted, "agent:svc", verifying_key=issuer)

    assert reminted.token_id in _revocation_ids(cfg.revocations_file), (
        "new authority minted into a held scope must be covered by the deny set"
    )
    rows = [
        json.loads(line)
        for line in Path(cfg.revocations_file).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    row = next(r for r in rows if r["token_id"] == reminted.token_id)
    assert "hold_active" in row["reason"], f"re-mint refusal must be named hold_active: {row}"


def test_remit_after_resume_is_not_snapped(env):
    """After the hold is released, ordinary registrations stay ordinary."""
    issuer, ledger_path, cfg = env
    ledger = DelegationLedger(ledger_path)
    root = issuer.mint(agent_id="agent:svc", tool="lookup", ttl_seconds=600)
    ledger.register(root, "agent:svc", verifying_key=issuer)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="agent", scope_id="agent:svc", reason="drill")
    mgr.resume(reason="drill over")

    later = issuer.mint(agent_id="agent:svc", tool="lookup", ttl_seconds=900)
    ledger.register(later, "agent:svc", verifying_key=issuer)
    assert later.token_id not in _revocation_ids(cfg.revocations_file)


def test_registration_into_held_chain_is_covered(env):
    """A chain hold covers tokens minted under the held token id."""
    issuer, ledger_path, cfg = env
    ledger = DelegationLedger(ledger_path)
    root = issuer.mint(agent_id="agent:svc", tool="lookup", ttl_seconds=600)
    ledger.register(root, "agent:svc", verifying_key=issuer)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="chain", scope_id=root.token_id, reason="chain compromise")

    child = issuer.attenuate(root)
    ledger.register(child, "agent:svc", verifying_key=issuer)
    assert child.token_id in _revocation_ids(cfg.revocations_file)


def test_registration_refused_when_held_scope_has_no_revocations_surface(env):
    """Fail-closed: no revocations surface means no uncovered authority."""
    issuer, ledger_path, cfg = env
    ledger = DelegationLedger(ledger_path)
    root = issuer.mint(agent_id="agent:svc", tool="lookup", ttl_seconds=600)
    ledger.register(root, "agent:svc", verifying_key=issuer)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="agent", scope_id="agent:svc", reason="incident")
    # the revocations surface is replaced by an unwritable directory:
    # the deny set cannot be extended, so new authority refuses (fail-closed)
    Path(cfg.revocations_file).unlink()
    Path(cfg.revocations_file).mkdir()

    reminted = issuer.mint(agent_id="agent:svc", tool="lookup", ttl_seconds=900)
    with pytest.raises(ValueError, match="hold_active"):
        ledger.register(reminted, "agent:svc", verifying_key=issuer)


def test_restamped_snapshot_resume_refused_and_receipted(tmp_path):
    """RED-027: a coherent re-stamp cannot commit attacker bytes."""
    policy = tmp_path / "policies.yaml"
    original = b"version: 1\nissuer: bank\npolicies:\n"
    policy.write_bytes(original)
    cfg = ContainmentConfig(
        policy_file=str(policy),
        revocations_file="",
        delegations_file="",
        receipts_path=str(tmp_path / "receipts.jsonl"),
        state_dir=str(tmp_path / "containment"),
        actor="op",
        global_min_approvers=1,
    )
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global", reason="drill")
    hold_receipt = mgr.status()["receipt_id"]

    attacker_policy = b"version: 1\nissuer: attacker\npolicies:\n"
    state_path = tmp_path / "containment" / "containment-state.json"
    state = json.loads(state_path.read_text())
    state["original_bytes_b64"] = base64.b64encode(attacker_policy).decode("ascii")
    state["original_sha256"] = hashlib.sha256(attacker_policy).hexdigest()
    state_path.write_text(json.dumps(state))

    result = mgr.resume()
    assert result["status"] == "resume_refused"
    assert result["reason"] == "snapshot_restamped"
    assert result["held"] is True
    # no attacker bytes, ever
    assert policy.read_bytes() != attacker_policy
    # the refusal is receipted; the hold is unchanged
    verdicts = [p["verdict"] for p in _receipts_payloads(cfg.receipts_path)]
    assert verdicts == ["containment_hold", VERDICT_RESUME_REFUSED]
    payloads = _receipts_payloads(cfg.receipts_path)
    assert payloads[-1]["extra"]["reason"] == "snapshot_restamped"
    assert payloads[-1]["extra"]["hold_receipt_id"] == hold_receipt


def test_restamped_bytes_alone_still_refuse(tmp_path):
    """The plain restore-digest mismatch path keeps its named refusal."""
    policy = tmp_path / "policies.yaml"
    policy.write_bytes(b"version: 1\nissuer: bank\npolicies:\n")
    cfg = ContainmentConfig(
        policy_file=str(policy),
        revocations_file="",
        delegations_file="",
        receipts_path=str(tmp_path / "receipts.jsonl"),
        state_dir=str(tmp_path / "containment"),
        actor="op",
        global_min_approvers=1,
    )
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global")
    state_path = tmp_path / "containment" / "containment-state.json"
    state = json.loads(state_path.read_text())
    state["original_sha256"] = "0" * 64
    state_path.write_text(json.dumps(state))
    with pytest.raises(ContainmentError, match="digest mismatch"):
        mgr.resume()


def test_resume_refuses_when_hold_receipt_stream_is_gone(tmp_path):
    """Fail-closed: a snapshot without its receipt cannot be verified."""
    policy = tmp_path / "policies.yaml"
    policy.write_bytes(b"version: 1\nissuer: bank\npolicies:\n")
    cfg = ContainmentConfig(
        policy_file=str(policy),
        revocations_file="",
        delegations_file="",
        receipts_path=str(tmp_path / "receipts.jsonl"),
        state_dir=str(tmp_path / "containment"),
        actor="op",
        global_min_approvers=1,
    )
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global")
    (tmp_path / "receipts.jsonl").unlink()
    with pytest.raises(ContainmentError, match="hold receipt stream"):
        mgr.resume()


def test_normal_resume_still_restores_bytes(tmp_path):
    """Non-bypass path is unchanged: full restore + VERDICT_RESUME receipt."""
    policy = tmp_path / "policies.yaml"
    original = b"version: 1\nissuer: bank\npolicies:\n"
    policy.write_bytes(original)
    cfg = ContainmentConfig(
        policy_file=str(policy),
        revocations_file="",
        delegations_file="",
        receipts_path=str(tmp_path / "receipts.jsonl"),
        state_dir=str(tmp_path / "containment"),
        actor="op",
        global_min_approvers=1,
    )
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global")
    result = mgr.resume()
    assert result["status"] == "resumed"
    assert policy.read_bytes() == original
    verdicts = [p["verdict"] for p in _receipts_payloads(cfg.receipts_path)]
    assert verdicts == ["containment_hold", VERDICT_RESUME]
