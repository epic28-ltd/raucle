"""M-of-N containment authorisation (threat-model mitigation M3).

Acceptance criteria:

- the default quorum (``min_approvers == 1``) is the v0 single-approver
  path: same states, same receipt extra keys — the demo default path is
  byte-identical (OPT-IN feature, default off);
- M=2: ``hold`` leaves the enforcement bytes untouched and enters a
  receipted *pending* state; one approval keeps it pending; the stop is
  applied only when the quorum of DISTINCT approver receipts is met;
- satisfied quorum => the hold applies and the hold receipt carries the
  whole approver roll;
- repeat approvals by the same identity, abort of an applied hold, and
  resume of a still-pending hold are all named errors, never silent;
- abort of a pending hold is receipted and leaves the bytes untouched.
"""

import base64
import json
from pathlib import Path

import pytest

from raucle.containment import (
    VERDICT_HOLD,
    VERDICT_HOLD_ABORT,
    VERDICT_HOLD_APPROVAL,
    VERDICT_HOLD_PENDING,
    ContainmentConfig,
    ContainmentError,
    ContainmentManager,
)

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""


def _policy(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "policies.yaml"
    path.write_text(POLICY)
    return path


def _manager(tmp_path: Path, min_approvers: int) -> ContainmentManager:
    return ContainmentManager(
        ContainmentConfig(
            policy_file=str(_policy(tmp_path)),
            receipts_path=str(tmp_path / "containment-receipts.jsonl"),
            state_dir=str(tmp_path / "containment"),
            actor="op",
            min_approvers=min_approvers,
        )
    )


def _receipts(tmp_path: Path) -> list[dict]:
    path = tmp_path / "containment-receipts.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        jws = json.loads(line)["jws"]
        part = jws.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        # containment receipts nest the extension under "extra"
        out.append({"verdict": payload["verdict"], "x": payload["extra"]})
    return out


def _verdicts(tmp_path: Path) -> list[str]:
    return [r["verdict"] for r in _receipts(tmp_path)]


# ---------------------------------------------------------------------------
# Default: M=1 is the v0 single-approver path, byte-identical
# ---------------------------------------------------------------------------


def test_default_m1_applies_immediately_with_v0_receipt_shape(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=1)
    outcome = manager.hold(scope="global", reason="incident")
    assert outcome["status"] == "held"
    assert set(outcome) == {
        "status",
        "scope",
        "scope_id",
        "target_file",
        "receipt_id",
        "revoked_ids",
    }
    # the hold receipt carries exactly the v0 extra keys — no M-of-N
    # additions on the default path (demo path byte-identical)
    holds = [r for r in _receipts(tmp_path) if r["verdict"] == VERDICT_HOLD]
    assert len(holds) == 1
    x = holds[0]["x"]
    assert set(x) == {
        "scope",
        "scope_id",
        "actor",
        "reason",
        "target_file",
        "sha256_before",
        "revoked_ids",
    }
    assert "lookup_balance" not in Path(manager.config.policy_file).read_text("utf-8")
    # resume restores the pre-hold bytes byte-exactly (state snapshot)
    state = json.loads(Path(manager.state_path).read_text("utf-8"))
    pre_hold = base64.b64decode(state["original_bytes_b64"])
    manager.resume(reason="drill over")
    assert Path(manager.config.policy_file).read_bytes() == pre_hold


def test_quorum_below_one_is_refused(tmp_path: Path):
    with pytest.raises(ContainmentError, match="quorum must be >= 1"):
        _manager(tmp_path, min_approvers=0)


# ---------------------------------------------------------------------------
# M=2: pending state, sequential distinct approvals, quorum application
# ---------------------------------------------------------------------------


def test_m2_hold_is_pending_and_touches_no_bytes(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    policy = Path(manager.config.policy_file)
    bytes_before = policy.read_bytes()
    outcome = manager.hold(scope="global", reason="incident")
    assert outcome["status"] == "pending"
    assert outcome["min_approvers"] == 2
    assert outcome["approvers"] == []
    # nothing is stopped yet: the enforcement bytes are untouched
    assert policy.read_bytes() == bytes_before
    # the pending state is receipted
    assert _verdicts(tmp_path) == [VERDICT_HOLD_PENDING]
    status = manager.status()
    assert status["held"] is False
    assert status["pending_hold"]["min_approvers"] == 2
    assert status["pending_hold"]["approvers"] == []


def test_m2_first_approval_keeps_pending(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    manager.hold(scope="global")
    outcome = manager.approve_hold(approver="alice")
    assert outcome["status"] == "pending"
    assert outcome["approvers"] == ["alice"]
    assert outcome["outstanding"] == 1
    # the approval is its own receipt; the stop is still not applied
    assert _verdicts(tmp_path) == [VERDICT_HOLD_PENDING, VERDICT_HOLD_APPROVAL]
    assert "lookup_balance" in Path(manager.config.policy_file).read_text("utf-8")


def test_m2_duplicate_approver_refused_named(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    manager.hold(scope="global")
    manager.approve_hold(approver="alice")
    with pytest.raises(ContainmentError, match="already receipted"):
        manager.approve_hold(approver="alice")
    # the dup attempt emitted nothing
    assert _verdicts(tmp_path) == [VERDICT_HOLD_PENDING, VERDICT_HOLD_APPROVAL]


def test_m2_empty_or_missing_approver_refused_named(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    manager.hold(scope="global")
    with pytest.raises(ContainmentError, match="approver identity is required"):
        manager.approve_hold(approver="  ")
    # a fresh deployment with no pending hold refuses named too
    other = _manager(tmp_path / "elsewhere", min_approvers=2)
    with pytest.raises(ContainmentError, match="no pending hold"):
        other.approve_hold(approver="bob")


def test_m2_quorum_satisfied_applies_receipted_hold(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    manager.hold(scope="global", reason="incident")
    manager.approve_hold(approver="alice")
    outcome = manager.approve_hold(approver="bob")
    assert outcome["status"] == "held"
    assert outcome["approvers"] == ["alice", "bob"]
    assert outcome["min_approvers"] == 2
    policy = Path(manager.config.policy_file).read_text("utf-8")
    # the deny-all swap happened only now
    assert "lookup_balance" not in policy
    verdicts = _verdicts(tmp_path)
    assert verdicts == [
        VERDICT_HOLD_PENDING,
        VERDICT_HOLD_APPROVAL,
        VERDICT_HOLD_APPROVAL,
        VERDICT_HOLD,
    ]
    x = [r for r in _receipts(tmp_path) if r["verdict"] == VERDICT_HOLD][0]["x"]
    assert x["approvers"] == ["alice", "bob"]
    assert x["min_approvers"] == 2
    assert x["pending_receipt_id"]
    # resume over a quorum hold works and restores the bytes
    state = json.loads(Path(manager.state_path).read_text("utf-8"))
    pre_hold = base64.b64decode(state["original_bytes_b64"])
    manager.resume(reason="incident closed")
    assert Path(manager.config.policy_file).read_bytes() == pre_hold


def test_m2_resume_while_pending_is_named(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    manager.hold(scope="global")
    manager.approve_hold(approver="alice")
    with pytest.raises(ContainmentError, match="still pending approval"):
        manager.resume()


def test_m2_second_hold_while_pending_is_named(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    manager.hold(scope="global")
    manager.approve_hold(approver="alice")
    with pytest.raises(ContainmentError, match="already pending approval"):
        manager.hold(scope="global")


def test_m2_abort_is_receipted_and_clears(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    policy = Path(manager.config.policy_file)
    before = policy.read_bytes()
    manager.hold(scope="global")
    manager.approve_hold(approver="alice")
    outcome = manager.abort_hold(approver="carol")
    assert outcome["status"] == "aborted"
    assert outcome["receipt_id"]
    assert _verdicts(tmp_path)
    assert _verdicts(tmp_path)[-1] == VERDICT_HOLD_ABORT
    assert policy.read_bytes() == before
    assert manager.status() == {
        "held": False,
        "quarantined_traces": [],
        "suspended_leases": [],
    }
    # a cleared pending hold can be re-held and approved afresh
    manager.hold(scope="global")
    manager.approve_hold(approver="alice")
    manager.approve_hold(approver="bob")
    assert manager.status()["held"] is True


def test_m2_abort_after_apply_is_refused_named(tmp_path: Path):
    manager = _manager(tmp_path, min_approvers=2)
    manager.hold(scope="global")
    manager.approve_hold(approver="alice")
    manager.approve_hold(approver="bob")
    with pytest.raises(ContainmentError, match="resume instead"):
        manager.abort_hold(approver="carol")


def test_pending_state_without_manager_config_reads_its_own_quorum(tmp_path: Path):
    """The pending record pins the quorum it was opened with."""
    manager = _manager(tmp_path, min_approvers=3)
    manager.hold(scope="global")
    status = manager.status()
    assert status["pending_hold"]["min_approvers"] == 3
    with pytest.raises(ContainmentError, match="already pending approval"):
        manager.hold(scope="global")
