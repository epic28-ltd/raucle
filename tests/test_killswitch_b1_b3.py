"""Killswitch build wave B1 + B3 (decisions closed 9 Nov).

B1 — global-scope M-of-N wiring: the GLOBAL containment stop is M-of-N by
default with quorum N=2 (``global_min_approvers``), riding the existing M3
pending/approval machinery; per-agent and per-chain scopes stay single-approver;
each quorum is overridable per deployment.

Acceptance criteria:
- default config: a global hold enters the receipted pending state, touching
  no enforcement bytes; a second DISTINCT approver is required before the
  stop applies (named pending state, never a silent single-approver stop);
- the fully-approved hold receipt carries the approver roll and quorum size;
- per-agent holds under the same default config still apply immediately with
  the v0 single-approver receipt shape;
- the global floor is overridable: ``global_min_approvers=1`` restores the
  v0 single-approver global path; >2 demands more approvers;
- a repeat approver identity is refused under its own name.

B3 — emergency authority stop button: DEFAULT-OFF per deployment; both
directions of the arm/disarm flip are themselves receipted, visible operator
transitions; a button-invoked hold refuses under a named error while the
button is disarmed.
"""

import base64
import json
from pathlib import Path

import pytest

from raucle.containment import (
    VERDICT_BUTTON_ARM,
    VERDICT_BUTTON_DISARM,
    VERDICT_HOLD,
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


def _setup(tmp_path: Path) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    return {"policy": str(policy), "dir": tmp_path}


def _manager(
    tmp_path: Path, *, min_approvers: int = 1, global_min_approvers: int = 2
) -> ContainmentManager:
    setup = _setup(tmp_path)
    revocations = tmp_path / "revocations.jsonl"
    revocations.touch()
    delegations = tmp_path / "delegations.jsonl"
    delegations.touch()
    return ContainmentManager(
        ContainmentConfig(
            policy_file=setup["policy"],
            revocations_file=str(revocations),
            delegations_file=str(delegations),
            receipts_path=str(tmp_path / "containment-receipts.jsonl"),
            state_dir=str(tmp_path / "containment"),
            actor="op",
            min_approvers=min_approvers,
            global_min_approvers=global_min_approvers,
        )
    )


def _seed_chain(tmp_path: Path) -> None:
    """Register one delegated capability chain for agent:svc so agent-scope
    holds have a real target (a hold refuses a no-op target, fail-closed)."""
    from raucle.capability import CapabilityIssuer, DelegationLedger

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger_path = tmp_path / "delegations.jsonl"
    ledger = DelegationLedger(ledger_path)
    root = issuer.mint(agent_id="agent:svc", tool="lookup_balance", constraints={}, ttl_seconds=600)
    child = issuer.attenuate(root)
    ledger.register(root, "agent:svc", verifying_key=issuer)
    ledger.register(child, "agent:svc", verifying_key=issuer)


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
        out.append({"verdict": payload["verdict"], "x": payload["extra"]})
    return out


def _held_bytes(tmp_path: Path) -> bytes:
    return (tmp_path / "policies.yaml").read_bytes()


# ---------------------------------------------------------------------------
# B1: global default quorum N=2
# ---------------------------------------------------------------------------


class TestGlobalDefaultQuorum:
    def test_default_global_hold_enters_pending_not_applied(self, tmp_path):
        """Default config: a GLOBAL hold is M-of-N with N=2 — receipted
        pending, zero enforcement bytes touched."""
        mgr = _manager(tmp_path)
        outcome = mgr.hold(scope="global", reason="incident")
        assert outcome["status"] == "pending"
        assert outcome["min_approvers"] == 2
        assert outcome["approvers"] == []
        assert outcome["outstanding"] == 2
        # enforcement bytes untouched
        assert _held_bytes(tmp_path).decode().count("tool: lookup_balance") == 1
        verdicts = [r["verdict"] for r in _receipts(tmp_path)]
        assert verdicts == [VERDICT_HOLD_PENDING]
        status = mgr.status()
        assert status["held"] is False
        assert status["pending_hold"]["min_approvers"] == 2

    def test_second_approver_required_named_failure(self, tmp_path):
        """NAMED failure shape: after one approval the stop is STILL not
        applied, and the state names the second approver as required —
        a single approval never silently becomes a stop."""
        mgr = _manager(tmp_path)
        original = _held_bytes(tmp_path)
        mgr.hold(scope="global", reason="incident")
        outcome = mgr.approve_hold(approver="alice")
        assert outcome["status"] == "pending"
        assert outcome["approvers"] == ["alice"]
        assert outcome["outstanding"] == 1
        assert outcome["min_approvers"] == 2
        # second-approver requirement is named on the receipt stream too
        approvals = [r["x"] for r in _receipts(tmp_path) if r["verdict"] == VERDICT_HOLD_APPROVAL]
        assert approvals
        assert approvals[0]["min_approvers"] == 2
        assert approvals[0]["approvers_before"] == []
        # and the enforcement surface is still untouched: the named pending
        # state is the refusal to stop on a single approver
        assert _held_bytes(tmp_path) == original
        assert mgr.status()["pending_hold"]["approvers"] == ["alice"]

    def test_quorum_met_applies_stop_with_approver_roll(self, tmp_path):
        mgr = _manager(tmp_path)
        mgr.hold(scope="global", reason="incident")
        mgr.approve_hold(approver="alice")
        outcome = mgr.approve_hold(approver="bob")
        assert outcome["status"] == "held"
        holds = [r["x"] for r in _receipts(tmp_path) if r["verdict"] == VERDICT_HOLD]
        assert len(holds) == 1
        assert holds[0]["approvers"] == ["alice", "bob"]
        assert holds[0]["min_approvers"] == 2
        # enforcement bytes now deny-all (policy swapped)
        assert "tool: lookup_balance" not in _held_bytes(tmp_path).decode()

    def test_per_agent_stays_single_approver_under_defaults(self, tmp_path):
        """B1 boundary: with the default config, an AGENT-scope hold applies
        immediately (single approver); the M-of-N floor is global-only."""
        mgr = _manager(tmp_path)
        _seed_chain(tmp_path)
        outcome = mgr.hold(scope="agent", scope_id="agent:svc", reason="compromise")
        assert outcome["status"] == "held"
        holds = [r["x"] for r in _receipts(tmp_path) if r["verdict"] == VERDICT_HOLD]
        assert len(holds) == 1
        assert "approvers" not in holds[0]
        assert "min_approvers" not in holds[0]

    def test_global_floor_overridable_to_single_approver(self, tmp_path):
        """Overridable: global_min_approvers=1 restores the v0 path."""
        mgr = _manager(tmp_path, global_min_approvers=1)
        outcome = mgr.hold(scope="global", reason="drill")
        assert outcome["status"] == "held"
        holds = [r["x"] for r in _receipts(tmp_path) if r["verdict"] == VERDICT_HOLD]
        assert "approvers" not in holds[0]

    def test_higher_global_quorum_demands_more_approvers(self, tmp_path):
        mgr = _manager(tmp_path, global_min_approvers=3)
        outcome = mgr.hold(scope="global", reason="incident")
        assert outcome["status"] == "pending"
        assert outcome["min_approvers"] == 3
        assert outcome["outstanding"] == 3
        mgr.approve_hold(approver="a")
        mgr.approve_hold(approver="b")
        still = mgr.approve_hold(approver="c")
        assert still["status"] == "held"

    def test_repeat_approver_named_refusal(self, tmp_path):
        mgr = _manager(tmp_path)
        mgr.hold(scope="global", reason="incident")
        mgr.approve_hold(approver="alice")
        with pytest.raises(ContainmentError, match="already receipted"):
            mgr.approve_hold(approver="alice")

    def test_pending_global_abort_receipted(self, tmp_path):
        mgr = _manager(tmp_path)
        mgr.hold(scope="global", reason="incident")
        outcome = mgr.abort_hold(approver="alice")
        assert outcome["status"] == "aborted"
        verdicts = [r["verdict"] for r in _receipts(tmp_path)]
        assert verdicts[-1] == "containment_hold_abort"
        assert mgr.status()["held"] is False
        assert mgr.status().get("pending_hold") is None


# ---------------------------------------------------------------------------
# B3: emergency authority stop button, default-off per deployment
# ---------------------------------------------------------------------------


class TestEmergencyStopButton:
    def test_default_disarmed_button_hold_refuses_named(self, tmp_path):
        """Default-off: a button-invoked hold refuses under its own name;
        the plain operator path is untouched by the arm gate."""
        mgr = _manager(tmp_path, global_min_approvers=1)
        _seed_chain(tmp_path)
        with pytest.raises(ContainmentError, match="emergency_stop_button_disarmed"):
            mgr.hold(scope="agent", scope_id="agent:svc", reason="panic", via_button=True)
        verdicts = [r["verdict"] for r in _receipts(tmp_path)]
        assert verdicts == []  # refused BEFORE any receipt is minted
        # plain hold (operator CLI path) still works on the disarmed deployment
        outcome = mgr.hold(scope="agent", scope_id="agent:svc", reason="compromise")
        assert outcome["status"] == "held"

    def test_arm_is_itself_a_receipted_transition(self, tmp_path):
        mgr = _manager(tmp_path)
        outcome = mgr.arm_button(operator="ops-lead", reason="raise posture")
        assert outcome["status"] == "armed"
        assert outcome["armed"] is True
        receipts = _receipts(tmp_path)
        arm = [r for r in receipts if r["verdict"] == VERDICT_BUTTON_ARM]
        assert len(arm) == 1
        assert arm[0]["x"]["operator"] == "ops-lead"
        assert arm[0]["x"]["arm_state"] == "armed"
        assert arm[0]["x"]["operator_key_fingerprint"]
        # persisted arm state survives a fresh manager (visible across restarts)
        mgr2 = _manager(tmp_path)
        assert mgr2.button_armed() is True
        assert mgr2.button_state()["operator"] == "ops-lead"
        assert mgr2.button_state()["receipt_id"] == outcome["receipt_id"]
        status = mgr2.status()
        assert status["emergency_stop_button"]["armed"] is True

    def test_double_arm_refused_named(self, tmp_path):
        mgr = _manager(tmp_path)
        mgr.arm_button(operator="ops-lead")
        with pytest.raises(ContainmentError, match="already armed"):
            mgr.arm_button(operator="ops-lead")

    def test_armed_button_hold_applies_then_disarm_relocks(self, tmp_path):
        """The full visible operator arc: arm -> receipted button stop ->
        disarm receipt, after which the button refuses again."""
        mgr = _manager(tmp_path, global_min_approvers=1)
        _seed_chain(tmp_path)
        arm_out = mgr.arm_button(operator="ops-lead", reason="incident window")
        outcome = mgr.hold(scope="agent", scope_id="agent:svc", reason="panic", via_button=True)
        assert outcome["status"] == "held"
        disarm = mgr.disarm_button(operator="ops-lead", reason="drill over")
        assert disarm["status"] == "disarmed"
        assert disarm["armed"] is False
        receipts = _receipts(tmp_path)
        arm = [r for r in receipts if r["verdict"] == VERDICT_BUTTON_ARM]
        dis = [r for r in receipts if r["verdict"] == VERDICT_BUTTON_DISARM]
        assert len(arm) == 1
        assert len(dis) == 1
        assert dis[0]["x"]["arm_receipt_id"] == arm_out["receipt_id"]
        assert dis[0]["x"]["arm_state"] == "disarmed"
        # re-locked: the button refuses again under its own named error
        with pytest.raises(ContainmentError, match="emergency_stop_button_disarmed"):
            mgr.hold(scope="agent", scope_id="agent:svc", reason="again", via_button=True)

    def test_disarm_without_arm_refused_named(self, tmp_path):
        mgr = _manager(tmp_path)
        with pytest.raises(ContainmentError, match="not armed; nothing to disarm"):
            mgr.disarm_button(operator="ops-lead")

    def test_arm_requires_operator_identity(self, tmp_path):
        mgr = _manager(tmp_path)
        with pytest.raises(ContainmentError, match="operator identity is required"):
            mgr.arm_button(operator="  ")
        with pytest.raises(ContainmentError, match="operator identity is required"):
            mgr.disarm_button(operator="")

    def test_default_global_stop_does_not_require_armed_button(self, tmp_path):
        """Decision split: the M-of-N MACHINERY is default-on and reachable
        via the plain operator path; only the BUTTON is default-off."""
        mgr = _manager(tmp_path)
        pending = mgr.hold(scope="global", reason="incident")
        assert pending["status"] == "pending"
        assert mgr.arm_button(operator="ops-lead")["armed"] is True
        applied = mgr.approve_hold(approver="alice")
        assert applied["status"] == "pending"
        applied = mgr.approve_hold(approver="bob")
        assert applied["status"] == "held"
