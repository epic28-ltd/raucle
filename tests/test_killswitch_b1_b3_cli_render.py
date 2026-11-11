"""B1/B3 CLI surface: arm/disarm button transitions render receipted output,
pending-hold M-of-N render names the outstanding approvals, and the
global-floor validation is named fail-closed."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from raucle import cli
from raucle.cli import _containment_render, _containment_status_render
from raucle.containment import (
    ContainmentConfig,
    ContainmentError,
    ContainmentManager,
)


@pytest.fixture
def containment_env(tmp_path, monkeypatch):
    """Point every containment surface at tmp_path."""
    (tmp_path / "policies.yaml").write_text("version: 1\npolicies: []\n")
    (tmp_path / "revocations.jsonl").touch()
    (tmp_path / "delegations.jsonl").touch()
    monkeypatch.setenv("RAUCLE_POLICY_FILE", str(tmp_path / "policies.yaml"))
    monkeypatch.setenv("RAUCLE_REVOCATIONS_FILE", str(tmp_path / "revocations.jsonl"))
    monkeypatch.setenv("RAUCLE_DELEGATIONS_FILE", str(tmp_path / "delegations.jsonl"))
    monkeypatch.setenv("RAUCLE_TRACE_QUARANTINE_FILE", str(tmp_path / "quarantine.jsonl"))
    monkeypatch.setenv("RAUCLE_LEASE_SUSPENSIONS_FILE", str(tmp_path / "leases.jsonl"))
    monkeypatch.setenv("RAUCLE_CONTAINMENT_RECEIPTS", str(tmp_path / "containment-receipts.jsonl"))
    monkeypatch.setenv("RAUCLE_CONTAINMENT_STATE_DIR", str(tmp_path / "containment"))
    (tmp_path / "quarantine.jsonl").touch()
    (tmp_path / "leases.jsonl").touch()
    monkeypatch.setenv("RAUCLE_ACTOR", "op")
    return tmp_path


class TestCliButtonTransitions:
    def test_arm_button_renders_receipted_armed_transition(self, tmp_path, containment_env, capsys):
        """B3: arming via the CLI names the operator and the receipt, and the
        arm is a receipted operator transition (never silent)."""
        rc = cli.main(["containment", "arm-button", "--approver", "op"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "emergency authority stop button: ARMED (receipted operator transition)" in out
        assert "armed by: op" in out
        assert "receipt:" in out
        # the arm state file exists and names the operator
        arm_state = json.loads((tmp_path / "containment" / "emergency-stop-arm.json").read_text())
        assert arm_state["armed"] is True
        assert arm_state["operator"] == "op"

        # status renders the armed button posture
        rc = cli.main(["containment", "status"])
        assert rc == 0
        status_out = capsys.readouterr().out
        assert "emergency authority stop button: ARMED at" in status_out
        assert "by op" in status_out

    def test_disarm_button_renders_receipted_disarmed_transition(
        self, tmp_path, containment_env, capsys
    ):
        cli.main(["containment", "arm-button", "--approver", "op"])
        capsys.readouterr()
        rc = cli.main(["containment", "disarm-button", "--approver", "op"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "emergency authority stop button: DISARMED (receipted operator transition)" in out
        assert "disarmed by: op" in out
        assert "receipt:" in out
        status_out = ""
        cli.main(["containment", "status"])
        status_out = capsys.readouterr().out
        assert (
            "emergency authority stop button: DISARMED (default-off per deployment)" in status_out
        )

    def test_abort_hold_dispatch_names_the_aborting_operator(self, containment_env, capsys):
        """The full CLI abort path is a receipted abort of a still-pending hold."""
        rc = cli.main(["containment", "hold", "global", "--reason", "incident"])
        assert rc == 0
        capsys.readouterr()
        rc = cli.main(["containment", "abort-hold", "--approver", "op", "--reason", "false alarm"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "containment aborted: scope=global" in out


class TestPendingHoldRender:
    def test_pending_hold_render_names_outstanding_and_scope_id(self, capsys):
        config = SimpleNamespace(state_dir="/sd")
        _containment_render(
            {
                "status": "pending",
                "scope": "global",
                "scope_id": "scope-1",
                "approvers": ["alice"],
                "min_approvers": 2,
                "outstanding": 1,
                "receipt_id": "r-1",
            },
            config,
            "hold",
        )
        out = capsys.readouterr().out
        assert "containment hold PENDING approval: scope=global (1/2 distinct approvers" in out
        assert "  id: scope-1" in out
        assert "  outstanding approvals required: 1" in out
        assert "approve with: raucle containment approve-hold --approver <identity>" in out

    def test_pending_hold_render_derives_outstanding_when_missing(self, capsys):
        _containment_render(
            {
                "status": "pending",
                "scope": "agent",
                "scope_id": "",
                "approvers": [],
                "min_approvers": 3,
                "receipt_id": "r-2",
            },
            SimpleNamespace(state_dir="/sd"),
            "hold",
        )
        out = capsys.readouterr().out
        assert "containment hold PENDING approval: scope=agent (0/3 distinct approvers" in out
        assert "  outstanding approvals required: 3" in out
        assert "  id: " not in out

    def test_status_render_armed_button_names_time_and_operator(self, capsys):
        _containment_status_render(
            {
                "held": False,
                "emergency_stop_button": {
                    "armed": True,
                    "armed_at": "2026-11-09T09:00:00Z",
                    "operator": "op",
                },
            }
        )
        out = capsys.readouterr().out
        assert "emergency authority stop button: ARMED at 2026-11-09T09:00:00Z by op" in out


class TestGlobalQuorumFloorValidation:
    def test_global_min_approvers_below_one_is_named_fail_closed(self, tmp_path):
        """The global M-of-N floor has a named guard: quorum < 1 can never
        arm a zero-approver stop."""
        base = dict(
            policy_file=str(tmp_path / "policies.yaml"),
            revocations_file=str(tmp_path / "revocations.jsonl"),
            delegations_file=str(tmp_path / "delegations.jsonl"),
            receipts_path=str(tmp_path / "receipts.jsonl"),
            state_dir=str(tmp_path / "state"),
            actor="op",
        )
        with pytest.raises(ContainmentError, match="global approver quorum must be >= 1, got 0"):
            ContainmentManager(ContainmentConfig(**base, min_approvers=1, global_min_approvers=0))
        with pytest.raises(ContainmentError, match="minimal approver quorum must be >= 1, got 0"):
            ContainmentManager(ContainmentConfig(**base, min_approvers=0, global_min_approvers=2))


class TestButtonStateReaders:
    def test_corrupt_arm_state_file_is_named_error(self, tmp_path):
        mgr = _mgr(tmp_path)
        arm = tmp_path / "state" / "emergency-stop-arm.json"
        arm.parent.mkdir(parents=True, exist_ok=True)
        arm.write_text("{not json")
        with pytest.raises(ContainmentError, match="emergency-stop arm state file is corrupt"):
            mgr.button_state()

    def test_arm_record_without_armed_true_reads_disarmed(self, tmp_path):
        mgr = _mgr(tmp_path)
        arm = tmp_path / "state" / "emergency-stop-arm.json"
        arm.parent.mkdir(parents=True, exist_ok=True)
        arm.write_text(json.dumps({"armed": False, "operator": "x"}))
        state = mgr.button_state()
        assert state == {"armed": False, "armed_at": "", "operator": "", "receipt_id": ""}


def _mgr(tmp_path):
    (tmp_path / "policies.yaml").write_text("version: 1\npolicies: []\n")
    (tmp_path / "revocations.jsonl").touch()
    (tmp_path / "delegations.jsonl").touch()
    return ContainmentManager(
        ContainmentConfig(
            policy_file=str(tmp_path / "policies.yaml"),
            revocations_file=str(tmp_path / "revocations.jsonl"),
            delegations_file=str(tmp_path / "delegations.jsonl"),
            receipts_path=str(tmp_path / "receipts.jsonl"),
            state_dir=str(tmp_path / "state"),
            actor="op",
            min_approvers=1,
            global_min_approvers=2,
        )
    )
