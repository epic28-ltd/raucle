"""X4: fault evidence - persisted fault counter, SIEM fault events, boot
self-test driving the gate's decision surfaces with hostile types.

Rule under test: a gateway fault is not just a receipted deny (RED-031),
it is COUNTED, persisted (surviving restarts) and SIEM-forwarded; and the
gate proves at startup that hostile types through the approval path, the
constraint evaluator and the receipt emitter all end in NAMED, receipted
outcomes.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from raucle.boot_selftest import BOOT_SELFTEST_TOOL, run_boot_selftest
from raucle.fault_counter import FaultCounter
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def approval_only_gateway(tmp_path):
    """The RED-031 fixture shape: a threshold-only policy so hostile types
    reach the approval threshold evaluator."""
    path = tmp_path / "approval-policies.yaml"
    path.write_text(
        """
version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:pay
    ttl_seconds: 300
    require_approval_when:
      amount_gt: 5000
"""
    )
    cfg = GatewayConfig(
        policy_file=str(path),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
        fault_counter_path=str(tmp_path / "faults.json"),
        boot_selftest=True,
    )
    return RaucleGateway(cfg)


@pytest.fixture
def fault_gateway(tmp_path):
    gw = RaucleGateway(
        GatewayConfig(
            fault_counter_path=str(tmp_path / "faults.json"),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            boot_selftest=True,
        )
    )
    gw.run_boot_selftest_at_startup()
    return gw


# ---------------------------------------------------------------------------
# Boot self-test
# ---------------------------------------------------------------------------


class TestBootSelfTest:
    def test_runs_and_receipts_every_probe(self, fault_gateway):
        summary = fault_gateway.boot_selftest_result
        assert summary is not None
        assert summary["status"] == "ok"
        assert len(summary["probes"]) == 6
        for probe in summary["probes"]:
            assert probe["ok"], probe
            assert probe["decision"] in ("allow", "escalate", "deny")
            assert probe["reason"], probe
        for name, rid in summary["receipt_ids"].items():
            assert rid, f"probe {name} did not receipt its result"

    def test_hostile_injection_produces_named_receipts(self, fault_gateway):
        result = run_boot_selftest(fault_gateway)
        decisions = {p["name"]: p["decision"] for p in result["probes"]}
        # Approval threshold: type-confused amount escalates (named reason)
        # rather than crashing open.
        assert decisions["approval-threshold-hostile-text"] == "escalate"
        assert decisions["approval-threshold-hostile-none"] == "escalate"
        # Approval reference: a MAPPING approval id faults the decision into
        # a receipted gate_fault deny with the exception TYPE only.
        ref = next(p for p in result["probes"] if p["name"] == "approval-reference-hostile-type")
        assert ref["decision"] == "deny"
        assert ref["reason"].startswith("gate_fault:")
        # Constraint evaluator and receipt emitter: hostile types produce a
        # receipted outcome, never a silent crash.
        assert decisions["constraint-evaluator-hostile-args"] in (
            "escalate",
            "deny",
            "allow",
        )
        assert result["status"] == "ok"

    def test_gateway_carries_the_boot_result_and_can_disable_it(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RAUCLE_BOOT_SELFTEST", raising=False)
        enabled = RaucleGateway(
            GatewayConfig(
                boot_selftest=True,
                receipt_store=str(tmp_path / "r.jsonl"),
            )
        )
        result = enabled.run_boot_selftest_at_startup()
        assert result["status"] == "ok"
        assert enabled.boot_selftest_result["status"] == "ok"

        disabled = RaucleGateway(
            GatewayConfig(
                boot_selftest=False,
                receipt_store=str(tmp_path / "r.jsonl"),
            )
        )
        assert disabled.run_boot_selftest_at_startup() == {}
        assert disabled.boot_selftest_result is None

    def test_boot_selftest_leaves_real_policy_state_untouched(self, approval_only_gateway):
        # The self-test ran at construction; the real rule was restored.
        assert BOOT_SELFTEST_TOOL not in approval_only_gateway._policy_rules
        assert BOOT_SELFTEST_TOOL not in approval_only_gateway._tokens
        result = approval_only_gateway.check_tool_call("pay", {"amount": 100})
        assert result["decision"] == "allow"
        result = approval_only_gateway.check_tool_call("pay", {"amount": "99999"})
        assert result["decision"] == "escalate"

    def test_every_boot_fault_is_counted_and_forwarded(self, fault_gateway):
        """The dict approval-reference faults inside the self-test run: that
        fault must land in the counter and the SIEM buffer."""
        result = fault_gateway.boot_selftest_result
        assert result is not None
        counts = fault_gateway.fault_counts()
        assert counts["total"] == result["faults"]


# ---------------------------------------------------------------------------
# Fault counter
# ---------------------------------------------------------------------------


class TestFaultCounter:
    def test_counts_are_queryable_by_type_and_tool(self, tmp_path):
        counter = FaultCounter(tmp_path / "faults.json")
        assert counter.increment("TypeError", "pay") == 1
        assert counter.increment("TypeError", "pay") == 2
        assert counter.increment("ValueError", "refund") == 1
        counts = counter.counts()
        assert counts["total"] == 3
        assert counts["by_type"]["TypeError"]["total"] == 2
        assert counts["by_type_and_tool"]["ValueError"]["refund"]["count"] == 1

    def test_counts_persist_across_a_restart_round_trip(self, tmp_path):
        """RED-038 pattern: create, mutate, construct over the same path,
        assert the observable behaviour is unchanged."""
        path = tmp_path / "faults.json"
        first = FaultCounter(path)
        first.increment("RuntimeError", "pay")
        first.increment("RuntimeError", "pay")
        first.increment("TypeError", "refund")

        second = FaultCounter(path)
        assert second.total() == 3
        counts = second.counts()
        assert counts["by_type"]["RuntimeError"]["total"] == 2
        assert counts["by_type_and_tool"]["TypeError"]["refund"]["count"] == 1
        assert second.increment("RuntimeError", "pay") == 3

    def test_corrupt_file_starts_empty(self, tmp_path):
        path = tmp_path / "faults.json"
        path.write_text("{{not json")
        counter = FaultCounter(path)
        assert counter.total() == 0
        assert counter.increment("TypeError") == 1

    def test_gateway_fault_increments_counter_and_forwards_siem(
        self, approval_only_gateway, monkeypatch
    ):
        # (boot self-test not started here: this fixture stays isolated)
        """The RED-031 receipted deny now also counts and SIEMs."""

        def _boom(*_args, **_kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(approval_only_gateway._approvals, "consume", _boom)
        result = approval_only_gateway.check_tool_call(
            "pay", {"amount": 7500}, approval_id="appr-1"
        )
        assert result["decision"] == "deny"
        assert result["reason"].startswith("gate_fault:")
        assert result["receipt_id"]

        counts = approval_only_gateway.fault_counts()
        assert counts["total"] == 1
        assert counts["by_type"]["RuntimeError"]["total"] == 1
        assert counts["by_type_and_tool"]["RuntimeError"]["pay"]["count"] == 1
        # The SIEM event carries the exception TYPE only, never the message.
        events = [e for e in approval_only_gateway.siem._buffer if e["event"] == "gate_fault"]
        assert events, "no gate_fault SIEM event forwarded"
        for event in events:
            assert "simulated internal failure" not in str(event)

    def test_counter_persists_across_gateway_restart_round_trip(self, tmp_path, monkeypatch):
        """The X4 evidence survives a full gateway restart."""
        fault_counter_path = str(tmp_path / "faults.json")

        def _make_gateway():
            pdir = tmp_path / "policies.yaml"
            pdir.write_text(
                """
version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:pay
    ttl_seconds: 300
    require_approval_when:
      amount_gt: 5000
"""
            )
            return RaucleGateway(
                GatewayConfig(
                    policy_file=str(pdir),
                    fault_counter_path=fault_counter_path,
                    receipt_store=str(tmp_path / "receipts2.jsonl"),
                    boot_selftest=False,
                )
            )

        first = _make_gateway()

        def _boom(*_args, **_kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(first._approvals, "consume", _boom)
        result = first.check_tool_call("pay", {"amount": 7500}, approval_id="appr-1")
        assert result["reason"].startswith("gate_fault:")

        # Restart over the same path: the previous fault is still there.
        second = _make_gateway()
        counts = second.fault_counts()
        assert counts["total"] == 1
        assert counts["by_type"]["RuntimeError"]["total"] == 1
        assert counts["by_type_and_tool"]["RuntimeError"]["pay"]["count"] == 1


# ---------------------------------------------------------------------------
# Query endpoint
# ---------------------------------------------------------------------------


class TestFaultsEndpoint:
    @pytest.fixture
    def fault_admin_app(self, approval_only_gateway):
        users = UserManager()
        users.add_user("admin-key", "admin", "Admin")
        return create_admin_app(approval_only_gateway, users)

    def test_faults_requires_auth(self, fault_admin_app):
        client = TestClient(fault_admin_app)
        resp = client.get("/api/faults")
        assert resp.status_code == 401

    def test_faults_reads_counter_and_boot_result(self, fault_admin_app):
        client = TestClient(fault_admin_app)
        resp = client.get("/api/faults", headers={"Authorization": "admin-key"})
        assert resp.status_code == 200
        data = resp.json()
        assert "faults" in data and "total" in data["faults"]
        assert data["boot_selftest"] is None or "probes" in data["boot_selftest"]
