"""Q17 gate hardening: atomic approval consumption (phase-3 review close 1).

Enforcement boundary this file pins: consuming an approval (and its
activation twin) is a compare-and-set under a lock, exactly one consume of
an approved request ever succeeds, a second caller is named refused with
``already consumed``, validation refusals never burn the approval, and the
expiry class keeps refusing with the 410 status before any payout.

The concurrent race uses a barrier-started thread pool over the REAL
manager: unfixed main was measured double-spending (dozens of concurrent
consumes succeeded on one approved request); the fix serialises the whole
read-validate-consume sequence under one lock per manager, so the race
device cannot get a second success past it.
"""

from __future__ import annotations

import threading
import time

import pytest

from raucle.activation import (
    ActivationApprovalManager,
    ActivationError,
    ActivationRequest,
)
from raucle.approvals import ApprovalError, ApprovalManager


def _race_args(entries: int = 2_000) -> dict[str, str]:
    """Caller arguments that cost real hash work per consume attempt.

    The canonical-JSON + sha256 work of this dict is what sat between the
    status check and the consumed write on unfixed code, so concurrent
    attempts reliably interleave there. On the fixed code the same work
    runs inside the manager's lock and cannot widen anything.
    """
    return {f"arg_{i:05d}": f"value-{i:05d}" for i in range(entries)}


class TestApprovalConsumeAtomicity:
    def test_hundred_concurrent_consumes_exactly_one_succeeds(self) -> None:
        """The headline pin: one approved request, 100 barrier-started
        concurrent consume attempts. Exactly one succeeds, the other 99 are
        named refused, zero double-spend."""
        manager = ApprovalManager(ttl_seconds=300)
        args = _race_args()
        request = manager.create_request(
            tool="wire_transfer",
            agent_id="agent:svc",
            args=args,
            reason="escalated transfer",
            trace_id="t-race",
        )
        manager.decide(request.request_id, approved=True, approver="op")

        callers = 100
        barrier = threading.Barrier(callers)
        successes: list[str] = []
        refusals: list[str] = []

        def attempt() -> None:
            barrier.wait()
            try:
                out = manager.consume(
                    request.request_id,
                    tool="wire_transfer",
                    agent_id="agent:svc",
                    args=args,
                )
                successes.append(out.status)
            except ApprovalError as exc:
                refusals.append(str(exc))

        threads = [threading.Thread(target=attempt) for _ in range(callers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(successes) == 1, f"double-spend: {len(successes)} consumed"
        assert len(refusals) == callers - 1
        assert all("already consumed" in refusal for refusal in refusals)
        assert request.status == "consumed"

    def test_consume_after_consume_refuses_named(self) -> None:
        """The named compare-and-set refusal: the second caller of an
        already-consumed request gets the named error, never success."""
        manager = ApprovalManager(ttl_seconds=300)
        request = manager.create_request(
            tool="wire_transfer",
            agent_id="agent:svc",
            args={"amount": 500},
            reason="escalated transfer",
            trace_id="t-1",
        )
        manager.decide(request.request_id, approved=True, approver="op")

        consumed = manager.consume(
            request.request_id, tool="wire_transfer", agent_id="agent:svc", args={"amount": 500}
        )
        assert consumed.status == "consumed"
        with pytest.raises(ApprovalError, match="already consumed"):
            manager.consume(
                request.request_id,
                tool="wire_transfer",
                agent_id="agent:svc",
                args={"amount": 500},
            )

    def test_validation_refusal_does_not_burn_the_approval(self) -> None:
        """A bound-checked mismatch refuses without flipping the status: the
        legitimate caller can still consume afterwards (single consumption
        is reserved for the call the approval actually authorises)."""
        manager = ApprovalManager(ttl_seconds=300)
        request = manager.create_request(
            tool="wire_transfer",
            agent_id="agent:svc",
            args={"amount": 500},
            reason="escalated transfer",
            trace_id="t-1",
        )
        manager.decide(request.request_id, approved=True, approver="op")

        with pytest.raises(ApprovalError, match="does not match this tool or agent"):
            manager.consume(request.request_id, tool="other_tool", agent_id="agent:svc", args={})
        with pytest.raises(ApprovalError, match="does not match these arguments"):
            manager.consume(
                request.request_id,
                tool="wire_transfer",
                agent_id="agent:svc",
                args={"amount": 5000},
            )
        assert request.status == "approved"
        consumed = manager.consume(
            request.request_id, tool="wire_transfer", agent_id="agent:svc", args={"amount": 500}
        )
        assert consumed.status == "consumed"

    def test_expired_pending_request_refuses_410(self) -> None:
        """Regression pin: expiry before consume refuses with the 410 class
        and the expired status, exactly as before the atomicity rework."""
        manager = ApprovalManager(ttl_seconds=1)
        request = manager.create_request(
            tool="wire_transfer",
            agent_id="agent:svc",
            args={"amount": 500},
            reason="escalated transfer",
            trace_id="t-1",
        )
        time.sleep(1.2)
        with pytest.raises(ApprovalError, match="expired") as exc_info:
            manager.consume(
                request.request_id,
                tool="wire_transfer",
                agent_id="agent:svc",
                args={"amount": 500},
            )
        assert exc_info.value.status_code == 410
        assert request.status == "expired"

    def test_expired_approved_request_refuses_410(self) -> None:
        """An approved request whose validity window has passed cannot
        authorise: consume refuses with the 410 class rather than paying out
        a stale approval. Unfixed main consumes such a request happily."""
        manager = ApprovalManager(ttl_seconds=1)
        request = manager.create_request(
            tool="wire_transfer",
            agent_id="agent:svc",
            args={"amount": 500},
            reason="escalated transfer",
            trace_id="t-1",
        )
        manager.decide(request.request_id, approved=True, approver="op")
        time.sleep(1.2)
        with pytest.raises(ApprovalError, match="expired") as exc_info:
            manager.consume(
                request.request_id,
                tool="wire_transfer",
                agent_id="agent:svc",
                args={"amount": 500},
            )
        assert exc_info.value.status_code == 410
        assert request.status == "expired"


class TestActivationConsumeAtomicity:
    """The activation twin carries the same single-consumption contract:
    the same barrier race, named refusal and expiry class."""

    def _manager_with_approved_request(
        self, ttl_seconds: int = 300
    ) -> tuple[ActivationApprovalManager, ActivationRequest]:
        now = int(time.time())
        manager = ActivationApprovalManager(ttl_seconds=ttl_seconds)
        request = ActivationRequest(
            request_id="actr_q17_pin",
            policy_id="pol-1",
            baseline_label="baseline-v1",
            candidate_label="candidate-v2",
            requested_by="operator:ops",
            artefact_digest="d" * 64,
            delta_summary={},
            artefact={},
            created_at=now,
            expires_at=now + ttl_seconds,
            status="pending",
        )
        # Request CONSTRUCTION flows are covered in test_activation_artefact;
        # this pin owns consume semantics only, so the request is staged
        # directly into the manager's request map then decided like any other.
        manager._requests[request.request_id] = request  # noqa: SLF001
        manager.decide(request.request_id, approved=True, approver="op")
        return manager, request

    def test_hundred_concurrent_consumes_exactly_one_succeeds(self) -> None:
        manager, request = self._manager_with_approved_request()
        callers = 100
        barrier = threading.Barrier(callers)
        successes: list[str] = []
        refusals: list[str] = []

        def attempt() -> None:
            barrier.wait()
            try:
                out = manager.consume(request.request_id)
                successes.append(out.status)
            except ActivationError as exc:
                refusals.append(str(exc))

        threads = [threading.Thread(target=attempt) for _ in range(callers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(successes) == 1, f"double-spend: {len(successes)} consumed"
        assert len(refusals) == callers - 1
        assert all("already consumed" in refusal for refusal in refusals)
        assert request.status == "consumed"

    def test_consume_after_consume_refuses_named(self) -> None:
        manager, request = self._manager_with_approved_request()
        assert manager.consume(request.request_id).status == "consumed"
        with pytest.raises(ActivationError, match="already consumed"):
            manager.consume(request.request_id)

    def test_expired_approved_request_refuses_410(self) -> None:
        manager, request = self._manager_with_approved_request(ttl_seconds=1)
        time.sleep(1.2)
        with pytest.raises(ActivationError, match="expired") as exc_info:
            manager.consume(request.request_id)
        assert exc_info.value.status_code == 410
        assert request.status == "expired"
