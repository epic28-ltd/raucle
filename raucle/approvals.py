"""Approval manager: human-in-the-loop approval requests for escalated
tool calls.

When the policy gate escalates a call (``require_approval_when`` matched),
an approval request is created, receipted, and surfaced to operators.
A human decision (approve or deny) is receipted too. The re-submitted call
carries the approval reference; the manager verifies it binds to the exact
tool, agent and arguments before the gate lets it through.

Design notes:

- Requests live in memory. The receipts are the durable record: the
  request, the decision and the action all appear in the chain, so losing
  the pending list to a restart loses nothing that needs proving - the
  in-flight approval is simply re-requested.
- Approvals bind to the sha256 of the canonical arguments: an approval for
  a 500-unit transfer cannot authorise a 5000-unit one.
- Consumption is single-shot. An approval pays for exactly one action.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any


def _args_hash(args: dict[str, Any]) -> str:
    from raucle.provenance import _canonical_json, _sha256_hex

    return _sha256_hex(_canonical_json(args))


@dataclass
class ApprovalRequest:
    request_id: str
    tool: str
    agent_id: str
    args_hash: str
    reason: str
    trace_id: str
    created_at: float
    expires_at: float
    status: str  # pending | approved | denied | consumed
    decided_at: float | None = None
    approver: str | None = None
    decided_receipt: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tool": self.tool,
            "agent_id": self.agent_id,
            "args_hash": self.args_hash,
            "reason": self.reason,
            "trace_id": self.trace_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "approver": self.approver,
        }


class ApprovalError(Exception):
    """Raised when an approval reference cannot be honoured."""

    def __init__(self, message: str, status_code: int = 404):
        super().__init__(message)
        self.status_code = status_code


class ApprovalManager:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        self._requests: dict[str, ApprovalRequest] = {}

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def create_request(
        self, *, tool: str, agent_id: str, args: dict[str, Any], reason: str, trace_id: str
    ) -> ApprovalRequest:
        now = time.time()
        request_id = (
            "apr_"
            + hashlib.sha256(
                (tool + agent_id + _args_hash(args) + str(now) + secrets.token_hex(8)).encode(
                    "utf-8"
                )
            ).hexdigest()[:16]
        )
        request = ApprovalRequest(
            request_id=request_id,
            tool=tool,
            agent_id=agent_id,
            args_hash=_args_hash(args),
            reason=reason,
            trace_id=trace_id,
            created_at=now,
            expires_at=now + self._ttl,
            status="pending",
        )
        self._requests[request_id] = request
        return request

    def decide(self, request_id: str, *, approved: bool, approver: str) -> ApprovalRequest:
        request = self._get(request_id)
        if request.status != "pending":
            raise ApprovalError(f"approval request {request_id} is not pending", 409)
        request.status = "approved" if approved else "denied"
        request.decided_at = time.time()
        request.approver = approver
        return request

    def consume(
        self, request_id: str, *, tool: str, agent_id: str, args: dict[str, Any]
    ) -> ApprovalRequest:
        """Validate an approval reference against a re-submitted call.

        Raises ApprovalError with a reason when the reference cannot
        authorise this call; returns the request and marks it consumed
        when it can.
        """
        request = self._get(request_id)
        if request.status != "approved":
            raise ApprovalError(f"approval request {request_id} is not approved")
        if request.tool != tool or request.agent_id != agent_id:
            raise ApprovalError("approval does not match this tool or agent")
        if request.args_hash != _args_hash(args):
            raise ApprovalError("approval does not match these arguments")
        request.status = "consumed"
        return request

    def pending(self) -> list[dict[str, Any]]:
        now = time.time()
        return [
            r.to_public_dict()
            for r in self._requests.values()
            if r.status == "pending" and r.expires_at > now
        ]

    def _get(self, request_id: str) -> ApprovalRequest:
        request = self._requests.get(request_id)
        if request is None:
            raise ApprovalError(f"unknown approval request {request_id}", 404)
        if request.status == "pending" and request.expires_at <= time.time():
            request.status = "expired"
            raise ApprovalError(f"approval request {request_id} expired", 410)
        return request
