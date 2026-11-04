"""P1.6c: receipted activation requests carrying the delta artefact.

A policy activation is an authority grant like any other, so it goes
through the approvals queue with the same receipt discipline as
escalated tool calls and suspensions. The difference is evidence: the
request carries the P1.6b blast-radius delta artefact computed at
request time, so the activate path shows the delta BEFORE confirmation
and the approver signs off on a bounded, digest-bound artefact.

Design notes (mirrors :mod:`raucle.approvals`):

- Requests live in memory. The receipts are the durable record: the
  request receipt embeds the delta summary and the artefact digest, so
  a restart loses nothing that needs proving.
- The artefact digest is the sha256 of the canonical artefact JSON. An
  artefact presented to the evidence pack must hash to the digest
  beside it or it is not the artefact the approver saw.
- Decisions are single-shot; an approved request authorises exactly
  one activation.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

ARTEFACT_KIND = "policy_activation_delta"


@dataclass
class ActivationRequest:
    request_id: str
    policy_id: str
    baseline_label: str
    candidate_label: str
    requested_by: str
    artefact_digest: str
    delta_summary: dict[str, Any]
    artefact: dict[str, Any]
    created_at: int
    expires_at: int
    status: str  # pending | approved | denied | consumed
    receipt_id: str | None = None
    decided_at: int | None = None
    approver: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Bounded row for the queue: the delta summary, never the raw
        decision rows' constraint context."""
        return {
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "baseline": self.baseline_label,
            "candidate": self.candidate_label,
            "requested_by": self.requested_by,
            "artefact_digest": self.artefact_digest,
            "delta_summary": self.delta_summary,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


class ActivationError(Exception):
    """Raised when an activation request cannot be honoured."""

    def __init__(self, message: str, status_code: int = 404):
        super().__init__(message)
        self.status_code = status_code


def delta_summary_from_artefact(artefact: dict[str, Any]) -> dict[str, Any]:
    """The bounded summary attached to the request payload.

    Flip count with receipt IDs, paths opened/closed with rule IDs,
    widened rules, preserved invariants, register sentence. Scalar or
    string values only (plus string lists): the summary rides signed
    receipt material where floats are banned.
    """
    return {
        "artefact_kind": artefact["artefact_kind"],
        "register_sentence": artefact["register_sentence"],
        "flipped_decisions": {
            "count": artefact["flipped_decisions"]["count"],
            "receipt_ids": [
                str(r["receipt_id"]) for r in artefact["flipped_decisions"]["rows"]
            ],
        },
        "authority_paths_opened": artefact["authority_paths_opened"],
        "authority_paths_closed": artefact["authority_paths_closed"],
        "authority_paths_changed": artefact["authority_paths_changed"],
        "delegation_hop_impact_count": len(artefact["delegation_hop_impact"]),
        "invariants_preserved": artefact["invariants_preserved"],
        "invariants_mode": artefact["invariants_mode"],
        "gaps": artefact["gaps"],
    }


class ActivationApprovalManager:
    """The activation-request side of the approvals queue."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        self._requests: dict[str, ActivationRequest] = {}

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def create_request(
        self,
        *,
        policy_id: str,
        requested_by: str,
        batch: Any,
        baseline_policy: Any,
        candidate_policy: Any,
        chain_graphs: dict[str, dict[str, Any]] | None = None,
        use_z3: bool = True,
    ) -> ActivationRequest:
        """Compute the delta at request time and attach the artefact."""
        from raucle.delta_report import (
            activation_artefact,
            build_delta_report,
            delta_artefact_digest,
        )

        report = build_delta_report(
            batch,
            baseline_policy=baseline_policy,
            candidate_policy=candidate_policy,
            chain_graphs=chain_graphs,
            use_z3=use_z3,
        )
        artefact = activation_artefact(report)
        summary = delta_summary_from_artefact(artefact)
        now = int(time.time())
        request_id = (
            "actr_"
            + hashlib.sha256(
                (
                    policy_id
                    + requested_by
                    + delta_artefact_digest(artefact)
                    + str(now)
                    + secrets.token_hex(8)
                ).encode("utf-8")
            ).hexdigest()[:16]
        )
        request = ActivationRequest(
            request_id=request_id,
            policy_id=policy_id,
            baseline_label=report.policy_versions["baseline"],
            candidate_label=report.policy_versions["candidate"],
            requested_by=requested_by,
            artefact_digest=delta_artefact_digest(artefact),
            delta_summary=summary,
            artefact=artefact,
            created_at=now,
            expires_at=now + self._ttl,
            status="pending",
        )
        self._requests[request_id] = request
        return request

    def decide(self, request_id: str, *, approved: bool, approver: str) -> ActivationRequest:
        request = self._get(request_id)
        if request.status != "pending":
            raise ActivationError(f"activation request {request_id} is not pending", 409)
        request.status = "approved" if approved else "denied"
        request.decided_at = int(time.time())
        request.approver = approver
        return request

    def consume(self, request_id: str) -> ActivationRequest:
        """Single-shot: an approved request pays for exactly one activation."""
        request = self._get(request_id)
        if request.status != "approved":
            raise ActivationError(f"activation request {request_id} is not approved")
        request.status = "consumed"
        return request

    def get(self, request_id: str) -> ActivationRequest:
        return self._get(request_id)

    def pending(self) -> list[dict[str, Any]]:
        now = int(time.time())
        return [
            r.to_public_dict()
            for r in self._requests.values()
            if r.status == "pending" and r.expires_at > now
        ]

    def _get(self, request_id: str) -> ActivationRequest:
        request = self._requests.get(request_id)
        if request is None:
            raise ActivationError(f"unknown activation request {request_id}", 404)
        if request.status == "pending" and request.expires_at <= int(time.time()):
            request.status = "expired"
            raise ActivationError(f"activation request {request_id} expired", 410)
        return request
