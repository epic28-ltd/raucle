"""Shared plumbing for the capability-guard adapters (private).

The guard adapters (openai_agents, pydantic_ai, google_adk, and the
crewai / langgraph family) ship one doctrine: the deny is evaluated
before any tool interaction, every decision lands in a signed receipt,
and an unattributed call denies with an honest null identity. The
per-adapter public surface mirrors the crewai adapter; this module
carries the identical private helpers ONCE so the growing family does
not duplicate them file by file.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

from raucle.audit import (
    HashChainSink,
    NullSink,
    _canonical_json,
    _sha256_hex,
)
from raucle.capability import Capability, CapabilityGate, GateDecision

logger = logging.getLogger(__name__)


class CapabilityDenied(Exception):
    """Raised by a guarded tool when the gate denies the call.

    The host framework surfaces the exception to the agent as a tool
    error; the denial receipt is emitted *before* the raise, so there is
    no path that drops a decision.
    """

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"raucle denied {tool!r}: {reason}")
        self.tool = tool
        self.reason = reason


def hash_args(args: dict[str, Any]) -> str:
    """The canonical args hash the capability receipts bind (crewai shape)."""
    try:
        return _sha256_hex(_canonical_json(args))
    except Exception:  # pragma: no cover - non-canonicalisable args
        return _sha256_hex(repr(sorted(args.items())).encode("utf-8"))


def evaluate_gate(
    gate: CapabilityGate,
    token: Capability | None,
    tool_name: str,
    call_args: dict[str, Any],
    agent_id: str | None,
) -> GateDecision:
    """Build the decision for an incoming tool call (fail-closed boundaries).

    B2 attribution doctrine: a call with no bound caller identity cannot
    be checked against the token's agent scope, so it denies rather than
    running attributed to a placeholder receipt.
    """
    if not agent_id:
        return GateDecision(
            allowed=False, reason="no acting agent identity (no caller agent_id bound)"
        )
    if token is None:
        return GateDecision(allowed=False, reason="no in-force capability token")
    return gate.check(token=token, tool=tool_name, args=call_args, agent_id=agent_id)


def emit_receipt(
    sink: HashChainSink | NullSink,
    *,
    framework: str,
    token: Capability | None,
    agent_id: str | None,
    tool: str,
    args: dict[str, Any],
    decision: GateDecision,
) -> None:
    """Hand one receipt (ALLOW or DENY) to the audit sink for the chain.

    Emission precedes enforcement in every adapter: a sink failure
    re-raises (an action without its receipt is unauthorised) and aborts
    an in-flight ALLOW.
    """
    receipt = {
        "kind": "capability_receipt",
        "issuer": token.issuer if token else "",
        "issuer_pubkey": token.key_id if token else "<unknown>",
        "agent_id": agent_id,
        "tool": tool,
        "call_args_hash": hash_args(args),
        "decision": "ALLOW" if decision.allowed else "DENY",
        "decision_reason": decision.reason or "",
        "framework": framework,
    }
    try:
        sink.append(receipt)
    except Exception:
        logger.exception("failed to emit capability receipt for %s", tool)
        raise


def declares_ctx_param(fn: Any, needle: str) -> bool:
    """Whether the tool function's first parameter is the framework context.

    Host frameworks hand the run context to functions whose first
    parameter carries the framework's context annotation; the text match
    covers both the class form and the subscripted generic, so the
    detection is version-robust without importing the framework.
    """
    params = list(inspect.signature(fn).parameters.values())
    if not params:
        return False
    annotation = params[0].annotation
    text = getattr(annotation, "__name__", None) or str(annotation)
    return needle in text


def gate_args(args: tuple[Any, ...], kwargs: dict[str, Any], needs_ctx: bool) -> dict[str, Any]:
    """Present the invocation to the gate in a canonical shape.

    The run context is never part of the hashed call args (it is the
    vehicle, not the payload); positional args are folded in by index so
    a positional call cannot slip past constraint evaluation.
    """
    if needs_ctx and args:
        args = args[1:]
    if kwargs and not args:
        return dict(kwargs)
    if args and not kwargs and len(args) == 1:
        return {"input": args[0]}
    combined: dict[str, Any] = {}
    for i, value in enumerate(args):
        combined[str(i)] = value
    combined.update(kwargs)
    return combined
