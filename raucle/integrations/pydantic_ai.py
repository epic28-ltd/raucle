"""raucle integration for Pydantic AI (``pydantic-ai`` >= 1.107, < 3).

Pydantic AI tools are plain functions registered on an :class:`~pydantic_ai.agent.Agent`
(either ``@agent.tool`` with a ``RunContext`` first parameter or
``@agent.tool_plain`` without), so the clean, fail-closed integration is a
**wrapping function**: :func:`guard_tool` returns a gated callable with the
original signature (via ``functools.wraps``, which Pydantic AI's own
argument-schema derivation follows), so the framework sees an identical
tool. The wrapper resolves the in-force capability token, asks the gate to
ALLOW/DENY the call, emits a signed receipt for the decision, and only then
delegates; a denied call raises :class:`CapabilityDenied` before the
function body runs - the tool never executes.

Attribution surface
-------------------

The acting agent id travels on the **run context**: Pydantic AI builds a
``RunContext`` per run and hands it to ``ctx``-declaring tools, and
``RunContext.agent`` is the ``Agent`` the tool is registered on. The guard
resolves the acting identity as:

1. the ``agent_id`` pinned at guard time (explicit binding wins), else
2. ``RunContext.agent.name`` (the framework's own identity for the
   executing agent - set ``Agent(..., name="agent:billing")``), else
3. DENY: an unattributed call cannot be checked against the token's agent
   scope, so it denies (bearer mode is closed, the B2 doctrine) and the
   deny receipt carries an honest null ``agent_id`` - never a placeholder.

Quick start
-----------

.. code-block:: python

    from pydantic_ai import Agent

    from raucle.audit import Ed25519Signer, HashChainSink
    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.integrations.pydantic_ai import guard_tool, set_in_force_token

    issuer = CapabilityIssuer.generate(issuer="acme.platform")
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())

    def transfer_funds(ctx: RunContext, to: str, amount: int) -> str:
        ...

    # agent_id binds the acting identity; an unattributed call denies.
    agent = Agent("openai:gpt-4o", name="agent:billing")
    agent.tool(guard_tool(transfer_funds, gate=gate, sink=sink,
                          agent_id="agent:billing"))

    set_in_force_token(issuer.mint(
        agent_id="agent:billing", tool="transfer_funds",
        constraints={"max_value": {"amount": 100}}, ttl_seconds=60,
    ))
    result = agent.run_sync("pay the invoice")

Every tool call the agent makes now passes the raucle gate before it runs;
the decision lands in the signed receipt chain (verify offline with
``raucle audit verify``). The gate never reads the agent's reasoning, so a
prompt-injected call is denied on the same path as a legitimate one.

Verified span (P2a, 18 Nov 2026, CPython 3.13): the guard and the
``RunContext`` attribution surface were probed live under pydantic-ai
1.107.10 / 2.59.0 / 2.65.0 / 2.70.0 (MIT); the extra is pinned to that
span. Requires Python >= 3.11 (upstream's own floor).

Install with ``pip install 'raucle[pydantic-ai]'``.
"""

from __future__ import annotations

import contextvars
import functools
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

try:  # pragma: no cover - import-time check
    from pydantic_ai.tools import RunContext  # noqa: F401  (presence probe)

    _HAS_PYDANTIC_AI = True
except ImportError:  # pragma: no cover
    _HAS_PYDANTIC_AI = False


class CapabilityDenied(Exception):
    """Raised by a guarded tool when the gate denies the call.

    Pydantic AI treats a raising tool as a tool error and surfaces the
    message back to the model (retry budget applies); the denial receipt is
    emitted *before* the raise, and the tool body never executes.
    """

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"raucle denied {tool!r}: {reason}")
        self.tool = tool
        self.reason = reason


# --- In-force token resolution (shared contextvar pattern) -----------------

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_pydantic_ai_in_force_token", default=None
)


def set_in_force_token(token: Capability | None) -> None:
    """Bind a capability token to the current context for guarded tools."""
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    """Read the bound token (or None)."""
    return _in_force_token.get()


def _hash_args(args: dict[str, Any]) -> str:
    try:
        return _sha256_hex(_canonical_json(args))
    except Exception:  # pragma: no cover - non-canonicalisable args
        return _sha256_hex(repr(sorted(args.items())).encode("utf-8"))


def _emit_receipt(
    sink: HashChainSink | NullSink,
    *,
    token: Capability | None,
    agent_id: str | None,
    tool: str,
    args: dict[str, Any],
    decision: GateDecision,
) -> None:
    receipt = {
        "kind": "capability_receipt",
        "issuer": token.issuer if token else "",
        "issuer_pubkey": token.key_id if token else "<unknown>",
        "agent_id": agent_id,
        "tool": tool,
        "call_args_hash": _hash_args(args),
        "decision": "ALLOW" if decision.allowed else "DENY",
        "decision_reason": decision.reason or "",
        "framework": "pydantic-ai",
    }
    try:
        sink.append(receipt)
    except Exception:
        # The sink's own fail-loud contract propagates: an action without
        # its receipt is unauthorised (fail-closed).
        logger.exception("failed to emit capability receipt for %s", tool)
        raise


def _evaluate_gate(
    gate: CapabilityGate,
    token: Capability | None,
    tool_name: str,
    call_args: dict[str, Any],
    agent_id: str | None,
) -> GateDecision:
    """Build the decision for an incoming tool call (fail-closed boundaries).

    B2 attribution doctrine (same as the crewai and langgraph adapters): a
    call with no bound caller identity cannot be checked against the
    token's agent scope, so it denies rather than running attributed to a
    placeholder receipt.
    """
    if not agent_id:
        return GateDecision(
            allowed=False, reason="no acting agent identity (no caller agent_id bound)"
        )
    if token is None:
        return GateDecision(allowed=False, reason="no in-force capability token")
    return gate.check(token=token, tool=tool_name, args=call_args, agent_id=agent_id)


def _identity_from_context(ctx: Any) -> str | None:
    """The acting identity Pydantic AI carries: ``RunContext.agent.name``.

    Version-robust by duck-typing (getattr chains, no isinstance), so the
    guard reads the same field across the verified span (1.107 - 2.x) and
    never crashes on a context shape it does not recognise.
    """
    agent = getattr(ctx, "agent", None)
    name = getattr(agent, "name", None)
    return name if isinstance(name, str) and name else None


def _declares_run_context(fn: Any) -> bool:
    """Whether the tool function's first parameter is the ``RunContext``.

    Pydantic AI's registration contract: a ``ctx``-declaring tool receives
    the run context as its first positional argument. The guard reads the
    annotation text so both the class form and the subscripted generic
    (``RunContext[Deps]``) match, and a plain tool is never mistaken for a
    context-bearing one.
    """
    params = list(inspect.signature(fn).parameters.values())
    if not params:
        return False
    annotation = params[0].annotation
    text = getattr(annotation, "__name__", None) or str(annotation)
    return "RunContext" in text


def _gate_args(args: tuple[Any, ...], kwargs: dict[str, Any], needs_ctx: bool) -> dict[str, Any]:
    """Present the invocation to the gate in a canonical shape.

    The run context is never part of the hashed call args (it is the
    vehicle, not the payload); positional args are folded in by index so a
    positional call cannot slip past constraint evaluation.
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


def _make_gated_function(
    original: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None,
) -> Any:
    """Build the gate-checked wrapper, preserving sync/async identity."""
    tool_name = getattr(original, "__name__", None) or "<unknown>"
    needs_ctx = _declares_run_context(original)

    def _decide(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        ctx = args[0] if needs_ctx and args and hasattr(args[0], "agent") else None
        acting = agent_id or _identity_from_context(ctx)
        call_args = _gate_args(args, kwargs, needs_ctx)
        token = get_in_force_token()
        decision = _evaluate_gate(gate, token, tool_name, call_args, acting)
        # Emission precedes enforcement: there is no path that drops a
        # decision, and a sink failure aborts an in-flight ALLOW too.
        _emit_receipt(
            sink,
            token=token,
            agent_id=acting,
            tool=tool_name,
            args=call_args,
            decision=decision,
        )
        if not decision.allowed:
            raise CapabilityDenied(tool_name, decision.reason or "denied")

    @functools.wraps(original)
    def gated_sync(*args: Any, **kwargs: Any) -> Any:
        _decide(args, kwargs)
        # A deny raised inside _decide; only an ALLOW reaches the delegate.
        return original(*args, **kwargs)

    @functools.wraps(original)
    async def gated_async(*args: Any, **kwargs: Any) -> Any:
        _decide(args, kwargs)
        return await original(*args, **kwargs)

    return gated_async if inspect.iscoroutinefunction(original) else gated_sync


def guard_tool(
    fn: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> Any:
    """Wrap a Pydantic AI tool function so every call is gated and receipted.

    Returns a callable with the original signature (``functools.wraps``),
    which Pydantic AI's own schema derivation follows, so registering the
    guarded function with ``@agent.tool`` / ``@agent.tool_plain`` produces
    the tool the model would have seen. The wrapper:

    1. resolves the in-force capability token,
    2. resolves the acting identity (pinned ``agent_id``, else
       ``RunContext.agent.name``),
    3. asks the gate to ALLOW/DENY the call with these arguments,
    4. emits a signed receipt for the decision,
    5. delegates on ALLOW, or raises :class:`CapabilityDenied` on DENY (or
       when no token is bound, or no identity is attributable).

    ``agent_id`` pins the caller identity the gate checks the token's agent
    scope against. Bearer mode is closed: with no pinned identity and no
    named ``Agent`` on the run context, the call denies and the deny
    receipt carries an honest null ``agent_id``.
    """
    if not _HAS_PYDANTIC_AI:
        raise RuntimeError(
            "guard_tool requires pydantic-ai. Install with: pip install 'raucle[pydantic-ai]'"
        )
    return _make_gated_function(fn, gate=gate, sink=sink, agent_id=agent_id)


def guard_tools(
    fns: list[Any],
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> list[Any]:
    """Wrap a list of Pydantic AI tool functions (convenience)."""
    return [guard_tool(fn, gate=gate, sink=sink, agent_id=agent_id) for fn in fns]


__all__ = [
    "CapabilityDenied",
    "guard_tool",
    "guard_tools",
    "set_in_force_token",
    "get_in_force_token",
]
