"""raucle integration for LangGraph (``langgraph`` ≥ 0.2).

LangGraph is stateful **graph** execution: an LLM node plans, a tool node
executes. raucle never sits on the model path — the model node is untouched.
The enforcement seam is the TOOL NODE layer: :func:`gate_tool` /
:func:`gate_tools` return wrapped tools that the host ``(ToolNode`` / the
``tools=`` argument of ``create_react_agent``) executes, and
:class:`RaucleToolNode` is a drop-in ``langgraph.prebuilt.ToolNode`` that
gates its tools at construction. Graph structure, routing and the model node
stay the deployer's own.

Quick start — custom graph
--------------------------

.. code-block:: python

    from langgraph.graph import StateGraph, MessagesState, START
    from langgraph.prebuilt import ToolNode, tools_condition

    from raucle.audit import Ed25519Signer, HashChainSink
    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.integrations.langgraph import RaucleToolNode, set_in_force_token

    issuer = CapabilityIssuer.generate(issuer="acme.platform")
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())

    def lookup_customer(customer_id: str) -> dict: ...

    builder = StateGraph(MessagesState)
    builder.add_node("agent", call_model)                    # your model node
    builder.add_node("tools", RaucleToolNode(                # gated tool node
        [lookup_customer], gate=gate, sink=sink, agent_id="agent-1",
    ))

Quick start — ``create_react_agent``
------------------------------------

.. code-block:: python

    from langgraph.prebuilt import create_react_agent
    from raucle.integrations.langgraph import gate_tools

    agent = create_react_agent(model, tools=gate_tools(tools, gate=gate,
                                                       sink=sink, agent_id="agent-1"))

Per session: bind the in-force capability token before invoking the graph
(``set_in_force_token(issuer.mint(agent_id="agent-1", tool="lookup_customer",
...))`` — the same ContextVar convention as every other adapter). Pass
``token_resolver=...`` for per-tenant / per-session dynamic lookup.

Denial behaviour
----------------

A denied call raises :class:`CapabilityDenied` from the wrapped tool — the
tool body never executes. ``ToolNode`` presents the exception's message back
to the graph as the tool response (with ``ToolNode``'s documented
``handle_tool_errors=True`` error handling), so the model sees
``raucle denied 'transfer_funds': ...``; with error handling disabled the
exception surfaces to the graph author instead. The DENY receipt is emitted
BEFORE the raise, so there is no path that drops a decision. The same
fail-closed doctrine applies at the boundaries: no token, empty agent
identity, or a receipt-sink failure — the ALLOW is aborted (an action
without its receipt is treated as unauthorised).

This adapter is complementary to :mod:`raucle.integrations.langchain`: the
callback handler covers LangChain ``AgentExecutor`` graphs, this module
covers LangGraph's tool-node layer with an identical receipt format.

Install with ``pip install 'raucle[langgraph]'``.
"""

from __future__ import annotations

import contextvars
import inspect
import logging
from collections.abc import Callable, Iterable
from typing import Any

from raucle.audit import (
    HashChainSink,
    NullSink,
    _canonical_json,
    _sha256_hex,
)
from raucle.capability import (
    Capability,
    CapabilityGate,
    GateDecision,
)

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import-time check, exercised via sys.modules stubs
    from langgraph.prebuilt import ToolNode  # type: ignore[import-not-found]

    _HAS_LANGGRAPH = True
except ImportError:  # pragma: no cover
    _HAS_LANGGRAPH = False

    class ToolNode:  # type: ignore[no-redef]
        """Stub used when ``langgraph`` is not installed.

        Subclassing this class outside a LangGraph deployment is a no-op;
        instantiating :class:`RaucleToolNode` raises a clear RuntimeError
        directing the user to install the extra.
        """


class CapabilityDenied(Exception):
    """Raised by a gated tool when the gate denies the call.

    LangGraph's ToolNode surfaces the exception message to the graph as the
    tool response (``handle_tool_errors=True``); the denial receipt is
    emitted *before* the raise, so there is no path that drops a decision.
    """

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"raucle denied {tool!r}: {reason}")
        self.tool = tool
        self.reason = reason


# --- In-force token resolution (shared contextvar pattern) ------------------

TokenResolver = Callable[[str], Capability | None]

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_langgraph_in_force_token", default=None
)


def set_in_force_token(token: Capability | None) -> None:
    """Bind a capability token to the current (a)sync context for gated tools."""
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    """Read the bound token (or None)."""
    return _in_force_token.get()


def _default_resolver(_tool_name: str) -> Capability | None:
    return get_in_force_token()


UNKNOWN_SIGNER = "<unknown>"
DEFAULT_LEAN_THEOREM_ID = "vcd.gate_soundness"


def _hash_args(args: Any) -> str:
    try:
        return "sha256:" + _sha256_hex(_canonical_json(args))
    except Exception:  # pragma: no cover - non-canonicalisable args
        return "sha256:" + _sha256_hex(repr(args).encode("utf-8", errors="replace"))


def _iso_now() -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + (
        f".{int((time.time() % 1) * 1000):03d}Z"
    )


def _emit_receipt(
    sink: HashChainSink | NullSink,
    *,
    token: Capability | None,
    agent_id: str,
    tool: str,
    args: Any,
    decision: GateDecision,
    lean_theorem_id: str,
) -> None:
    """Hand one receipt (allow OR deny) to the audit sink for the chain.

    A sink failure re-raises: receipt-emission failure must never degrade to
    a silent untracked execution (the caller downgrades an in-flight ALLOW
    to the raised error instead).
    """
    receipt = {
        "kind": "capability_receipt",
        "issuer": token.issuer if token else "",
        "issuer_pubkey": token.key_id if token else UNKNOWN_SIGNER,
        "schema_hash": None,
        "policy_proof_hash": token.policy_proof_hash if token else None,
        "lean_theorem_id": lean_theorem_id,
        "attenuation_chain": list(decision.chain or [])
        or ([] if token is None else [token.token_id]),
        "agent_id": agent_id,
        "tool": tool,
        "call_args_hash": _hash_args(args),
        "decision": "ALLOW" if decision.allowed else "DENY",
        "decision_reason": decision.reason or "",
        "framework": "langgraph",
        "timestamp": _iso_now(),
    }
    try:
        sink.append(receipt)
    except Exception:
        logger.exception("raucle: receipt sink failure for tool=%s", tool)
        raise


def _evaluate_gate(
    gate: CapabilityGate,
    token: Capability | None,
    tool_name: str,
    call_args: Any,
    agent_id: str | None,
) -> GateDecision:
    """Build the decision for an incoming tool call (fail-closed boundaries)."""
    if not agent_id:
        # B2: an empty agent_id is not an identity - deny rather than mint a
        # receipt attributed to a placeholder (same doctrine as the gateway
        # and the other adapters, v0.23.2).
        return GateDecision(allowed=False, reason="no acting agent identity (agent_id empty)")
    if token is None:
        return GateDecision(allowed=False, reason="no in-force capability token")
    return gate.check(token=token, tool=tool_name, args=call_args, agent_id=agent_id)


def _enforce_decision(decision: GateDecision, tool_name: str, raise_on_deny: bool) -> None:
    """Raise on a denial, or warn in explicit shadow mode."""
    if decision.allowed:
        return
    if raise_on_deny:
        raise CapabilityDenied(tool_name, decision.reason or "denied")
    logger.warning(
        "raucle shadow-mode: %s denied (%s) but call proceeding", tool_name, decision.reason
    )


def _present_call_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """Present the invocation to the gate in a canonical shape.

    Tool calls arrive as a structured kwargs dict (the normal ToolNode path);
    a single positional argument (string-convention single-input tools) is
    presented as ``{"input": ...}``, matching the langchain adapter's
    convention. Anything else is presented verbatim for content binding.
    """
    if kwargs and not args:
        return kwargs
    if args and not kwargs and len(args) == 1:
        return {"input": args[0]}
    combined: dict[str, Any] = {}
    for i, value in enumerate(args):
        combined[str(i)] = value
    combined.update(kwargs)
    return combined


def _make_gated_handler(
    tool_name: str,
    original: Callable[..., Any],
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None,
    resolver: TokenResolver,
    raise_on_deny: bool,
    lean_theorem_id: str,
) -> Callable[..., Any]:
    """Build a gate-checked wrapper around ``original``.

    The wrapper preserves the original signature via ``functools.wraps`` —
    host frameworks derive the tool's args schema from
    ``inspect.signature`` (which follows ``__wrapped__``), so a bare
    ``**kwargs`` closure would break every structured-args tool call —
    and keeps the original's sync/async identity, since langgraph (and
    langchain-core) pick the invocation path from the object at hand.
    """
    import functools

    def _run_decision(
        args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> tuple[Capability | None, Any, GateDecision]:
        call_args = _present_call_args(args, kwargs)
        token = resolver(tool_name)
        return token, call_args, _evaluate_gate(gate, token, tool_name, call_args, agent_id)

    def _finish(
        run_original: Callable[[], Any],
        token: Capability | None,
        call_args: Any,
        decision: GateDecision,
    ) -> Any:
        # Emission comes before enforcement and before any execution: a
        # sink failure therefore also aborts an in-flight ALLOW
        # (fail-closed — an action without its receipt is unauthorised).
        _emit_receipt(
            sink,
            token=token,
            agent_id=agent_id or "<unbound>",
            tool=tool_name,
            args=call_args,
            decision=decision,
            lean_theorem_id=lean_theorem_id,
        )
        _enforce_decision(decision, tool_name, raise_on_deny)
        return run_original()

    @functools.wraps(original)
    def gated_sync(*args: Any, **kwargs: Any) -> Any:
        token, call_args, decision = _run_decision(args, kwargs)
        return _finish(lambda: original(*args, **kwargs), token, call_args, decision)

    @functools.wraps(original)
    async def gated_async(*args: Any, **kwargs: Any) -> Any:
        token, call_args, decision = _run_decision(args, kwargs)
        if not inspect.iscoroutinefunction(original):
            return _finish(lambda: original(*args, **kwargs), token, call_args, decision)
        return await _finish(lambda: original(*args, **kwargs), token, call_args, decision)

    wrapper = gated_async if inspect.iscoroutinefunction(original) else gated_sync
    functools.wraps(original)(wrapper)
    return wrapper


def gate_tool(
    tool: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str,
    token_resolver: TokenResolver | None = None,
    raise_on_deny: bool = True,
    lean_theorem_id: str = DEFAULT_LEAN_THEOREM_ID,
) -> Any:
    """Wrap a single LangGraph tool so every call is gated and receipted.

    ``tool`` may be:

    * a plain python callable (``langgraph``/``ToolNode`` converts callables
      to tools itself) — a signature-preserving gated callable is returned;
    * a langchain tool object exposing callable ``func`` / ``coroutine``
      slots (e.g. ``@tool``-decorated ``StructuredTool``) — a copy of the
      tool is returned with the gated handlers bound into those slots, so
      ``name`` / ``description`` / ``args_schema`` (what the model sees) are
      unchanged.

    Anything whose underlying callable cannot be located is refused with
    ``ValueError`` — an ungated tool would be a hole in "every tool call
    passes the gate". Note raucle also never touches the model node: gating
    is per tool execution inside the tool node, never on the model path.
    """
    if not _HAS_LANGGRAPH:
        raise RuntimeError(
            "gate_tool requires langgraph. Install with: pip install 'raucle[langgraph]'"
        )

    resolver = token_resolver or _default_resolver

    if callable(tool) and not hasattr(tool, "invoke"):
        # Plain callable: wrap in place, preserving sync/async identity.
        return _make_gated_handler(
            getattr(tool, "__name__", UNKNOWN_SIGNER),
            tool,
            gate=gate,
            sink=sink,
            agent_id=agent_id,
            resolver=resolver,
            raise_on_deny=raise_on_deny,
            lean_theorem_id=lean_theorem_id,
        )

    inner_func = getattr(tool, "func", None)
    inner_coro = getattr(tool, "coroutine", None)
    model_copy = getattr(tool, "model_copy", None)

    if not (callable(inner_func) or callable(inner_coro)) or not callable(model_copy):
        raise ValueError(
            f"raucle: cannot gate {tool!r} (no inner callable found). Gate the "
            f"underlying python function instead — an ungated tool call would "
            f"bypass the gate and its receipt."
        )

    tool_name = getattr(tool, "name", None) or getattr(inner_func, "__name__", UNKNOWN_SIGNER)
    gated = model_copy(deep=True)

    def _bind(slot: Callable[..., Any], key: str) -> None:
        setattr(
            gated,
            key,
            _make_gated_handler(
                tool_name,
                slot,
                gate=gate,
                sink=sink,
                agent_id=agent_id,
                resolver=resolver,
                raise_on_deny=raise_on_deny,
                lean_theorem_id=lean_theorem_id,
            ),
        )

    if callable(inner_func):
        _bind(inner_func, "func")
    if callable(inner_coro):
        _bind(inner_coro, "coroutine")
    return gated


def gate_tools(
    tools: Iterable[Any],
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str,
    token_resolver: TokenResolver | None = None,
    raise_on_deny: bool = True,
    lean_theorem_id: str = DEFAULT_LEAN_THEOREM_ID,
) -> list[Any]:
    """Wrap a list of tools with :func:`gate_tool` (convenience)."""
    return [
        gate_tool(
            t,
            gate=gate,
            sink=sink,
            agent_id=agent_id,
            token_resolver=token_resolver,
            raise_on_deny=raise_on_deny,
            lean_theorem_id=lean_theorem_id,
        )
        for t in tools
    ]


class RaucleToolNode(ToolNode):
    """A ``langgraph.prebuilt.ToolNode`` whose tools all pass the raucle gate.

    Use it as the tool node of a LangGraph graph; the wrapped decisions
    land in the signed receipt chain either way. Denials surface to the
    graph through ToolNode's own error handling (``handle_tool_errors=True``
    presents ``CapabilityDenied``'s message as the tool response); with
    that disabled the exception propagates to the graph instead. Either
    way the tool body never ran. raucle sits on the TOOL NODE layer only:
    the model node, edges and execution semantics are your own.

    Parameters mirror :func:`gate_tool` plus every ``ToolNode`` keyword
    (``handle_tool_errors``, ``messages_key``, ...), forwarded untouched.
    """

    def __init__(
        self,
        tools: Any,
        *,
        gate: CapabilityGate,
        sink: HashChainSink | NullSink,
        agent_id: str,
        token_resolver: TokenResolver | None = None,
        raise_on_deny: bool = True,
        lean_theorem_id: str = DEFAULT_LEAN_THEOREM_ID,
        **tool_node_kwargs: Any,
    ) -> None:
        if not _HAS_LANGGRAPH:
            raise RuntimeError(
                "RaucleToolNode requires langgraph. Install with: pip install 'raucle[langgraph]'"
            )
        gated = gate_tools(
            tools,
            gate=gate,
            sink=sink,
            agent_id=agent_id,
            token_resolver=token_resolver,
            raise_on_deny=raise_on_deny,
            lean_theorem_id=lean_theorem_id,
        )
        super().__init__(gated, **tool_node_kwargs)


__all__ = [
    "CapabilityDenied",
    "RaucleToolNode",
    "TokenResolver",
    "gate_tool",
    "gate_tools",
    "get_in_force_token",
    "set_in_force_token",
]
