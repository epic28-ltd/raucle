"""raucle integration for Google Agent Development Kit (``google-adk`` >= 1.39, < 3).

Google ADK tools are plain functions with the shape
``def tool(args: dict, tool_context: ToolContext) -> dict``, registered on an
``LlmAgent`` directly or wrapped in ``google.adk.tools.FunctionTool`` (which
handles both sync and async functions). So the clean, fail-closed
integration is a **wrapping function**: :func:`guard_tool` returns a gated
callable with the original signature (via ``functools.wraps``, which ADK's
own signature validation follows), so the framework sees an identical tool.
The wrapper resolves the in-force capability token, asks the gate to
ALLOW/DENY the call, emits a signed receipt for the decision, and only then
delegates; a denied call raises :class:`CapabilityDenied` before the
function body runs - the tool never executes.

Attribution surface
-------------------

The acting agent id travels on the **invocation context**: ADK hands each
tool call a ``ToolContext`` whose invocation context (``_invocation_context``,
stored by ADK's ``ReadonlyContext`` base across the verified span) carries
the executing agent - ``invocation_context.agent.name``, the ``LlmAgent``'s
own name. ADK names are identifiers (``billing_agent``; colons are refused
by ADK's own validation), while raucle capability ids carry the
``agent:`` scheme - so the guard joins the namespaces deterministically:
an ADK agent named ``billing_agent`` acts as ``agent:billing_agent``
(already-scheme-valid names pass through unchanged). Mint the token for
the joined id, or pin it at guard time. The guard resolves the acting
identity as:

1. the ``agent_id`` pinned at guard time (explicit binding wins), else
2. the invocation context's agent name joined into the raucle scheme
   (version-robust getattr traversal over the public and stored-private
   spellings, never an isinstance check), else
3. DENY: an unattributed call cannot be checked against the token's agent
   scope, so it denies (bearer mode is closed, the B2 doctrine) and the
   deny receipt carries an honest null ``agent_id`` - never a placeholder.

Quick start
-----------

.. code-block:: python

    from google.adk.agents import LlmAgent
    from google.adk.tools import FunctionTool

    from raucle.audit import Ed25519Signer, HashChainSink
    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.integrations.google_adk import guard_tool, set_in_force_token

    issuer = CapabilityIssuer.generate(issuer="acme.platform")
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())

    def transfer_funds(args: dict, tool_context: ToolContext) -> dict:
        ...

    # agent_id binds the acting identity; an unattributed call denies.
    # ADK names its agents with plain identifiers, so the raucle id is the
    # joined form: billing_agent -> agent:billing_agent.
    agent = LlmAgent(
        name="billing_agent",
        model="gemini-2.0-flash",
        tools=[FunctionTool(guard_tool(transfer_funds, gate=gate, sink=sink,
                                       agent_id="agent:billing_agent"))],
    )

    set_in_force_token(issuer.mint(
        agent_id="agent:billing_agent", tool="transfer_funds",
        constraints={"max_value": {"amount": 100}}, ttl_seconds=60,
    ))

Every tool call the agent makes now passes the raucle gate before it runs;
the decision lands in the signed receipt chain (verify offline with
``raucle audit verify``). The gate never reads the agent's reasoning, so a
prompt-injected call is denied on the same path as a legitimate one.

Verified span (P2a, 18 Nov 2026, CPython 3.13): the guard and the
``ToolContext`` attribution surface were probed live under google-adk
1.39.1 / 2.7.0 / 2.11.0 / 2.14.1 (Apache-2.0); the extra is pinned to
that span. Requires Python >= 3.11 (upstream's own floor).

Install with ``pip install 'raucle[google-adk]'``.
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
)
from raucle.capability import Capability, CapabilityGate
from raucle.integrations._guard_core import (
    CapabilityDenied,
    emit_receipt,
    evaluate_gate,
)

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import-time check
    from google.adk.tools import ToolContext  # noqa: F401  (presence probe)

    _HAS_GOOGLE_ADK = True
except ImportError:  # pragma: no cover
    _HAS_GOOGLE_ADK = False


# --- In-force token resolution (shared contextvar pattern) -----------------

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_google_adk_in_force_token", default=None
)


def set_in_force_token(token: Capability | None) -> None:
    """Bind a capability token to the current context for guarded tools."""
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    """Read the bound token (or None)."""
    return _in_force_token.get()


def _normalise_agent_name(name: str) -> str:
    """Join an ADK agent name into the raucle ``agent:`` scheme the way
    the tokens' agent scope matches: an already-schemed id passes through,
    a bare identifier gains the scheme prefix (``billing_agent`` ->
    ``agent:billing_agent``). Empty or non-scheme-but-schemed inputs are
    not possible through the caller (it checks ``isinstance(name, str)
    and name``), and an unexpected shape degrades upstream to an honest
    unattributed deny."""
    return name if name.startswith("agent:") else f"agent:{name}"


def _identity_from_tool_context(tool_context: Any) -> str | None:
    """The acting identity ADK carries: the invocation context's agent name.

    Version-robust by duck-typing: read the invocation context through its
    public property spelling where one exists and the stored private
    attribute otherwise (``ReadonlyContext._invocation_context`` across the
    whole verified span), then the agent and its name (joined into the
    raucle scheme, see :func:`_normalise_agent_name`). No isinstance
    check, so an unexpected context shape degrades to an honest
    unattributed deny rather than a crash.
    """
    invocation = getattr(tool_context, "invocation_context", None) or getattr(
        tool_context, "_invocation_context", None
    )
    agent = getattr(invocation, "agent", None)
    name = getattr(agent, "name", None)
    if isinstance(name, str) and name:
        return _normalise_agent_name(name)
    return None


def _make_gated_function(
    original: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None,
) -> Any:
    """Build the gate-checked wrapper, preserving sync/async identity."""
    tool_name = getattr(original, "__name__", None) or "<unknown>"

    def _extract_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[dict[str, Any], Any]:
        """Present either call spelling as (call_args, tool_context).

        ADK calls tools positionally as fn(args, tool_context); the
        keyword spelling is accepted too without weakening either.
        """
        call_args: dict[str, Any] | None = None
        tool_context: Any = None
        if args:
            call_args = args[0] if isinstance(args[0], dict) else {"input": args[0]}
            if len(args) > 1:
                tool_context = args[1]
        if "args" in kwargs:
            value = kwargs["args"]
            call_args = value if isinstance(value, dict) else {"input": value}
        if "tool_context" in kwargs:
            tool_context = kwargs["tool_context"]
        return call_args or {}, tool_context

    def _decide(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        call_args, tool_context = _extract_call(args, kwargs)
        acting = agent_id or _identity_from_tool_context(tool_context)
        token = get_in_force_token()
        decision = evaluate_gate(gate, token, tool_name, call_args, acting)
        # Emission precedes enforcement: there is no path that drops a
        # decision, and a sink failure aborts an in-flight ALLOW too.
        emit_receipt(
            sink,
            framework="google-adk",
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
    """Wrap a Google ADK tool function so every call is gated and receipted.

    Returns a callable with the original ``(args, tool_context)`` signature
    (``functools.wraps``), so registering it - directly on an ``LlmAgent`` or
    through ``FunctionTool(guard_tool(...))`` - produces the tool the model
    would have seen. The wrapper:

    1. resolves the in-force capability token,
    2. resolves the acting identity (pinned ``agent_id``, else the agent
       name on the tool context's invocation context),
    3. asks the gate to ALLOW/DENY the call with these arguments,
    4. emits a signed receipt for the decision,
    5. delegates on ALLOW, or raises :class:`CapabilityDenied` on DENY (or
       when no token is bound, or no identity is attributable).

    ``agent_id`` pins the caller identity the gate checks the token's agent
    scope against. Bearer mode is closed: with no pinned identity and no
    agent name on the invocation context, the call denies and the deny
    receipt carries an honest null ``agent_id``.
    """
    if not _HAS_GOOGLE_ADK:
        raise RuntimeError(
            "guard_tool requires google-adk. Install with: pip install 'raucle[google-adk]'"
        )
    return _make_gated_function(fn, gate=gate, sink=sink, agent_id=agent_id)


def guard_tools(
    fns: list[Any],
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> list[Any]:
    """Wrap a list of Google ADK tool functions (convenience)."""
    return [guard_tool(fn, gate=gate, sink=sink, agent_id=agent_id) for fn in fns]


__all__ = [
    "CapabilityDenied",
    "guard_tool",
    "guard_tools",
    "set_in_force_token",
    "get_in_force_token",
]
