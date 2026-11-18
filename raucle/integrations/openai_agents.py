"""raucle guardrails for the OpenAI Agents SDK (``openai-agents`` >= 0.19, < 0.26).

The OpenAI Agents SDK runs *guardrails* — user-supplied checks executed
before the model call (input guardrails) or before the agent's output is
delivered (output guardrails) — and trips a wire when the check fails.
This module adapts raucle's :class:`~raucle.scanner.Scanner` (prompt-
injection / jailbreak / exfiltration detection) to that contract:

- :func:`input_guardrail` scans the user prompt crossing into the agent.
- :func:`output_guardrail` scans the agent's final output.

Both emit a signed receipt for every scan when an audit sink is supplied
(whether clean or not — a clean scan you cannot evidence is worthless),
fail-closed: a scanner exception trips the wire rather than passing the
payload through.

Capability guard (P2a)
----------------------

:func:`guard_tool` / :func:`guard_tools` wrap the SDK's ``FunctionTool``
objects (or plain tool functions) with the same gate the crewai and
langgraph adapters ship: the in-force capability token decides
ALLOW/DENY before the tool body runs, every decision lands in the signed
receipt chain, and an unattributed call denies (bearer mode closed) with
an honest null ``agent_id`` in the deny receipt. The acting identity is
the ``agent_id`` pinned at guard time, else the SDK's invocation context
(``ToolContext.agent.name``, or the run context's ``agent_id`` key); name
the ``Agent`` with a raucle-scheme id (``Agent(name="agent:billing")``)
or pin the identity so the token's agent scope can match.

Quick start
-----------

.. code-block:: python

    from agents import Agent, Runner
    from raucle.scanner import Scanner
    from raucle.integrations.openai_agents import (
        input_guardrail,
        output_guardrail,
    )

    scanner = Scanner()
    agent = Agent(
        name="assistant",
        input_guardrails=[input_guardrail(scanner)],
        output_guardrails=[output_guardrail(scanner)],
    )
    await Runner.run(agent, "hello world")
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import hashlib
import inspect
import json
import logging
from collections.abc import Mapping
from typing import Any

from raucle.audit import HashChainSink, NullSink
from raucle.capability import Capability, CapabilityGate, GateDecision
from raucle.integrations._guard_core import (
    CapabilityDenied,
    declares_ctx_param,
    emit_receipt,
    evaluate_gate,
    gate_args,
)
from raucle.scanner import Scanner

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import-time check
    from agents import GuardrailFunctionOutput, InputGuardrail, OutputGuardrail

    _HAS_OPENAI_AGENTS = True
except ImportError:  # narrowed by _require_sdk() at call time
    GuardrailFunctionOutput = InputGuardrail = OutputGuardrail = None  # type: ignore[assignment]
    _HAS_OPENAI_AGENTS = False

__all__ = [
    "CapabilityDenied",
    "get_in_force_token",
    "guard_function",
    "guard_tool",
    "guard_tools",
    "has_openai_agents",
    "input_guardrail",
    "output_guardrail",
    "set_in_force_token",
]


def has_openai_agents() -> bool:
    """Whether the ``openai-agents`` package is importable."""
    return _HAS_OPENAI_AGENTS


def _require_sdk() -> None:
    if not _HAS_OPENAI_AGENTS:
        raise RuntimeError(
            "openai_agents guardrails require the 'openai-agents' package. "
            "Install with: pip install 'openai-agents'"
        )


def _receipt(
    *, stage: str, text_hash: str, verdict: str, action: str, agent_id: str
) -> dict[str, Any]:
    return {
        "kind": "guardrail_receipt",
        "agent_id": agent_id,
        "framework": "openai-agents",
        "stage": stage,
        "input_hash": text_hash,
        "verdict": verdict,
        "action": action,
    }


async def _scan_and_receipt(
    scanner: Scanner,
    sink: HashChainSink | NullSink,
    text: str,
    *,
    stage: str,
    agent_id: str,
) -> tuple[Any, bool]:
    """Scan ``text`` (raising through on scanner failure = fail-closed),
    append a receipt, and return the (ScanResult, tripwire) pair."""
    try:
        result = await asyncio.to_thread(scanner.scan, text)
    except Exception:
        # Fail-closed: an unusable guardrail must never pass traffic.
        logger.exception("raucle OpenAI-Agents guardrail scan failed (%s)", stage)
        raise
    try:
        await asyncio.to_thread(
            sink.append,
            _receipt(
                stage=stage,
                text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                verdict=result.verdict,
                action=result.action,
                agent_id=agent_id,
            ),
        )
    except Exception:
        logger.exception("failed to append raucle guardrail receipt")
        raise
    tripwire = getattr(result, "action", "ALLOW") == "BLOCK"
    return result, tripwire


def _extract_text(payload: Any) -> str:
    """The guardrail callable receives a plain string (input guardrail) or
    the agent's output object (output guardrail) — coerce both to text."""
    if isinstance(payload, str):
        return payload
    for attr in ("output", "input", "message", "text"):
        value = getattr(payload, attr, None)
        if isinstance(value, str):
            return value
    return str(payload)


def input_guardrail(
    scanner: Scanner,
    *,
    sink: HashChainSink | NullSink | None = None,
    name: str = "raucle_input_guardrail",
) -> Any:
    """Return an OpenAI Agents SDK input guardrail backed by ``scanner``.

    The returned callable has the SDK's guardrail shape
    ``(ctx, agent, input) -> GuardrailFunctionOutput``; the tripwire fires
    on any scan action of ``BLOCK``.
    """
    _require_sdk()
    assert GuardrailFunctionOutput is not None and InputGuardrail is not None  # _require_sdk
    audit_sink: HashChainSink | NullSink = sink if sink is not None else NullSink()

    async def _guardrail(ctx: Any, agent: Any, prompt: Any) -> Any:
        result, tripwire = await _scan_and_receipt(
            scanner,
            audit_sink,
            _extract_text(prompt),
            stage="input",
            agent_id=getattr(agent, "name", "") or "",
        )
        return GuardrailFunctionOutput(
            output_info={
                "verdict": result.verdict,
                "categories": list(result.categories),
                "confidence": result.confidence,
            },
            tripwire_triggered=tripwire,
        )

    _guardrail.guardrail_name = name
    # The SDK is guaranteed importable here (_require_sdk raised otherwise),
    # so the plain-callable fallback branch is dead code and is not kept.
    return InputGuardrail(guardrail_function=_guardrail, name=name, run_in_parallel=False)


def output_guardrail(
    scanner: Scanner,
    *,
    sink: HashChainSink | NullSink | None = None,
    name: str = "raucle_output_guardrail",
) -> Any:
    """Return an OpenAI Agents SDK output guardrail backed by ``scanner``.

    Identical contract to :func:`input_guardrail` but runs the scanner's
    output-side detection over the agent's final output object.
    """
    _require_sdk()
    assert GuardrailFunctionOutput is not None and OutputGuardrail is not None  # _require_sdk
    audit_sink: HashChainSink | NullSink = sink if sink is not None else NullSink()

    async def _guardrail(ctx: Any, agent: Any, output: Any) -> Any:
        result, tripwire = await _scan_and_receipt(
            scanner,
            audit_sink,
            _extract_text(output),
            stage="output",
            agent_id=getattr(agent, "name", "") or "",
        )
        return GuardrailFunctionOutput(
            output_info={
                "verdict": result.verdict,
                "categories": list(result.categories),
                "confidence": result.confidence,
            },
            tripwire_triggered=tripwire,
        )

    _guardrail.guardrail_name = name
    return OutputGuardrail(guardrail_function=_guardrail, name=name)


# --- Capability guard (P2a) -------------------------------------------------
#
# The guardrail adapters above scan content crossing into/out of the agent.
# The capability guard is the other half of raucle's doctrine for this SDK:
# a wrapping gate around TOOLS, mirroring the crewai/langgraph adapters -
# the in-force capability token decides ALLOW/DENY before the tool body
# runs, every decision lands in the signed receipt chain, and an
# unattributed call denies (bearer mode closed, the B2 doctrine).
#
# Verified span (P2a, 18 Nov 2026, CPython 3.13): probed live under
# openai-agents 0.19.1 / 0.21.0 / 0.23.1 / 0.25.0 (MIT). ``FunctionTool``
# is a plain class across the span whose constructor takes
# (name, description, params_json_schema, on_invoke_tool, ...), so an
# existing tool is rebuilt field-by-field via constructor reflection and a
# plain callable is gated first and converted with the SDK's own
# ``function_tool``. The invocation context the SDK hands to
# ``on_invoke_tool`` is its internal ``agents.tool.ToolContext`` (wrapping
# the ``RunContextWrapper``); the guard reads it duck-typed.


_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_openai_agents_in_force_token", default=None
)


def set_in_force_token(token: Capability | None) -> None:
    """Bind a capability token to the current context for guarded tools."""
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    """Read the bound token (or None)."""
    return _in_force_token.get()


def _identity_from_context(ctx: Any) -> str | None:
    """The acting identity the SDK carries, duck-typed (version-robust).

    Order: the SDK's own acting-agent surface first (``ToolContext.agent``
    -> ``name``, present across the verified span), then the deployer's run
    context (``RunContextWrapper.context``: a mapping's ``agent_id`` key or
    an object's ``agent_id`` attribute). Identities must carry the raucle
    ``agent:`` scheme to match a token's agent scope - name the Agent
    accordingly (``Agent(name="agent:billing")``) or pin ``agent_id`` at
    guard time.
    """
    agent = getattr(ctx, "agent", None)
    name = getattr(agent, "name", None)
    if isinstance(name, str) and name:
        return name
    context = getattr(ctx, "context", None)
    # The SDK's ToolContext wraps the RunContextWrapper, which wraps the
    # deployer's run context: unwrap the wrapper layers until the payload
    # is in reach (a mapping or a plain object), then read its agent_id.
    for _ in range(2):
        if isinstance(context, Mapping) or not hasattr(context, "context"):
            break
        context = context.context
    if isinstance(context, Mapping):
        candidate = context.get("agent_id")
    else:
        candidate = getattr(context, "agent_id", None)
    return candidate if isinstance(candidate, str) and candidate else None


def _decide_call(
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    tool_name: str,
    agent_id: str | None,
    ctx: Any,
    call_args: dict[str, Any],
) -> None:
    acting = agent_id or _identity_from_context(ctx)
    token = get_in_force_token()
    decision = evaluate_gate(gate, token, tool_name, call_args, acting)
    # Emission precedes enforcement: there is no path that drops a
    # decision, and a sink failure aborts an in-flight ALLOW too.
    emit_receipt(
        sink,
        framework="openai-agents",
        token=token,
        agent_id=acting,
        tool=tool_name,
        args=call_args,
        decision=decision,
    )
    if not decision.allowed:
        raise CapabilityDenied(tool_name, decision.reason or "denied")


def _parse_tool_arguments(arguments: str) -> dict[str, Any]:
    """Parse the wire args the SDK hands ``on_invoke_tool``.

    Fail-closed: arguments that do not parse into an object cannot be
    constraint-checked, so the caller denies (receipted) rather than
    guessing what the model meant.
    """
    parsed = json.loads(arguments)
    return dict(parsed) if isinstance(parsed, Mapping) else {}


def guard_function(
    fn: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> Any:
    """Wrap a tool FUNCTION (sync or async) with the gate, signature kept.

    Returns a ``functools.wraps``-preserved callable the SDK's
    ``function_tool`` converts identically to the original (the schema is
    derived from the signature, which follows ``__wrapped__``). The
    resolved acting identity is the pinned ``agent_id``, else the run
    context the SDK passes at call time; a call with neither denies.
    """
    if not _HAS_OPENAI_AGENTS:
        raise RuntimeError(
            "guard_function requires the 'openai-agents' package. "
            "Install with: pip install 'openai-agents'"
        )
    tool_name = getattr(fn, "__name__", None) or "<unknown>"
    needs_ctx = declares_ctx_param(fn, "RunContextWrapper")

    def _decide(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        ctx = args[0] if needs_ctx and args and hasattr(args[0], "context") else None
        call_args = gate_args(args, kwargs, needs_ctx)
        _decide_call(
            gate=gate,
            sink=sink,
            tool_name=tool_name,
            agent_id=agent_id,
            ctx=ctx,
            call_args=call_args,
        )

    @functools.wraps(fn)
    def gated_sync(*args: Any, **kwargs: Any) -> Any:
        _decide(args, kwargs)
        # A deny raised inside _decide; only an ALLOW reaches the delegate.
        return fn(*args, **kwargs)

    @functools.wraps(fn)
    async def gated_async(*args: Any, **kwargs: Any) -> Any:
        _decide(args, kwargs)
        return await fn(*args, **kwargs)

    return gated_async if inspect.iscoroutinefunction(fn) else gated_sync


def _rebuild_function_tool(tool: Any, gated_invoke: Any) -> Any:
    """Rebuild a ``FunctionTool`` around the gated invoke, field-by-field.

    ``FunctionTool`` is a plain class across the verified span (not a
    pydantic model, so no ``model_copy``); its constructor takes
    ``(name, description, params_json_schema, on_invoke_tool, ...)`` with
    version-varying optional fields. Every constructor parameter the
    installed version accepts is copied from the original instance where
    the instance exposes it, so decoration options (strict mode, failure
    handlers, timeouts) survive the rebuild; the schema is carried over
    verbatim, never re-derived.
    """
    from agents import FunctionTool

    params = list(inspect.signature(FunctionTool.__init__).parameters.values())[1:]
    carried: dict[str, Any] = {}
    for param in params:
        if param.name in {"name", "description", "params_json_schema", "on_invoke_tool"}:
            continue
        if hasattr(tool, param.name):
            carried[param.name] = getattr(tool, param.name)
    return FunctionTool(
        name=tool.name,
        description=tool.description,
        params_json_schema=tool.params_json_schema,
        on_invoke_tool=gated_invoke,
        **carried,
    )


def guard_tool(
    tool: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> Any:
    """Wrap an OpenAI Agents SDK tool so every call is gated and receipted.

    ``tool`` may be:

    * a ``FunctionTool`` (e.g. ``@function_tool``-decorated) - a new
      ``FunctionTool`` is returned with the same ``name`` / ``description``
      / ``params_json_schema`` (and every decoration option the installed
      version carries) whose ``on_invoke_tool`` gates the call and only
      then delegates to the original;
    * a plain sync or async function - the gated function is converted with
      the SDK's own ``function_tool``, so the schema the model sees is
      identical to undecorated registration.

    The gate runs BEFORE any tool interaction: a denied call raises
    :class:`CapabilityDenied` and the tool body never executes. The acting
    identity resolves as the pinned ``agent_id``, else the SDK's
    invocation context; a call with neither denies and the deny receipt
    carries an honest null ``agent_id`` (never a placeholder).
    """
    _require_sdk()
    from agents import FunctionTool, function_tool

    if isinstance(tool, FunctionTool):
        tool_name = tool.name
        original_invoke = tool.on_invoke_tool

        async def gated_invoke(ctx: Any, arguments: str) -> Any:
            try:
                call_args = _parse_tool_arguments(arguments)
                unparseable = False
            except (json.JSONDecodeError, TypeError):
                call_args = {}
                unparseable = True
            if unparseable:
                decision = GateDecision(
                    allowed=False, reason="tool arguments not parseable as JSON object"
                )
                emit_receipt(
                    sink,
                    framework="openai-agents",
                    token=get_in_force_token(),
                    agent_id=agent_id or _identity_from_context(ctx),
                    tool=tool_name,
                    args={},
                    decision=decision,
                )
                raise CapabilityDenied(tool_name, decision.reason)
            _decide_call(
                gate=gate,
                sink=sink,
                tool_name=tool_name,
                agent_id=agent_id,
                ctx=ctx,
                call_args=call_args,
            )
            return await original_invoke(ctx, arguments)

        return _rebuild_function_tool(tool, gated_invoke)

    if callable(tool):
        return function_tool(guard_function(tool, gate=gate, sink=sink, agent_id=agent_id))

    raise ValueError(
        f"raucle: cannot gate {tool!r} (expected a FunctionTool or a plain "
        f"callable - an ungated tool call would bypass the gate and its receipt)"
    )


def guard_tools(
    tools: list[Any],
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> list[Any]:
    """Wrap a list of OpenAI Agents SDK tools with :func:`guard_tool`."""
    return [guard_tool(t, gate=gate, sink=sink, agent_id=agent_id) for t in tools]
