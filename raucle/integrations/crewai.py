"""raucle integration for CrewAI (``crewai`` >= 1.0).

CrewAI tools are ``crewai.tools.BaseTool`` subclasses whose ``run(**kwargs)``
calls ``_run`` directly — there is no callback layer that swallows exceptions
(unlike langchain-core). So the clean, fail-closed integration is a **wrapping
tool**: :func:`guard_tool` returns a ``BaseTool`` that gates the call against
the in-force capability token, emits a signed receipt for the ALLOW/DENY
decision, and only then delegates to the wrapped tool's ``_run``. A denied
call raises :class:`CapabilityDenied`, which CrewAI surfaces back to the agent
— the tool body never executes.

Quick start
-----------

.. code-block:: python

    from crewai import Agent, Task, Crew
    from crewai.tools import BaseTool

    from raucle.audit import Ed25519Signer, HashChainSink
    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.integrations.crewai import guard_tools, set_in_force_token

    issuer = CapabilityIssuer.generate(issuer="acme.platform")
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())

    raw_tools = [TransferFundsTool(), LookupCustomerTool()]
    # agent_id binds the acting identity the gate holds the call against;
    # an unattributed call denies (bearer mode is closed, B2 doctrine)
    tools = guard_tools(raw_tools, gate=gate, sink=sink, agent_id="agent:billing")

    # Per session: bind the token scoped to what THIS task may do.
    set_in_force_token(issuer.mint(
        agent_id="agent:billing", tool="transfer_funds",
        constraints={"max_value": {"amount": 100}}, ttl_seconds=60,
    ))

    agent = Agent(role="biller", goal="...", tools=tools, ...)
    Crew(agents=[agent], tasks=[Task(...)]).kickoff()

Every tool call the crew makes now passes the raucle gate before it runs; the
decision is recorded in the signed receipt chain (verify offline with
``raucle audit verify``). The gate never reads the agent's reasoning, so
a prompt-injected call is denied on the same path as a legitimate one.

Install with ``pip install 'raucle[crewai]'``.
"""

from __future__ import annotations

import contextvars
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

#: Receipts bind the argument view the gate evaluated: "normalised" when the
#: invocation was bound against the wrapped tool's signature, "verbatim" when
#: no usable signature resolved and the caller-shaped view rides instead.
ARGS_BINDING_NORMALISED = "normalised"
ARGS_BINDING_VERBATIM = "verbatim"

try:  # pragma: no cover - import-time check
    from crewai.tools import BaseTool  # type: ignore[import-not-found]

    _HAS_CREWAI = True
except ImportError:  # pragma: no cover
    BaseTool = object  # type: ignore[assignment,misc]
    _HAS_CREWAI = False


class CapabilityDenied(Exception):
    """Raised by a guarded tool when the gate denies the call.

    CrewAI surfaces the exception to the agent's reasoning loop; the denial
    receipt is emitted *before* the raise, so there is no path that drops a
    decision.
    """

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"raucle denied {tool!r}: {reason}")
        self.tool = tool
        self.reason = reason


# --- In-force token resolution (shared contextvar pattern) -----------------

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_crewai_in_force_token", default=None
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


def _verbatim_call_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """The caller-shaped argument view used when no signature can bind.

    Positionals fold in by index so the gate sees every argument the
    executor will receive (the old ``dict(kwargs)`` view dropped them
    silently); the residual is marked ``verbatim`` in the receipt and
    logged.
    """
    combined: dict[str, Any] = {str(i): value for i, value in enumerate(args)}
    combined.update(kwargs)
    return combined


def _normalise_call_args(
    exec_target: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
) -> tuple[dict[str, Any], str]:
    """Bind the invocation against the executor's signature.

    The gate evaluation, the receipt digest and the executed arguments must
    carry the SAME semantic arguments (H(arguments_gate) ==
    H(arguments_executor)): binding against ``exec_target``'s signature -
    the implementation the call forwards to - maps positionals onto real
    parameter names and applies defaults, so a positional call cannot slip
    past the gate's argument view while executing with arguments the gate
    never saw.

    Variadic captures are spread back into the view: var-keyword members
    carry their actual caller names (name-keyed constraints must still see
    them - a tool declared ``**kwargs`` would otherwise fold its real field
    names under the parameter name and the constraints would pass
    vacuously), and var-positional members fold in by index. Falls back to
    the caller-shaped verbatim view ONLY when no signature can be resolved
    or the invocation cannot be bound; the residual is marked ``verbatim``
    in the receipt and logged with the tool name.
    """
    try:
        signature = inspect.signature(exec_target)
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
    except (TypeError, ValueError) as exc:
        logger.warning(
            "raucle crewai: unnormalised arguments for %s (no usable signature: %s); "
            "the receipt carries the verbatim residual",
            tool_name,
            exc,
        )
        return _verbatim_call_args(args, kwargs), ARGS_BINDING_VERBATIM
    view: dict[str, Any] = {}
    positional_index = 0
    for name, value in bound.arguments.items():
        param = signature.parameters[name]
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            for member in value:  # type: ignore[union-attr]
                view[str(positional_index)] = member
                positional_index += 1
        elif param.kind is inspect.Parameter.VAR_KEYWORD:
            view.update(value or {})  # type: ignore[arg-type]
        else:
            view[name] = value
    return view, ARGS_BINDING_NORMALISED


def _emit_receipt(
    sink: HashChainSink | NullSink,
    *,
    token: Capability | None,
    agent_id: str | None,
    tool: str,
    args: dict[str, Any],
    decision: GateDecision,
    args_binding: str,
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
        # Whether the digest binds the signature-bound argument view
        # ("normalised") or the honest caller-shaped residual ("verbatim").
        "args_binding": args_binding,
        "framework": "crewai",
    }
    try:
        sink.append(receipt)
    except Exception:
        # The sink's own fail-loud contract (require_receipts) propagates; a
        # plain logging sink must not take down the crew.
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

    B2 attribution doctrine: bearer mode is closed. The B2 audit (v0.23.3)
    recorded this leg as shipped, but the crewai.py change was lost in
    transit and no CI job installed the extra, so the red test hid behind
    importorskip until the D1 regression hunt reproduced it under crewai
    1.6.1 (and then 1.0.0 / 1.5.0 / 1.15.41 - the gap was never
    version-specific). A call with no bound caller identity cannot be
    checked against the token's agent scope, so it denies rather than
    running attributed to a placeholder receipt.
    """
    if token is None:
        return GateDecision(allowed=False, reason="no in-force capability token")
    if not agent_id:
        return GateDecision(
            allowed=False, reason="no acting agent identity (no caller agent_id bound)"
        )
    return gate.check(token=token, tool=tool_name, args=call_args, agent_id=agent_id)


def guard_tool(
    tool: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> Any:
    """Wrap a CrewAI ``BaseTool`` so every call is gated and receipted.

    Returns a new ``BaseTool`` with the same ``name``/``description``/
    ``args_schema`` (so the agent sees an identical tool) whose ``_run``:

    1. resolves the in-force capability token,
    2. asks the gate to ALLOW/DENY the call with these arguments,
    3. emits a signed receipt for the decision,
    4. delegates to the wrapped tool on ALLOW, or raises
       :class:`CapabilityDenied` on DENY (or when no token is bound, or
       when no caller identity is bound).

    ``agent_id`` pins the caller identity the gate checks the token's
    agent scope against. Bearer mode is closed (the B2 attribution
    doctrine): a call with no bound identity cannot be attributed, so it
    denies with the decision receipted - the guard never runs a call it
    cannot attribute, and the deny receipt carries an honest null
    ``agent_id`` rather than a placeholder.

    The invocation is bound against the wrapped tool's implementation
    signature (``inspect.signature(...).bind(...)``, defaults applied)
    before the gate evaluates it: positionals land on real parameter
    names, so the gate evaluation, the receipt digest and the executed
    arguments carry the same semantic arguments. When no signature can be
    resolved the call falls back to the caller-shaped verbatim view, and
    the receipt records the residual (``args_binding: "verbatim"``) plus a
    log line naming the tool.
    """
    if not _HAS_CREWAI:
        raise RuntimeError("guard_tool requires crewai. Install with: pip install 'raucle[crewai]'")

    wrapped = tool
    tool_name = getattr(tool, "name", None) or "<unknown>"
    # CrewAI 1.x BaseTool has no ``arun``/``_arun`` surface at all (sync
    # ``run`` -> ``_run`` only), so detect an async impl from the wrapped
    # tool's own class definition rather than comparing against a stub.
    wrapped_arun = type(wrapped).__dict__.get("_arun")

    class _GuardedTool(BaseTool):  # type: ignore[misc,valid-type]
        name: str = wrapped.name
        description: str = wrapped.description
        args_schema: type = wrapped.args_schema

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            # Gate on the SIGNATURE-BOUND argument view: positionals bind to
            # the wrapped tool's real parameter names (defaults applied), so
            # the gate evaluation, the receipt digest and the executed
            # arguments carry the same semantic arguments.
            call_args, args_binding = _normalise_call_args(wrapped._run, args, kwargs, tool_name)
            token = get_in_force_token()
            decision = _evaluate_gate(gate, token, tool_name, call_args, agent_id)
            _emit_receipt(
                sink,
                token=token,
                agent_id=agent_id,
                tool=tool_name,
                args=call_args,
                decision=decision,
                args_binding=args_binding,
            )

            if not decision.allowed:
                raise CapabilityDenied(tool_name, decision.reason or "denied")

            # Delegate to the original tool's implementation.
            return wrapped._run(*args, **kwargs)

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            # Gate synchronously (the decision is CPU-bound), then await the
            # wrapped async impl if it has one. The binding target matches
            # the implementation the call forwards to.
            exec_target = wrapped._arun if wrapped_arun is not None else wrapped._run
            call_args, args_binding = _normalise_call_args(exec_target, args, kwargs, tool_name)
            token = get_in_force_token()
            decision = _evaluate_gate(gate, token, tool_name, call_args, agent_id)
            _emit_receipt(
                sink,
                token=token,
                agent_id=agent_id,
                tool=tool_name,
                args=call_args,
                decision=decision,
                args_binding=args_binding,
            )
            if not decision.allowed:
                raise CapabilityDenied(tool_name, decision.reason or "denied")
            # Use the wrapped tool's own async impl if it defines one;
            # otherwise fall back to the sync impl.
            if wrapped_arun is not None:
                return await wrapped._arun(*args, **kwargs)
            return wrapped._run(*args, **kwargs)

        async def arun(self, *args: Any, **kwargs: Any) -> Any:
            """Async entry point guarded tools expose exposes to async consumers.

            CrewAI 1.x's ``BaseTool`` itself has no ``arun``; users driving
            tools from asyncio code call ``await guarded.arun(...)`` so the
            gate runs inside *their* event loop instead of behind
            ``asyncio.run`` in ``BaseTool.run``.
            """
            return await self._arun(*args, **kwargs)

    return _GuardedTool()


def guard_tools(
    tools: list[Any],
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str | None = None,
) -> list[Any]:
    """Wrap a list of CrewAI tools with :func:`guard_tool` (convenience)."""
    return [guard_tool(t, gate=gate, sink=sink, agent_id=agent_id) for t in tools]


__all__ = [
    "CapabilityDenied",
    "guard_tool",
    "guard_tools",
    "set_in_force_token",
    "get_in_force_token",
]
