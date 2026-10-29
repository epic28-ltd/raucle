"""raucle integration for AutoGen (``autogen-agentchat`` ≥ 0.4).

AutoGen 0.4's ``AssistantAgent`` calls tools via a ``ToolRunner`` /
``FunctionTool.run`` flow. We wrap a list of tools with
:func:`gated_tools` — each returned ``FunctionTool`` checks the
in-force capability token before delegating to the original handler
and emits a signed receipt either way.

Quick start
-----------

.. code-block:: python

    from autogen_agentchat.agents import AssistantAgent
    from autogen_core.tools import FunctionTool

    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.audit import HashChainSink, Ed25519Signer
    from raucle.integrations.autogen import (
        gated_tools,
        set_in_force_token,
        CapabilityDenied,
    )

    issuer = CapabilityIssuer(...)
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("./receipts.log", signer=Ed25519Signer.generate())

    async def lookup_customer(customer_id: str) -> dict: ...

    raw_tool = FunctionTool(lookup_customer, description="Look up a customer.")
    gated   = gated_tools([raw_tool], gate=gate, sink=sink, agent_id="agent-1")

    agent = AssistantAgent("assistant", model_client=..., tools=gated)

    token = issuer.mint(agent_id="agent-1", tool="lookup_customer",
                        constraints={"customer_id": "12345"}, ttl_seconds=60)
    set_in_force_token(token)
    await agent.run(task="Get email for customer 12345")

Denial behaviour
----------------

A denial raises :class:`CapabilityDenied` from the gated tool's
``run`` method, which AutoGen surfaces as a tool-failure event to the
model. The model can re-plan or escalate; the receipt chain has
already captured the decision.

Install with ``pip install 'raucle[autogen]'``.
"""

from __future__ import annotations

import contextvars
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


try:  # pragma: no cover
    from autogen_core.tools import FunctionTool  # type: ignore[import-not-found]

    _HAS_AUTOGEN = True
except ImportError:  # pragma: no cover

    class FunctionTool:  # type: ignore[no-redef]
        """Stub when autogen-core is missing."""

    _HAS_AUTOGEN = False


class CapabilityDenied(Exception):
    """Raised when the in-force token denies a tool call."""

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"raucle denied {tool!r}: {reason}")
        self.tool = tool
        self.reason = reason


# --- In-force token resolution ---------------------------------------------

TokenResolver = Callable[[str], Capability | None]

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_autogen_in_force_token", default=None
)


def set_in_force_token(token: Capability | None) -> None:
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    return _in_force_token.get()


def _default_resolver(_tool_name: str) -> Capability | None:
    return get_in_force_token()


def _hash_args(args: dict[str, Any]) -> str:
    return "sha256:" + _sha256_hex(_canonical_json(args))


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
    args: dict[str, Any],
    decision: GateDecision,
    lean_theorem_id: str,
) -> None:
    receipt = {
        "issuer": token.issuer if token else "",
        "issuer_pubkey": token.key_id if token else "<unknown>",
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
        "timestamp": _iso_now(),
    }
    try:
        sink.append(receipt)
    except Exception:
        logger.exception("raucle: receipt sink failure for tool=%s", tool)
        raise


def gated_tools(
    tools: Iterable[Any],
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str,
    token_resolver: TokenResolver | None = None,
    raise_on_deny: bool = True,
    lean_theorem_id: str = "vcd.gate_soundness",
    allow_ungated: bool = False,
) -> list[Any]:
    """Wrap a list of AutoGen tools with capability-gating + receipts.

    Each wrapped tool runs the gate ``check`` against the in-force token
    before invoking the underlying handler and emits one signed receipt
    per call regardless of allow / deny.

    The original tools are not mutated; a new list of wrapped tools is
    returned. Tools that are not ``FunctionTool`` instances are passed
    through unchanged with a warning logged.
    """
    if not _HAS_AUTOGEN:
        raise RuntimeError(
            "gated_tools requires autogen-core. Install with: pip install 'raucle[autogen]'"
        )

    resolver = token_resolver or _default_resolver
    out: list[Any] = []
    for t in tools:
        if not isinstance(t, FunctionTool):
            # Fail closed by default: an ungated tool is a hole in "every tool
            # call passes the gate". Only pass it through if the deployer opts
            # in (migration / shadow mode).
            if not allow_ungated:
                raise ValueError(
                    f"raucle: cannot gate {t!r} (not a FunctionTool). Pass "
                    f"allow_ungated=True to pass unsupported tools through ungated "
                    f"(NOT recommended — those tool calls bypass the gate)."
                )
            logger.warning("raucle: %r is not a FunctionTool; passing through UNGATED", t)
            out.append(t)
            continue
        out.append(
            _wrap_function_tool(
                t,
                gate=gate,
                sink=sink,
                agent_id=agent_id,
                resolver=resolver,
                raise_on_deny=raise_on_deny,
                lean_theorem_id=lean_theorem_id,
                allow_ungated=allow_ungated,
            )
        )
    return out


def _wrap_function_tool(
    inner: Any,
    *,
    gate: CapabilityGate,
    sink: HashChainSink | NullSink,
    agent_id: str,
    resolver: TokenResolver,
    raise_on_deny: bool,
    lean_theorem_id: str,
    allow_ungated: bool = False,
) -> Any:
    """Return a FunctionTool whose handler runs the gate first.

    Implemented by wrapping the original Python callable rather than
    subclassing FunctionTool, so we stay compatible across point
    releases of autogen-core.
    """
    original_func = getattr(inner, "_func", None) or getattr(inner, "func", None)
    if original_func is None:
        # A FunctionTool-typed object whose inner callable we cannot find is a
        # tool we cannot gate — fail closed by default (round-5 F4). Passing it
        # through ungated would be a hole in "every tool call passes the gate".
        if not allow_ungated:
            raise ValueError(
                f"raucle: cannot find inner callable on {inner!r}; refusing to pass it "
                f"through ungated. Pass allow_ungated=True to override (NOT recommended)."
            )
        logger.warning("raucle: cannot find inner callable on %r; passing through UNGATED", inner)
        return inner

    tool_name = getattr(inner, "name", None) or original_func.__name__
    description = getattr(inner, "description", "") or original_func.__doc__ or ""

    async def gated(**kwargs: Any) -> Any:
        token = resolver(tool_name)
        # B2: an empty agent_id is not an identity - deny rather than mint
        # a receipt attributed to "" (fail-closed attribution, same doctrine
        # as the gateway, v0.23.2).
        if not agent_id:
            decision = GateDecision(
                allowed=False, reason="no acting agent identity (agent_id empty)"
            )
        else:
            decision = _evaluate_gate(gate, token, tool_name, kwargs, agent_id)

        _emit_receipt(
            sink,
            token=token,
            agent_id=agent_id,
            tool=tool_name,
            args=kwargs,
            decision=decision,
            lean_theorem_id=lean_theorem_id,
        )

        _enforce_decision(decision, tool_name, raise_on_deny)

        # Delegate. Preserve sync vs async semantics.
        import inspect

        if inspect.iscoroutinefunction(original_func):
            return await original_func(**kwargs)
        return original_func(**kwargs)

    # B2 fix: preserve the original callable's signature (via __wrapped__)
    # so autogen's FunctionTool builds the args model from the REAL tool
    # signature - the bare **kwargs closure made every structured-arg call
    # fail validation ("kwargs: Field required").
    import functools

    functools.wraps(original_func)(gated)

    return FunctionTool(gated, description=description, name=tool_name)


def _evaluate_gate(
    gate: CapabilityGate,
    token: Any,
    tool_name: str,
    kwargs: dict[str, Any],
    agent_id: str,
) -> GateDecision:
    """Evaluate the capability gate, or deny when no token is in force."""
    if token is None:
        return GateDecision(allowed=False, reason="no in-force capability token")
    # Pass agent_id so the gate enforces the token's agent scope.
    # Without it the gate skips the descendant check entirely, so a
    # token minted for agent A would authorize a call stamped agent B
    # (round-3 #2). The other adapters all forward agent_id.
    return gate.check(token=token, tool=tool_name, args=kwargs, agent_id=agent_id)


def _enforce_decision(decision: GateDecision, tool_name: str, raise_on_deny: bool) -> None:
    """Raise or warn based on the gate decision."""
    if decision.allowed:
        return
    if raise_on_deny:
        raise CapabilityDenied(tool_name, decision.reason or "denied")
    # shadow-mode: warn but proceed
    logger.warning(
        "raucle shadow-mode: %s denied (%s) but call proceeding",
        tool_name,
        decision.reason,
    )


__all__ = [
    "gated_tools",
    "CapabilityDenied",
    "TokenResolver",
    "set_in_force_token",
    "get_in_force_token",
]
