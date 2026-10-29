"""raucle integration for LangChain (``langchain-core`` ≥ 0.3).

Provides a ``BaseCallbackHandler`` that intercepts every tool invocation
in a LangChain ``AgentExecutor`` / ``Runnable`` graph, gates it against
the in-force capability token, and emits a signed capability receipt
for both ALLOW and DENY decisions.

Quick start
-----------

.. code-block:: python

    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_openai import ChatOpenAI
    from langchain_core.tools import tool

    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.audit import HashChainSink, Ed25519Signer
    from raucle.integrations.langchain import (
        RaucleCallbackHandler,
        set_in_force_token,
    )

    issuer = CapabilityIssuer(...)
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("./receipts.log", signer=Ed25519Signer.generate())
    handler = RaucleCallbackHandler(gate=gate, sink=sink)

    @tool
    def lookup_customer(customer_id: str) -> dict: ...

    agent = create_tool_calling_agent(ChatOpenAI(), [lookup_customer], prompt=...)
    executor = AgentExecutor(agent=agent, tools=[lookup_customer], callbacks=[handler])

    # Per-session: bind the token before invoking the agent.
    token = issuer.mint(
        agent_id="agent-1",
        tool="lookup_customer",
        constraints={"customer_id": "12345"},
        ttl_seconds=60,
    )
    set_in_force_token(token)
    result = executor.invoke({"input": "What's the email for customer 12345?"})

Availability note
-----------------

The handler runs with ``raise_error=True`` (load-bearing — without it
langchain-core swallows the deny and the tool runs anyway). A consequence:
if the receipt sink itself fails, the call is aborted even when the gate
would ALLOW it. That is deliberate fail-closed accountability — an action
without its receipt is treated as unauthorised — but it means an audit-sink
outage halts tool traffic. Point the sink at storage with the same
availability budget as the agent.

Denial behaviour
----------------

When the in-force token's gate rejects a tool call, the handler raises a
``CapabilityDenied`` exception from ``on_tool_start``. LangChain
surfaces that exception back to the agent's reasoning loop, which can
choose to ask the user, mint a new token, or fail. Either way the
denial is recorded in the signed receipt chain — there is no path
through this handler that drops a decision.

Limitations
-----------

* Streaming tool outputs aren't introspected; the receipt records the
  call decision, not the output stream.
* If a tool is invoked outside the executor (raw ``tool.invoke(...)``),
  this handler isn't on the path. Use the
  ``raucle_capability_required`` decorator from ``raucle.capability``
  for that case.

Install with ``pip install 'raucle[langchain]'``.
"""

from __future__ import annotations

import contextvars
import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

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


# --- Lazy host-framework import --------------------------------------------

try:  # pragma: no cover - import-time check
    from langchain_core.callbacks import (  # type: ignore[import-not-found]
        BaseCallbackHandler,
    )

    _HAS_LANGCHAIN = True
except ImportError:  # pragma: no cover

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Stub when langchain-core is missing — instantiation will raise."""

    _HAS_LANGCHAIN = False


class CapabilityDenied(Exception):
    """Raised inside ``on_tool_start`` when the gate denies a call.

    The agent executor surfaces this back to the LLM reasoning loop;
    receipts of the denial are emitted before the raise.
    """

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"raucle denied {tool!r}: {reason}")
        self.tool = tool
        self.reason = reason


# --- In-force token resolution ---------------------------------------------

TokenResolver = Callable[[dict[str, Any]], Capability | None]

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_langchain_in_force_token", default=None
)


def set_in_force_token(token: Capability | None) -> None:
    """Bind a capability token to the current (a)sync context."""
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    """Read the bound token (or None)."""
    return _in_force_token.get()


def _default_resolver(_serialized: dict[str, Any]) -> Capability | None:
    return get_in_force_token()


# --- Internal helpers (mirror agent_framework.py) --------------------------


def _blacklist_on_named_field(token: Capability) -> bool:
    """True if the token carries a blacklist constraint keyed on a field other
    than ``input``.

    Blacklist kinds (``forbidden_values``, ``forbidden_field_combinations``)
    fail OPEN when the named field is absent from the call. When a LangChain
    tool passes an opaque string we can only present it as ``{"input": ...}``,
    so such a blacklist would pass vacuously. The caller fails closed in that
    case. Positive constraints (allowed_values/starts_with/bounds) fail closed
    on the wrapped args already, so they are not consulted here.
    """
    c = getattr(token, "constraints", None) or {}
    if any(fld != "input" for fld in (c.get("forbidden_values") or {})):
        return True
    for combo in c.get("forbidden_field_combinations") or []:
        if any(fld != "input" for fld in combo):
            return True
    return False


def _hash_args(args: Any) -> str:
    if isinstance(args, str):
        # LangChain often hands tool input as a string; canonicalise to
        # {"input": "..."} for consistent hashing.
        return "sha256:" + _sha256_hex(_canonical_json({"input": args}))
    if not isinstance(args, dict):
        try:
            args = dict(args)
        except (TypeError, ValueError):
            args = {"_raw": repr(args)}
    return "sha256:" + _sha256_hex(_canonical_json(args))


def _iso_now() -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + (
        f".{int((time.time() % 1) * 1000):03d}Z"
    )


# --- The callback handler --------------------------------------------------


class RaucleCallbackHandler(BaseCallbackHandler):
    """LangChain ``BaseCallbackHandler`` enforcing capability tokens.

    Parameters
    ----------
    gate
        The capability gate that holds the trusted-issuer keys and
        applies attenuation / scope checks.
    sink
        A ``HashChainSink`` (or ``NullSink`` for tests) the handler
        appends signed receipts to. One receipt per tool invocation.
    token_resolver
        Override the default ``ContextVar``-based lookup. Useful for
        per-tenant lookups in shared agents.
    raise_on_deny
        When True (default), raise ``CapabilityDenied`` if the gate
        denies a call — LangChain surfaces this to the agent. When
        False, silently log + emit a deny receipt and let the tool run
        (only useful for shadow-mode rollouts).
    """

    def __init__(
        self,
        *,
        gate: CapabilityGate,
        sink: HashChainSink | NullSink,
        token_resolver: TokenResolver | None = None,
        raise_on_deny: bool = True,
        lean_theorem_id: str = "vcd.gate_soundness",
        require_agent_id: bool = True,
    ) -> None:
        if not _HAS_LANGCHAIN:
            raise RuntimeError(
                "RaucleCallbackHandler requires langchain-core. "
                "Install with: pip install 'raucle[langchain]'"
            )
        super().__init__()
        # SECURITY — load-bearing, do not remove. langchain-core's callback
        # manager catches handler exceptions and logs them as warnings unless
        # the handler sets ``raise_error``. With the default (False), the
        # CapabilityDenied raised by on_tool_start is swallowed and the tool
        # RUNS ANYWAY — the gate becomes advisory, a fail-open. raise_error
        # makes the deny actually block the call. run_inline keeps the
        # handler on the calling thread so the exception propagates to the
        # tool invocation rather than a worker.
        self.raise_error = True
        self.run_inline = True
        self.gate = gate
        self.sink = sink
        self._resolver = token_resolver or _default_resolver
        self._raise_on_deny = raise_on_deny
        self._lean_theorem_id = lean_theorem_id
        # B2: default True - deny when no independent caller agent_id is
        # available in the call metadata. An unattributed execution mints no
        # placeholder identity; the attempt is denied with the reason
        # recorded (the same fail-closed doctrine as the gateway, v0.23.2).
        # Opt out explicitly with require_agent_id=False to restore the
        # legacy bearer-mode trust.
        self._require_agent_id = require_agent_id

    # LangChain calls this BEFORE the tool executes. Raising blocks the call.
    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = (serialized or {}).get("name") or "<unknown>"
        # LC ≥0.3 passes structured args via `inputs`; fall back to input_str.
        call_args: Any = inputs if inputs is not None else input_str

        token = self._resolver(serialized or {})
        # B2: no placeholder identities in minted receipts - the acting
        # agent id is the bound one or the attempt denies (receipt carries
        # an honest null).
        bound_agent_id = (metadata or {}).get("agent_id")
        agent_id = bound_agent_id

        decision = self._make_decision(token, tool_name, call_args, bound_agent_id)

        self._emit_receipt(
            token=token,
            agent_id=agent_id,
            tool=tool_name,
            args=call_args,
            decision=decision,
        )

        if not decision.allowed and self._raise_on_deny:
            raise CapabilityDenied(tool_name, decision.reason or "denied")

    def _make_decision(
        self,
        token: Any,
        tool_name: str,
        call_args: Any,
        bound_agent_id: str | None,
    ) -> GateDecision:
        """Build the gate decision for an incoming tool call."""
        if token is None:
            return GateDecision(allowed=False, reason="no in-force capability token")

        if self._require_agent_id and bound_agent_id is None:
            # Strict mode: no independent caller identity means the token's agent
            # scope cannot be enforced against the caller — fail closed rather
            # than fall back to trusting the token holder (round-3 run-2 #F2).
            return GateDecision(
                allowed=False,
                reason="require_agent_id is set but no caller agent_id in metadata",
            )

        if not isinstance(call_args, dict) and _blacklist_on_named_field(token):
            # Opaque string tool input: we cannot map it to the constrained
            # field names, so wrapping it as {"input": ...} would make a
            # forbidden_values / forbidden_field_combinations blacklist pass
            # vacuously (round-3b #5 — blacklists fail OPEN here). Fail closed
            # instead. Positive constraints (allowed_values/starts_with/bounds)
            # already fail closed on the wrapped args, so they need no guard.
            return GateDecision(
                allowed=False,
                reason=(
                    "cannot enforce a blacklist constraint on an opaque string "
                    "tool input via this adapter; use a structured-args tool or "
                    "an allowed_values whitelist for the security-critical field"
                ),
            )

        check_args = call_args if isinstance(call_args, dict) else {"input": call_args}
        # Pass the caller's agent_id so the gate enforces the token's agent
        # scope (previously the LangChain path left tokens effectively
        # unbound — the agent_id was only recorded in the receipt).
        return self.gate.check(
            token=token, tool=tool_name, args=check_args, agent_id=bound_agent_id
        )

    # We don't need on_tool_end / on_tool_error for receipts — the
    # decision was logged at start. LangChain calls them anyway; the
    # base class no-ops are fine.

    # --- Receipt emission -----------------------------------------------

    def _emit_receipt(
        self,
        *,
        token: Capability | None,
        agent_id: str,
        tool: str,
        args: Any,
        decision: GateDecision,
    ) -> None:
        receipt = {
            "issuer": token.issuer if token else "",
            # We carry the issuer's pinned key id rather than the raw PEM
            # in the receipt; verifiers look up the PEM from the issuer
            # registry at audit time.
            "issuer_pubkey": token.key_id if token else "<unknown>",
            "schema_hash": None,
            "policy_proof_hash": token.policy_proof_hash if token else None,
            "lean_theorem_id": self._lean_theorem_id,
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
            self.sink.append(receipt)
        except Exception:
            # A sink failure must not silently mask a denial; re-raise.
            logger.exception("raucle: receipt sink failure for tool=%s", tool)
            raise


__all__ = [
    "RaucleCallbackHandler",
    "CapabilityDenied",
    "TokenResolver",
    "set_in_force_token",
    "get_in_force_token",
]
