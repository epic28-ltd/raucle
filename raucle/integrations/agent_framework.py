"""raucle middleware for the Microsoft Agent Framework (≥ 1.0, GA 2026-04-03).

Drop-in ``FunctionMiddleware`` that produces a signed capability receipt for
every tool call an Agent Framework agent makes. See the design proposal at
``docs/proposals/agent-framework-middleware.md`` for the full rationale,
threat-model deltas, and milestone plan.

Quick start
-----------

.. code-block:: python

    from agent_framework import ChatAgent
    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.audit import HashChainSink, Ed25519Signer
    from raucle.integrations.agent_framework import (
        RaucleFunctionMiddleware,
        set_in_force_token,
    )

    issuer = CapabilityIssuer(...)
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("./receipts.log", signer=Ed25519Signer.generate())

    agent = ChatAgent(chat_client=..., tools=[...])
    agent.middleware.add(RaucleFunctionMiddleware(gate=gate, sink=sink))

    # Per-session token wiring — call this when a session opens
    token = issuer.mint(agent_id="agent-1", tool="...", constraints={...}, ttl_seconds=60)
    set_in_force_token(token)

The middleware short-circuits any tool call whose arguments fail the in-force
token's gate check, emitting a signed denial receipt either way.

Status
------

This module is a **working skeleton** as of raucle v0.11.0a. The
public surface (the ``RaucleFunctionMiddleware`` class, the ``TokenResolver``
typedef, and the ``set_in_force_token`` / ``get_in_force_token`` helpers) is
intended to be stable. Remaining known limitations are tracked as M4 in the
design proposal: streaming-response receipts and downstream-middleware result
mutation. Pull requests welcome.

Strict modes (house convention, opt-in via environment)
-------------------------------------------------------

- ``RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1``: durable-receipt mode. The
  receipt for a call is persisted BEFORE the downstream call starts; a
  sink failure refuses the call through the adapter's middleware
  termination refusal (the receipt must be durably persisted or the
  downstream call does not start). The default stays advisory (a sink
  failure is caught and logged) for development continuity: ad-hoc dev
  agents run against a console sink whose flapping must not take the
  agent down, while production deployments that promise durable evidence
  set the flag.
- ``RAUCLE_MW_REQUIRE_AGENT_ID=1``: strict caller-identity mode. A call
  whose framework context surfaces NO independent caller identity (nothing
  at ``metadata``, ``session.state`` nor ``agent.id``) is denied by name
  - it never falls back to the token's ``agent_id``, which would degrade
  the gate's agent-scope check to a bearer-token model. The default is
  off; multi-agent production deployments should enable it (an operator
  can always bind a per-agent identity, so the strict mode costs nothing
  where agents are first-class).

Receipt schema citation
-----------------------

Receipts cite the schema registry entry the gate enforced: when the gate
was constructed with a ``ToolSchemaRegistry`` (the registry deployments
load from the ``RAUCLE_TOOL_SCHEMA_MANIFEST`` manifest), the receipt's
``schema_hash`` is the digest of the exact registered definition the gate
used, and ``schema_evidence`` reads ``"bound"``. When no schema resolution
exists for the called tool the receipt carries ``schema_hash=None`` AND
``schema_evidence="unbound"`` - a receipt never implies schema-bound
verification without the hash.

The integration depends on ``agent-framework>=1.0``; install with
``pip install 'raucle[agent-framework]'``.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
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

#: Durable-receipt strict mode (Q18): refuse a call rather than proceed when
#: the receipt could not be durably persisted. Default off (advisory).
ENV_MW_REQUIRE_DURABLE_RECEIPT = "RAUCLE_MW_REQUIRE_DURABLE_RECEIPT"
#: Strict caller-identity mode (Q18): deny when the framework context carries
#: no independent caller identity instead of falling back to the token's
#: bearer identity. Default off.
ENV_MW_REQUIRE_AGENT_ID = "RAUCLE_MW_REQUIRE_AGENT_ID"


def _env_flag(name: str) -> bool:
    """Env truthiness, matching the audit strict-mode convention."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


# --- Lazy host-framework import --------------------------------------------
# We refuse to fail at import-time if `agent_framework` isn't installed; users
# who installed `raucle` without the extra should still be able to
# `from raucle.integrations import agent_framework` and get a clear
# RuntimeError only when they try to instantiate the middleware.

try:  # pragma: no cover - import-time check, not exercised in unit tests
    from agent_framework import (  # type: ignore[import-not-found]
        FunctionMiddleware,
        MiddlewareTermination,
    )

    _HAS_AGENT_FRAMEWORK = True
except ImportError:  # pragma: no cover
    _HAS_AGENT_FRAMEWORK = False

    class FunctionMiddleware:  # type: ignore[no-redef]
        """Stub used when ``agent-framework`` is not installed.

        Subclassing this class outside of an Agent Framework deployment is a
        no-op; instantiating ``RaucleFunctionMiddleware`` will raise a clear
        RuntimeError directing the user to install the extra.
        """

    class MiddlewareTermination(Exception):  # type: ignore[no-redef]
        """Stub for control-flow exception when ``agent-framework`` is missing."""

        def __init__(self, message: str = "", *, result: Any = None) -> None:
            super().__init__(message)
            self.result = result


# --- In-force token resolution ---------------------------------------------
# Agents emit tool calls under a session's in-force capability token. We
# resolve via an asyncio-safe ContextVar by default; deployers can override
# with a custom callable for more sophisticated scoping (per-tenant,
# per-agent, distributed-cache-backed, etc.).

TokenResolver = Callable[["FunctionInvocationContext"], Capability | None]  # noqa: F821

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_in_force_token", default=None
)


_UNKNOWN = "<unknown>"  # named once (Sonar S1192)


def set_in_force_token(token: Capability | None) -> None:
    """Bind a capability token to the current async context.

    Call this when a session begins (e.g. when handling the first message of a
    user conversation). The token remains in force for the lifetime of the
    asyncio context — concurrent sessions get independent token bindings.
    """
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    """Return the capability token bound to the current async context, if any."""
    return _in_force_token.get()


def _default_resolver(_context: Any) -> Capability | None:
    """Default resolver: read the in-force token from the asyncio context.

    Deployers can substitute a custom resolver by passing
    ``token_resolver=...`` to ``RaucleFunctionMiddleware``.
    """
    return get_in_force_token()


# --- Receipt construction ---------------------------------------------------


@dataclass(frozen=True)
class CapabilityReceipt:
    """A signed, content-addressed record of a single gate decision.

    Matches the receipt format documented in ``docs/spec/provenance/v1.md``
    and in the ``Anatomy of a receipt`` section of raucle.com. The signature
    is produced by the configured sink's ``Ed25519Signer``; everything else
    is content-addressed and self-describing.
    """

    issuer: str
    issuer_pubkey: str
    schema_hash: str | None
    policy_proof_hash: str | None
    lean_theorem_id: str
    attenuation_chain: list[str]
    # Honest null on the deny/attribution path: None when no caller
    # identity was bound, never a placeholder string (receipt-index v3:
    # continuity is never fabricated).
    agent_id: str | None
    tool: str
    call_args_hash: str
    decision: str  # "ALLOW" or "DENY"
    decision_reason: str
    timestamp: str  # ISO 8601 with millisecond precision
    signature: str | None  # populated by the sink

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "issuer_pubkey": self.issuer_pubkey,
            "schema_hash": self.schema_hash,
            # The honest evidence marker: a receipt only reads "bound" when a
            # schema hash actually rides the body - unbound evidence is named
            # rather than inferred, so no consumer can mistake a null hash
            # for schema-bound verification.
            "schema_evidence": ("bound" if self.schema_hash else "unbound"),
            "policy_proof_hash": self.policy_proof_hash,
            "lean_theorem_id": self.lean_theorem_id,
            "attenuation_chain": self.attenuation_chain,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "call_args_hash": self.call_args_hash,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }


def _hash_args(args: dict[str, Any]) -> str:
    """SHA-256 of canonical-JSON-serialised tool-call arguments."""
    return "sha256:" + _sha256_hex(_canonical_json(args))


def _receipt_event(receipt: CapabilityReceipt) -> dict[str, Any]:
    """The audit-chain event shape for one capability receipt."""
    return {"kind": "capability_receipt", "receipt": receipt.to_dict()}


def _iso_now() -> str:
    """ISO 8601 timestamp with millisecond precision and explicit Z suffix."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + (
        f".{int((time.time() % 1) * 1000):03d}Z"
    )


# --- The middleware ---------------------------------------------------------


class RaucleFunctionMiddleware(FunctionMiddleware):
    """``FunctionMiddleware`` that gates tool calls and emits capability receipts.

    Wire into an Agent Framework agent with::

        agent.middleware.add(RaucleFunctionMiddleware(gate=..., sink=...))

    On each tool invocation:

      * Look up the in-force capability token (via ``token_resolver``).
      * If no token is bound, emit a DENY receipt with reason ``"no token in
        force"`` and refuse the call.
      * Resolve the caller identity from the framework context, in priority
        order (``metadata``, ``session.state``, ``agent.id``). Under
        ``RAUCLE_MW_REQUIRE_AGENT_ID=1`` a context with no identity at any
        source is denied by name; otherwise the identity falls back to the
        token's ``agent_id`` (a bearer-token model).
      * Else, call ``gate.check(token, tool=..., args=...)``.
      * On ``decision.allowed``: PERSIST the receipt first (the receipt is
        durably appended before ``call_next()`` runs), then invoke
        ``call_next()`` so the tool runs. Under
        ``RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1`` a sink failure refuses the
        call instead of proceeding; without the flag (the advisory default)
        a sink failure is logged loudly and the call proceeds, for
        development continuity.
      * On ``decision.denied``: persist the receipt, short-circuit (do *not*
        call ``call_next()``), set ``context.result`` to a structured
        refusal, refuse via ``MiddlewareTermination``.

    Residual, recorded openly: the emitted receipt binds the CALL-TIME
    arguments the gate evaluated; middleware downstream of raucle may mutate
    the result afterwards, and the receipt's vantage does not extend past
    the decision point (the M4 downstream-mutation limitation).

    Parameters
    ----------
    gate
        The :class:`~raucle.capability.CapabilityGate` instance the
        middleware will check tool calls against. When the gate carries a
        ``ToolSchemaRegistry`` (deployments load one from the
        ``RAUCLE_TOOL_SCHEMA_MANIFEST`` manifest), receipts cite the digest
        of the registered definition the gate enforced; without one the
        receipt carries ``schema_hash=None`` and the honest
        ``schema_evidence="unbound"`` marker.
    sink
        An audit sink that writes receipts. Defaults to a :class:`NullSink`
        (receipts are still constructed but not persisted); production
        deployments should pass a :class:`~raucle.audit.HashChainSink`.
    token_resolver
        Callable that, given the Agent Framework invocation context, returns
        the in-force ``Capability`` token or ``None``. Defaults to the
        asyncio ContextVar populated by :func:`set_in_force_token`.
    lean_theorem_id
        The Lean 4 theorem identifier the receipts should cite as the
        soundness anchor. Defaults to ``"vcd.gate_soundness"`` (the gate-
        soundness theorem in ``paper/lean/``).
    require_durable_receipt
        Durable-receipt mode. ``None`` (default) resolves the
        ``RAUCLE_MW_REQUIRE_DURABLE_RECEIPT`` environment flag at
        construction; an explicit bool overrides the environment. When
        truthy, the receipt must be durably persisted before the downstream
        call starts and a sink failure refuses the call (named through the
        middleware termination refusal); when falsy, a sink failure is
        caught and logged (advisory default for dev continuity).
    require_agent_id
        Strict caller-identity mode. ``None`` (default) resolves the
        ``RAUCLE_MW_REQUIRE_AGENT_ID`` environment flag at construction; an
        explicit bool overrides the environment. When truthy, a framework
        context that surfaces no independent caller identity is denied by
        name rather than falling back to the token's ``agent_id`` (multi-
        agent production deployments should enable this; the strict mode
        costs nothing where operators bind per-agent identities).
    """

    def __init__(
        self,
        *,
        gate: CapabilityGate,
        sink: HashChainSink | NullSink | None = None,
        token_resolver: TokenResolver | None = None,
        lean_theorem_id: str = "vcd.gate_soundness",
        require_durable_receipt: bool | None = None,
        require_agent_id: bool | None = None,
    ) -> None:
        if not _HAS_AGENT_FRAMEWORK:
            raise RuntimeError(
                "RaucleFunctionMiddleware requires the 'agent-framework' "
                "Python package. Install with `pip install "
                "'raucle[agent-framework]'`."
            )
        self._gate = gate
        self._sink: HashChainSink | NullSink = sink if sink is not None else NullSink()
        self._token_resolver: TokenResolver = token_resolver or _default_resolver
        self._lean_theorem_id = lean_theorem_id
        # Strict modes resolve the environment once, at construction, so a
        # deployment's promise is fixed for the middleware's lifetime (the
        # audit sink_from_env convention).
        self._require_durable_receipt: bool = (
            _env_flag(ENV_MW_REQUIRE_DURABLE_RECEIPT)
            if require_durable_receipt is None
            else bool(require_durable_receipt)
        )
        self._require_agent_id: bool = (
            _env_flag(ENV_MW_REQUIRE_AGENT_ID)
            if require_agent_id is None
            else bool(require_agent_id)
        )

    async def process(
        self,
        context: Any,  # agent_framework.FunctionInvocationContext at runtime
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """The hook the Agent Framework calls for every tool invocation."""
        token = self._token_resolver(context)
        tool_name = self._extract_tool_name(context)
        call_args = self._extract_args(context)
        # Caller identity must come from the framework context, NOT the token —
        # otherwise the gate's agent_id scope check is tautological (it would
        # compare the token's own agent_id against itself and always pass,
        # letting a token minted for agent A be used by a different caller B).
        # Prefer the independent context identity; only when the framework does
        # not surface one do we fall back to the token's agent_id, which
        # degrades to a bearer-token model (the caller is trusted to hold the
        # right token). Deployers who can surface a caller id (via
        # context.metadata / session state) get real agent_id scope enforcement.
        caller_id = self._extract_agent_id(context)

        # No token bound? Fail-closed. When the context DID declare a caller
        # identity, the deny receipt still attributes the attempt to it.
        if token is None:
            receipt = self._build_receipt(
                token=None,
                agent_id=caller_id or None,
                tool=tool_name,
                args=call_args,
                decision=GateDecision(allowed=False, reason="no capability token in force"),
            )
            self._emit_receipt_for_mode(receipt, context)
            self._raise_refusal(context, "no capability token in force")

        # Strict caller identity (Q18 Close 1): with no independent caller
        # identity at ANY documented source, the gate's agent scope cannot
        # be enforced against the caller, so the strict mode denies by name
        # - it never falls back to the bearer identity the token carries.
        if caller_id is None and self._require_agent_id:
            decision = GateDecision(
                allowed=False,
                reason=(
                    "no independent caller identity in the framework context "
                    f"({ENV_MW_REQUIRE_AGENT_ID})"
                ),
            )
            receipt = self._build_receipt(
                token=token,
                agent_id=None,
                tool=tool_name,
                args=call_args,
                decision=decision,
            )
            self._emit_receipt_for_mode(receipt, context)
            self._raise_refusal(context, decision.reason)

        agent_id = caller_id or (token.agent_id if token is not None else None)

        # Gate check.
        decision = self._gate.check(token, tool=tool_name, agent_id=agent_id, args=call_args)
        receipt = self._build_receipt(
            token=token, agent_id=agent_id, tool=tool_name, args=call_args, decision=decision
        )

        if decision.allowed:
            # Persist BEFORE execution: the receipt is durably appended
            # before call_next runs, so every allowed call carries its audit
            # record even when everything downstream fails afterwards. In
            # durable mode a sink failure refuses the call (the downstream
            # call does not start without its receipt); in the advisory
            # default the failure is logged and the call proceeds (dev
            # continuity - see the class docstring).
            self._emit_receipt_for_mode(receipt, context)
            await call_next()
        else:
            self._emit_receipt_for_mode(receipt, context)
            self._raise_refusal(context, decision.reason)

    # --- Helpers --------------------------------------------------------

    def _build_receipt(
        self,
        *,
        token: Capability | None,
        agent_id: str | None,
        tool: str,
        args: dict[str, Any],
        decision: GateDecision,
    ) -> CapabilityReceipt:
        return CapabilityReceipt(
            issuer=(token.issuer if token else _UNKNOWN),
            issuer_pubkey=(token.key_id if token else _UNKNOWN),
            # Cite the EXACT schema-registry entry the gate enforced: the
            # digest of the registered definition for this tool (the
            # registry deployments load from RAUCLE_TOOL_SCHEMA_MANIFEST).
            # No schema resolution for this tool -> None plus the honest
            # "unbound" evidence marker the receipt body carries.
            schema_hash=self._tool_definition_digest(tool),
            policy_proof_hash=(token.policy_proof_hash if token else None),
            lean_theorem_id=self._lean_theorem_id,
            attenuation_chain=(decision.chain or ([] if token is None else [token.token_id])),
            # Honest null contract: the receipt carries agent_id verbatim
            # when the caller declared it, or None when it did not - a
            # fabricated placeholder would corrupt chain continuity.
            agent_id=agent_id or None,
            tool=tool,
            call_args_hash=_hash_args(args),
            decision=("ALLOW" if decision.allowed else "DENY"),
            decision_reason=decision.reason,
            timestamp=_iso_now(),
            signature=None,  # populated by sink.write below
        )

    def _tool_definition_digest(self, tool: str) -> str | None:
        """The digest of the schema-registry entry the gate enforces, or None.

        ``CapabilityGate`` stores the ``ToolSchemaRegistry`` it was
        constructed with (``tool_schemas=...`` - the registry a deployment
        loads from the ``RAUCLE_TOOL_SCHEMA_MANIFEST`` manifest); reading it
        here is the deliberate integration seam so a receipt cites the SAME
        definition digest the gate's schema stage checked. A gate without a
        registry, or a tool unknown to it, yields no resolution.
        """
        registry = getattr(self._gate, "_tool_schemas", None)
        if registry is None:
            return None
        if not registry.has_schema(tool):
            return None
        return registry.definition_digest(tool)

    def _emit(self, receipt: CapabilityReceipt) -> None:
        """Hand the receipt to the audit sink (advisory failure semantics)."""
        try:
            # HashChainSink wraps each event in a hash-chain entry and
            # signs periodically; NullSink discards.
            self._sink.append(_receipt_event(receipt))
        except Exception:
            # Never let receipt emission break the agent's main path —
            # but log loudly. A deployment that silently drops receipts is a
            # broken deployment; the deployer needs to know.
            logger.exception("raucle: failed to emit capability receipt")

    def _emit_receipt_for_mode(self, receipt: CapabilityReceipt, context: Any) -> None:
        """Hand the receipt to the sink, honouring the durable-receipt mode.

        Advisory default: a sink failure is logged loudly and the call
        proceeds (development continuity). Durable mode
        (``RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1``): the receipt must be
        durably persisted - a sink failure refuses the call through the
        middleware termination refusal, so the downstream call does not
        start without its receipt.
        """
        if not self._require_durable_receipt:
            self._emit(receipt)
            return
        try:
            self._sink.append(_receipt_event(receipt))
        except Exception as exc:
            logger.exception(
                "raucle: receipt sink failure in durable mode for tool=%s", receipt.tool
            )
            self._raise_refusal(
                context,
                "receipt persistence required "
                f"({ENV_MW_REQUIRE_DURABLE_RECEIPT}): sink failure: {exc}",
            )

    # --- Context extraction (defensive against schema variation) ---------
    # The exact shape of `FunctionInvocationContext` is stable as of Agent
    # Framework 1.0 but we keep these as named helpers so future Microsoft
    # API tweaks land in one place.

    @staticmethod
    def _extract_tool_name(context: Any) -> str:
        # AF docs name this `context.function.name`.
        try:
            return str(context.function.name)
        except AttributeError:  # pragma: no cover
            return "<unknown_tool>"

    @staticmethod
    def _extract_args(context: Any) -> dict[str, Any]:
        # AF docs name this `context.arguments` (a Mapping[str, Any]).
        try:
            args = context.arguments
        except AttributeError:  # pragma: no cover
            return {}
        if args is None:
            return {}
        if isinstance(args, dict):
            return dict(args)
        # Other Mapping types — coerce.
        try:
            return dict(args)
        except (TypeError, ValueError):  # pragma: no cover
            return {}

    @staticmethod
    def _extract_agent_id(context: Any) -> str | None:
        """Resolve the independent caller identity from the framework context.

        ``FunctionInvocationContext``'s identity is deployer-bound, so we read
        the documented sources in priority order:

        1. ``context.metadata["agent_id"]`` - the deployer-populated primary;
        2. ``context.session.state["agent_id"]`` - session-state-populated;
        3. ``context.agent.id`` - the agent object the framework runs (the
           surface the framework docs name for middleware-invoked agents;
           previously this source was missed - Finding 80).

        This is the PREFERRED source for the gate's agent_id scope check: when
        present, the gate enforces that the in-force token's agent_id covers the
        actual caller. Only when the context surfaces no identity does the
        caller fall back to the token's own agent_id (a bearer-token model where
        the holder is trusted) - or, under strict identity mode
        (``RAUCLE_MW_REQUIRE_AGENT_ID=1``), the call is denied instead. Returns
        None when no caller identity is known.
        """
        try:
            md = getattr(context, "metadata", None) or {}
            if isinstance(md, dict) and md.get("agent_id"):
                return str(md["agent_id"])
        except Exception:  # pragma: no cover
            pass
        try:
            sess = getattr(context, "session", None)
            state = getattr(sess, "state", None) if sess is not None else None
            if isinstance(state, dict) and state.get("agent_id"):
                return str(state["agent_id"])
        except Exception:  # pragma: no cover
            pass
        try:
            agent = getattr(context, "agent", None)
            agent_id = getattr(agent, "id", None) if agent is not None else None
            if agent_id:
                return str(agent_id)
        except Exception:  # pragma: no cover
            pass
        return None

    @staticmethod
    def _raise_refusal(context: Any, reason: str) -> None:
        """Short-circuit the middleware chain with a structured refusal.

        ``MiddlewareTermination(message, result=...)`` is the Agent Framework
        contract for "stop the chain and return the supplied result to the
        agent". The agent observes a tool call that returned the refusal
        payload, without the actual tool implementation having run.
        """
        refusal = {
            "raucle": {
                "decision": "DENY",
                "reason": reason,
                "advice": "request a token with broader scope, or revise the call args",
            }
        }
        refusal_json = json.dumps(refusal)
        # Setting context.result is belt-and-braces; MiddlewareTermination's
        # `result` argument is what the framework uses.
        try:
            context.result = refusal_json
        except Exception:  # pragma: no cover
            logger.exception("raucle: could not set refusal on context.result")
        raise MiddlewareTermination(reason, result=refusal_json)


__all__ = [
    "CapabilityReceipt",
    "RaucleFunctionMiddleware",
    "TokenResolver",
    "get_in_force_token",
    "set_in_force_token",
]
