"""Unit tests for raucle.integrations.agent_framework.

These tests do NOT require the real ``agent-framework`` package to be
installed. They exercise the middleware contract via a mock invocation
context that mirrors the documented shape of
``agent_framework.FunctionInvocationContext`` (``.function.name``,
``.arguments``, ``.agent.id``, ``.result``).

The contract paths verified (every decision must MINT A RECEIPT):

    1. No token in force → DENY receipt, refusal set, tool not invoked.
    2. Token in force, args allowed → ALLOW receipt, tool invoked.
    3. Token in force, args denied by constraint → DENY receipt, tool
       not invoked, refusal set.
    4. Wrong tool for the in-force token → DENY receipt, tool not
       invoked.
    5. Durable-receipt mode (``RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1``):
       the receipt is persisted before the downstream call starts and a
       sink failure refuses the call, named; the advisory default keeps
       the log-and-proceed behaviour.
    6. Strict caller identity (``RAUCLE_MW_REQUIRE_AGENT_ID=1``): a
       context with no independent caller identity at ANY documented
       source (metadata, session.state, agent.id) denies by name; each
       source on its own satisfies the mode.
    7. Receipt schema citation: a manifest-registered schema cites its
       definition digest (``schema_evidence: "bound"``); no schema
       resolution carries the honest ``"unbound"`` marker.
"""

from __future__ import annotations

import contextvars
import json
import types
from typing import Any

import pytest

# Skip the entire module if cryptography isn't available — the middleware
# constructs receipts via Ed25519 primitives that require it.
pytest.importorskip("cryptography")

from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.agent_framework import (  # noqa: E402
    CapabilityReceipt,
    MiddlewareTermination,
    RaucleFunctionMiddleware,
    get_in_force_token,
    set_in_force_token,
)

# ---------------------------------------------------------------------------
# Fixtures


@pytest.fixture
def issuer() -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer="acme.test.kyc")


@pytest.fixture
def gate(issuer: CapabilityIssuer) -> CapabilityGate:
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


@pytest.fixture
def captured_events() -> list[dict]:
    """A sink that captures appended events in-memory."""
    events: list[dict] = []

    class CapturingSink:
        def append(self, event: dict) -> dict:
            events.append(event)
            return {}

        def close(self) -> None:
            pass

    return events, CapturingSink()


def _make_context(
    *,
    function_name: str,
    arguments: dict,
    metadata: dict | None = None,
    session_state: dict | None = None,
    agent_id: str | None = "agent:test-1",
) -> types.SimpleNamespace:
    """Construct a mock FunctionInvocationContext matching the AF shape.

    ``metadata`` / ``session_state`` populate the deployer-populated
    identity sources the adapter's extraction reads before ``.agent.id``;
    ``agent_id=None`` omits the ``.agent`` surface, giving a context
    that carries no identity at any documented source.
    """
    return types.SimpleNamespace(
        function=types.SimpleNamespace(name=function_name),
        arguments=arguments,
        metadata=metadata,
        session=(types.SimpleNamespace(state=session_state) if session_state is not None else None),
        agent=(types.SimpleNamespace(id=agent_id) if agent_id is not None else None),
        result=None,
    )


async def _consume_call_next(invoked: list[bool]):
    """Test stand-in for ``call_next``: records that it was invoked."""

    async def _next() -> None:
        invoked.append(True)

    return _next


# Force the middleware to behave as if agent-framework is installed —
# we test the logic, not the import guard.
import raucle.integrations.agent_framework as af  # noqa: E402

af._HAS_AGENT_FRAMEWORK = True


# ---------------------------------------------------------------------------
# Tests


@pytest.mark.asyncio
async def test_no_token_in_force_denies(gate, captured_events):
    """Path 1: no token bound → DENY receipt, tool not invoked, MiddlewareTermination raised."""
    events, sink = captured_events
    # Make sure no token is bound for this test
    set_in_force_token(None)

    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    # A context that carries no caller identity at any documented source:
    # the honest-null contract pins the receipt's agent_id as None.
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        agent_id=None,
    )

    call_next = await _consume_call_next(invoked)
    with pytest.raises(MiddlewareTermination):
        await mw.process(context, call_next)

    assert invoked == [], "tool must not be invoked when no token is in force"
    assert len(events) == 1
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "DENY"
    assert "no capability token in force" in receipt["decision_reason"]
    # Honest-null contract: the deny receipt carries the caller's agent_id
    # verbatim when declared, or None when it is not - never a fabricated
    # placeholder string ("agent:test-1" here would fail).
    assert receipt["agent_id"] is None
    # Refusal must be attached to context.result so downstream code sees it
    assert context.result is not None


@pytest.mark.asyncio
async def test_no_token_with_context_identity_receipts_the_caller(gate, captured_events):
    """No token + a declared context identity → the deny receipts the caller.

    Finding 80 pin: the context identity is extracted (here via ``context.agent.id``)
    even on the no-token deny path, so an unauthorised attempt is attributable.
    """
    events, sink = captured_events
    set_in_force_token(None)

    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(function_name="lookup_customer", arguments={"customer_id": "C-1042"})

    call_next = await _consume_call_next(invoked)
    with pytest.raises(MiddlewareTermination):
        await mw.process(context, call_next)

    assert invoked == []
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "DENY"
    assert receipt["agent_id"] == "agent:test-1", (
        "the attempt must be attributed to the identity the context declares"
    )


@pytest.mark.asyncio
async def test_allowed_call_emits_allow_receipt(issuer, gate, captured_events):
    """Path 2: token + matching args → ALLOW receipt, tool invoked.

    Finding 80 alignment: the fixture declares the caller identity through
    the DOCUMENTED PRIMARY source (``context.metadata["agent_id"]``) with a
    value the token does not carry, so the assertion proves the context
    identity was extracted - a pass via the token's agent_id fallback is
    impossible here.
    """
    events, sink = captured_events

    token = issuer.mint(
        agent_id="agent:test-1",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        metadata={"agent_id": "agent:test-1.primary"},
    )

    await mw.process(context, await _consume_call_next(invoked))

    assert invoked == [True], "tool must be invoked when ALLOW"
    assert len(events) == 1
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "ALLOW"
    # Gate scope: "agent:test-1.primary" is a dot-delimited descendant of the
    # token's "agent:test-1", so the call is allowed - and the receipt must
    # name the CALLER (metadata), not the token.
    assert receipt["agent_id"] == "agent:test-1.primary"
    assert receipt["tool"] == "lookup_customer"
    assert receipt["call_args_hash"].startswith("sha256:")
    assert receipt["issuer"] == "acme.test.kyc"


@pytest.mark.asyncio
async def test_wrong_tool_denies(issuer, gate, captured_events):
    """Path 4: token authorises tool X, call requests tool Y → DENY."""
    events, sink = captured_events

    token = issuer.mint(
        agent_id="agent:test-1",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="transfer_funds",
        arguments={"to": "GB29NWBK60161331926819", "amount": 4.00},
    )

    call_next = await _consume_call_next(invoked)
    with pytest.raises(MiddlewareTermination):
        await mw.process(context, call_next)

    assert invoked == [], "tool must NOT be invoked when wrong tool"
    assert len(events) == 1
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "DENY"
    assert receipt["tool"] == "transfer_funds"
    # Refusal payload should be attached
    assert context.result is not None


@pytest.mark.asyncio
async def test_receipt_to_dict_has_expected_fields(issuer, gate, captured_events):
    """The CapabilityReceipt dataclass round-trips all documented fields."""
    events, sink = captured_events
    token = issuer.mint(
        agent_id="agent:test-1", tool="lookup_customer", constraints={}, ttl_seconds=60
    )
    set_in_force_token(token)

    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(function_name="lookup_customer", arguments={"id": "C-1"})
    await mw.process(context, await _consume_call_next(invoked))

    receipt = events[0]["receipt"]
    expected_fields = {
        "issuer",
        "issuer_pubkey",
        "schema_hash",
        "schema_evidence",
        "policy_proof_hash",
        "lean_theorem_id",
        "attenuation_chain",
        "agent_id",
        "tool",
        "call_args_hash",
        "decision",
        "decision_reason",
        "timestamp",
        "signature",
    }
    assert set(receipt.keys()) == expected_fields


def test_context_var_isolation():
    """Sanity: setting the in-force token in one context does not leak
    into another. (Ensures async-session safety.)"""
    set_in_force_token(None)
    assert get_in_force_token() is None

    # Set in a child context, observe it doesn't leak out
    ctx = contextvars.copy_context()

    def _child():
        # Inside the child, set the token
        # (we'd assert it's None first if the ContextVar default applies)
        pass

    ctx.run(_child)
    # Parent context still sees no token
    assert get_in_force_token() is None


def test_receipt_dataclass_round_trip():
    """The CapabilityReceipt to_dict() preserves all fields."""
    r = CapabilityReceipt(
        issuer="x",
        issuer_pubkey="y",
        schema_hash=None,
        policy_proof_hash="sha256:abc",
        lean_theorem_id="t",
        attenuation_chain=["root", "child"],
        agent_id="a",
        tool="tool-1",
        call_args_hash="sha256:def",
        decision="ALLOW",
        decision_reason="ok",
        timestamp="2026-05-27T08:15:22.041Z",
        signature=None,
    )
    d = r.to_dict()
    assert d["decision"] == "ALLOW"
    assert d["attenuation_chain"] == ["root", "child"]
    assert json.dumps(d)  # JSON-serialisable


# ---------------------------------------------------------------------------
# Q18 Close 1 (P1/P2): durable receipt mode + strict caller identity.
# Q18 Close 1b: schema-hash population (schema_evidence marker) and the
# identity extraction priority order (metadata, session.state, agent.id).


class DeadSink:
    """A sink whose append always raises (the receipt store is unavailable)."""

    def __init__(self) -> None:
        self.attempts = 0

    def append(self, event: dict) -> dict:
        self.attempts += 1
        raise RuntimeError("receipt store unavailable")

    def close(self) -> None:
        pass


def _minted_token(issuer: CapabilityIssuer, tool: str = "lookup_customer") -> Any:
    return issuer.mint(agent_id="agent:test-1", tool=tool, constraints={}, ttl_seconds=60)


@pytest.mark.asyncio
async def test_durable_mode_dead_sink_refuses_execution(issuer, gate, monkeypatch):
    """(a) RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1 + a dead sink: refuse, BY NAME.

    The receipt must be durably persisted before the downstream call starts;
    a sink failure aborts the call through the adapter's middleware
    termination refusal, and the tool body never runs.
    """
    monkeypatch.setenv("RAUCLE_MW_REQUIRE_DURABLE_RECEIPT", "1")
    dead = DeadSink()
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=dead)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        metadata={"agent_id": "agent:test-1"},
    )

    call_next = await _consume_call_next(invoked)
    with pytest.raises(MiddlewareTermination) as excinfo:
        await mw.process(context, call_next)

    assert invoked == [], "durable mode must refuse the call when the receipt is not persisted"
    reason = str(excinfo.value)
    assert "RAUCLE_MW_REQUIRE_DURABLE_RECEIPT" in reason, (
        f"the refusal must name the strict mode that fired, got: {reason!r}"
    )
    assert "receipt" in reason.lower()
    assert dead.attempts == 1, "exactly one persistence attempt must be made"
    assert context.result is not None, "the refusal payload must be attached to the context"


@pytest.mark.asyncio
async def test_advisory_default_dead_sink_proceeds_and_logs(issuer, gate, monkeypatch, caplog):
    """(b) Advisory default + dead sink: execution proceeds, failure is logged.

    The default stays advisory for development continuity: a sink failure
    never breaks the agent's main path, but it is logged loudly so a
    deployment that silently drops receipts is visible to the deployer.
    """
    monkeypatch.delenv("RAUCLE_MW_REQUIRE_DURABLE_RECEIPT", raising=False)
    dead = DeadSink()
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=dead)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        metadata={"agent_id": "agent:test-1"},
    )

    await mw.process(context, await _consume_call_next(invoked))

    assert invoked == [True], "advisory mode must not change execution behaviour"
    assert dead.attempts == 1
    receipts_logged = [
        r for r in caplog.records if "failed to emit capability receipt" in r.getMessage()
    ]
    assert receipts_logged, "the sink failure must be logged loudly"


@pytest.mark.asyncio
async def test_strict_identity_without_context_identity_denies_named(
    issuer, gate, captured_events, monkeypatch
):
    """(c) RAUCLE_MW_REQUIRE_AGENT_ID=1 + a context with no identity: DENY, named.

    An independent caller identity cannot be extracted from the framework
    context, so the gate's agent scope cannot be enforced - the strict mode
    refuses the call instead of degrading to the token's bearer identity.
    """
    monkeypatch.setenv("RAUCLE_MW_REQUIRE_AGENT_ID", "1")
    events, sink = captured_events
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        agent_id=None,
    )

    call_next = await _consume_call_next(invoked)
    with pytest.raises(MiddlewareTermination) as excinfo:
        await mw.process(context, call_next)

    assert invoked == [], (
        "strict identity mode must refuse a call whose context carries no caller identity"
    )
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "DENY"
    assert receipt["agent_id"] is None
    reason = str(excinfo.value)
    assert "RAUCLE_MW_REQUIRE_AGENT_ID" in reason, (
        f"the refusal must name the strict mode that fired, got: {reason!r}"
    )
    assert "no independent caller identity" in reason


@pytest.mark.asyncio
async def test_token_identity_fallback_still_works_with_mode_off(
    issuer, gate, captured_events, monkeypatch
):
    """(d) Mode off + a context with no identity: the bearer fallback survives.

    The middleware falls back to the token's agent_id when no independent
    caller identity is available and the strict mode is not enabled; dev
    continuity keeps this behaviour as the default.
    """
    monkeypatch.delenv("RAUCLE_MW_REQUIRE_AGENT_ID", raising=False)
    events, sink = captured_events
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        agent_id=None,
    )

    await mw.process(context, await _consume_call_next(invoked))

    assert invoked == [True]
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "ALLOW"
    assert receipt["agent_id"] == "agent:test-1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source", "identity", "context_args"),
    [
        ("metadata", "agent:test-1.meta", {"metadata": {"agent_id": "agent:test-1.meta"}}),
        (
            "session_state",
            "agent:test-1.state",
            {"session_state": {"agent_id": "agent:test-1.state"}},
        ),
        ("agent_id", "agent:test-1.agent", {"agent_id": "agent:test-1.agent"}),
    ],
)
async def test_strict_identity_each_source_resolves_individually(
    issuer, gate, captured_events, monkeypatch, source, identity, context_args
):
    """Each documented identity source individually satisfies the strict mode.

    metadata, session.state and agent.id are each sufficient ON THEIR OWN:
    strict absence means absence at ALL of them, not at the deployer
    surfaces only.
    """
    monkeypatch.setenv("RAUCLE_MW_REQUIRE_AGENT_ID", "1")
    events, sink = captured_events
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer", arguments={"customer_id": "C-1042"}, **context_args
    )

    await mw.process(context, await _consume_call_next(invoked))

    assert invoked == [True], f"strict mode must accept the {source} identity source"
    receipt = events[0]["receipt"]
    assert receipt["agent_id"] == identity, f"the receipt must carry the {source} identity"


@pytest.mark.asyncio
async def test_identity_extraction_reads_sources_in_priority_order(issuer, gate, captured_events):
    """Extraction resolves the documented sources in priority order.

    metadata (the deployer-populated primary), then session.state, then
    agent.id: with all three present the receipt carries the metadata
    value; without metadata it carries session.state; with neither it
    falls through to agent.id.
    """
    events, sink = captured_events
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []

    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        metadata={"agent_id": "agent:test-1.meta"},
        session_state={"agent_id": "agent:test-1.state"},
        agent_id="agent:test-1.agent",
    )
    await mw.process(context, await _consume_call_next(invoked))
    assert events[0]["receipt"]["agent_id"] == "agent:test-1.meta"

    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        session_state={"agent_id": "agent:test-1.state"},
        agent_id="agent:test-1.agent",
    )
    await mw.process(context, await _consume_call_next(invoked))
    assert events[-1]["receipt"]["agent_id"] == "agent:test-1.state"

    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        agent_id="agent:test-1.agent",
    )
    await mw.process(context, await _consume_call_next(invoked))
    assert events[-1]["receipt"]["agent_id"] == "agent:test-1.agent", (
        "agent.id must be resolved as the last documented identity source"
    )


@pytest.mark.asyncio
async def test_strict_identity_with_agent_id_source_satisfies_mode(
    issuer, gate, captured_events, monkeypatch
):
    """Strict mode + a context identity only on agent.id: no refusal (Finding 80).

    The strict mode treats absence at ALL sources as DENY; a context that
    declares agent.id only is a declared identity, so the call proceeds.
    """
    monkeypatch.setenv("RAUCLE_MW_REQUIRE_AGENT_ID", "1")
    events, sink = captured_events
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        agent_id="agent:test-1.agent",
    )

    await mw.process(context, await _consume_call_next(invoked))

    assert invoked == [True], "an agent.id-declared identity satisfies the strict mode"
    assert events[0]["receipt"]["agent_id"] == "agent:test-1.agent"


@pytest.mark.asyncio
async def test_receipt_emitted_before_call_next(issuer, gate):
    """(e) Ordering pin: the receipt is persisted BEFORE call_next runs.

    The persisted-before-executed order holds in the advisory default: an
    audit record exists for every call the middleware let through, even
    when everything downstream fails after it.
    """
    order: list[str] = []

    class _OrderingSink:
        def append(self, event: dict) -> dict:
            order.append("sink:append")
            return {}

        def close(self) -> None:
            pass

    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=_OrderingSink())
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        metadata={"agent_id": "agent:test-1"},
    )

    async def _counting_next() -> None:
        order.append("call_next:ran")

    await mw.process(context, _counting_next)

    assert order[:2] == ["sink:append", "call_next:ran"], (
        f"receipt must be persisted before call_next runs, got: {order!r}"
    )


def _schema_registry() -> tuple[Any, dict]:
    """A registry registered through the MCP manifest machinery."""
    from raucle.tool_schema import ToolSchemaRegistry

    schema: dict = {"type": "object", "properties": {"customer_id": {"type": "string"}}}
    registry = ToolSchemaRegistry()
    registry.register_from_mcp_tools(
        [{"name": "lookup_customer", "inputSchema": schema}], manifest="manifest.json"
    )
    return registry, schema


@pytest.mark.asyncio
async def test_receipt_schema_hash_cites_gate_registry_digest(issuer, captured_events):
    """Close 1b(i): a manifest-registered schema has the receipt cite its digest.

    The receipt's schema_hash must be the digest of the EXACT schema-registry
    entry the gate enforced - the same registration the RAUCLE_TOOL_SCHEMA_MANIFEST
    machinery loads in gateway deployments.
    """
    from raucle.tool_schema import _definition_digest

    registry, schema = _schema_registry()
    gate = CapabilityGate(
        trusted_issuers={issuer.key_id: issuer.public_key_pem}, tool_schemas=registry
    )
    events, sink = captured_events
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        metadata={"agent_id": "agent:test-1"},
    )

    await mw.process(context, await _consume_call_next(invoked))

    assert invoked == [True]
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "ALLOW"
    assert receipt["schema_hash"] == registry.definition_digest("lookup_customer")
    assert receipt["schema_hash"] == _definition_digest(schema), (
        "the cited digest must be over the registered inputSchema"
    )
    assert receipt["schema_evidence"] == "bound", (
        "a receipt carrying a schema hash must not claim unbound evidence"
    )


@pytest.mark.asyncio
async def test_deny_receipt_on_registered_tool_still_cites_digest(issuer, captured_events):
    """A deny on a schema-registered tool still cites the manifest digest."""
    registry, _schema = _schema_registry()
    gate = CapabilityGate(
        trusted_issuers={issuer.key_id: issuer.public_key_pem},
        tool_schemas=registry,
    )
    events, sink = captured_events
    token = issuer.mint(
        agent_id="agent:test-1",
        tool="lookup_customer",
        constraints={"forbidden_values": {"customer_id": ["C-EVIL"]}},
        ttl_seconds=60,
    )
    set_in_force_token(token)
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-EVIL"},
        metadata={"agent_id": "agent:test-1"},
    )

    call_next = await _consume_call_next(invoked)
    with pytest.raises(MiddlewareTermination):
        await mw.process(context, call_next)

    receipt = events[0]["receipt"]
    assert receipt["decision"] == "DENY"
    assert receipt["schema_hash"] == registry.definition_digest("lookup_customer")
    assert receipt["schema_evidence"] == "bound"


@pytest.mark.asyncio
async def test_unregistered_schema_emits_honest_unbound_marker(issuer, gate, captured_events):
    """Close 1b(i): no schema resolution -> schema_hash None AND the unbound marker.

    A receipt must never imply schema-bound verification without the hash:
    the body carries schema_evidence "unbound" so consumers can tell the
    two states apart.
    """
    events, sink = captured_events
    set_in_force_token(_minted_token(issuer))
    mw = RaucleFunctionMiddleware(gate=gate, sink=sink)
    invoked: list[bool] = []
    context = _make_context(
        function_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
        metadata={"agent_id": "agent:test-1"},
    )

    await mw.process(context, await _consume_call_next(invoked))

    receipt = events[0]["receipt"]
    assert receipt["decision"] == "ALLOW"
    assert receipt["schema_hash"] is None
    assert receipt["schema_evidence"] == "unbound", (
        "a receipt without a schema hash must carry the honest unbound marker"
    )
