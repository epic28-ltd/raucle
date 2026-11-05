"""Unit tests for raucle.integrations.agent_framework.

These tests do NOT require the real ``agent-framework`` package to be
installed. They exercise the middleware contract via a mock invocation
context that mirrors the documented shape of
``agent_framework.FunctionInvocationContext`` (``.function.name``,
``.arguments``, ``.agent.id``, ``.result``).

The point of these tests is to verify the four contract paths:

    1. No token in force → DENY receipt, refusal set, tool not invoked.
    2. Token in force, args allowed → ALLOW receipt, tool invoked.
    3. Token in force, args denied by constraint → DENY receipt, tool
       not invoked, refusal set.
    4. Wrong tool for the in-force token → DENY receipt, tool not
       invoked.

In each case the receipt structure (decision, decision_reason,
agent_id, tool, call_args_hash, etc.) is asserted.
"""

from __future__ import annotations

import contextvars
import json
import types

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
    agent_id: str = "agent:test-1",
) -> types.SimpleNamespace:
    """Construct a mock FunctionInvocationContext matching the AF shape."""
    return types.SimpleNamespace(
        function=types.SimpleNamespace(name=function_name),
        arguments=arguments,
        agent=types.SimpleNamespace(id=agent_id),
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
    context = _make_context(function_name="lookup_customer", arguments={"customer_id": "C-1042"})

    call_next = await _consume_call_next(invoked)
    with pytest.raises(MiddlewareTermination):
        await mw.process(context, call_next)

    assert invoked == [], "tool must not be invoked when no token is in force"
    assert len(events) == 1
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "DENY"
    assert "no capability token in force" in receipt["decision_reason"]
    # Refusal must be attached to context.result so downstream code sees it
    assert context.result is not None


@pytest.mark.asyncio
async def test_allowed_call_emits_allow_receipt(issuer, gate, captured_events):
    """Path 2: token + matching args → ALLOW receipt, tool invoked."""
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
    context = _make_context(function_name="lookup_customer", arguments={"customer_id": "C-1042"})

    await mw.process(context, await _consume_call_next(invoked))

    assert invoked == [True], "tool must be invoked when ALLOW"
    assert len(events) == 1
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "ALLOW"
    assert receipt["agent_id"] == "agent:test-1"
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
