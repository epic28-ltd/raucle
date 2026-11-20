"""End-to-end tests for the Google ADK integration against real google-adk.

Requires the ``google-adk`` extra (``pip install 'raucle[google-adk]'``);
skipped otherwise. The ``Test (integration extras, P2a)`` CI job installs
the extra and owns this proof (the base dev env stays hermetic, so these
skip there - the same skip-decision shape as the crewai suite).

Verified span (P2a investigation, 18 Nov 2026, CPython 3.13): the guard and
the attribution surface below were probed live under google-adk
1.39.1 / 2.7.0 / 2.11.0 / 2.14.1. ``ToolContext`` stores the invocation
context on ``ReadonlyContext._invocation_context`` across that whole span
and ``FunctionTool`` invokes tools positionally as ``fn(args, tc)`` for
both sync and async functions; the extra is pinned to the span in
pyproject. Attribution surface: the acting agent id travels on the
invocation context (``tool_context`` -> ``_invocation_context`` ->
``agent.name``, ADK identifiers like ``billing_agent``), or is pinned at
guard time via ``agent_id`` - a call with neither denies (the B2 doctrine:
bearer mode is closed, deny receipts carry an honest null).
"""

from __future__ import annotations

import inspect
import json
import pathlib

import pytest

pytest.importorskip("google.adk.tools")
pytest.importorskip("cryptography")

from google.adk.tools import FunctionTool, ToolContext  # noqa: E402

from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.google_adk import (  # noqa: E402
    CapabilityDenied,
    guard_tool,
    guard_tools,
    set_in_force_token,
)


class _Session:
    """The session surface ToolContext's constructor reads (state)."""

    state: dict = {}


class _Agent:
    def __init__(self, name: str | None) -> None:
        self.name = name


class _Invocation:
    """The invocation-context surface the guard reads: agent -> name.

    The real ``InvocationContext`` is a pydantic model ADK builds per run;
    ``ToolContext`` accepts this faithful stand-in (the constructor only
    reads ``session.state``), and the guard's getattr traversal reads the
    same ``agent.name`` field a live run carries.
    """

    def __init__(self, agent_name: str | None) -> None:
        self.agent = _Agent(agent_name)
        self.session = _Session()
        self.invocation_id = "test-invocation"


def _tool_context(agent_name: str | None) -> ToolContext:
    return ToolContext(invocation_context=_Invocation(agent_name))


class _Body:
    calls: list[dict] = []


def transfer_funds(args: dict, tool_context: ToolContext) -> dict:  # noqa: ARG001
    """Transfer money (test tool). Records its own execution."""
    _Body.calls.append(dict(args))
    return {"status": f"TRANSFERRED {args.get('amount')} -> {args.get('to')}"}


async def atransfer_funds(args: dict, tool_context: ToolContext) -> dict:  # noqa: ARG001
    """Transfer money async (test tool)."""
    _Body.calls.append(dict(args))
    return {"status": f"TRANSFERRED {args.get('amount')} -> {args.get('to')}"}


@pytest.fixture
def env(tmp_path: pathlib.Path):
    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    signer = Ed25519Signer.generate()
    log = tmp_path / "receipts.jsonl"
    sink = HashChainSink(log, signer=signer)
    token = issuer.mint(
        agent_id="agent:billing_agent",
        tool="transfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "allowed_values": {"to": ["acct:ok"]},
        },
        ttl_seconds=60,
    )
    set_in_force_token(token)
    _Body.calls.clear()
    yield issuer, gate, sink, signer, log
    set_in_force_token(None)


def _receipts(log: pathlib.Path) -> list[dict]:
    events = []
    for line in log.read_text().strip().splitlines():
        rec = json.loads(line)
        events.append(rec.get("event", rec))
    return [e for e in events if e.get("kind") == "capability_receipt"]


def test_guarded_tool_preserves_signature(env):
    _issuer, gate, sink, *_ = env
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
    assert str(inspect.signature(guarded)) == str(inspect.signature(transfer_funds))
    assert guarded.__name__ == "transfer_funds"


def test_attributed_call_allows_and_receipt_carries_identity(env):
    _issuer, gate, sink, _signer, log = env
    tc = _tool_context("billing_agent")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
    out = guarded({"to": "acct:ok", "amount": 50}, tc)
    assert out["status"] == "TRANSFERRED 50 -> acct:ok"
    receipts = _receipts(log)
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["agent_id"] == "agent:billing_agent"
    assert receipts[0]["tool"] == "transfer_funds"
    assert receipts[0]["framework"] == "google-adk"


def test_tool_context_supplies_acting_identity(env):
    """No pinned agent_id: ADK's own attribution surface (the invocation
    context's agent name) binds the call - joined into the raucle scheme
    (billing_agent -> agent:billing_agent) - and the receipt carries it."""
    _issuer, gate, sink, _signer, log = env
    tc = _tool_context("billing_agent")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink)  # no agent_id pinned
    guarded({"to": "acct:ok", "amount": 50}, tc)
    receipts = _receipts(log)
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["agent_id"] == "agent:billing_agent"


def test_unattributed_call_denies(env):
    """B2 doctrine: no pinned identity and no agent name on the invocation
    context - the call denies, the body never runs, and the deny receipt
    carries an honest null agent_id (never a placeholder)."""
    _issuer, gate, sink, _signer, log = env
    tc = _tool_context(None)
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink)  # bearer-mode attempt
    with pytest.raises(CapabilityDenied, match="no acting agent identity"):
        guarded({"to": "acct:ok", "amount": 50}, tc)
    assert _Body.calls == []
    receipts = _receipts(log)
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["agent_id"] is None
    assert "unbound" not in json.dumps(receipts[0])


@pytest.mark.asyncio
async def test_unattributed_async_call_denies(env):
    _issuer, gate, sink, _signer, log = env
    tc = _tool_context(None)
    guarded = guard_tool(atransfer_funds, gate=gate, sink=sink)  # bearer-mode attempt
    with pytest.raises(CapabilityDenied, match="no acting agent identity"):
        await guarded({"to": "acct:ok", "amount": 50}, tc)
    assert _Body.calls == []
    receipts = _receipts(log)
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["agent_id"] is None


def test_constraint_violation_denies_and_blocks_body(env):
    _issuer, gate, sink, _signer, log = env
    tc = _tool_context("billing_agent")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
    with pytest.raises(CapabilityDenied):
        guarded({"to": "acct:attacker", "amount": 9900}, tc)
    assert _Body.calls == []
    assert _receipts(log)[0]["decision"] == "DENY"


def test_missing_token_fails_closed(env):
    _issuer, gate, sink, *_ = env
    set_in_force_token(None)
    tc = _tool_context("billing_agent")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
    with pytest.raises(CapabilityDenied, match="no in-force capability token"):
        guarded({"to": "acct:ok", "amount": 1}, tc)
    assert _Body.calls == []


def test_both_decisions_land_in_verifiable_chain(env):
    _issuer, gate, sink, signer, log = env
    tc = _tool_context("billing_agent")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
    guarded({"to": "acct:ok", "amount": 50}, tc)
    with pytest.raises(CapabilityDenied):
        guarded({"to": "acct:attacker", "amount": 9900}, tc)
    sink.close()
    report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(log)
    assert report.valid
    assert report.event_count == 2


def test_function_tool_invokes_the_guarded_path(env):
    """The real registration shape: FunctionTool(guarded) keeps ADK's own
    call convention (``ft.func(args, tool_context)``), and the gate runs
    inside it - the deny blocks the body under the framework's path, not
    just the direct-call shape."""
    _issuer, gate, sink, _signer, log = env
    ft = FunctionTool(
        guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
    )
    tc = _tool_context("billing_agent")
    _Body.calls.clear()
    out = ft.func({"to": "acct:ok", "amount": 50}, tc)
    assert out["status"].startswith("TRANSFERRED")
    assert len(_Body.calls) == 1
    with pytest.raises(CapabilityDenied):
        ft.func({"to": "acct:attacker", "amount": 9900}, tc)
    assert len(_Body.calls) == 1  # the denied attempt never reached the body
    assert [r["decision"] for r in _receipts(log)] == ["ALLOW", "DENY"]


@pytest.mark.asyncio
async def test_async_tool_gates_through_function_tool(env):
    issuer, gate, sink, _signer, log = env
    # A token scoped to the async tool, minted from the fixture's own
    # issuer (the house rule: a second scenario mints rather than rebinding).
    token = issuer.mint(
        agent_id="agent:billing_agent",
        tool="atransfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "allowed_values": {"to": ["acct:ok"]},
        },
        ttl_seconds=60,
    )
    set_in_force_token(token)
    try:
        ft = FunctionTool(
            guard_tool(atransfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
        )
        tc = _tool_context("billing_agent")
        _Body.calls.clear()
        out = await ft.func({"to": "acct:ok", "amount": 50}, tc)
        assert out["status"].startswith("TRANSFERRED")
        with pytest.raises(CapabilityDenied):
            await ft.func({"to": "acct:attacker", "amount": 9900}, tc)
        assert len(_Body.calls) == 1
    finally:
        set_in_force_token(None)


def test_guard_tools_wraps_a_list(env):
    _issuer, gate, sink, *_ = env
    tools = guard_tools(
        [transfer_funds, atransfer_funds], gate=gate, sink=sink, agent_id="agent:billing_agent"
    )
    assert len(tools) == 2
    assert all(t.__name__ in ("transfer_funds", "atransfer_funds") for t in tools)
