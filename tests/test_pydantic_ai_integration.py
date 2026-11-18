"""End-to-end tests for the Pydantic AI integration against real pydantic-ai.

Requires the ``pydantic-ai`` extra (``pip install 'raucle[pydantic-ai]'``);
skipped otherwise. The ``Test (integration extras)`` CI job installs the
extra and owns this proof (the base dev env stays hermetic, so these skip
there - the same skip-decision shape as the crewai suite).

Verified span (P2a investigation, 18 Nov 2026, CPython 3.13): the guard and
the attribution surface below were probed live under pydantic-ai
1.107.10 / 2.59.0 / 2.65.0 / 2.70.0. The RunContext fields the guard reads
(``agent`` -> ``name``) are identical across that whole span; the extra is
pinned to it in pyproject. Attribution surface: the acting agent id travels
on ``RunContext.agent.name`` (the Agent the tool is registered on), or is
pinned at guard time via ``agent_id`` - a call with neither denies (the B2
doctrine: bearer mode is closed, deny receipts carry an honest null).
"""

from __future__ import annotations

import contextlib
import inspect
import json
import pathlib

import pytest

pytest.importorskip("pydantic_ai")
pytest.importorskip("cryptography")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402
from pydantic_ai.tools import RunContext  # noqa: E402
from pydantic_ai.usage import RunUsage  # noqa: E402

from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.pydantic_ai import (  # noqa: E402
    CapabilityDenied,
    guard_tool,
    guard_tools,
    set_in_force_token,
)


def _run_context(agent_name: str | None) -> RunContext:
    """A real ``RunContext`` built the way pydantic-ai builds one in a run.

    ``TestModel`` keeps this offline (no provider credentials, no network);
    the fields the guard reads (``agent``, ``deps``) are the framework's
    own, so this is the genuine attribution surface, not a stand-in.
    """
    agent = Agent(TestModel(), name=agent_name)
    return RunContext(
        deps=None,
        model=TestModel(),
        usage=RunUsage(),
        agent=agent,
        prompt="test",
        tool_call_id="call-1",
        retry=0,
    )


class _Body:
    calls: list[dict] = []


class _Balance:
    calls: list[dict] = []


def transfer_funds(ctx: RunContext, to: str, amount: int) -> str:  # noqa: ARG001
    """Transfer money (test tool). Records its own execution."""
    _Body.calls.append({"to": to, "amount": amount})
    return f"TRANSFERRED {amount} -> {to}"


def lookup_balance(ctx: RunContext, account: str) -> str:  # noqa: ARG001
    """Look up a balance (test tool). Records its own execution."""
    _Balance.calls.append({"account": account})
    return f"BALANCE {account}"


async def atransfer_funds(ctx: RunContext, to: str, amount: int) -> str:  # noqa: ARG001
    """Transfer money async (test tool)."""
    _Body.calls.append({"to": to, "amount": amount})
    return f"TRANSFERRED {amount} -> {to}"


@pytest.fixture
def env(tmp_path: pathlib.Path):
    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    signer = Ed25519Signer.generate()
    log = tmp_path / "receipts.jsonl"
    sink = HashChainSink(log, signer=signer)
    token = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "allowed_values": {"to": ["acct:ok"]},
        },
        ttl_seconds=60,
    )
    set_in_force_token(token)
    _Body.calls.clear()
    yield gate, sink, signer, log
    set_in_force_token(None)


def _receipts(log: pathlib.Path) -> list[dict]:
    events = []
    for line in log.read_text().strip().splitlines():
        rec = json.loads(line)
        events.append(rec.get("event", rec))
    return [e for e in events if e.get("kind") == "capability_receipt"]


def test_guarded_tool_preserves_signature(env):
    gate, sink, *_ = env
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing")
    assert str(inspect.signature(guarded)) == str(inspect.signature(transfer_funds))
    assert guarded.__name__ == "transfer_funds"


def test_attributed_call_allows_and_receipt_carries_identity(env):
    gate, sink, *_ = env
    ctx = _run_context("agent:billing")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing")
    assert guarded(ctx, to="acct:ok", amount=50) == "TRANSFERRED 50 -> acct:ok"
    receipts = _receipts(_log_of(env))
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["agent_id"] == "agent:billing"
    assert receipts[0]["tool"] == "transfer_funds"
    assert receipts[0]["framework"] == "pydantic-ai"


def _log_of(env):
    return env[3]


def test_run_context_supplies_acting_identity(env):
    """No pinned agent_id: the framework's own attribution surface (the
    Agent the tool is registered on, carried on RunContext.agent.name)
    binds the call; the receipt carries that identity."""
    gate, sink, *_ = env
    ctx = _run_context("agent:billing")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink)  # no agent_id pinned
    assert guarded(ctx, to="acct:ok", amount=50) == "TRANSFERRED 50 -> acct:ok"
    receipts = _receipts(_log_of(env))
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["agent_id"] == "agent:billing"


def test_unattributed_call_denies(env):
    """B2 doctrine: no pinned identity and no named Agent on the run
    context - the call denies, the body never runs, and the deny receipt
    carries an honest null agent_id (never a placeholder)."""
    gate, sink, *_ = env
    ctx = _run_context(None)
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink)  # bearer-mode attempt
    with pytest.raises(CapabilityDenied, match="no acting agent identity"):
        guarded(ctx, to="acct:ok", amount=50)
    assert _Body.calls == []
    receipts = _receipts(_log_of(env))
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["agent_id"] is None
    assert "unbound" not in json.dumps(receipts[0])


@pytest.mark.asyncio
async def test_unattributed_async_call_denies(env):
    gate, sink, *_ = env
    ctx = _run_context(None)
    guarded = guard_tool(atransfer_funds, gate=gate, sink=sink)  # bearer-mode attempt
    with pytest.raises(CapabilityDenied, match="no acting agent identity"):
        await guarded(ctx, to="acct:ok", amount=50)
    assert _Body.calls == []
    receipts = _receipts(_log_of(env))
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["agent_id"] is None


def test_constraint_violation_denies_and_blocks_body(env):
    gate, sink, *_ = env
    ctx = _run_context("agent:billing")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing")
    with pytest.raises(CapabilityDenied):
        guarded(ctx, to="acct:attacker", amount=9900)
    assert _Body.calls == []
    assert _receipts(_log_of(env))[0]["decision"] == "DENY"


def test_missing_token_fails_closed(env):
    gate, sink, *_ = env
    set_in_force_token(None)
    ctx = _run_context("agent:billing")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing")
    with pytest.raises(CapabilityDenied, match="no in-force capability token"):
        guarded(ctx, to="acct:ok", amount=1)
    assert _Body.calls == []


def test_both_decisions_land_in_verifiable_chain(env):
    gate, sink, signer, log = env
    ctx = _run_context("agent:billing")
    guarded = guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing")
    guarded(ctx, to="acct:ok", amount=50)
    with pytest.raises(CapabilityDenied):
        guarded(ctx, to="acct:attacker", amount=9900)
    sink.close()
    report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(log)
    assert report.valid
    assert report.event_count == 2


@pytest.mark.asyncio
async def test_async_path_gates_too(env):
    _, sink, *_ = env
    # A token scoped to the async tool, minted from this test's own issuer
    # (the house fixture rule: a second scenario needing another token
    # mints its own rather than rebinding the fixture's).
    issuer = CapabilityIssuer.generate(issuer="async.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:billing",
        tool="atransfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "allowed_values": {"to": ["acct:ok"]},
        },
        ttl_seconds=60,
    )
    set_in_force_token(token)
    try:
        ctx = _run_context("agent:billing")
        guarded = guard_tool(atransfer_funds, gate=gate, sink=sink, agent_id="agent:billing")
        assert await guarded(ctx, to="acct:ok", amount=50) == "TRANSFERRED 50 -> acct:ok"
        with pytest.raises(CapabilityDenied):
            await guarded(ctx, to="acct:attacker", amount=9900)
    finally:
        set_in_force_token(None)


def test_guard_tools_wraps_a_list(env):
    gate, sink, *_ = env
    tools = guard_tools(
        [transfer_funds, atransfer_funds], gate=gate, sink=sink, agent_id="agent:billing"
    )
    assert len(tools) == 2
    assert all(t.__name__ in ("transfer_funds", "atransfer_funds") for t in tools)


def test_real_framework_run_calls_the_guarded_tool(env):
    """The full framework path: TestModel (offline) drives a tool call, the
    framework builds the real RunContext, and the guard receipts the call
    with the identity the framework carried - proving the adapter sits on
    the genuine execution path, not just the direct-call shape."""
    gate, sink, *_ = env
    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate2 = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token2 = issuer.mint(agent_id="agent:billing", tool="lookup_balance", ttl_seconds=60)
    set_in_force_token(token2)
    try:
        agent = Agent(TestModel(), name="agent:billing")
        agent.tool(guard_tool(lookup_balance, gate=gate2, sink=sink, agent_id="agent:billing"))
        _Balance.calls.clear()
        result = agent.run_sync("look up a balance")
        assert result.output is not None
        assert _Balance.calls, "the guarded tool never ran under the real framework"
        receipts = _receipts(_log_of(env))
        assert receipts[0]["decision"] == "ALLOW"
        assert receipts[0]["agent_id"] == "agent:billing"
        assert receipts[0]["tool"] == "lookup_balance"
    finally:
        set_in_force_token(None)


def test_real_framework_run_denies_synthetic_out_of_scope_call(env):
    """TestModel cannot read the token's constraints, so its synthetic
    arguments honestly violate them: the guard must deny on the REAL
    framework path, the tool body must never run, and every attempt lands
    as a receipted deny attributed to the pinned identity."""
    gate, sink, *_ = env
    agent = Agent(TestModel(), name="agent:billing")
    agent.tool(guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing"))
    _Body.calls.clear()
    with contextlib.suppress(Exception):
        # The framework surfaces the denied tool call as a tool error; the
        # outcome of the RUN is pydantic-ai's, the deny is raucle's.
        agent.run_sync("transfer some money")
    assert _Body.calls == []
    receipts = _receipts(_log_of(env))
    assert receipts
    assert all(r["decision"] == "DENY" for r in receipts)
    assert all(r["agent_id"] == "agent:billing" for r in receipts)
