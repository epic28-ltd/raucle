"""End-to-end tests for the LangChain integration against real langchain-core.

The decisive regression here: langchain-core's callback manager *swallows*
handler exceptions (logs a warning) unless the handler sets ``raise_error``.
Without it, the CapabilityDenied raised by ``on_tool_start`` never reached the
caller and the denied tool RAN ANYWAY — the gate was advisory (fail-open).
These tests run the real ``tool.run(..., callbacks=[handler])`` path, not a
mocked handler call, so the swallowing layer is in the loop.
"""

from __future__ import annotations

import pathlib

import pytest

pytest.importorskip("langchain_core")
pytest.importorskip("cryptography")

from langchain_core.tools import tool  # noqa: E402

from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.langchain import (  # noqa: E402
    CapabilityDenied,
    RaucleCallbackHandler,
    set_in_force_token,
)


@tool
def transfer_funds(to: str, amount: int) -> str:
    """Transfer `amount` to `to` (test tool)."""
    return f"TRANSFERRED {amount} -> {to}"


@pytest.fixture
def env(tmp_path: pathlib.Path):
    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    signer = Ed25519Signer.generate()
    log = tmp_path / "receipts.jsonl"
    sink = HashChainSink(log, signer=signer)
    handler = RaucleCallbackHandler(gate=gate, sink=sink)
    token = issuer.mint(
        agent_id="agent:test",
        tool="transfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "allowed_values": {"to": ["acct:ok"]},
        },
        ttl_seconds=60,
    )
    set_in_force_token(token)
    yield handler, sink, signer, log
    set_in_force_token(None)


def test_handler_sets_raise_error_and_run_inline(env):
    """Load-bearing flags: without raise_error the deny is swallowed by
    langchain-core's callback manager and the tool executes anyway."""
    handler, *_ = env
    assert handler.raise_error is True
    assert handler.run_inline is True


def test_deny_actually_blocks_tool_execution(env):
    """The fail-open regression: a denied call must raise through the REAL
    langchain-core callback path, not just emit a receipt."""
    handler, *_ = env
    with pytest.raises(CapabilityDenied):
        transfer_funds.run(
            {"to": "acct:attacker", "amount": 9900},
            callbacks=[handler],
            metadata={"agent_id": "agent:test"},
        )


def test_allowed_call_executes(env):
    handler, *_ = env
    out = transfer_funds.run(
        {"to": "acct:ok", "amount": 50}, callbacks=[handler], metadata={"agent_id": "agent:test"}
    )
    assert out == "TRANSFERRED 50 -> acct:ok"


def test_both_decisions_land_in_verifiable_chain(env):
    handler, sink, signer, log = env
    transfer_funds.run(
        {"to": "acct:ok", "amount": 50}, callbacks=[handler], metadata={"agent_id": "agent:test"}
    )
    with pytest.raises(CapabilityDenied):
        transfer_funds.run(
            {"to": "acct:attacker", "amount": 9900},
            callbacks=[handler],
            metadata={"agent_id": "agent:test"},
        )
    sink.close()
    report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(log)
    assert report.valid
    assert report.event_count == 2


def test_demo_script_passes_self_check():
    """The shipped example is a runnable self-test; keep it that way."""
    import subprocess
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, str(root / "examples" / "langchain_demo" / "demo.py")],
        capture_output=True,
        text=True,
        cwd=root,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DENIED by gate" in proc.stdout
    assert "chain valid: True" in proc.stdout


@pytest.mark.asyncio
async def test_async_deny_blocks_arun(env):
    """Pin the AsyncCallbackManager path (codex review follow-up): a deny must
    propagate through `arun`, not only the sync dispatch."""
    handler, *_ = env
    with pytest.raises(CapabilityDenied):
        await transfer_funds.arun(
            {"to": "acct:attacker", "amount": 9900},
            callbacks=[handler],
            metadata={"agent_id": "agent:test"},
        )


@pytest.mark.asyncio
async def test_async_deny_blocks_ainvoke_config_callbacks(env):
    """Handler attached via RunnableConfig (the AgentExecutor-style wiring)."""
    handler, *_ = env
    with pytest.raises(CapabilityDenied):
        await transfer_funds.ainvoke(
            {"to": "acct:attacker", "amount": 9900},
            config={"callbacks": [handler], "metadata": {"agent_id": "agent:test"}},
        )


@pytest.mark.asyncio
async def test_async_allow_executes(env):
    handler, *_ = env
    out = await transfer_funds.arun(
        {"to": "acct:ok", "amount": 50}, callbacks=[handler], metadata={"agent_id": "agent:test"}
    )
    assert out == "TRANSFERRED 50 -> acct:ok"
