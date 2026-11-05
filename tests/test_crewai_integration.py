"""End-to-end tests for the CrewAI integration against real crewai.

Requires the ``crewai`` extra (``pip install 'raucle[crewai]'``); skipped
otherwise. These drive the genuine ``BaseTool.run(**kwargs)`` path — the same
path a Crew uses — so a denied call is verified to block the real tool body, not
a mock.

SKIP DECISION (2026-11-05): ``crewai>=1.0`` has no Python 3.14 distribution
(the dev venv is py3.14), so these tests are documented-excluded locally; the
CI 3.11-3.13 matrix installs the extra and owns this proof. Until a py3.14
crewai exists, ``tests/test_integrations_contract.py`` covers the wrapper's
own surface against a faithful BaseTool stand-in. Backlog: retire the
stand-ins when a py3.14-compatible crewai ships.
"""

from __future__ import annotations

import pathlib

import pytest

pytest.importorskip("crewai")
pytest.importorskip("cryptography")

from crewai.tools import BaseTool  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.crewai import (  # noqa: E402
    CapabilityDenied,
    guard_tool,
    guard_tools,
    set_in_force_token,
)


class _Args(BaseModel):
    to: str
    amount: int


class _Pay(BaseTool):
    name: str = "transfer_funds"
    description: str = "Transfer money (test tool)"
    args_schema: type = _Args

    def _run(self, to: str, amount: int) -> str:
        return f"TRANSFERRED {amount} -> {to}"


@pytest.fixture
def env(tmp_path: pathlib.Path):
    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    signer = Ed25519Signer.generate()
    log = tmp_path / "receipts.jsonl"
    sink = HashChainSink(log, signer=signer)
    guarded = guard_tool(_Pay(), gate=gate, sink=sink)
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
    yield guarded, sink, signer, log
    set_in_force_token(None)


def test_guarded_tool_preserves_interface(env):
    guarded, *_ = env
    assert guarded.name == "transfer_funds"
    assert list(guarded.args_schema.model_fields) == ["to", "amount"]


def test_allowed_call_runs_the_real_tool(env):
    guarded, *_ = env
    assert guarded.run(to="acct:ok", amount=50) == "TRANSFERRED 50 -> acct:ok"


def test_denied_call_blocks_tool_body(env):
    guarded, *_ = env
    with pytest.raises(CapabilityDenied):
        guarded.run(to="acct:attacker", amount=9900)


def test_missing_token_fails_closed(env):
    guarded, *_ = env
    set_in_force_token(None)
    with pytest.raises(CapabilityDenied):
        guarded.run(to="acct:ok", amount=1)


def test_both_decisions_land_in_verifiable_chain(env):
    guarded, sink, signer, log = env
    guarded.run(to="acct:ok", amount=50)
    with pytest.raises(CapabilityDenied):
        guarded.run(to="acct:attacker", amount=9900)
    sink.close()
    report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(log)
    assert report.valid
    assert report.event_count == 2


@pytest.mark.asyncio
async def test_async_path_gates_too(env):
    guarded, *_ = env
    assert await guarded.arun(to="acct:ok", amount=50) == "TRANSFERRED 50 -> acct:ok"
    with pytest.raises(CapabilityDenied):
        await guarded.arun(to="acct:attacker", amount=9900)


def test_guard_tools_wraps_a_list(env):
    _, sink, *_ = env
    issuer = CapabilityIssuer.generate(issuer="t2")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    tools = guard_tools([_Pay(), _Pay()], gate=gate, sink=sink)
    assert len(tools) == 2
    assert all(t.name == "transfer_funds" for t in tools)


def test_demo_script_passes_self_check():
    import subprocess
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, str(root / "examples" / "crewai_demo" / "demo.py")],
        capture_output=True,
        text=True,
        cwd=root,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DENIED by gate" in proc.stdout
    assert "chain valid: True" in proc.stdout
