"""Optional-framework integrations: the skip decision + stub-backed coverage.

DECISION (recorded 2026-11-05): neither optional framework can be installed
in this environment's Python 3.14 venv — ``crewai>=1.0`` has no py3.14
distribution and ``agent-framework>=1.0`` fails joint resolution for the
same reason — so ``test_crewai_integration.py`` and
``test_agent_framework_real.py`` (real-framework end-to-end) stay
skipped-when-missing as designed; no behaviour change to those files.

What this file adds instead: the genuine code of
``raucle.integrations.crewai`` and ``raucle.integrations.agt_backend``
exercised against faithful, minimal stand-ins for the two framework
interfaces they consume (CrewAI's ``BaseTool`` and AGT's
``BackendDecision`` dataclass). These are contract tests for OUR surface —
gating, receipts, delegation, graceful degradation — not mocks of raucle;
the real-framework CI matrix (3.11-3.13) still owns the end-to-end proof.

Backlog note: when a py3.14-compatible crewai/agent-framework exists, the
real-framework suites take over entirely and these stand-ins can be
retired.
"""

from __future__ import annotations

import json
import sys
import types
from dataclasses import dataclass, field
from typing import Any

import pytest

from raucle.audit import Ed25519Signer
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations import agt_backend as agt_backend_mod
from raucle.integrations import crewai as crewai_mod

# ---------------------------------------------------------------------------
# CrewAI stand-in: the BaseTool surface the wrapper relies on
# ---------------------------------------------------------------------------


class _StubBaseTool:
    """The minimal crewai.tools.BaseTool shape: class attrs + run/_run."""

    name: str = ""
    description: str = ""
    args_schema: type = dict

    def _run(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - overridden
        raise NotImplementedError

    def _arun(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise NotImplementedError


@pytest.fixture
def crewai_integration(monkeypatch):
    tools_mod = types.ModuleType("crewai.tools")
    tools_mod.BaseTool = _StubBaseTool
    crew_pkg = types.ModuleType("crewai")
    crew_pkg.tools = tools_mod
    monkeypatch.setitem(sys.modules, "crewai", crew_pkg)
    monkeypatch.setitem(sys.modules, "crewai.tools", tools_mod)
    crewai_mod._HAS_CREWAI = True
    crewai_mod.BaseTool = _StubBaseTool
    yield crewai_mod
    crewai_mod._HAS_CREWAI = False
    crewai_mod.BaseTool = object


class _PayTool(_StubBaseTool):
    name = "transfer_funds"
    description = "Transfer money"
    args_schema = dict

    def _run(self, **kwargs: Any) -> str:
        self.ran = True  # type: ignore[attr-defined]
        return "sent"


@pytest.fixture
def issued() -> Any:
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:pay",
        tool="transfer_funds",
        constraints={"allowed_values": {"to": ["ACC-001"]}},
        ttl_seconds=300,
        policy_proof_hash="ab" * 32,
    )
    return issuer, gate, token


def _sink(tmp_path):
    from raucle.audit import HashChainSink

    return HashChainSink(
        tmp_path / "audit.jsonl",
        signer=Ed25519Signer.generate(),
    )


def test_guard_tool_without_crewai_raises_runtime_error(monkeypatch, tmp_path, issued):
    _issuer, gate, _token = issued
    monkeypatch.setattr(crewai_mod, "_HAS_CREWAI", False)
    sink = _sink(tmp_path)
    tool = _PayTool()
    with pytest.raises(RuntimeError, match="crewai"):
        crewai_mod.guard_tool(tool, gate=gate, sink=sink)


def test_guarded_tool_allow_delegates_and_receipts(crewai_integration, tmp_path, issued):
    _issuer, gate, token = issued
    mod = crewai_integration
    sink = _sink(tmp_path)
    mod.set_in_force_token(token)
    guarded = mod.guard_tool(_PayTool(), gate=gate, sink=sink, agent_id="agent:pay")
    assert guarded.name == "transfer_funds"
    assert guarded._run(to="ACC-001") == "sent"
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    events = []
    for line in lines:
        rec = json.loads(line)
        events.append(rec.get("event", rec))
    receipts = [e for e in events if e.get("kind") == "capability_receipt"]
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["framework"] == "crewai"


def test_guarded_tool_deny_blocks_the_tool_body(crewai_integration, tmp_path, issued):
    _issuer, gate, token = issued
    mod = crewai_integration
    mod.set_in_force_token(token)
    tool = _PayTool()
    guarded = mod.guard_tool(tool, gate=gate, sink=_sink(tmp_path), agent_id="agent:pay")
    with pytest.raises(mod.CapabilityDenied) as exc_info:
        guarded._run(to="ACC-999")
    assert "transfer_funds" in str(exc_info.value)
    assert not getattr(tool, "ran", False)  # body never executed


def test_guarded_tool_without_token_denies(crewai_integration, tmp_path, issued):
    _issuer, gate, _token = issued
    mod = crewai_integration
    mod.set_in_force_token(None)
    guarded = mod.guard_tool(_PayTool(), gate=gate, sink=_sink(tmp_path))
    with pytest.raises(mod.CapabilityDenied, match="no in-force capability token"):
        guarded._run(to="ACC-001")


def test_guard_tools_wraps_every_tool(crewai_integration, tmp_path, issued):
    _issuer, gate, token = issued
    mod = crewai_integration
    mod.set_in_force_token(token)
    tools = [mod.guard_tool(_PayTool(), gate=gate, sink=_sink(tmp_path)) for _ in range(1)]
    wrapped = mod.guard_tools(tools, gate=gate, sink=_sink(tmp_path))
    assert len(wrapped) == 1
    assert wrapped[0].name == "transfer_funds"


def test_guarded_tool_arun_falls_back_to_sync_impl(crewai_integration, tmp_path, issued):
    _issuer, gate, token = issued
    mod = crewai_integration
    mod.set_in_force_token(token)
    guarded = mod.guard_tool(_PayTool(), gate=gate, sink=_sink(tmp_path), agent_id="agent:pay")

    import asyncio

    out = asyncio.run(guarded._arun(to="ACC-001"))
    assert out == "sent"


# ---------------------------------------------------------------------------
# AGT backend: the BackendDecision dataclass the backend renders into
# ---------------------------------------------------------------------------


@dataclass
class FullBackendDecision:
    allowed: bool
    action: str
    reason: str
    backend: str
    evaluation_ms: float
    proof_artefact: str | None = None
    verification_pointers: dict[str, str] = field(default_factory=dict)


@dataclass
class LegacyBackendDecision:
    """Pre-PR-2610 AGT: no assurance fields."""

    allowed: bool
    action: str
    reason: str
    backend: str
    evaluation_ms: float


def _agent_os_module(decision_cls: type) -> types.ModuleType:
    agent_os = types.ModuleType("agent_os")
    policies = types.ModuleType("agent_os.policies")
    backends = types.ModuleType("agent_os.policies.backends")
    backends.BackendDecision = decision_cls  # type: ignore[attr-defined]
    agent_os.policies = policies  # type: ignore[attr-defined]
    policies.backends = backends  # type: ignore[attr-defined]
    return agent_os


@pytest.fixture
def agent_os_full(monkeypatch):
    monkeypatch.setitem(sys.modules, "agent_os", _agent_os_module(FullBackendDecision))
    monkeypatch.setitem(
        sys.modules, "agent_os.policies", _agent_os_module(FullBackendDecision).policies
    )
    monkeypatch.setitem(
        sys.modules,
        "agent_os.policies.backends",
        _agent_os_module(FullBackendDecision).policies.backends,
    )
    return agt_backend_mod


def _backend(gate, base="https://verify.example.com"):
    return agt_backend_mod.RauclePolicyBackend(gate=gate, verification_base_url=base)


def test_agt_backend_name_and_pointers(agent_os_full, issued):
    _issuer, gate, _token = issued
    backend = _backend(gate)
    assert backend.name.startswith("raucle.vcd@")
    pointers = backend._pointers()
    assert pointers["issuer_pubkey"].endswith("/.well-known/raucle-issuer.pub")
    backend_lean = agt_backend_mod.RauclePolicyBackend(
        gate=gate,
        verification_base_url="https://verify.example.com",
        lean_development_path="/lean/",
    )
    assert "lean_development" in backend_lean._pointers()


def test_agt_backend_no_token_denies(agent_os_full, issued):
    _issuer, gate, _token = issued
    from raucle.integrations.agent_framework import set_in_force_token

    set_in_force_token(None)
    backend = _backend(gate)
    decision = backend.evaluate(
        {"tool_name": "transfer_funds", "agent_id": "agent:pay", "arguments": {"to": "ACC-001"}}
    )
    assert decision.allowed is False
    assert decision.reason == "no capability token in force"


def test_agt_backend_allows_covered_call(agent_os_full, issued):
    _issuer, gate, token = issued
    from raucle.integrations.agent_framework import set_in_force_token

    set_in_force_token(token)
    backend = _backend(gate)
    decision = backend.evaluate(
        {"tool_name": "transfer_funds", "agent_id": "agent:pay", "arguments": {"to": "ACC-001"}}
    )
    assert decision.allowed is True
    assert decision.proof_artefact  # assurance field present in the full AGT


def test_agt_backend_denies_out_of_scope_tool(agent_os_full, issued):
    _issuer, gate, token = issued
    from raucle.integrations.agent_framework import set_in_force_token

    set_in_force_token(token)
    backend = _backend(gate)
    decision = backend.evaluate(
        {"tool_name": "other_tool", "agent_id": "agent:pay", "arguments": {}}
    )
    assert decision.allowed is False
    assert "does not cover" in decision.reason


def test_agt_backend_denies_constraint_violation(agent_os_full, issued):
    _issuer, gate, token = issued
    from raucle.integrations.agent_framework import set_in_force_token

    set_in_force_token(token)
    backend = _backend(gate)
    decision = backend.evaluate(
        {"tool_name": "transfer_funds", "agent_id": "agent:pay", "arguments": {"to": "ACC-999"}}
    )
    assert decision.allowed is False


def test_agt_backend_sub_agent_id_matches(agent_os_full, issued, monkeypatch):
    _issuer, gate, token = issued
    from raucle.integrations.agent_framework import set_in_force_token

    set_in_force_token(token)
    backend = _backend(gate)
    # hierarchical extension is accepted; malformed look-alikes are not
    decision = backend.evaluate(
        {
            "tool_name": "transfer_funds",
            "agent_id": "agent:pay.region-1",
            "arguments": {"to": "ACC-001"},
        }
    )
    assert decision.allowed is True
    bad = backend.evaluate(
        {
            "tool_name": "transfer_funds",
            "agent_id": "agent:pay..evil",
            "arguments": {"to": "ACC-001"},
        }
    )
    assert bad.allowed is False


def test_agt_backend_degrades_on_legacy_decision(agent_os_full, issued, monkeypatch):
    """Pre-PR-2610 AGT: verdicts stay correct, assurance fields dropped."""
    _issuer, gate, token = issued

    class _Policies:
        pass

    legacy_os = types.ModuleType("agent_os")
    legacy_policies = types.ModuleType("agent_os.policies")
    legacy_backends = types.ModuleType("agent_os.policies.backends")
    legacy_backends.BackendDecision = LegacyBackendDecision  # type: ignore[attr-defined]
    legacy_os.policies = legacy_policies  # type: ignore[attr-defined]
    legacy_policies.backends = legacy_backends  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agent_os", legacy_os)
    monkeypatch.setitem(sys.modules, "agent_os.policies", legacy_policies)
    monkeypatch.setitem(sys.modules, "agent_os.policies.backends", legacy_backends)

    from raucle.integrations.agent_framework import set_in_force_token

    set_in_force_token(token)
    backend = _backend(gate)
    decision = backend.evaluate(
        {"tool_name": "transfer_funds", "agent_id": "agent:pay", "arguments": {"to": "ACC-001"}}
    )
    assert decision.allowed is True
    assert not hasattr(decision, "proof_artefact")
