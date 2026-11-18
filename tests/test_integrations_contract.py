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
import os
import pathlib
import subprocess
import sys
import types
from dataclasses import dataclass, field
from typing import Any

import pytest

from raucle.audit import Ed25519Signer
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations import agt_backend as agt_backend_mod
from raucle.integrations import crewai as crewai_mod

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

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
    # D1: restore the PRIOR module state, not a hardcoded False - when the
    # crewai extra is installed (the integration-extras CI job), clobbering
    # _HAS_CREWAI to False here would poison every later crewai test in the
    # same pytest process.
    had_crewai = crewai_mod._HAS_CREWAI
    prev_base_tool = crewai_mod.BaseTool
    crewai_mod._HAS_CREWAI = True
    crewai_mod.BaseTool = _StubBaseTool
    yield crewai_mod
    crewai_mod._HAS_CREWAI = had_crewai
    crewai_mod.BaseTool = prev_base_tool


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


def test_guarded_tool_unattributed_denies(crewai_integration, tmp_path, issued):
    """D1: bearer mode is closed - a valid token does not authorise a call
    with no bound caller identity, and the deny is receipted honestly."""
    _issuer, gate, token = issued
    mod = crewai_integration
    mod.set_in_force_token(token)
    tool = _PayTool()
    guarded = mod.guard_tool(tool, gate=gate, sink=_sink(tmp_path))  # no agent_id bound
    with pytest.raises(mod.CapabilityDenied, match="no acting agent identity"):
        guarded._run(to="ACC-001")
    assert not getattr(tool, "ran", False)  # body never executed
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    events = []
    for line in lines:
        rec = json.loads(line)
        events.append(rec.get("event", rec))
    receipts = [e for e in events if e.get("kind") == "capability_receipt"]
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["agent_id"] is None  # honest null, never a placeholder
    assert "unbound" not in json.dumps(receipts[0]), receipts[0]


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


# ---------------------------------------------------------------------------
# P2a adapters (pydantic-ai, google-adk): the same contract shape the crewai
# stand-in section pins, so the wrapper's own surface is covered even in the
# hermetic dev env where the extras are absent. The real-framework suites
# (test_pydantic_ai_integration.py / test_google_adk_integration.py) own the
# end-to-end proof and run in the integration-extras CI jobs.
# ---------------------------------------------------------------------------


class _StubRunContextAgent:
    """The Agent surface the pydantic-ai guard reads (name only)."""

    def __init__(self, name: str | None) -> None:
        self.name = name


class _StubRunContext:
    """The RunContext surface the guard reads: agent -> name."""

    def __init__(self, agent_name: str | None) -> None:
        self.agent = _StubRunContextAgent(agent_name)
        self.deps = None


@pytest.fixture
def pydantic_ai_stub(monkeypatch):
    tools_mod = types.ModuleType("pydantic_ai.tools")
    tools_mod.RunContext = _StubRunContext  # type: ignore[attr-defined]
    pkg = types.ModuleType("pydantic_ai")
    pkg.tools = tools_mod  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pydantic_ai", pkg)
    monkeypatch.setitem(sys.modules, "pydantic_ai.tools", tools_mod)
    import raucle.integrations.pydantic_ai as pa_mod

    # D1 rule: restore the PRIOR module state, never hardcode the
    # absent-state, so an extras venv's real flag is not poisoned.
    had = pa_mod._HAS_PYDANTIC_AI
    pa_mod._HAS_PYDANTIC_AI = True
    yield pa_mod
    pa_mod._HAS_PYDANTIC_AI = had


@pytest.fixture
def google_adk_stub(monkeypatch):
    tools_mod = types.ModuleType("google.adk.tools")

    class _StubToolContext:  # the surface the guard reads (invocation context)
        def __init__(self, invocation_context=None):  # noqa: ANN001
            self._invocation_context = invocation_context

    tools_mod.ToolContext = _StubToolContext  # type: ignore[attr-defined]
    adk_mod = types.ModuleType("google.adk")
    adk_mod.tools = tools_mod  # type: ignore[attr-defined]
    google_pkg = types.ModuleType("google")
    google_pkg.adk = adk_mod  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", google_pkg)
    monkeypatch.setitem(sys.modules, "google.adk", adk_mod)
    monkeypatch.setitem(sys.modules, "google.adk.tools", tools_mod)
    import raucle.integrations.google_adk as adk_guard

    had = adk_guard._HAS_GOOGLE_ADK
    adk_guard._HAS_GOOGLE_ADK = True
    yield adk_guard
    adk_guard._HAS_GOOGLE_ADK = had


def test_pydantic_ai_guard_without_pydantic_ai_raises(monkeypatch, tmp_path, issued):
    _issuer, gate, _token = issued
    import raucle.integrations.pydantic_ai as pa_mod

    monkeypatch.setattr(pa_mod, "_HAS_PYDANTIC_AI", False)
    sink = _sink(tmp_path)
    with pytest.raises(RuntimeError, match="pydantic-ai"):
        pa_mod.guard_tool(lambda ctx, to: to, gate=gate, sink=sink)


def test_pydantic_ai_guard_unattributed_denies(pydantic_ai_stub, tmp_path, issued):
    """Bearer mode is closed: a valid token does not authorise a call with
    no bound caller identity, and the deny is receipted honestly."""
    _issuer, gate, token = issued
    pa_mod = pydantic_ai_stub
    pa_mod.set_in_force_token(token)
    ran: list = []

    def lookup(ctx: object, to: str) -> str:  # noqa: ARG001
        ran.append(to)
        return f"LOOKED UP {to}"

    guarded = pa_mod.guard_tool(lookup, gate=gate, sink=_sink(tmp_path))  # no agent_id bound
    stub_ctx = _StubRunContext(None)
    with pytest.raises(pa_mod.CapabilityDenied, match="no acting agent identity"):
        guarded(stub_ctx, to="ACC-001")
    assert ran == []
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    events = [json.loads(line).get("event", json.loads(line)) for line in lines]
    receipts = [e for e in events if e.get("kind") == "capability_receipt"]
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["agent_id"] is None
    assert "unbound" not in json.dumps(receipts[0])


def test_pydantic_ai_guard_attributed_allow_receipts(pydantic_ai_stub, tmp_path, issued):
    _issuer, gate, token = issued
    pa_mod = pydantic_ai_stub
    pa_mod.set_in_force_token(token)
    guarded = pa_mod.guard_tool(
        _pyd_transfer_funds(),
        gate=gate,
        sink=_sink(tmp_path),
        agent_id="agent:pay",
    )
    assert guarded(_StubRunContext("agent:pay"), to="ACC-001") == "TRANSFERRED ACC-001"
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    events = [json.loads(line).get("event", json.loads(line)) for line in lines]
    receipts = [e for e in events if e.get("kind") == "capability_receipt"]
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["agent_id"] == "agent:pay"


def _pyd_transfer_funds():
    # Declared under the stub the fixture installs, so the guard's
    # ctx-detection (annotation text) recognises the parameter and the
    # run-context identity path is genuinely exercised.
    from pydantic_ai.tools import RunContext

    def transfer_funds(ctx: RunContext, to: str) -> str:
        return f"TRANSFERRED {to}"

    return transfer_funds


def test_pydantic_ai_context_supplies_identity(pydantic_ai_stub, tmp_path, issued):
    """The run context's agent name binds the call when nothing is pinned."""
    _issuer, gate, token = issued
    pa_mod = pydantic_ai_stub
    pa_mod.set_in_force_token(token)
    guarded = pa_mod.guard_tool(_pyd_transfer_funds(), gate=gate, sink=_sink(tmp_path))
    guarded(_StubRunContext("agent:pay"), to="ACC-001")
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    events = [json.loads(line).get("event", json.loads(line)) for line in lines]
    receipts = [e for e in events if e.get("kind") == "capability_receipt"]
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["agent_id"] == "agent:pay"


def test_google_adk_guard_without_google_adk_raises(monkeypatch, tmp_path, issued):
    _issuer, gate, _token = issued
    import raucle.integrations.google_adk as adk_guard

    monkeypatch.setattr(adk_guard, "_HAS_GOOGLE_ADK", False)
    sink = _sink(tmp_path)
    with pytest.raises(RuntimeError, match="google-adk"):
        adk_guard.guard_tool(lambda args, tc: args, gate=gate, sink=sink)


def test_google_adk_guard_unattributed_denies(google_adk_stub, tmp_path, issued):
    _issuer, gate, token = issued
    adk_guard = google_adk_stub
    adk_guard.set_in_force_token(token)
    ran: list = []

    def lookup(args: dict, tool_context: object) -> dict:  # noqa: ARG001
        ran.append(dict(args))
        return {"ok": True}

    guarded = adk_guard.guard_tool(lookup, gate=gate, sink=_sink(tmp_path))  # no agent_id
    from google.adk.tools import ToolContext as _TC  # the stub installed above

    with pytest.raises(adk_guard.CapabilityDenied, match="no acting agent identity"):
        guarded({"to": "ACC-001"}, _TC(invocation_context=None))
    assert ran == []
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    events = [json.loads(line).get("event", json.loads(line)) for line in lines]
    receipts = [e for e in events if e.get("kind") == "capability_receipt"]
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["agent_id"] is None
    assert "unbound" not in json.dumps(receipts[0])


def test_module_import_survives_without_pydantic_ai_subprocess(tmp_path):
    """A clean interpreter without pydantic-ai imports the adapter fine; a
    blocker package shadowing any installed pydantic_ai constructs the
    absence under every install shape (the langgraph rule)."""
    blocker = tmp_path / "no_pydantic_ai"
    (blocker / "pydantic_ai").mkdir(parents=True)
    (blocker / "pydantic_ai" / "__init__.py").write_text(
        'raise ImportError("pydantic_ai blocked: raucle import-survival test")\n'
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(blocker)
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from raucle.integrations import pydantic_ai as m;"
            "print(m._HAS_PYDANTIC_AI);"
            "print('guard_tool' in m.__all__)",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.splitlines() == ["False", "True"]


def test_module_import_survives_without_google_adk_subprocess(tmp_path):
    """Same rule for google-adk: the blocker shadows google.adk only (the
    google namespace itself stays intact)."""
    blocker = tmp_path / "no_google_adk"
    (blocker / "google" / "adk").mkdir(parents=True)
    (blocker / "google" / "adk" / "__init__.py").write_text(
        'raise ImportError("google.adk blocked: raucle import-survival test")\n'
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(blocker)
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from raucle.integrations import google_adk as m;"
            "print(m._HAS_GOOGLE_ADK);"
            "print('guard_tool' in m.__all__)",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.splitlines() == ["False", "True"]
