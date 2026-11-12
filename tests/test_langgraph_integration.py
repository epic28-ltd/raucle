"""End-to-end tests for the LangGraph integration (tool-node layer).

LangGraph is not a dev dependency (the dev extra must stay hermetic and
resolvable on every CI python), so — per the house skip-decision pattern
(``tests/test_integrations_contract.py``) — these tests exercise the genuine
``raucle.integrations.langgraph`` code against a faithful, minimal stand-in
for the langgraph surface the adapter consumes:

* ``langgraph.prebuilt.ToolNode`` — the public node contract (tools by name,
  tool-call execution, exception → tool-response presentation under
  ``handle_tool_errors=True``) our ``RaucleToolNode`` subclasses;
* a ``StructuredTool``-shaped object (``name``/``description``/``args_schema``
  + ``func``/``coroutine`` slots + ``model_copy``) the copy-path wrapper
  rebinds.

These are contract tests for OUR surface — gating, receipts, token binding,
graceful degradation, chain integrity — not mocks of raucle. The module's
top-level import itself (this file) proves the adapter never imports
langgraph at import time. When a langgraph extra is installed in a matrix
environment, a real-SDK tripwire test along the ``test_agent_framework_real``
pattern can follow.

Coverage classes mirror ``test_crewai_integration.py`` /
``test_agent_framework_real.py``: allowed call receipted; denied call
receipts a deny with the exception presented to the graph; degraded gate;
capability-token binding; receipt chain integrity; offline verification.
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import pathlib
import subprocess
import sys
import types
from dataclasses import dataclass, field
from typing import Any

import pytest

pytest.importorskip("cryptography")

import raucle.integrations.langgraph as lg  # noqa: E402 (import itself is the proof)
from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# langgraph stand-ins: the public surface the adapter consumes
# ---------------------------------------------------------------------------


@dataclass
class _StubToolMessage:
    """The tool response the graph sees (content carries the denial)."""

    content: Any
    tool_call_id: str = ""
    name: str = ""


@dataclass
class _StubAIMessage:
    """Model node output carrying tool_calls (never touched by the adapter)."""

    tool_calls: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _StubState:
    messages: list[Any]


class _StubToolNode:
    """Faithful minimal ToolNode: executes tool_calls, presents errors.

    Mirrors langgraph.prebuilt.ToolNode's documented node contract: look up
    each tool call's tool by name, execute it with the call args, and — under
    ``handle_tool_errors=True`` (ToolNode's default) — present a raised
    exception's message as the tool response instead of collapsing the node.
    """

    def __init__(self, tools: Any, *, handle_tool_errors: bool = True, **kwargs: Any) -> None:
        self.handle_tool_errors = handle_tool_errors
        self.tools_by_name: dict[str, Any] = {}
        for t in tools:
            name = getattr(t, "name", None) or getattr(t, "__name__", "<unknown>")
            self.tools_by_name[name] = t

    def _execute(self, tool: Any, tool_input: Any) -> Any:
        if hasattr(tool, "invoke"):
            return tool.invoke(tool_input)
        if isinstance(tool_input, dict):
            return tool(**tool_input)
        return tool(tool_input)

    def node(self, state: Any) -> dict[str, Any]:
        last = state.messages[-1]
        out: list[_StubToolMessage] = []
        for tc in getattr(last, "tool_calls", []):
            tool = self.tools_by_name[tc["name"]]
            try:
                content: Any = self._execute(tool, tc["args"])
            except Exception as exc:  # the ToolNode presentation contract
                if not self.handle_tool_errors:
                    raise
                content = f"Error: {exc}"
            out.append(_StubToolMessage(content=content, tool_call_id=tc.get("id", "")))
        return {"messages": out}

    async def anode(self, state: Any) -> dict[str, Any]:
        last = state.messages[-1]
        out: list[_StubToolMessage] = []
        for tc in getattr(last, "tool_calls", []):
            tool = self.tools_by_name[tc["name"]]
            try:
                result = self._execute(tool, tc["args"])
                if inspect.isawaitable(result):
                    result = await result
            except Exception as exc:
                if not self.handle_tool_errors:
                    raise
                result = f"Error: {exc}"  # type: ignore[assignment]
            out.append(_StubToolMessage(content=result, tool_call_id=tc.get("id", "")))
        return {"messages": out}

    def invoke(self, state: Any) -> dict[str, Any]:
        return self.node(state)


class _StubStructuredTool:
    """Minimal StructuredTool shape: name/description/args_schema + slots."""

    def __init__(
        self,
        *,
        name: str,
        description: str = "",
        func: Any = None,
        coroutine: Any = None,
        args_schema: Any = None,
    ) -> None:
        self.name = name
        self.description = description
        self.func = func
        self.coroutine = coroutine
        self.args_schema = args_schema

    def model_copy(self, *, deep: bool = False) -> _StubStructuredTool:
        return _StubStructuredTool(
            name=self.name,
            description=self.description,
            func=self.func,
            coroutine=self.coroutine,
            args_schema=self.args_schema,
        )

    def invoke(self, tool_input: Any, config: Any = None) -> Any:
        if self.func is None:  # pragma: no cover - mirrors StructuredTool's refusal
            raise NotImplementedError("tool has no synchronous implementation")
        if isinstance(tool_input, dict):
            return self.func(**tool_input)
        return self.func(tool_input)

    async def ainvoke(self, tool_input: Any, config: Any = None) -> Any:
        if self.coroutine is None:  # pragma: no cover - mirrors StructuredTool's refusal
            raise NotImplementedError("tool has no asynchronous implementation")
        call = (
            self.coroutine(**tool_input)
            if isinstance(tool_input, dict)
            else self.coroutine(tool_input)
        )
        return await call


# ---------------------------------------------------------------------------
# Test tool: the body records its own execution
# ---------------------------------------------------------------------------


@dataclass
class _Body:
    calls: list[dict[str, Any]] = field(default_factory=list)


_body = _Body()


def transfer_funds(to: str, amount: int) -> str:
    """Test tool: records the call, then moves the (imaginary) money."""
    _body.calls.append({"to": to, "amount": amount})
    return f"TRANSFERRED {amount} -> {to}"


async def atransfer_funds(to: str, amount: int) -> str:
    return f"TRANSFERRED {amount} -> {to}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def lg_installed(monkeypatch: pytest.MonkeyPatch):
    """Make ``langgraph`` importable as the faithful stub and reload the
    adapter, so ``RaucleToolNode`` genuinely subclasses the standing
    ``ToolNode`` base (the real SDK's registration path)."""
    prebuilt = types.ModuleType("langgraph.prebuilt")
    prebuilt.ToolNode = _StubToolNode  # type: ignore[attr-defined]
    langgraph_pkg = types.ModuleType("langgraph")
    langgraph_pkg.prebuilt = prebuilt  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langgraph", langgraph_pkg)
    monkeypatch.setitem(sys.modules, "langgraph.prebuilt", prebuilt)
    importlib.reload(lg)
    assert lg._HAS_LANGGRAPH is True
    yield lg
    importlib.reload(lg)


def _sink(tmp_path: pathlib.Path) -> HashChainSink:
    return HashChainSink(
        tmp_path / "receipts.jsonl",
        signer=Ed25519Signer.generate(),
    )


@pytest.fixture
def issued() -> Any:
    """One issuer (mints from it twice where a second token is needed)."""
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:pay",
        tool="transfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "allowed_values": {"to": ["ACC-001"]},
        },
        ttl_seconds=300,
        policy_proof_hash="ab" * 32,
    )
    return issuer, gate, token


def _node(lgmod: Any, gate: Any, sink: Any, *, agent_id: str = "agent:pay", **kwargs: Any) -> Any:
    return lgmod.RaucleToolNode([transfer_funds], gate=gate, sink=sink, agent_id=agent_id, **kwargs)


def _graph_state(call_args: dict[str, Any], call_id: str = "call-1") -> _StubState:
    return _StubState(
        messages=[
            _StubAIMessage(),
            _StubAIMessage(
                tool_calls=[{"name": "transfer_funds", "args": call_args, "id": call_id}]
            ),
        ]
    )


def _chain_events(path: pathlib.Path) -> list[dict[str, Any]]:
    """Parse the hash-chain file through the ``event`` wrapper (house rule)."""
    events = []
    for line in path.read_text().strip().splitlines():
        rec = json.loads(line)
        events.append(rec.get("event", rec))
    return [e for e in events if e.get("kind") == "capability_receipt"]


# ---------------------------------------------------------------------------
# Degraded gate
# ---------------------------------------------------------------------------


@pytest.fixture
def _no_langgraph(monkeypatch, tmp_path, issued):
    """Missing host framework: import survives (module-level); fixture
    applies the degraded state so the tests below contain exactly one
    invocation that can raise."""
    _, gate, _ = issued
    monkeypatch.setattr(lg, "_HAS_LANGGRAPH", False)
    return _sink(tmp_path), gate


def test_gate_tool_without_langgraph_raises_runtime_error(_no_langgraph):
    """gate_tool refuses with the install hint — the adapter degrades, never half-works."""
    sink, gate = _no_langgraph
    with pytest.raises(RuntimeError, match="langgraph"):
        lg.gate_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:pay")


def test_raucle_tool_node_without_langgraph_raises_runtime_error(_no_langgraph):
    """RaucleToolNode instantiation refuses with the same install hint."""
    sink, gate = _no_langgraph
    with pytest.raises(RuntimeError, match="langgraph"):
        lg.RaucleToolNode([transfer_funds], gate=gate, sink=sink, agent_id="agent:pay")


def test_module_import_survives_without_langgraph_subprocess():
    """A clean interpreter without langgraph imports the adapter module fine."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from raucle.integrations import langgraph as m;"
            "print(m._HAS_LANGGRAPH);"
            "print('RaucleToolNode' in m.__all__)",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.splitlines() == ["False", "True"]


def test_sink_failure_aborts_allow(lg_installed, tmp_path, issued):
    """Degraded receipt layer: an in-flight ALLOW is aborted — an action
    without its receipt is treated as unauthorised (fail-closed)."""
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)

    class _BrokenSink:
        def append(self, event: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("audit storage unavailable")

        def close(self) -> None:
            pass

    gated = lg_installed.gate_tool(
        transfer_funds, gate=gate, sink=_BrokenSink(), agent_id="agent:pay"
    )
    _body.calls.clear()
    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        gated(to="ACC-001", amount=50)
    assert _body.calls == []


# ---------------------------------------------------------------------------
# Allowed call receipted (+ interface preservation, the wraps contract)
# ---------------------------------------------------------------------------


def test_allowed_plain_callable_runs_and_receipts(lg_installed, tmp_path, issued):
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)
    sink = _sink(tmp_path)
    gated = lg_installed.gate_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:pay")
    _body.calls.clear()
    assert gated(to="ACC-001", amount=50) == "TRANSFERRED 50 -> ACC-001"
    assert _body.calls == [{"to": "ACC-001", "amount": 50}]
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "ALLOW"
    assert receipts[0]["tool"] == "transfer_funds"
    assert receipts[0]["framework"] == "langgraph"
    assert receipts[0]["agent_id"] == "agent:pay"
    assert receipts[0]["attenuation_chain"] == [token.token_id]
    assert receipts[0]["call_args_hash"] == lg._hash_args({"to": "ACC-001", "amount": 50})


def test_structured_tool_copy_preserves_interface(lg_installed, tmp_path, issued):
    """The model-visible tool (name/description/args_schema) is unchanged."""
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)
    sink = _sink(tmp_path)
    inner = _StubStructuredTool(
        name="transfer_funds",
        description="Transfer money",
        func=transfer_funds,
        args_schema={"to": "str", "amount": "int"},
    )
    gated = lg_installed.gate_tool(inner, gate=gate, sink=sink, agent_id="agent:pay")
    assert gated is not inner
    assert gated.name == "transfer_funds"
    assert gated.description == "Transfer money"
    assert gated.args_schema == inner.args_schema
    assert gated.invoke({"to": "ACC-001", "amount": 50}) == "TRANSFERRED 50 -> ACC-001"
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert receipts[0]["decision"] == "ALLOW"


def test_wrapped_callable_preserves_signature(lg_installed, tmp_path, issued):
    """House B2 rule: host frameworks derive the tool's args model from
    inspect.signature — the gate wrapper must not break that."""
    _issuer, gate, _token = issued
    gated = lg_installed.gate_tool(
        transfer_funds, gate=gate, sink=_sink(tmp_path), agent_id="agent:pay"
    )
    assert str(inspect.signature(gated)) == str(inspect.signature(transfer_funds))


def test_raucle_tool_node_is_a_host_toolnode(lg_installed, tmp_path, issued):
    """The framework's isinstance/registration contract: a RaucleToolNode
    IS a ToolNode (it subclasses the standing ToolNode base)."""
    _issuer, gate, _token = issued
    node = _node(lg_installed, gate, _sink(tmp_path))
    assert isinstance(node, _StubToolNode)
    assert _StubToolNode in node.__class__.__mro__


# ---------------------------------------------------------------------------
# Denied call: receipted deny + exception presented to the graph
# ---------------------------------------------------------------------------


def test_denied_call_receipts_deny_and_message_reaches_graph(lg_installed, tmp_path, issued):
    """Constraint-violating call: the tool body never runs, CapabilityDenied's
    message is presented to the graph as the tool response, DENY receipted."""
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)
    sink = _sink(tmp_path)
    node = _node(lg_installed, gate, sink)
    _body.calls.clear()
    state = _graph_state({"to": "ACC-999", "amount": 9900})
    result = node.node(state)
    assert _body.calls == []  # body never executed
    msg = result["messages"][0]
    assert "raucle denied 'transfer_funds'" in msg.content
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "DENY"


@pytest.mark.asyncio
async def test_denial_presented_on_async_graph_path(lg_installed, tmp_path, issued):
    """Async node execution presents the denial the same way, receipted."""
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)
    sink = _sink(tmp_path)
    node = _node(lg_installed, gate, sink)
    _body.calls.clear()
    state = _graph_state({"to": "ACC-001", "amount": 9900})  # max_value violated
    result = await node.anode(state)
    assert _body.calls == []
    msg = result["messages"][0]
    assert "raucle denied 'transfer_funds'" in msg.content
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert receipts[0]["decision"] == "DENY"


@pytest.fixture
def _deny_node(lg_installed, tmp_path, issued):
    """handle_tool_errors=False node bound to one in-force token, prepared
    outside the exception test so it holds a single possibly-throwing
    invocation."""
    _, gate, token = issued
    lg_installed.set_in_force_token(token)
    node = _node(lg_installed, gate, _sink(tmp_path), handle_tool_errors=False)
    _body.calls.clear()
    return node


def test_error_presentation_disabled_propagates_no_weakening(_deny_node):
    """handle_tool_errors=False: the denial propagates to the graph author
    instead of a tool message — the tool body still never ran."""
    state = _graph_state({"to": "ACC-999"})  # state built before the raise scope
    with pytest.raises(lg.CapabilityDenied):
        _deny_node.node(state)
    assert _body.calls == []


# ---------------------------------------------------------------------------
# Capability-token binding
# ---------------------------------------------------------------------------


def test_no_token_denies_receipted(lg_installed, tmp_path, issued):
    """Fail-closed with no token in force: deny presented to the graph and
    receipted (an attributable boundary of the adapter, not noise)."""
    _issuer, gate, _token = issued
    lg_installed.set_in_force_token(None)
    sink = _sink(tmp_path)
    node = _node(lg_installed, gate, sink)
    _body.calls.clear()
    result = node.node(_graph_state({"to": "ACC-001", "amount": 50}))
    assert _body.calls == []
    assert "no in-force capability token" in result["messages"][0].content
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert receipts[0]["decision"] == "DENY"
    assert receipts[0]["decision_reason"] == "no in-force capability token"


def test_empty_agent_id_denies_receipted(lg_installed, tmp_path, issued):
    """B2: an empty agent_id is not an identity — deny, never a placeholder."""
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)
    sink = _sink(tmp_path)
    node = _node(lg_installed, gate, sink, agent_id="")
    _body.calls.clear()
    result = node.node(_graph_state({"to": "ACC-001", "amount": 50}))
    assert _body.calls == []
    assert "no acting agent identity" in result["messages"][0].content
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert receipts[0]["decision"] == "DENY"


def test_agent_mismatch_denies_attributable(lg_installed, tmp_path, issued):
    """The gate enforces the token's agent scope against the CALLER's agent
    id (forwarded, not tautological)."""
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)
    sink = _sink(tmp_path)
    node = _node(lg_installed, gate, sink, agent_id="agent:other")
    _body.calls.clear()
    result = node.node(_graph_state({"to": "ACC-001", "amount": 50}))
    assert _body.calls == []
    assert "does not match token" in result["messages"][0].content
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert receipts[0]["decision"] == "DENY"


def test_out_of_scope_tool_denies_receipted(lg_installed, tmp_path, issued):
    """A token bound for a different tool denies on this tool's call
    (second token minted from the SAME issuer, per the house fixture rule)."""
    issuer, gate, _token = issued
    other = issuer.mint(
        agent_id="agent:pay",
        tool="read_balance",
        constraints={},
        ttl_seconds=300,
    )
    lg_installed.set_in_force_token(other)
    sink = _sink(tmp_path)
    node = _node(lg_installed, gate, sink)
    _body.calls.clear()
    result = node.node(_graph_state({"to": "ACC-001", "amount": 50}))
    assert _body.calls == []
    assert "token bound to tool 'read_balance'" in result["messages"][0].content
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert receipts[0]["decision"] == "DENY"


def test_token_resolver_binds_dynamically(lg_installed, tmp_path, issued):
    """Per-tenant binding: the resolver, not a static token, decides."""
    _unused_issuer, gate, minted = issued
    lg_installed.set_in_force_token(None)  # static contextvar deliberately empty
    tenant_tokens = {"acme.bank": minted, "attacker.bank": None}
    resolver_calls: list[str] = []

    def resolver(tool_name: str) -> Any:
        resolver_calls.append(tool_name)
        return tenant_tokens["attacker.bank"]

    sink = _sink(tmp_path)
    node = lg_installed.RaucleToolNode(
        [transfer_funds],
        gate=gate,
        sink=sink,
        agent_id="agent:pay",
        token_resolver=resolver,
    )
    _body.calls.clear()
    result = node.node(_graph_state({"to": "ACC-001", "amount": 50}))
    assert _body.calls == []
    assert "no in-force capability token" in result["messages"][0].content
    assert resolver_calls == ["transfer_funds"]


# ---------------------------------------------------------------------------
# Receipt chain integrity + offline verification
# ---------------------------------------------------------------------------


def test_allow_and_deny_land_in_one_verifiable_chain(lg_installed, tmp_path, issued):
    """Both decisions in one hash chain; the public verifier accepts it."""
    _issuer, gate, token = issued
    signer = Ed25519Signer.generate()
    log = tmp_path / "receipts.jsonl"
    sink = HashChainSink(log, signer=signer)
    lg_installed.set_in_force_token(token)
    node = _node(lg_installed, gate, sink)
    _body.calls.clear()
    node.node(_graph_state({"to": "ACC-001", "amount": 50}, call_id="c-allow"))
    node.node(_graph_state({"to": "ACC-999", "amount": 9900}, call_id="c-deny"))
    sink.close()
    report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(log)
    assert report.valid
    assert report.event_count == 2


def test_offline_receipt_payload_carries_bound_fields(lg_installed, tmp_path, issued):
    """Decode the chain bytes: the receipt binds issuer, policy proof, tool,
    agent, args hash and the delegated chain — the offline verification set."""
    _issuer, gate, token = issued
    signer = Ed25519Signer.generate()
    log = tmp_path / "receipts.jsonl"
    sink = HashChainSink(log, signer=signer)
    lg_installed.set_in_force_token(token)
    node = _node(lg_installed, gate, sink)
    _body.calls.clear()
    node.node(_graph_state({"to": "ACC-001", "amount": 50}))
    sink.close()
    report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(log)
    assert report.valid
    allow = _chain_events(log)[0]
    assert allow["decision"] == "ALLOW"
    assert allow["issuer"] == "acme.bank"
    assert allow["policy_proof_hash"] == "ab" * 32
    assert allow["agent_id"] == "agent:pay"
    assert allow["tool"] == "transfer_funds"
    assert allow["framework"] == "langgraph"
    assert allow["lean_theorem_id"] == "vcd.gate_soundness"
    assert allow["attenuation_chain"] == [token.token_id]
    assert allow["call_args_hash"].startswith("sha256:")
    assert allow["call_args_hash"] == lg._hash_args({"to": "ACC-001", "amount": 50})
    assert allow["timestamp"].endswith("Z")


# ---------------------------------------------------------------------------
# Convenience + async tool slot
# ---------------------------------------------------------------------------


def test_gate_tools_wraps_a_list(lg_installed, tmp_path, issued):
    """The create_react_agent ``tools=`` path: every tool is gated."""
    _issuer, gate, _token = issued
    tools = lg_installed.gate_tools(
        [transfer_funds, transfer_funds], gate=gate, sink=_sink(tmp_path), agent_id="agent:pay"
    )
    assert len(tools) == 2
    assert all(getattr(t, "__name__", "") == "transfer_funds" for t in tools)


@pytest.mark.asyncio
async def test_async_tool_slot_gated(lg_installed, tmp_path, issued):
    """A coroutine-slot tool (async @tool) is gated on the async path too."""
    _issuer, gate, token = issued
    lg_installed.set_in_force_token(token)
    sink = _sink(tmp_path)
    async_tool = _StubStructuredTool(name="transfer_funds", coroutine=atransfer_funds)
    gated = lg_installed.gate_tool(async_tool, gate=gate, sink=sink, agent_id="agent:pay")
    assert gated.coroutine is not atransfer_funds  # the gated handler is bound in
    assert await gated.ainvoke({"to": "ACC-001", "amount": 50}) == "TRANSFERRED 50 -> ACC-001"
    with pytest.raises(lg.CapabilityDenied):
        await gated.ainvoke({"to": "ACC-999", "amount": 9900})
    receipts = _chain_events(tmp_path / "receipts.jsonl")
    assert [r["decision"] for r in receipts] == ["ALLOW", "DENY"]
