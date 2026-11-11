"""End-to-end tests for ``raucle.integrations.autogen`` (``gated_tools``).

These tests do NOT require the real ``autogen-agentchat`` package. They
exercise the adapter contract through a stand-in ``FunctionTool`` that
mirrors the documented AutoGen 0.4 tool shape (``_func``, ``name``,
``description``, async ``run_json``) — the same mock-boundary pattern as
``tests/test_agent_framework_integration.py``.

Contract paths verified — every decision must MINT A RECEIPT:

    1. No token in force → DENY receipt, ``CapabilityDenied``, tool not
       invoked (fail-closed on the missing capability token).
    2. Token in force, args within scope → ALLOW receipt, tool invoked,
       result returned.
    3. Token in force, args beyond scope → DENY receipt,
       ``CapabilityDenied``, tool not invoked.
    4. Both decisions land in a chain that verifies offline.
"""

from __future__ import annotations

import functools
import inspect
import typing

import pytest

pytest.importorskip("cryptography")

import raucle.integrations.autogen as autogen  # noqa: E402
from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.autogen import (  # noqa: E402
    CapabilityDenied,
    gated_tools,
    get_in_force_token,
    set_in_force_token,
)


class StubFunctionTool:
    """Stand-in mirroring autogen_core.tools.FunctionTool's documented shape.

    The real class stores the callable, builds an args model from its
    signature (via ``inspect``/``__wrapped__``) and ``run_json`` dispatches
    keyword arguments to the handler.
    """

    def __init__(
        self, func: typing.Callable, *, name: str | None = None, description: str = ""
    ) -> None:
        self._func = func
        self.name = name or func.__name__
        self.description = description

    async def run_json(self, args: dict, cancellation_token: object = None) -> typing.Any:
        result = self._func(**args)
        if inspect.isawaitable(result):
            result = await result
        return result


def lookup_customer(customer_id: str) -> dict:
    return {"customer_id": customer_id, "email": "c@example.com"}


@pytest.fixture(autouse=True)
def _patch_function_tool(monkeypatch: pytest.MonkeyPatch):
    """Point the adapter's import-guard at the documented stand-in shape."""
    monkeypatch.setattr(autogen, "_HAS_AUTOGEN", True)
    monkeypatch.setattr(autogen, "FunctionTool", StubFunctionTool)
    set_in_force_token(None)
    yield
    set_in_force_token(None)


@pytest.fixture
def issuer() -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer="acme.test.kyc")


@pytest.fixture
def gate(issuer: CapabilityIssuer) -> CapabilityGate:
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


class CapturingSink:
    """In-memory sink: records the appended receipt dicts (autogen adapter
    appends the receipt payload itself, unlike the middleware adapters'
    {"receipt": ...} envelopes)."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def append(self, event: dict) -> dict:
        self.events.append(event)
        return {}

    def close(self) -> None:
        pass


@pytest.fixture
def sink() -> CapturingSink:
    return CapturingSink()


def _mint(
    issuer: CapabilityIssuer, *, tool: str = "lookup_customer", constraints: dict | None = None
):
    return issuer.mint(
        agent_id="agent:test-1",
        tool=tool,
        constraints=constraints if constraints is not None else {},
        ttl_seconds=60,
    )


# ---------------------------------------------------------------------------
# Path tests


@pytest.mark.asyncio
async def test_allow_path_invokes_handler_and_receipts(issuer, gate, sink):
    """Path 2: token + matching args → ALLOW receipt, handler invoked."""
    set_in_force_token(_mint(issuer))
    tool = gated_tools(
        [StubFunctionTool(lookup_customer)], gate=gate, sink=sink, agent_id="agent:test-1"
    )[0]
    out = await tool.run_json({"customer_id": "C-1042"})
    assert out == {"customer_id": "C-1042", "email": "c@example.com"}
    assert len(sink.events) == 1, "exactly one receipt per decision"
    receipt = sink.events[0]
    assert receipt["decision"] == "ALLOW"
    assert receipt["tool"] == "lookup_customer"
    assert receipt["agent_id"] == "agent:test-1"
    assert receipt["call_args_hash"].startswith("sha256:")
    assert receipt["issuer"] == "acme.test.kyc"
    assert receipt["lean_theorem_id"] == "vcd.gate_soundness"


@pytest.mark.asyncio
async def test_allow_path_via_token_resolver(issuer, gate, sink):
    """The token_resolver seam must be honoured, not just the contextvar."""
    token = _mint(issuer)

    def resolver(tool_name: str):
        return token

    tool = gated_tools(
        [StubFunctionTool(lookup_customer)],
        gate=gate,
        sink=sink,
        agent_id="agent:test-1",
        token_resolver=resolver,
    )[0]
    out = await tool.run_json({"customer_id": "C-1042"})
    assert out is not None
    assert sink.events[0]["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_no_token_fails_closed_with_deny_receipt(issuer, gate, sink):
    """Path 1 FAIL-CLOSED: no in-force token → DENY receipt, no execution."""
    invoked: list[bool] = []

    def handler(**kwargs):
        invoked.append(True)
        return {}

    tool = gated_tools(
        [StubFunctionTool(handler, name="lookup_customer")],
        gate=gate,
        sink=sink,
        agent_id="agent:test-1",
    )[0]
    with pytest.raises(CapabilityDenied):
        await tool.run_json({"customer_id": "C-1042"})
    assert invoked == [], "a call with no in-force token must never reach the tool"
    assert len(sink.events) == 1
    receipt = sink.events[0]
    assert receipt["decision"] == "DENY"
    assert "no in-force capability token" in receipt["decision_reason"]


@pytest.mark.asyncio
async def test_out_of_scope_args_denied_and_receipted(issuer, gate, sink):
    """Path 3: token scopes the tool but the args break a constraint."""
    set_in_force_token(_mint(issuer, constraints={"starts_with": {"customer_id": "C-"}}))
    tool = gated_tools(
        [StubFunctionTool(lookup_customer)], gate=gate, sink=sink, agent_id="agent:test-1"
    )[0]
    with pytest.raises(CapabilityDenied):
        await tool.run_json({"customer_id": "ATTACKER"})
    receipt = sink.events[0]
    assert receipt["decision"] == "DENY"
    assert receipt["call_args_hash"].startswith("sha256:")


@pytest.mark.asyncio
async def test_wrong_tool_denies(issuer, gate, sink):
    """Token authorises tool X; call requests tool Y → DENY, no execution."""
    set_in_force_token(_mint(issuer, tool="lookup_customer"))
    invoked: list[bool] = []

    def transfer(**kwargs):
        invoked.append(True)

    tool = gated_tools(
        [StubFunctionTool(transfer, name="transfer_funds")],
        gate=gate,
        sink=sink,
        agent_id="agent:test-1",
    )[0]
    with pytest.raises(CapabilityDenied):
        await tool.run_json({"to": "attacker", "amount": 100})
    assert invoked == []
    assert sink.events[0]["decision"] == "DENY"
    assert sink.events[0]["tool"] == "transfer_funds"


@pytest.mark.asyncio
async def test_wrong_agent_scope_denies(issuer, gate, sink):
    """A token minted for agent A must not authorise a call stamped agent B.

    This pins the round-3 fix: the adapter forwards agent_id into
    gate.check so the gate enforces the token's agent scope.
    """
    set_in_force_token(_mint(issuer))  # minted for agent:test-1
    other = "agent:imposter"
    tool = gated_tools([StubFunctionTool(lookup_customer)], gate=gate, sink=sink, agent_id=other)[0]
    with pytest.raises(CapabilityDenied):
        await tool.run_json({"customer_id": "C-1042"})
    assert sink.events[0]["decision"] == "DENY"
    assert sink.events[0]["agent_id"] == other


# ---------------------------------------------------------------------------
# Receipt integrity


@pytest.mark.asyncio
async def test_allow_and_deny_land_in_a_verifiable_chain(issuer, sink, tmp_path):
    """Receipts from both paths append into one HashChainSink that the
    offline AuditVerifier accepts."""
    log = tmp_path / "receipts.jsonl"
    signer = Ed25519Signer.generate()
    chain_sink = HashChainSink(log, signer=signer)
    real_issuer = CapabilityIssuer.generate(issuer="acme.test.chain")
    gate = CapabilityGate(trusted_issuers={real_issuer.key_id: real_issuer.public_key_pem})

    tool = gated_tools(
        [StubFunctionTool(lookup_customer)], gate=gate, sink=chain_sink, agent_id="agent:test-1"
    )[0]

    set_in_force_token(_mint(real_issuer))
    await tool.run_json({"customer_id": "C-1"})  # ALLOW

    set_in_force_token(None)
    with pytest.raises(CapabilityDenied):
        await tool.run_json({"customer_id": "C-2"})  # DENY

    chain_sink.close()
    report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(log)
    assert report.valid
    assert report.event_count == 2


# ---------------------------------------------------------------------------
# Fail-closed / fail-open edges


def test_non_functiontool_fails_closed_by_default(issuer, gate, sink):
    """An ungated tool is a hole in 'every tool call passes the gate'."""
    with pytest.raises(ValueError, match="not a FunctionTool"):
        gated_tools([lambda: "raw"], gate=gate, sink=sink, agent_id="agent:test-1")


def test_non_functiontool_passthrough_requires_opt_in(issuer, gate, sink):
    t = object()
    out = gated_tools([t], gate=gate, sink=sink, agent_id="a", allow_ungated=True)
    assert out == [t]


def test_unknowable_functiontool_fails_closed(issuer, gate, sink):
    """A FunctionTool-typed object with no findable inner callable cannot
    be gated — refuse rather than pass it through ungated (round-5 F4)."""

    class OpaqueTool(StubFunctionTool):
        def __init__(self) -> None:
            self.name = "opaque"
            self.description = ""

    with pytest.raises(ValueError, match="inner callable"):
        gated_tools([OpaqueTool()], gate=gate, sink=sink, agent_id="agent:test-1")


def test_unknowable_functiontool_passthrough_requires_opt_in(issuer, gate, sink):
    opaque = OpaqueToolLike()
    out = gated_tools([opaque], gate=gate, sink=sink, agent_id="a", allow_ungated=True)
    assert out == [opaque]


class OpaqueToolLike(StubFunctionTool):
    def __init__(self) -> None:
        self.name = "opaque"
        self.description = ""


@pytest.mark.asyncio
async def test_empty_agent_id_fails_closed_attribution(issuer, gate, sink):
    """B2: an empty agent_id is not an identity — DENY receipt rather than
    minting evidence attributed to \"\"."""
    set_in_force_token(_mint(issuer))
    invoked: list[bool] = []
    tool = gated_tools(
        [StubFunctionTool(lambda **kw: invoked.append(True))], gate=gate, sink=sink, agent_id=""
    )[0]
    with pytest.raises(CapabilityDenied, match="agent_id"):
        await tool.run_json({"customer_id": "C-1"})
    assert invoked == []
    receipt = sink.events[0]
    assert receipt["decision"] == "DENY"
    assert "agent identity" in receipt["decision_reason"]


@pytest.mark.asyncio
async def test_shadow_mode_receipts_deny_but_proceeds(issuer, gate, sink, caplog):
    """raise_on_deny=False: the deny is receipted, the call proceeds, and a
    warning names the tool (shadow / migration mode)."""
    invoked: list[bool] = []
    tool = gated_tools(
        [StubFunctionTool(lambda **kw: invoked.append(True), name="lookup_customer")],
        gate=gate,
        sink=sink,
        agent_id="agent:test-1",
        raise_on_deny=False,
    )[0]
    await tool.run_json({"customer_id": "C-1042"})  # no token in force
    assert invoked == [True], "shadow mode must proceed, that is its contract"
    assert sink.events[0]["decision"] == "DENY"
    assert any("shadow-mode" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_async_handler_and_signature_preserved(issuer, gate, sink):
    """B2: functools.wraps keeps the ORIGINAL signature (autoGen builds the
    args model from inspect.signature(__wrapped__)), and async handlers are
    awaited."""

    async def async_lookup(customer_id: str) -> dict:
        return {"async": customer_id}

    set_in_force_token(_mint(issuer, tool="async_lookup"))
    tool = gated_tools(
        [StubFunctionTool(async_lookup)], gate=gate, sink=sink, agent_id="agent:test-1"
    )[0]
    out = await tool.run_json({"customer_id": "C-9"})
    assert out == {"async": "C-9"}

    inner = tool._func
    assert inner.__name__ == "async_lookup"
    assert inner.__wrapped__ is async_lookup, "signature source must be the original callable"
    assert not isinstance(inner.__wrapped__, functools.partial)


def test_contextvar_roundtrip_and_reset():
    set_in_force_token(None)
    assert get_in_force_token() is None
    sentinel = object()
    set_in_force_token(typing.cast(typing.Any, sentinel))
    assert get_in_force_token() is sentinel
    set_in_force_token(None)
    assert get_in_force_token() is None


def test_gated_tools_requires_autogen(monkeypatch, issuer, gate, sink):
    """Without autogen-core the adapter must refuse loudly, not no-op."""
    monkeypatch.setattr(autogen, "_HAS_AUTOGEN", False)
    with pytest.raises(RuntimeError, match="autogen-core"):
        gated_tools([StubFunctionTool(lookup_customer)], gate=gate, sink=sink, agent_id="a")
