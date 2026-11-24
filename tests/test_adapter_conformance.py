"""Q18 Close 3: the common adapter conformance suite family.

One parametrised test module covering the conformance table the external
reviewer defined for the adapter family, run across crewai, langgraph,
agent_framework, autogen and langchain with the honest-skip packaging
convention: every adapter's rows importorskip its own extra, so a venv
without the extra honestly reports SKIP instead of a false pass.

The table:

1. no token denies
2. wrong agent denies
3. wrong tool denies
4. forbidden argument denies
5. receipt-store-unavailable denies in durable mode
6. tool exception keeps the ALLOW decision + outcome recorded
7. original unwrapped tool invocation is NOT blocked by the wrapper

Registered residual (row 7, kept honest by design): the wrapper gates its
own call sites only. DEPLOYMENT TOOL COVERAGE - guaranteeing every tool an
agent can reach is the guarded one - is a deployment concern the wrapper
cannot enforce in-process; this suite records that residual openly rather
than claiming prevention.
"""

from __future__ import annotations

import asyncio
import types
import uuid
from typing import Any

import pytest

pytest.importorskip("cryptography")

from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402

CONFORMANCE_ADAPTERS = ["agent_framework", "autogen", "crewai", "langchain", "langgraph"]

#: The default allowed call arguments every harness drives.
_ALLOWED_KWARGS = {"customer_id": "C-1042", "amount": 1}
_FORBIDDEN_KWARGS = {"customer_id": "C-EVIL", "amount": 1}


class DeadSink:
    """A sink whose append always raises (the receipt store is unavailable)."""

    def __init__(self) -> None:
        self.attempts = 0

    def append(self, event: dict) -> dict:
        self.attempts += 1
        raise RuntimeError("receipt store unavailable")

    def close(self) -> None:
        pass


class CapturingSink:
    """A sink that captures appended events in memory."""

    def __init__(self, events: list[dict]) -> None:
        self.events = events

    def append(self, event: dict) -> dict:
        self.events.append(event)
        return {}

    def close(self) -> None:
        pass


class _HarnessBase:
    """Shared conformance machinery for one adapter surface.

    Subclasses prepare the adapter, drive ONE guarded call and expose the
    recorded decisions + executions through the same vocabulary for every
    adapter.
    """

    name: str = "?"
    #: adapter module (set by prepare)
    module: Any = None
    tool_name = "transfer_funds"
    agent_id = "agent:test"

    def __init__(self, issuer: CapabilityIssuer, gate: CapabilityGate) -> None:
        self.issuer = issuer
        self.gate = gate
        self.events: list[dict] = []
        self.impl_calls: list[dict] = []
        # Rows flip this flag to make the wrapped tool body raise mid-run.
        self.impl_should_raise = False
        self.prepare()

    # -- adapter-agnostic helpers -----------------------------------------

    def token(
        self,
        *,
        agent_id: str | None = None,
        tool: str | None = None,
        constraints: dict | None = None,
    ) -> Any:
        return self.issuer.mint(
            agent_id=agent_id or self.agent_id,
            tool=tool or self.tool_name,
            constraints=constraints if constraints is not None else {},
            ttl_seconds=60,
        )

    def set_token(self, token: Any) -> None:
        self.module.set_in_force_token(token)

    def clear_token(self) -> None:
        self.module.set_in_force_token(None)

    def receipt(self) -> dict:
        """The last receipt the adapter emitted (shape normalised)."""
        last = self.events[-1]
        return last.get("receipt", last)

    def rebuild(self, sink: Any | None = None) -> None:
        """Rebuild the adapter machinery against a (possibly dead) sink."""
        if sink is None:
            sink = CapturingSink(self.events)
        self.install_rebuilt(sink)

    @property
    def deny_error(self) -> type[Exception]:
        """The typed exception the adapter refuses a denied call with."""
        if self.name == "agent_framework":
            from raucle.integrations.agent_framework import MiddlewareTermination

            return MiddlewareTermination
        return self.module.CapabilityDenied

    @property
    def sink_failure_error(self) -> type[Exception]:
        """The typed exception a receipt-store failure surfaces as.

        The guard adapters let the sink's failure propagate as the raw
        store error (emission precedes enforcement, so the store error
        aborts the call); the middleware refuses through its termination
        mechanism in durable mode.
        """
        if self.name == "agent_framework":
            from raucle.integrations.agent_framework import MiddlewareTermination

            return MiddlewareTermination
        return RuntimeError

    # -- the overridable adapter seams -------------------------------------

    def prepare(self) -> None:  # pragma: no cover - subclass contract
        raise NotImplementedError

    def install_rebuilt(self, sink: Any) -> None:  # pragma: no cover
        raise NotImplementedError

    async def call_guarded(self, **kwargs: Any) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def call_raw(self, **kwargs: Any) -> Any:  # pragma: no cover
        raise NotImplementedError


class _AgentFrameworkHarness(_HarnessBase):
    """Drives RaucleFunctionMiddleware through a mock invocation context."""

    name = "agent_framework"

    def prepare(self) -> None:
        pytest.importorskip("agent_framework")
        from raucle.integrations import agent_framework as module

        self.module = module
        self._install(CapturingSink(self.events))

    def _install(self, sink: Any) -> None:
        from raucle.integrations.agent_framework import RaucleFunctionMiddleware

        self._sink = sink
        self._mw = RaucleFunctionMiddleware(gate=self.gate, sink=sink)

    def install_rebuilt(self, sink: Any) -> None:
        from raucle.integrations.agent_framework import RaucleFunctionMiddleware

        self._sink = sink
        self._mw = RaucleFunctionMiddleware(gate=self.gate, sink=sink)

    async def call_guarded(self, **kwargs: Any) -> Any:
        context = types.SimpleNamespace(
            function=types.SimpleNamespace(name=self.tool_name),
            arguments=dict(kwargs),
            metadata={"agent_id": self.agent_id},
            session=None,
            agent=None,
            result=None,
        )

        async def _next() -> None:
            self.impl_calls.append({"tool": self.tool_name, **kwargs})
            if self.impl_should_raise:
                raise ValueError("boom")

        await self._mw.process(context, _next)
        return None

    async def call_raw(self, **kwargs: Any) -> Any:
        async def _inner() -> None:
            self.impl_calls.append({"tool": self.tool_name, **kwargs})
            if self.impl_should_raise:
                raise ValueError("boom")

        await _inner()
        return None


class _AutogenHarness(_HarnessBase):
    """Drives the gated AutoGen FunctionTool through its run_json surface."""

    name = "autogen"

    def prepare(self) -> None:
        from raucle.integrations import autogen as module

        if not module._HAS_AUTOGEN:
            pytest.skip("autogen-core extra not installed")
        self.module = module
        self._install(CapturingSink(self.events))

    def _install(self, sink: Any) -> None:
        from autogen_core.tools import FunctionTool

        self._sink = sink

        async def impl(customer_id: str = "unset", amount: int = 0) -> dict:
            self.impl_calls.append({"customer_id": customer_id, "amount": amount})
            if self.impl_should_raise:
                raise ValueError("boom")
            return {"ran": customer_id}

        self._raw_tool = FunctionTool(
            impl, description="conformance transfer tool", name=self.tool_name
        )
        self._gated = self.module.gated_tools(
            [self._raw_tool], gate=self.gate, sink=sink, agent_id=self.agent_id
        )[0]

    def install_rebuilt(self, sink: Any) -> None:
        self._install(sink)

    async def call_guarded(self, **kwargs: Any) -> Any:
        return await self._gated.run_json(dict(kwargs), None)

    async def call_raw(self, **kwargs: Any) -> Any:
        return await self._raw_tool.run_json(dict(kwargs), None)


class _CrewaiHarness(_HarnessBase):
    """Drives the CrewAI guarded tool through BaseTool.run's delegate."""

    name = "crewai"

    def prepare(self) -> None:
        pytest.importorskip("crewai")
        self.module = pytest.importorskip("raucle.integrations.crewai", reason="adapter module")
        self._install(CapturingSink(self.events))

    def _install(self, sink: Any) -> None:
        from crewai.tools import BaseTool
        from pydantic import BaseModel

        class _Args(BaseModel):
            customer_id: str = "unset"
            amount: int = 0

        recorder = self.impl_calls
        flag = self

        class _Transfer(BaseTool):  # type: ignore[misc,valid-type]
            name: str = self.tool_name
            description: str = "conformance transfer tool"
            args_schema: type = _Args

            def _run(self, customer_id: str, amount: int) -> str:
                recorder.append({"customer_id": customer_id, "amount": amount})
                if flag.impl_should_raise:
                    raise ValueError("boom")
                return f"RUN {customer_id}"

        self._raw_tool = _Transfer()
        self._sink = sink
        self._gated = self.module.guard_tool(
            self._raw_tool, gate=self.gate, sink=sink, agent_id=self.agent_id
        )

    def install_rebuilt(self, sink: Any) -> None:
        self._install(sink)

    async def call_guarded(self, **kwargs: Any) -> Any:
        # CrewAI's BaseTool.run calls _run directly with no callback layer
        # that swallows exceptions (the adapter docstring records this), so
        # the deny/tool-exception contract surfaces through raise paths.
        return self._gated.run(**kwargs)

    async def call_raw(self, **kwargs: Any) -> Any:
        return self._raw_tool.run(**kwargs)


class _LangchainHarness(_HarnessBase):
    """Drives RaucleCallbackHandler.on_tool_start (the enforcement seam).

    The handler is an interposer: on an ALLOW the tool call proceeds inside
    the framework - recorded here by invoking the tool body after the ALLOW,
    exactly as the framework would.
    """

    name = "langchain"

    def prepare(self) -> None:
        pytest.importorskip("langchain_core")
        self.module = pytest.importorskip("raucle.integrations.langchain", reason="adapter module")
        self._install(CapturingSink(self.events))

    def _install(self, sink: Any) -> None:
        from raucle.integrations.langchain import RaucleCallbackHandler

        self._sink = sink
        self._handler = RaucleCallbackHandler(gate=self.gate, sink=sink)

    def install_rebuilt(self, sink: Any) -> None:
        self._install(sink)

    async def call_guarded(self, **kwargs: Any) -> Any:
        self._handler.on_tool_start(
            serialized={"name": self.tool_name},
            input_str="",
            run_id=uuid.uuid4(),
            metadata={"agent_id": self.agent_id},
            inputs=dict(kwargs),
        )
        self.impl_calls.append({"tool": self.tool_name, **kwargs})
        if self.impl_should_raise:
            raise ValueError("boom")
        return None

    async def call_raw(self, **kwargs: Any) -> Any:
        self.impl_calls.append({"tool": self.tool_name, **kwargs})
        return None


class _LanggraphHarness(_HarnessBase):
    """Drives the LangGraph gated callable directly (the tool-node surface)."""

    name = "langgraph"

    def prepare(self) -> None:
        pytest.importorskip("langgraph")
        self.module = pytest.importorskip("raucle.integrations.langgraph", reason="adapter module")
        self._install(CapturingSink(self.events))

    def _install(self, sink: Any) -> None:
        from raucle.integrations.langgraph import gate_tool

        self._sink = sink
        recorder = self.impl_calls
        flag = self

        def transfer_funds(customer_id: str, amount: int = 0):
            recorder.append({"customer_id": customer_id, "amount": amount})
            if flag.impl_should_raise:
                raise ValueError("boom")
            return f"RUN {customer_id}"

        self._raw_tool = transfer_funds
        self._gated = gate_tool(transfer_funds, gate=self.gate, sink=sink, agent_id=self.agent_id)

    def install_rebuilt(self, sink: Any) -> None:
        self._install(sink)

    async def call_guarded(self, **kwargs: Any) -> Any:
        return self._gated(**kwargs)

    async def call_raw(self, **kwargs: Any) -> Any:
        return self._raw_tool(**kwargs)


@pytest.fixture(params=CONFORMANCE_ADAPTERS)
def harness(request, issuer):
    """One harness per conformance adapter, honestly skipped per extra."""
    issuer = request.getfixturevalue("issuer")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    builders = {
        "agent_framework": _AgentFrameworkHarness,
        "autogen": _AutogenHarness,
        "crewai": _CrewaiHarness,
        "langchain": _LangchainHarness,
        "langgraph": _LanggraphHarness,
    }
    h = builders[request.param](issuer, gate)
    yield h
    h.clear_token()


@pytest.fixture
def issuer() -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer="acme.test.conformance")


# ---------------------------------------------------------------------------
# The conformance table


@pytest.mark.asyncio
async def test_no_token_denies(harness):
    """Row 1: no token in force -> the call denies and the tool never runs."""
    harness.clear_token()

    with pytest.raises(harness.deny_error):
        await harness.call_guarded(**_ALLOWED_KWARGS)

    assert harness.impl_calls == [], "no-token calls must never reach the tool body"
    receipt = harness.receipt()
    assert receipt["decision"] == "DENY"
    assert (
        "no in-force capability token" in receipt["decision_reason"]
        or "token" in receipt["decision_reason"]
    )


@pytest.mark.asyncio
async def test_wrong_agent_denies(harness):
    """Row 2: a caller whose identity does not match the token's scope denies."""
    harness.set_token(harness.token(agent_id="agent:elsewhere"))

    with pytest.raises(harness.deny_error):
        await harness.call_guarded(**_ALLOWED_KWARGS)

    assert harness.impl_calls == [], "a wrong-agent call must never reach the tool body"
    receipt = harness.receipt()
    assert receipt["decision"] == "DENY"
    assert "does not match token" in receipt["decision_reason"]


@pytest.mark.asyncio
async def test_wrong_tool_denies(harness):
    """Row 3: a token bound to another tool denies the cross-tool call."""
    harness.set_token(harness.token(tool="lookup_customer"))

    with pytest.raises(harness.deny_error):
        await harness.call_guarded(**_ALLOWED_KWARGS)

    assert harness.impl_calls == [], "a wrong-tool call must never reach the tool body"
    receipt = harness.receipt()
    assert receipt["decision"] == "DENY"
    assert "bound to tool" in receipt["decision_reason"]


@pytest.mark.asyncio
async def test_forbidden_argument_denies(harness):
    """Row 4: a call carrying an argument the token forbids denies."""
    harness.set_token(harness.token(constraints={"forbidden_values": {"customer_id": ["C-EVIL"]}}))

    with pytest.raises(harness.deny_error):
        await harness.call_guarded(**_FORBIDDEN_KWARGS)

    assert harness.impl_calls == [], "a forbidden-argument call must never reach the tool body"
    receipt = harness.receipt()
    assert receipt["decision"] == "DENY"


@pytest.mark.asyncio
async def test_receipt_store_unavailable_denies_in_durable_mode(harness, monkeypatch):
    """Row 5: an unusable receipt store refuses the call (fail-closed).

    The guard adapters make emission precede enforcement unconditionally;
    the middleware requires RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1 to switch
    from its advisory default to the durable refusal, and its refusal
    names the mode.
    """
    if harness.name == "agent_framework":
        monkeypatch.setenv("RAUCLE_MW_REQUIRE_DURABLE_RECEIPT", "1")
        harness.rebuild(DeadSink())
    else:
        harness.rebuild(DeadSink())
    harness.set_token(harness.token())

    with pytest.raises(harness.sink_failure_error) as excinfo:
        await harness.call_guarded(**_ALLOWED_KWARGS)

    assert harness.impl_calls == [], (
        "a durable-mode sink failure must refuse the call before any execution"
    )
    if harness.name == "agent_framework":
        assert "RAUCLE_MW_REQUIRE_DURABLE_RECEIPT" in str(excinfo.value)
    if harness.name in ("crewai", "langgraph", "autogen", "langchain"):
        assert harness._sink.attempts >= 1


@pytest.mark.asyncio
async def test_tool_exception_keeps_allow_decision_and_records_outcome(harness):
    """Row 6: the tool exploding mid-body does not rewrite the ALLOW decision.

    The receipt stays ALLOW and the failure surfaces to the caller - the
    decision the gate made is the recorded one.
    """
    harness.set_token(harness.token())
    harness.impl_should_raise = True

    with pytest.raises(ValueError, match="boom"):
        await harness.call_guarded(**_ALLOWED_KWARGS)

    assert harness.impl_calls, "the tool body must have been entered before raising"
    receipt = harness.receipt()
    assert receipt["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_unwrapped_invocation_is_not_blocked_by_the_wrapper(harness):
    """Row 7 (registered residual): the ORIGINAL tool is not gated.

    The wrapper governs its own call sites only. Deployment coverage -
    guaranteeing that agents can only reach the guarded tool - is a
    registered deployment concern; this row records the residual honestly
    instead of claiming prevention.
    """
    harness.set_token(harness.token(constraints={"forbidden_values": {"customer_id": ["C-EVIL"]}}))

    # The guard itself denies the forbidden arguments...
    with pytest.raises(harness.deny_error):
        await harness.call_guarded(**_FORBIDDEN_KWARGS)
    assert harness.impl_calls == []

    # ...and the original, unguarded surface runs them anyway.
    await harness.call_raw(**_FORBIDDEN_KWARGS)

    assert harness.impl_calls, (
        "the unwrapped invocation is outside the wrapper's reach (registered residual)"
    )


@pytest.mark.asyncio
async def test_concurrent_sessions_keep_tokens_isolated(harness):
    """Row 8: concurrent sessions cannot read each other's in-force token.

    Two asyncio tasks in one loop: one binds an in-force token, the other
    holds none. The bound session's call allows and the unbound session's
    call denies - no cross-contamination through the ContextVar seam.
    """
    outcomes: dict[str, str] = {}
    valid_token = harness.token()

    async def _task_a() -> None:
        harness.set_token(valid_token)
        try:
            await harness.call_guarded(**_ALLOWED_KWARGS)
            outcomes["a"] = "allowed"
        except Exception:
            outcomes["a"] = "denied:unexpected"

    async def _task_b() -> None:
        harness.clear_token()
        try:
            await harness.call_guarded(**_ALLOWED_KWARGS)
            outcomes["b"] = "allowed"
        except Exception:
            outcomes["b"] = "denied"

    await asyncio.gather(_task_a(), _task_b())

    assert outcomes["a"] == "allowed", f"the token-bound session must proceed, got {outcomes}"
    assert outcomes["b"] == "denied", (
        f"the token-less session must deny, not inherit the sibling's token: {outcomes}"
    )
