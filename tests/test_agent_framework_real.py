"""End-to-end integration test against the real ``agent-framework`` package.

Skipped automatically when ``agent-framework`` is not installed; the
contract-level tests in ``test_agent_framework_integration.py`` cover the
unit-level behaviour without that dependency.

SKIP DECISION (2026-11-05): ``agent-framework>=1.0`` cannot be resolved on
this environment's Python 3.14 dev venv (no compatible distribution), so the
real-framework milestone tests stay CI-owned (3.11-3.13 matrix); locally the
contract-level suite keeps the wire-up covered. Backlog: revisit when a
py3.14 wheel exists.

What this file proves
---------------------

The integration's wire-up against ``agent-framework`` 1.6+ actually works:

  - RaucleFunctionMiddleware is a valid subclass of agent_framework's real
    FunctionMiddleware ABC (the framework will accept it via
    ``isinstance(...)`` checks at registration time).
  - Constructing a real ``FunctionInvocationContext`` and passing it to
    ``RaucleFunctionMiddleware.process`` produces the expected receipt
    on the ALLOW path and the expected ``MiddlewareTermination`` on the
    DENY path.
  - The agent-framework's ``MiddlewareTermination(result=...)`` carries
    the refusal payload back to the framework, exactly as the framework
    documents.

This is the M2 milestone for ``docs/proposals/agent-framework-middleware.md``.
"""

from __future__ import annotations

import pytest

# Skip whole module unless agent-framework is installed.
agent_framework = pytest.importorskip("agent_framework")
pytest.importorskip("cryptography")

from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.agent_framework import (  # noqa: E402
    RaucleFunctionMiddleware,
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
def captured_events():
    events: list[dict] = []

    class CapturingSink:
        def append(self, event: dict) -> dict:
            events.append(event)
            return {}

        def close(self) -> None:
            pass

    return events, CapturingSink()


# ---------------------------------------------------------------------------
# Helpers using the real agent-framework types


def _real_context(*, tool_name: str, arguments: dict, agent_id: str | None = None):
    """Construct an actual ``FunctionInvocationContext`` from the real package."""
    from agent_framework import FunctionInvocationContext, tool

    # A real FunctionTool the framework recognises.
    @tool(approval_mode="never_require")
    def _f(**_kwargs):
        return "executed"

    # Override the name so we can test the wrong-tool path
    _f.name = tool_name

    metadata: dict = {}
    if agent_id is not None:
        metadata["agent_id"] = agent_id

    return FunctionInvocationContext(
        function=_f,
        arguments=arguments,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Tests


def test_real_middleware_is_recognised_as_subclass():
    """raucle's middleware passes the framework's isinstance check."""
    from agent_framework import FunctionMiddleware as RealBase

    assert issubclass(RaucleFunctionMiddleware, RealBase)


@pytest.mark.asyncio
async def test_real_context_allow_path(issuer, gate, captured_events):
    """Path 2 with the real FunctionInvocationContext: ALLOW receipt emitted."""
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

    async def _next() -> None:
        invoked.append(True)

    context = _real_context(
        tool_name="lookup_customer",
        arguments={"customer_id": "C-1042"},
    )

    await mw.process(context, _next)

    assert invoked == [True]
    assert len(events) == 1
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "ALLOW"
    assert receipt["tool"] == "lookup_customer"


@pytest.mark.asyncio
async def test_real_context_deny_raises_middleware_termination(issuer, gate, captured_events):
    """Path 4 with the real context: DENY raises MiddlewareTermination
    carrying the refusal payload as documented by the framework."""
    from agent_framework import MiddlewareTermination as RealTermination

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

    async def _next() -> None:
        invoked.append(True)

    context = _real_context(
        tool_name="transfer_funds",
        arguments={"to": "GB29NWBK60161331926819", "amount": 4.00},
    )

    with pytest.raises(RealTermination) as exc_info:
        await mw.process(context, _next)

    assert invoked == []
    assert len(events) == 1
    receipt = events[0]["receipt"]
    assert receipt["decision"] == "DENY"

    # The framework's MiddlewareTermination carries the refusal payload as
    # the `result` attribute. Verify it's there and parseable.
    import json

    refusal = json.loads(exc_info.value.result)
    assert refusal["raucle"]["decision"] == "DENY"
    assert "advice" in refusal["raucle"]
