"""Q18 Close 2: argument normalisation across the wrapper adapters.

The wrapper adapters used to gate on ``dict(kwargs)`` (crewai) or fold a
single positional under the key ``input`` (langgraph) while forwarding the
RAW invocation to the wrapped tool, so a positional call bypassed the gate's
argument view while executing with arguments the gate never saw.

The fix binds the invocation against the wrapped tool's signature
(``inspect.signature(...).bind(...)``, defaults applied) per adapter, so the
gate evaluation, the receipt digest and the executed arguments carry the SAME
semantic arguments (H(arguments_gate) == H(arguments_executor)). When no
signature can be resolved the adapters fall back to the previous heuristic
and log the unnormalised-args residual in the receipt.

Red-first rows (the OLD behaviour is the falsified baseline):
positional calls gated on real parameter names, mixed positional+keyword,
defaults bound into the gate view, variadic signatures, nested structures,
the langgraph single-positional bind-by-name, and the honest fallback.
These tests require the adapter extras; they honestly skip when the extra
is not installed (the Q9 packaging convention).
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402


class _EventSink:
    """Sink capturing receipt dicts (flat, adapter-issued shape)."""

    def __init__(self, events: list[dict]) -> None:
        self.events = events

    def append(self, event: dict) -> dict:
        self.events.append(event)
        return {}

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _clear_adapter_tokens():
    """Reset every adapter's in-force token after each test.

    The adapters each carry a module-level ContextVar; a token left bound
    by one row must never leak into the next row's decision.
    """
    yield
    from raucle.integrations import agent_framework, autogen, crewai, langchain, langgraph

    for module in (agent_framework, autogen, crewai, langchain, langgraph):
        module.set_in_force_token(None)


@pytest.fixture
def issuer() -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer="acme.test.kyc")


def _gate(issuer: CapabilityIssuer) -> CapabilityGate:
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


# ---------------------------------------------------------------------------
# crewai: the guarded tool binds positionals against the wrapped _run signature


@pytest.fixture
def crewai_module():
    pytest.importorskip("crewai")
    from raucle.integrations import crewai as crewai_adapter

    return crewai_adapter


def _crew_args_model():
    from pydantic import BaseModel

    class _Args(BaseModel):
        customer_id: str = "unset"
        amount: int = 100
        details: dict | None = None

    return _Args


def _crew_transfer_class(recorder: list[dict], base_cls: type, args_model: type) -> type:
    class _Transfer(base_cls):  # type: ignore[misc,valid-type]
        name: str = "transfer_funds"
        description: str = "Transfer money (normalisation test tool)"
        args_schema: type = args_model

        def _run(
            self,
            customer_id: str = "unset",
            amount: int = 100,
            details: dict | None = None,
        ) -> str:
            recorder.append({"customer_id": customer_id, "amount": amount, "details": details})
            return f"RUN {customer_id} {amount}"

    return _Transfer


def _crew_variadic_class(recorder: list[dict], base_cls: type) -> type:
    class _Variadic(base_cls):  # type: ignore[misc,valid-type]
        name: str = "variadic_tool"
        description: str = "Variadic tool (normalisation test tool)"

        def _run(self, *rest: int, **more: int) -> str:
            recorder.append({"rest": rest, "more": more})
            return "VARIADIC RUN"

    return _Variadic


def _crew_guard(crewai_module, issuer, tool, events) -> object:
    return crewai_module.guard_tool(
        tool, gate=_gate(issuer), sink=_EventSink(events), agent_id="agent:test"
    )


CREW_FORBIDDEN = {"customer_id": ["C-EVIL"]}


def test_crewai_positional_denies_on_real_parameter_name(crewai_module, issuer):
    """Positional invocation binds to the REAL parameter names: a call that
    passes a forbidden customer_id positionally now DENIES (the old kwargs
    view dropped positionals, so the gate missed the constraint entirely)."""
    events: list[dict] = []
    recorder: list[dict] = []
    cls = _crew_transfer_class(recorder, crewai_module.BaseTool, _crew_args_model())
    set_token = crewai_module.set_in_force_token
    set_token(
        issuer.mint(
            agent_id="agent:test",
            tool="transfer_funds",
            constraints={"forbidden_values": CREW_FORBIDDEN},
            ttl_seconds=60,
        )
    )
    guarded = _crew_guard(crewai_module, issuer, cls(), events)

    with pytest.raises(crewai_module.CapabilityDenied):
        guarded._run("C-EVIL", 10)

    assert recorder == [], "the tool body must never run on a denied call"
    receipt = events[-1]
    assert receipt["decision"] == "DENY"
    assert receipt["call_args_hash"] == crewai_module._hash_args(
        {"customer_id": "C-EVIL", "amount": 10, "details": None}
    ), "the deny digest must bind the bound argument view (defaults included)"
    assert receipt["args_binding"] == "normalised"


def test_crewai_max_value_denies_on_positional_amount(crewai_module, issuer):
    """max_value-style constraints target positional arguments by NAME."""
    events: list[dict] = []
    recorder: list[dict] = []
    cls = _crew_transfer_class(recorder, crewai_module.BaseTool, _crew_args_model())
    crewai_module.set_in_force_token(
        issuer.mint(
            agent_id="agent:test",
            tool="transfer_funds",
            constraints={"max_value": {"amount": 100}},
            ttl_seconds=60,
        )
    )
    guarded = _crew_guard(crewai_module, issuer, cls(), events)

    with pytest.raises(crewai_module.CapabilityDenied):
        guarded._run("C-1042", 500)

    assert recorder == []
    receipt = events[-1]
    assert receipt["decision"] == "DENY"
    assert receipt["call_args_hash"] == crewai_module._hash_args(
        {"customer_id": "C-1042", "amount": 500, "details": None}
    )


def test_crewai_mixed_positional_and_keyword_gate_on_joined_view(crewai_module, issuer):
    """Mixed positional+keyword calls gate on the JOINED bound argument view."""
    events: list[dict] = []
    recorder: list[dict] = []
    cls = _crew_transfer_class(recorder, crewai_module.BaseTool, _crew_args_model())
    crewai_module.set_in_force_token(
        issuer.mint(
            agent_id="agent:test",
            tool="transfer_funds",
            constraints={"forbidden_values": CREW_FORBIDDEN},
            ttl_seconds=60,
        )
    )
    guarded = _crew_guard(crewai_module, issuer, cls(), events)

    result = guarded._run("C-1042", amount=50)

    assert result == "RUN C-1042 50"
    assert len(recorder) == 1
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["call_args_hash"] == crewai_module._hash_args(
        {"customer_id": "C-1042", "amount": 50, "details": None}
    )
    assert receipt["args_binding"] == "normalised"


def test_crewai_defaults_bound_into_the_gate_view(crewai_module, issuer):
    """Defaults apply in the gate view so callers cannot dodge a bound field
    by omitting it: amount defaults to 100 and the token caps it at 50."""
    events: list[dict] = []
    recorder: list[dict] = []
    cls = _crew_transfer_class(recorder, crewai_module.BaseTool, _crew_args_model())
    crewai_module.set_in_force_token(
        issuer.mint(
            agent_id="agent:test",
            tool="transfer_funds",
            constraints={"max_value": {"amount": 50}},
            ttl_seconds=60,
        )
    )
    guarded = _crew_guard(crewai_module, issuer, cls(), events)

    with pytest.raises(crewai_module.CapabilityDenied):
        guarded._run("C-1042")

    assert recorder == [], "the default amount must be gated, not silently allowed"
    receipt = events[-1]
    assert receipt["decision"] == "DENY"
    assert receipt["call_args_hash"] == crewai_module._hash_args(
        {"customer_id": "C-1042", "amount": 100, "details": None}
    )


def test_crewai_variadic_signature_gated_as_variadic(crewai_module, issuer):
    """A variadic tool still gates: the bound view carries the captured
    var-positional tuple and var-keyword mapping under their names."""
    events: list[dict] = []
    recorder: list[dict] = []
    cls = _crew_variadic_class(recorder, crewai_module.BaseTool)
    crewai_module.set_in_force_token(
        issuer.mint(
            agent_id="agent:test",
            tool="variadic_tool",
            constraints={},
            ttl_seconds=60,
        )
    )
    guarded = _crew_guard(crewai_module, issuer, cls(), events)

    result = guarded._run(1, 2, x=3)

    assert result == "VARIADIC RUN"
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["args_binding"] == "normalised"
    # Var-positional members fold in by index; var-keyword members carry
    # their actual caller names so name-keyed constraints still see them.
    assert receipt["call_args_hash"] == crewai_module._hash_args({"0": 1, "1": 2, "x": 3})


def test_crewai_nested_structures_bind_semantically(crewai_module, issuer):
    """Nested argument structures bind to names unchanged and hash equally."""
    events: list[dict] = []
    recorder: list[dict] = []
    cls = _crew_transfer_class(recorder, crewai_module.BaseTool, _crew_args_model())
    crewai_module.set_in_force_token(
        issuer.mint(agent_id="agent:test", tool="transfer_funds", constraints={}, ttl_seconds=60)
    )
    guarded = _crew_guard(crewai_module, issuer, cls(), events)

    nested = {"branch": {"deep": [1, 2, {"leaf": True}]}}
    result = guarded._run("C-1042", 10, nested)

    assert result == "RUN C-1042 10"
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["call_args_hash"] == crewai_module._hash_args(
        {"customer_id": "C-1042", "amount": 10, "details": nested}
    )
    assert recorder[-1]["details"] == nested, "the tool saw the nested structure verbatim"


def test_crewai_gate_digest_matches_executor_arguments(crewai_module, issuer):
    """H(arguments_gate) == H(arguments_executor) for the guarded wrapper.

    The receipt digest must bind the same semantic arguments the tool body
    received: both sides carry the bound view (the executor binds against
    the same signature).
    """
    events: list[dict] = []
    recorder: list[dict] = []
    cls = _crew_transfer_class(recorder, crewai_module.BaseTool, _crew_args_model())
    crewai_module.set_in_force_token(
        issuer.mint(agent_id="agent:test", tool="transfer_funds", constraints={}, ttl_seconds=60)
    )
    guarded = _crew_guard(crewai_module, issuer, cls(), events)

    guarded._run("C-1042", 33)

    assert len(recorder) == 1
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["call_args_hash"] == crewai_module._hash_args(dict(recorder[0]))


def test_crewai_unresolvable_signature_falls_back_with_residual(crewai_module, issuer, caplog):
    """When no signature can be resolved the previous view is kept, marked and
    logged: the receipt records the unnormalised-args residual honestly."""
    events: list[dict] = []
    recorder: list[dict] = []

    class _BrokenSigTool(crewai_module.BaseTool):  # type: ignore[misc,valid-type]
        name: str = "transfer_funds"
        description: str = "Tool with an unresolvable signature"

        def _run(self, customer_id: str = "unset", amount: int = 100) -> str:
            recorder.append({"customer_id": customer_id, "amount": amount})
            return "FALLBACK RUN"

    # An invalid __signature__ makes inspect.signature() raise TypeError,
    # exercising the fallback path deterministically. CrewAI's BaseTool
    # derives args_schema from the signature at CLASS construction, so the
    # poison lands on the shared function AFTER instantiation.
    tool = _BrokenSigTool()
    _BrokenSigTool._run.__signature__ = 42  # type: ignore[assignment]

    crewai_module.set_in_force_token(
        issuer.mint(agent_id="agent:test", tool="transfer_funds", constraints={}, ttl_seconds=60)
    )
    guarded = _crew_guard(crewai_module, issuer, tool, events)

    result = guarded._run("C-1042", 10)

    assert result == "FALLBACK RUN"
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["args_binding"] == "verbatim", (
        "the receipt must mark the unnormalised-args residual honestly"
    )
    assert any(
        "transfer_funds" in r.getMessage() and "signature" in r.getMessage().lower()
        for r in caplog.records
    ), "the fallback residual must be logged with the tool name"


# ---------------------------------------------------------------------------
# langgraph: a single positional binds by the tool's real parameter name


@pytest.fixture
def langgraph_module():
    pytest.importorskip("langgraph")
    from raucle.integrations import langgraph as langgraph_adapter

    return langgraph_adapter


def _lg_recording():
    """A recording tool with defaults, one fresh function object per call."""

    def transfer_funds(customer_id: str, amount: int = 100, details: dict | None = None):
        transfer_funds.calls.append(  # type: ignore[attr-defined]
            {"customer_id": customer_id, "amount": amount, "details": details}
        )
        return f"RUN {customer_id} {amount}"

    transfer_funds.calls = []  # type: ignore[attr-defined]
    return transfer_funds


def _lg_guard(langgraph_module, issuer, tool_callable, events, constraints) -> object:
    from raucle.integrations.langgraph import gate_tool, set_in_force_token

    set_in_force_token(
        issuer.mint(
            agent_id="agent:lg",
            tool=tool_callable.__name__,
            constraints=constraints,
            ttl_seconds=60,
        )
    )
    return gate_tool(
        tool_callable, gate=_gate(issuer), sink=_EventSink(events), agent_id="agent:lg"
    )


def test_langgraph_single_positional_binds_by_parameter_name(langgraph_module, issuer):
    """The single-positional case binds by the tool's REAL parameter name.

    Old behaviour wrapped a lone positional under ``{"input": ...}`` so
    name-keyed constraints never saw it - the falsified baseline.
    """
    from raucle.integrations import langgraph as lg

    events: list[dict] = []
    tool = _lg_recording()
    gated = _lg_guard(
        langgraph_module,
        issuer,
        tool,
        events,
        {"forbidden_values": {"customer_id": ["C-EVIL"]}},
    )

    with pytest.raises(langgraph_module.CapabilityDenied):
        gated("C-EVIL")

    assert tool.calls == [], "the tool body must never run on a denied call"
    receipt = events[-1]
    assert receipt["decision"] == "DENY"
    assert receipt["call_args_hash"] == lg._hash_args(
        {"customer_id": "C-EVIL", "amount": 100, "details": None}
    )
    assert receipt["args_binding"] == "normalised"


def test_langgraph_single_positional_allowed_binds_real_name(langgraph_module, issuer):
    from raucle.integrations import langgraph as lg

    events: list[dict] = []
    tool = _lg_recording()
    gated = _lg_guard(
        langgraph_module, issuer, tool, events, {"forbidden_values": {"customer_id": ["C-EVIL"]}}
    )

    result = gated("C-1042")

    assert result == "RUN C-1042 100"
    assert tool.calls == [{"customer_id": "C-1042", "amount": 100, "details": None}]
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["call_args_hash"] == lg._hash_args(
        {"customer_id": "C-1042", "amount": 100, "details": None}
    )
    assert receipt["args_binding"] == "normalised"


def test_langgraph_multi_positional_binds_by_name(langgraph_module, issuer):
    from raucle.integrations import langgraph as lg

    events: list[dict] = []
    tool = _lg_recording()
    gated = _lg_guard(langgraph_module, issuer, tool, events, {"max_value": {"amount": 100}})

    with pytest.raises(langgraph_module.CapabilityDenied):
        gated("C-1042", 500)

    assert tool.calls == []
    receipt = events[-1]
    assert receipt["decision"] == "DENY"
    assert receipt["call_args_hash"] == lg._hash_args(
        {"customer_id": "C-1042", "amount": 500, "details": None}
    )


def test_langgraph_mixed_positional_and_keyword(langgraph_module, issuer):
    from raucle.integrations import langgraph as lg

    events: list[dict] = []
    tool = _lg_recording()
    gated = _lg_guard(
        langgraph_module, issuer, tool, events, {"forbidden_values": {"customer_id": ["C-EVIL"]}}
    )

    result = gated("C-1042", amount=50)

    assert result == "RUN C-1042 50"
    assert tool.calls == [{"customer_id": "C-1042", "amount": 50, "details": None}]
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["call_args_hash"] == lg._hash_args(
        {"customer_id": "C-1042", "amount": 50, "details": None}
    )


def test_langgraph_defaults_bound_into_the_gate_view(langgraph_module, issuer):
    from raucle.integrations import langgraph as lg

    events: list[dict] = []
    tool = _lg_recording()
    gated = _lg_guard(langgraph_module, issuer, tool, events, {"max_value": {"amount": 50}})

    with pytest.raises(langgraph_module.CapabilityDenied):
        gated("C-1042")

    assert tool.calls == [], "the default amount must be gated, not silently allowed"
    receipt = events[-1]
    assert receipt["decision"] == "DENY"
    assert receipt["call_args_hash"] == lg._hash_args(
        {"customer_id": "C-1042", "amount": 100, "details": None}
    )


def test_langgraph_variadic_signature_gated_as_variadic(langgraph_module, issuer):
    from raucle.integrations import langgraph as lg

    events: list[dict] = []

    def variadic_tool(*rest: int, **more: int):
        variadic_tool.calls.append({"rest": rest, "more": more})  # type: ignore[attr-defined]
        return "VARIADIC RUN"

    variadic_tool.calls = []  # type: ignore[attr-defined]
    gated = _lg_guard(langgraph_module, issuer, variadic_tool, events, {})

    result = gated(1, 2, x=3)

    assert result == "VARIADIC RUN"
    assert variadic_tool.calls == [{"rest": (1, 2), "more": {"x": 3}}]
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["args_binding"] == "normalised"
    # Var-positional members fold in by index; var-keyword members carry
    # their actual caller names so name-keyed constraints still see them.
    assert receipt["call_args_hash"] == lg._hash_args({"0": 1, "1": 2, "x": 3})


def test_langgraph_nested_structures_bind_semantically(langgraph_module, issuer):
    from raucle.integrations import langgraph as lg

    events: list[dict] = []
    tool = _lg_recording()
    gated = _lg_guard(langgraph_module, issuer, tool, events, {})

    nested = {"branch": {"deep": [1, 2, {"leaf": True}]}}
    result = gated("C-1042", 10, nested)

    assert result == "RUN C-1042 10"
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["call_args_hash"] == lg._hash_args(
        {"customer_id": "C-1042", "amount": 10, "details": nested}
    )
    assert tool.calls[-1]["details"] == nested


def test_langgraph_unresolvable_signature_falls_back_with_residual(
    langgraph_module, issuer, caplog
):
    """No resolvable signature: the previous ``{"input": ...}`` heuristic is
    kept, the receipt marks the residual and the fallback is logged."""
    from raucle.integrations import langgraph as lg

    events: list[dict] = []

    def opaque_tool(customer_id: str):
        return "FALLBACK RUN"

    opaque_tool.__signature__ = 42  # type: ignore[assignment]

    gated = _lg_guard(langgraph_module, issuer, opaque_tool, events, {})

    result = gated("C-1042")

    assert result == "FALLBACK RUN"
    receipt = events[-1]
    assert receipt["decision"] == "ALLOW"
    assert receipt["args_binding"] == "verbatim", (
        "the receipt must mark the unnormalised-args residual honestly"
    )
    assert receipt["call_args_hash"] == lg._hash_args({"input": "C-1042"})
    assert any("signature" in r.getMessage().lower() for r in caplog.records), (
        "the fallback residual must be logged"
    )
