"""X1: schema-bound tool-call enforcement tests.

Covers: the acceptance case (``amount: number`` denies the string
``"99999"`` with no max bound), undeclared-field load errors, MCP +
OpenAPI source paths, type-coercion edges (bool/int), and the
schema/rule-conflict load failure.
"""

from __future__ import annotations

import pytest

from raucle.tool_schema import (
    SchemaPolicyLoadError,
    ToolSchemaError,
    ToolSchemaRegistry,
    extract_rule_fields,
)

_ACCEPT_SCHEMA = {
    "type": "object",
    "properties": {
        "recipient": {"type": "string"},
        "amount": {"type": "number"},
    },
    "required": ["recipient", "amount"],
}


# ---------------------------------------------------------------------------
# Acceptance case + call-time validation
# ---------------------------------------------------------------------------


def test_acceptance_type_confused_amount_denies():
    """amount: number denies \"99999\" with no max bound on the rule."""
    reg = ToolSchemaRegistry()
    reg.register("send_money", dict(_ACCEPT_SCHEMA))
    assert reg.violations("send_money", {"recipient": "alice@example", "amount": "99999"})


def test_acceptance_schema_bound_number_passes():
    reg = ToolSchemaRegistry()
    reg.register("send_money", dict(_ACCEPT_SCHEMA))
    assert reg.violations("send_money", {"recipient": "alice@example", "amount": 99999}) == []


def test_unregistered_tool_has_no_schema_verdict():
    reg = ToolSchemaRegistry()
    assert reg.violations("unknown_tool", {"amount": "99999"}) == []


def test_violations_reason_names_schema_violation():
    reg = ToolSchemaRegistry()
    reg.register("send_money", dict(_ACCEPT_SCHEMA))
    reasons = reg.violations("send_money", {"amount": "99999"})
    assert reasons and "schema_violation" in reasons[0]


def test_undeclared_argument_denies_when_additional_properties_false():
    reg = ToolSchemaRegistry()
    reg.register(
        "send_money",
        {
            "type": "object",
            "properties": {"amount": {"type": "number"}},
            "additionalProperties": False,
        },
    )
    # 'recepient' (typo) smuggles the forbidden value under a new name.
    reasons = reg.violations("send_money", {"amount": 5, "recepient": "evil@attacker"})
    assert reasons
    assert "recepient" in reasons[0]


def test_undeclared_argument_allowed_without_additional_properties_false():
    reg = ToolSchemaRegistry()
    reg.register("send_money", {"type": "object", "properties": {"amount": {"type": "number"}}})
    assert reg.violations("send_money", {"amount": 5, "note": "n"}) == []


def test_non_object_args_deny():
    reg = ToolSchemaRegistry()
    reg.register("send_money", dict(_ACCEPT_SCHEMA))
    assert reg.violations("send_money", ["99999"])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Type-coercion edges
# ---------------------------------------------------------------------------


def test_bool_is_not_integer():
    reg = ToolSchemaRegistry()
    reg.register("t", {"type": "object", "properties": {"n": {"type": "integer"}}})
    assert reg.violations("t", {"n": True})


def test_bool_is_not_number():
    reg = ToolSchemaRegistry()
    reg.register("t", {"type": "object", "properties": {"n": {"type": "number"}}})
    assert reg.violations("t", {"n": False})


def test_float_denied_for_integer():
    reg = ToolSchemaRegistry()
    reg.register("t", {"type": "object", "properties": {"n": {"type": "integer"}}})
    assert reg.violations("t", {"n": 1.5})


def test_int_accepted_for_number():
    reg = ToolSchemaRegistry()
    reg.register("t", {"type": "object", "properties": {"n": {"type": "number"}}})
    assert reg.violations("t", {"n": 3}) == []


def test_number_type_mismatch_kinds():
    reg = ToolSchemaRegistry()
    reg.register(
        "t",
        {
            "type": "object",
            "properties": {
                "s": {"type": "string"},
                "b": {"type": "boolean"},
                "a": {"type": "array"},
                "o": {"type": "object"},
            },
        },
    )
    reasons = reg.violations("t", {"s": 1, "b": "true", "a": "x", "o": []})
    assert len(reasons) == 4


def test_nan_is_not_number():
    reg = ToolSchemaRegistry()
    reg.register("t", {"type": "object", "properties": {"n": {"type": "number"}}})
    assert reg.violations("t", {"n": float("nan")})


# ---------------------------------------------------------------------------
# Load-time binding: undeclared field errors
# ---------------------------------------------------------------------------


def test_undeclared_policy_field_is_load_time_error():
    reg = ToolSchemaRegistry()
    reg.register("send_money", {"type": "object", "properties": {"amount": {"type": "number"}}})
    # amount is declared — this bind succeeds.
    reg.bind_policy("send_money", {"max_value": {"amount": 100}})
    # recipient2 is NOT declared in the schema — a load-time error.
    with pytest.raises(SchemaPolicyLoadError) as exc2:
        reg.bind_policy(
            "send_money",
            {"forbidden_values": {"recipient2": ["evil@attacker"]}},
        )
    msg = str(exc2.value)
    assert "send_money" in msg and "recipient2" in msg


def test_declared_policy_field_binds():
    reg = ToolSchemaRegistry()
    reg.register("send_money", dict(_ACCEPT_SCHEMA))
    reg.bind_policy(
        "send_money",
        {"max_value": {"amount": 100}, "forbidden_values": {"recipient": ["x@y"]}},
    )


def test_bind_policy_without_registered_schema_refuses():
    reg = ToolSchemaRegistry()
    with pytest.raises(SchemaPolicyLoadError) as exc:
        reg.bind_policy("send_money", {"max_value": {"amount": 100}})
    msg = str(exc.value)
    assert "send_money" in msg
    assert "no registered parameter schema" in msg


def test_schema_rule_conflict_load_failure_variants():
    reg = ToolSchemaRegistry()
    reg.register("t", {"type": "object", "properties": {"a": {"type": "string"}}})
    for kind in ("allowed_values", "max_value", "min_value", "starts_with"):
        with pytest.raises(SchemaPolicyLoadError):
            reg.bind_policy("t", {kind: {"undeclared_field": ["x"]}})
    with pytest.raises(SchemaPolicyLoadError):
        reg.bind_policy("t", {"required_present": ["nope"]})
    with pytest.raises(SchemaPolicyLoadError):
        reg.bind_policy("t", {"forbidden_field_combinations": [["a", "nope"]]})


def test_extract_rule_fields_rejects_unmodelled_kind():
    with pytest.raises(ToolSchemaError):
        extract_rule_fields({"mystery_kind": {"a": [1]}})


# ---------------------------------------------------------------------------
# Registration-shape failure (load-time, fail closed)
# ---------------------------------------------------------------------------


def test_register_rejects_non_object_schema():
    reg = ToolSchemaRegistry()
    with pytest.raises(ToolSchemaError):
        reg.register("t", "number")  # type: ignore[arg-type]


def test_register_rejects_non_object_properties():
    reg = ToolSchemaRegistry()
    with pytest.raises(ToolSchemaError):
        reg.register("t", {"type": "object", "properties": ["a"]})


def test_conflicting_re_registration_is_load_error():
    reg = ToolSchemaRegistry()
    reg.register("t", {"type": "object", "properties": {"a": {"type": "string"}}})
    with pytest.raises(SchemaPolicyLoadError):
        reg.register("t", {"type": "object", "properties": {"b": {"type": "string"}}})
    # identical re-registration is idempotent
    reg.register("t", {"type": "object", "properties": {"a": {"type": "string"}}})


# ---------------------------------------------------------------------------
# Source paths: MCP (primary) and OpenAPI fragment (secondary)
# ---------------------------------------------------------------------------


def test_mcp_tools_list_payload_registers():
    reg = ToolSchemaRegistry()
    reg.register_from_mcp_tools(
        [
            {
                "name": "send_money",
                "description": "send",
                "inputSchema": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}},
                    "required": ["amount"],
                },
            }
        ]
    )
    assert reg.has_schema("send_money")
    assert reg.violations("send_money", {"amount": "99999"})
    reg.bind_policy("send_money", {"max_value": {"amount": 100}})


def test_mcp_payload_missing_input_schema_is_load_error():
    reg = ToolSchemaRegistry()
    with pytest.raises(SchemaPolicyLoadError) as exc:
        reg.register_from_mcp_tools([{"name": "no_schema_tool"}])
    assert "no_schema_tool" in str(exc.value)


def test_mcp_payload_malformed_is_load_error():
    reg = ToolSchemaRegistry()
    with pytest.raises(SchemaPolicyLoadError):
        reg.register_from_mcp_tools("not-a-list")  # type: ignore[arg-type]
    with pytest.raises(SchemaPolicyLoadError):
        reg.register_from_mcp_tools([{"inputSchema": {"type": "object"}}])


def test_openapi_fragment_requestpath_registers():
    reg = ToolSchemaRegistry()
    reg.register_from_openapi_fragment(
        {
            "paths": {
                "/payments": {
                    "post": {
                        "operationId": "create_payment",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"amount": {"type": "number"}},
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
    )
    assert reg.violations("create_payment", {"amount": "99999"})
    assert reg.violations("create_payment", {"amount": 1}) == []


def test_openapi_fragment_query_parameters_registers():
    reg = ToolSchemaRegistry()
    reg.register_from_openapi_fragment(
        {
            "paths": {
                "/search": {
                    "get": {
                        "operationId": "search_docs",
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                        ],
                    }
                }
            }
        }
    )
    assert reg.violations("search_docs", {"q": "ok", "limit": "many"})
    assert reg.violations("search_docs", {"q": "ok", "limit": 10}) == []


def test_openapi_operation_without_schema_is_load_error():
    reg = ToolSchemaRegistry()
    with pytest.raises(SchemaPolicyLoadError):
        reg.register_from_openapi_fragment({"paths": {"/noop": {"post": {"operationId": "noop"}}}})


def test_openapi_operation_without_operation_id_is_load_error():
    reg = ToolSchemaRegistry()
    with pytest.raises(SchemaPolicyLoadError):
        reg.register_from_openapi_fragment(
            {
                "paths": {
                    "/x": {
                        "post": {
                            "requestBody": {
                                "content": {"application/json": {"schema": {"type": "object"}}}
                            }
                        }
                    }
                }
            }
        )


# ---------------------------------------------------------------------------
# Gate integration
# ---------------------------------------------------------------------------


def test_gate_denies_type_confused_args_with_named_reason():
    # The full acceptance path: gate + registry, token without any bound.
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityGate, CapabilityIssuer

    iss = CapabilityIssuer.generate(issuer="platform.example")
    reg = ToolSchemaRegistry()
    reg.register("send_money", dict(_ACCEPT_SCHEMA))
    reg.bind_policy("send_money", {"required_present": ["amount"]})
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        tool_schemas=reg,
    )
    cap = iss.mint(
        agent_id="agent:billing",
        tool="send_money",
        constraints={"required_present": ["amount"]},
    )
    decision = gate.check(
        cap,
        tool="send_money",
        agent_id="agent:billing",
        args={"amount": "99999"},
    )
    assert decision.denied
    assert "schema_violation" in decision.reason
    assert "amount" in decision.reason


def test_gate_allows_schema_valid_args():
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityGate, CapabilityIssuer

    iss = CapabilityIssuer.generate(issuer="platform.example")
    reg = ToolSchemaRegistry()
    reg.register("send_money", dict(_ACCEPT_SCHEMA))
    reg.bind_policy("send_money", {"required_present": ["amount"]})
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        tool_schemas=reg,
    )
    cap = iss.mint(
        agent_id="agent:billing",
        tool="send_money",
        constraints={"required_present": ["amount"]},
    )
    decision = gate.check(
        cap,
        tool="send_money",
        agent_id="agent:billing",
        args={"amount": 42},
    )
    assert decision.allowed, decision.reason


def test_gate_without_registry_ignores_type_confusion_legacy_path():
    """A tool without a registered schema keeps the legacy name-based path."""
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityGate, CapabilityIssuer

    iss = CapabilityIssuer.generate(issuer="platform.example")
    gate = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem})
    cap = iss.mint(agent_id="agent:x", tool="legacy_tool")
    decision = gate.check(cap, tool="legacy_tool", agent_id="agent:x", args={"anything": "any"})
    assert decision.allowed


def test_gate_rejects_non_registry_tool_schemas_arg():
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityGate, CapabilityIssuer

    iss = CapabilityIssuer.generate(issuer="platform.example")
    with pytest.raises(ValueError):
        CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem}, tool_schemas={})


# ---------------------------------------------------------------------------
# Conformance vectors (standards/test-vectors/schema_enforcement_v1_*.json)
# ---------------------------------------------------------------------------

import json
from pathlib import Path

_VECTORS = Path(__file__).resolve().parent.parent / "standards" / "test-vectors"


def test_vector_01_replays_as_deny():
    v = json.loads((_VECTORS / "schema_enforcement_v1_01_type_confusion_denies.json").read_text())
    reg = ToolSchemaRegistry()
    reg.register(v["tool"], v["inputSchema"])
    reasons = reg.violations(v["tool"], v["args"])
    assert reasons
    assert f"schema_violation: {reasons[0]}" == v["decision"]["reason"]


def test_vector_02_load_error_message_matches():
    v = json.loads(
        (_VECTORS / "schema_enforcement_v1_02_undeclared_field_load_error.json").read_text()
    )
    reg = ToolSchemaRegistry()
    reg.register(v["tool"], v["inputSchema"])
    with pytest.raises(SchemaPolicyLoadError) as exc:
        reg.bind_policy(v["tool"], v["policy_rule"])
    assert str(exc.value) == v["load"]["message"]
    assert v["tool"] in str(exc.value)


def test_vector_03_replays_bool_coercion_deny():
    v = json.loads((_VECTORS / "schema_enforcement_v1_03_bool_not_integer.json").read_text())
    reg = ToolSchemaRegistry()
    reg.register(v["tool"], v["inputSchema"])
    reasons = reg.violations(v["tool"], v["args"])
    assert reasons
    assert f"schema_violation: {reasons[0]}" == v["decision"]["reason"]
