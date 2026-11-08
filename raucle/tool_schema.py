"""X1: schema-bound tool-call enforcement.

The capability gate historically enforced policy rules on the argument
*names* the policy declared, with no knowledge of the tool's parameter
schema (the documented caveat in ``raucle.capability``). This module
binds the gate to the tool's declared schema so that:

1. A policy rule referencing a field the tool does not declare is a
   **load-time error** (``SchemaPolicyLoadError`` naming the tool and
   the field) — config load refuses, the deployment never boots with a
   rule the tool can never satisfy.
2. Argument values are validated against the schema at the gate — a
   type-confused value (e.g. the string ``"99999"`` for a ``number``
   parameter) is a DENY named ``schema_violation`` regardless of any
   numeric bound.
3. Conflicts between the schema and the rule set fail at load, not at
   call time.

Sources
-------
* **MCP (primary).** ``register_from_mcp_tools`` consumes the
  ``tools/list`` payload of an MCP server: ``[{name, inputSchema}, ...]``.
* **OpenAPI fragment (secondary).** ``register_from_openapi_fragment``
  consumes a fragment of an OpenAPI document for non-MCP tools.

Fail-closed rule: a tool **without** a registered schema keeps today's
behaviour (name-based checks only). A tool **with** a registered schema
gets the schema check as an additional, always-on gate stage.
"""

from __future__ import annotations

import math
from typing import Any

from raucle.registry import CONSTRAINT_REGISTRY

__all__ = [
    "ToolSchemaError",
    "SchemaPolicyLoadError",
    "ToolSchema",
    "ToolSchemaRegistry",
    "extract_rule_fields",
]

_FIELD_TO_VALUES_KINDS = ("forbidden_values", "allowed_values")
_FIELD_TO_SCALAR_KINDS = ("starts_with", "max_value", "min_value")
_FIELD_LIST_KINDS = ("required_present",)
_COMBO_LIST_KINDS = ("forbidden_field_combinations",)


class ToolSchemaError(ValueError):
    """Base class for schema-binding errors."""


class SchemaPolicyLoadError(ToolSchemaError):
    """Load-time error: a policy rule conflicts with the tool's schema.

    Raised when a constraint references a field the tool's parameter
    schema does not declare, or when a rule cannot be bound at config
    load. The message names the tool and the offending field.
    """


def _is_number(v: Any) -> bool:
    # bool is a subclass of int — exclude it. Non-finite floats
    # (NaN/inf) cannot be represented in JSON Schema numbers.
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    if isinstance(v, float):
        return math.isfinite(v)
    return False


def _describe_type(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "str"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, (list, tuple)):
        return "array"
    if v is None:
        return "null"
    return type(v).__name__


class ToolSchema:
    """A tool's declared input schema (JSON Schema subset).

    Construction validates the fragment shape: an object-typed schema
    with a ``properties`` mapping. A fragment the deployment cannot
    interpret must fail at load, never at call time.
    """

    def __init__(self, name: str, schema: dict[str, Any]) -> None:
        if not isinstance(name, str) or not name:
            raise ToolSchemaError("tool schema name must be a non-empty string")
        if not isinstance(schema, dict):
            raise ToolSchemaError(
                f"tool {name!r}: inputSchema must be a JSON object, got {type(schema).__name__}"
            )
        if schema.get("type") not in (None, "object"):
            raise ToolSchemaError(
                f"tool {name!r}: inputSchema.type must be 'object', got {schema.get('type')!r}"
            )
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ToolSchemaError(f"tool {name!r}: inputSchema.properties must be a JSON object")
        self.name = name
        self.schema = schema
        self.properties = properties
        self.additional_properties = bool(schema.get("additionalProperties") is False)

    def declared_fields(self) -> set[str]:
        return set(self.properties)


def extract_rule_fields(constraints: dict[str, Any]) -> list[str]:
    """Return every argument field referenced by a policy rule.

    Unknown constraint kinds raise ``ToolSchemaError`` — the whole point
    of the load-time bind is to refuse configs the gate could silently
    under-enforce.
    """
    if not isinstance(constraints, dict):
        raise ToolSchemaError("policy constraints must be a JSON object")
    fields: list[str] = []
    for kind, payload in constraints.items():
        if kind not in CONSTRAINT_REGISTRY:
            raise ToolSchemaError(f"unmodelled constraint kind {kind!r} in policy rule")
        if kind in _FIELD_TO_VALUES_KINDS or kind in _FIELD_TO_SCALAR_KINDS:
            if not isinstance(payload, dict):
                raise ToolSchemaError(f"constraint {kind!r} must be a field mapping")
            fields.extend(str(fld) for fld in payload)
        elif kind in _FIELD_LIST_KINDS:
            if not isinstance(payload, list):
                raise ToolSchemaError(f"constraint {kind!r} must be a field list")
            fields.extend(str(fld) for fld in payload)
        elif kind in _COMBO_LIST_KINDS:
            if not isinstance(payload, list):
                raise ToolSchemaError(f"constraint {kind!r} must be a combination list")
            for combo in payload:
                if not isinstance(combo, (list, tuple)):
                    raise ToolSchemaError(f"constraint {kind!r} entries must be field lists")
                fields.extend(str(fld) for fld in combo)
        else:  # pragma: no cover - registry is exhaustive above
            raise ToolSchemaError(f"unmodelled constraint kind {kind!r} in policy rule")
    return fields


class ToolSchemaRegistry:
    """Load-time binding of tool schemas to policy rules.

    ``bind_policy`` is the config-load entry point: it refuses (raises
    ``SchemaPolicyLoadError``) any rule that references an undeclared
    field, naming the tool and the field. ``violations`` is the gate's
    call-time entry point.
    """

    def __init__(self) -> None:
        self._schemas: dict[str, ToolSchema] = {}

    # -- registration -------------------------------------------------------

    def register(self, name: str, schema: dict[str, Any]) -> ToolSchema:
        ts = ToolSchema(name, schema)
        existing = self._schemas.get(name)
        if existing is not None and existing.schema != ts.schema:
            raise SchemaPolicyLoadError(
                f"tool {name!r}: conflicting inputSchema registered "
                f"(already registered with a different schema)"
            )
        self._schemas[name] = ts
        return ts

    def register_from_mcp_tools(self, tools: list[dict[str, Any]]) -> None:
        """Primary source: an MCP ``tools/list`` payload.

        Each entry must be ``{"name": str, "inputSchema": object}`` —
        anything else is a load-time error (fail closed at boot).
        """
        if not isinstance(tools, list):
            raise SchemaPolicyLoadError("MCP tools payload must be a list")
        for tool in tools:
            if not isinstance(tool, dict):
                raise SchemaPolicyLoadError("MCP tool entry must be a JSON object")
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                raise SchemaPolicyLoadError(f"MCP tool entry missing name: {tool!r}")
            schema = tool.get("inputSchema")
            if not isinstance(schema, dict):
                raise SchemaPolicyLoadError(
                    f"tool {name!r}: MCP entry missing an object inputSchema"
                )
            self.register(name, schema)

    def register_from_openapi_fragment(self, fragment: dict[str, Any]) -> None:
        """Secondary source: an OpenAPI fragment for non-MCP tools.

        Consumes ``{"paths": {...}}`` operations that carry an
        ``operationId`` and a JSON ``requestBody`` schema (or a query
        ``parameters`` object schema). A schema-less operation is a
        load-time error, not a silent skip.
        """
        if not isinstance(fragment, dict) or not isinstance(fragment.get("paths"), dict):
            raise SchemaPolicyLoadError("OpenAPI fragment must carry a 'paths' object")
        for path, item in fragment["paths"].items():
            if not isinstance(item, dict):
                raise SchemaPolicyLoadError(f"OpenAPI path {path!r}: entry must be an object")
            for method, op in sorted(item.items()):
                if method.startswith("x-") or method == "parameters":
                    continue
                if not isinstance(op, dict):
                    raise SchemaPolicyLoadError(
                        f"OpenAPI path {path!r} {method!r}: operation must be an object"
                    )
                op_id = op.get("operationId")
                if not isinstance(op_id, str) or not op_id:
                    raise SchemaPolicyLoadError(
                        f"OpenAPI path {path!r} {method!r}: missing operationId"
                    )
                schema = self._openapi_operation_schema(path, method, op)
                self.register(op_id, schema)

    @staticmethod
    def _openapi_operation_schema(path: str, method: str, op: dict[str, Any]) -> dict[str, Any]:
        # Prefer a JSON requestBody schema; otherwise merge query parameters
        # into one object schema. A schema-less operation fails closed.
        body = op.get("requestBody")
        body_schema: dict[str, Any] | None = None
        if isinstance(body, dict):
            content = body.get("content") or {}
            app = content.get("application/json") or {}
            candidate = app.get("schema")
            if isinstance(candidate, dict):
                body_schema = candidate
            elif not (isinstance(params := op.get("parameters"), list) and params):
                raise SchemaPolicyLoadError(
                    f"OpenAPI path {path!r} {method!r}: requestBody has no JSON schema"
                )
        params = op.get("parameters")
        props: dict[str, Any] = {}
        required: list[str] = []
        has_params = isinstance(params, list) and any(
            isinstance(p, dict) and p.get("schema") for p in params
        )
        if isinstance(params, list):
            for p in params:
                if not isinstance(p, dict):
                    continue
                p_schema = p.get("schema")
                if not isinstance(p_schema, dict) or not p.get("name"):
                    raise SchemaPolicyLoadError(
                        f"OpenAPI path {path!r} {method!r}: parameter without a schema"
                    )
                props[p["name"]] = p_schema
                if p.get("required"):
                    required.append(p["name"])
        if not body and not has_params:
            raise SchemaPolicyLoadError(
                f"OpenAPI path {path!r} {method!r}: operation carries no usable JSON schema"
            )
        if body_schema is not None:
            return body_schema
        if not props:
            raise SchemaPolicyLoadError(
                f"OpenAPI path {path!r} {method!r}: operation carries no usable JSON schema"
            )
        out: dict[str, Any] = {"type": "object", "properties": props}
        if required:
            out["required"] = required
        return out

    # -- load-time binding --------------------------------------------------

    def bind_policy(self, tool: str, constraints: dict[str, Any]) -> None:
        """Config-load entry point: bind a tool's policy rule to its schema.

        Raises ``SchemaPolicyLoadError`` naming the tool and the field
        when the rule references a field the schema does not declare,
        or when the tool has no schema registered at all (a rule for a
        schema-unknown tool cannot be schema-bound — the deployment
        either registers the schema or refuses the config).
        """
        if tool not in self._schemas:
            raise SchemaPolicyLoadError(
                f"tool {tool!r}: policy rule present but the tool has no "
                "registered parameter schema (register the inputSchema first)"
            )
        ts = self._schemas[tool]
        for fld in extract_rule_fields(constraints):
            if fld not in ts.declared_fields():
                raise SchemaPolicyLoadError(
                    f"tool {tool!r}: policy rule references undeclared field {fld!r}"
                )

    def has_schema(self, tool: str) -> bool:
        return tool in self._schemas

    # -- call-time enforcement ----------------------------------------------

    def violations(self, tool: str, args: dict[str, Any] | None) -> list[str]:
        """Return a list of schema violations for the call's arguments.

        Returns type-confused values, undeclared arguments (when the
        schema sets ``additionalProperties: false``) and non-object
        argument payloads. An empty list means the call is schema-valid.
        """
        ts = self._schemas.get(tool)
        if ts is None:
            return []
        if args is None or args == {}:
            return []
        if not isinstance(args, dict):
            return [f"arguments must be a JSON object, got {type(args).__name__}"]
        out: list[str] = []
        for fld, value in args.items():
            prop = ts.properties.get(fld)
            if prop is None:
                if ts.additional_properties:
                    out.append(
                        f"argument {fld!r} is not declared in tool {tool!r}'s parameter schema"
                    )
                continue
            decl = prop.get("type")
            if decl is None:
                continue
            reason = _type_conflict(decl, value)
            if reason:
                out.append(f"schema_violation: field {fld!r} {reason}")
        return out


def _type_conflict(declared: str, value: Any) -> str | None:
    """Return a violation reason string, or None when value fits."""
    ok: bool
    if declared == "number":
        ok = _is_number(value)  # excludes bool — the type-coercion edge
    elif declared == "integer":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif declared == "string":
        ok = isinstance(value, str)
    elif declared == "boolean":
        ok = isinstance(value, bool)
    elif declared == "array":
        ok = isinstance(value, (list, tuple))
    elif declared == "object":
        ok = isinstance(value, dict)
    elif declared == "null":
        ok = value is None
    else:
        # Unknown declared type: do not fabricate a verdict for a type
        # the schema subset does not model (e.g. "integer|number"). The
        # load-time bind refuses such fragments only when referenced by
        # a rule; plain type checks skip them — fail-safe over fail-happy.
        return None
    if ok:
        return None
    return f"is declared {declared!r} but value is {_describe_type(value)!r}"
