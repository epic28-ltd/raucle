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

W2 (definition drift, EPIC W) extends the bind: every registration
computes a ``definition_digest`` (sha256 over the schema's canonical
JSON), gate receipts for schema-registered tools carry it, and the
explicit reload path supersedes a changed definition while returning
the drift (old and new digests only, never schema content) for the
gateway to receipt as evidence.

W1 (state verification, EPIC W) adds the write-to-read pairing
registry: operator-declared ``state_pairings`` entries bind each
write tool to the read tool that reads the state back, validated
fail-closed at config load against this same schema registry. A
pairing referencing an unknown tool or an undeclared id field
raises a ``SchemaPolicyLoadError``-class error at config load, never
at call time.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from raucle.registry import CONSTRAINT_REGISTRY

__all__ = [
    "ToolSchemaError",
    "SchemaPolicyLoadError",
    "ToolSchema",
    "ToolSchemaRegistry",
    "StatePairing",
    "StatePairingRegistry",
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


def _definition_digest(schema: dict[str, Any]) -> str:
    """The definition digest (EPIC W lane W2): sha256 over the schema's
    canonical JSON. Key order and the manifest file's byte layout do not
    change the digest, content does, so the same definition binds the
    same digest across restarts and hosts."""
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ToolSchema:
    """A tool's declared input schema (JSON Schema subset).

    Construction validates the fragment shape: an object-typed schema
    with a ``properties`` mapping. A fragment the deployment cannot
    interpret must fail at load, never at call time.
    """

    def __init__(self, name: str, schema: dict[str, Any], manifest: str = "") -> None:
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
        try:
            # W2: the digest binds at registration; a fragment the
            # deployment cannot canonicalise fails at load, never at
            # receipt time.
            self.digest = _definition_digest(schema)
        except ValueError as exc:
            raise ToolSchemaError(
                f"tool {name!r}: inputSchema is not JSON-serialisable ({exc}); "
                "non-finite numbers are not valid JSON"
            ) from exc
        # W2: the manifest source path the schema was registered from,
        # so receipts can name the pin the verifier recomputes against.
        self.manifest = manifest

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
        fields.extend(_rule_fields_for_kind(kind, payload))
    return fields


def _rule_fields_for_kind(kind: str, payload: Any) -> list[str]:
    """The argument fields one constraint payload binds, with shape checks."""
    if kind in _FIELD_TO_VALUES_KINDS or kind in _FIELD_TO_SCALAR_KINDS:
        if not isinstance(payload, dict):
            raise ToolSchemaError(f"constraint {kind!r} must be a field mapping")
        return [str(fld) for fld in payload]
    if kind in _FIELD_LIST_KINDS:
        if not isinstance(payload, list):
            raise ToolSchemaError(f"constraint {kind!r} must be a field list")
        return [str(fld) for fld in payload]
    if kind in _COMBO_LIST_KINDS:
        if not isinstance(payload, list):
            raise ToolSchemaError(f"constraint {kind!r} must be a combination list")
        fields: list[str] = []
        for combo in payload:
            if not isinstance(combo, (list, tuple)):
                raise ToolSchemaError(f"constraint {kind!r} entries must be field lists")
            fields.extend(str(fld) for fld in combo)
        return fields
    raise ToolSchemaError(  # pragma: no cover - registry is exhaustive above
        f"unmodelled constraint kind {kind!r} in policy rule"
    )


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

    def register(self, name: str, schema: dict[str, Any], manifest: str = "") -> ToolSchema:
        ts = ToolSchema(name, schema, manifest=manifest)
        existing = self._schemas.get(name)
        if existing is not None and existing.schema != ts.schema:
            raise SchemaPolicyLoadError(
                f"tool {name!r}: conflicting inputSchema registered "
                f"(already registered with a different schema)"
            )
        self._schemas[name] = ts
        return ts

    def register_from_mcp_tools(self, tools: list[dict[str, Any]], manifest: str = "") -> None:
        """Primary source: an MCP ``tools/list`` payload.

        Each entry must be ``{"name": str, "inputSchema": object}`` —
        anything else is a load-time error (fail closed at boot).
        """
        for name, schema in self._validated_mcp_entries(tools):
            self.register(name, schema, manifest=manifest)

    @staticmethod
    def _validated_mcp_entries(
        tools: list[dict[str, Any]],
    ) -> list[tuple[str, dict[str, Any]]]:
        """Validated ``(name, inputSchema)`` pairs from an MCP payload."""
        if not isinstance(tools, list):
            raise SchemaPolicyLoadError("MCP tools payload must be a list")
        out: list[tuple[str, dict[str, Any]]] = []
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
            out.append((name, schema))
        return out

    def reload_from_mcp_tools(
        self, tools: list[dict[str, Any]], manifest: str = ""
    ) -> list[dict[str, Any]]:
        """The W2 reload path: re-register every entry, superseding a
        changed definition instead of refusing it, and return the drift
        records (tool, old and new digests, manifest) for the gateway to
        receipt as evidence. Old and new digests only: schema content
        never leaves the registry. Entries absent from the payload stay
        registered (removal is a named follow-up, never a silent drop)."""
        drift: list[dict[str, Any]] = []
        for name, schema in self._validated_mcp_entries(tools):
            incoming = ToolSchema(name, schema, manifest=manifest)
            existing = self._schemas.get(name)
            if existing is not None and existing.digest != incoming.digest:
                drift.append(
                    {
                        "tool": name,
                        "old_definition_digest": existing.digest,
                        "new_definition_digest": incoming.digest,
                        "manifest": manifest,
                    }
                )
            self._schemas[name] = incoming
        return drift

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
                self._register_openapi_operation(path, method, op)

    def _register_openapi_operation(self, path: str, method: str, op: Any) -> None:
        """Validate one OpenAPI operation and register its derived schema."""
        if not isinstance(op, dict):
            raise SchemaPolicyLoadError(
                f"OpenAPI path {path!r} {method!r}: operation must be an object"
            )
        op_id = op.get("operationId")
        if not isinstance(op_id, str) or not op_id:
            raise SchemaPolicyLoadError(f"OpenAPI path {path!r} {method!r}: missing operationId")
        schema = self._openapi_operation_schema(path, method, op)
        self.register(op_id, schema)

    @staticmethod
    def _openapi_body_schema(path: str, method: str, op: dict[str, Any]) -> dict[str, Any] | None:
        """The requestBody's JSON schema when present and well-formed."""
        body = op.get("requestBody")
        if not isinstance(body, dict):
            return None
        content = body.get("content") or {}
        app = content.get("application/json") or {}
        candidate = app.get("schema")
        if isinstance(candidate, dict):
            return candidate
        params = op.get("parameters")
        if not (isinstance(params, list) and params):
            raise SchemaPolicyLoadError(
                f"OpenAPI path {path!r} {method!r}: requestBody has no JSON schema"
            )
        return None

    @staticmethod
    def _openapi_param_rows(
        path: str, method: str, op: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], bool]:
        """Validated query-parameter rows: (props, required, has_params)."""
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
        return props, required, has_params

    @staticmethod
    def _openapi_operation_schema(path: str, method: str, op: dict[str, Any]) -> dict[str, Any]:
        # Prefer a JSON requestBody schema; otherwise merge query parameters
        # into one object schema. A schema-less operation fails closed.
        body = op.get("requestBody")
        body_schema = ToolSchemaRegistry._openapi_body_schema(path, method, op)
        props, required, has_params = ToolSchemaRegistry._openapi_param_rows(path, method, op)
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

    def definition_digest(self, tool: str) -> str | None:
        """The definition digest bound at registration (EPIC W lane W2),
        or None when the tool has no registered schema."""
        ts = self._schemas.get(tool)
        return ts.digest if ts is not None else None

    def definition_manifest(self, tool: str) -> str:
        """The manifest source path the tool's schema was registered from
        (empty string when registered without one)."""
        ts = self._schemas.get(tool)
        return ts.manifest if ts is not None else ""

    def declared_fields(self, tool: str) -> set[str] | None:
        """The tool's declared input field names, or None when the tool
        has no registered schema (EPIC W lane W1: the pairing registry
        validates its id_pointer against the read tool's declared
        fields, the same load-time bind as ``bind_policy``)."""
        ts = self._schemas.get(tool)
        return set(ts.properties) if ts is not None else None

    def registered_tools(self) -> list[str]:
        """Every tool with a registered schema, sorted for stable output."""
        return sorted(self._schemas)

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


class StatePairing:
    """EPIC W lane W1: one operator-declared write-to-read pairing.

    The entry binds the write tool whose state a read-back verifies,
    the read tool that performs it, the id pointer naming the field
    the read carries (and the handle is extracted through), and the
    optional field-presence names the read response must show. The
    entry id is derived deterministically as
    ``<write_tool>:<read_tool>``, so receipts cite a stable, nameable
    pairing across restarts and hosts. Names only: an entry never
    carries schema content.
    """

    def __init__(
        self,
        *,
        write_tool: str,
        read_tool: str,
        id_pointer: str,
        require_field_classes: list[str] | tuple[str, ...] = (),
    ) -> None:
        for field_name, value in (
            ("write_tool", write_tool),
            ("read_tool", read_tool),
            ("id_pointer", id_pointer),
        ):
            if not isinstance(value, str) or not value:
                raise SchemaPolicyLoadError(
                    f"state_pairings entry field {field_name!r} must be a non-empty string"
                )
        classes = list(require_field_classes or [])
        for cls in classes:
            if not isinstance(cls, str) or not cls:
                raise SchemaPolicyLoadError(
                    "state_pairings require_field_classes entries must be non-empty strings"
                )
        self.write_tool = write_tool
        self.read_tool = read_tool
        self.id_pointer = id_pointer
        self.require_field_classes = tuple(classes)
        self.pairing_id = f"{write_tool}:{read_tool}"

    def row(self) -> dict[str, Any]:
        """The bounded-disclosure row: identifiers and field names
        only, never content."""
        return {
            "pairing_id": self.pairing_id,
            "write_tool": self.write_tool,
            "read_tool": self.read_tool,
            "id_pointer": self.id_pointer,
            "require_field_classes": list(self.require_field_classes),
        }


class StatePairingRegistry:
    """EPIC W lane W1: the write-to-read pairing registry, bound at
    config load against the :class:`ToolSchemaRegistry`.

    ``register`` follows the tool_schema load-time doctrine: refuse
    configs the gate could silently under-enforce. A pairing
    referencing an unknown tool or an undeclared id field raises a
    ``SchemaPolicyLoadError``-class error at config load, never at
    call time. One pairing per write tool keeps the paired read
    deterministic; a second entry for the same write tool refuses
    the config.
    """

    def __init__(self, schemas: ToolSchemaRegistry) -> None:
        self._schemas = schemas
        self._by_id: dict[str, StatePairing] = {}
        self._by_write: dict[str, StatePairing] = {}

    def register(self, entry: dict[str, Any]) -> StatePairing:
        """Validate and bind one pairing entry (fail-closed at load)."""
        if not isinstance(entry, dict):
            raise SchemaPolicyLoadError("state_pairings entry must be a JSON object")
        pairing = StatePairing(
            write_tool=str(entry.get("write_tool") or ""),
            read_tool=str(entry.get("read_tool") or ""),
            id_pointer=str(entry.get("id_pointer") or ""),
            require_field_classes=list(entry.get("require_field_classes") or []),
        )
        for role, tool in (("write", pairing.write_tool), ("read", pairing.read_tool)):
            if not self._schemas.has_schema(tool):
                raise SchemaPolicyLoadError(
                    f"state_pairings entry {pairing.pairing_id!r} references unknown "
                    f"{role} tool {tool!r} (register the inputSchema first)"
                )
        declared = self._schemas.declared_fields(pairing.read_tool)
        if declared is None or pairing.id_pointer not in declared:
            raise SchemaPolicyLoadError(
                f"state_pairings entry {pairing.pairing_id!r} names id field "
                f"{pairing.id_pointer!r}, which the read tool {pairing.read_tool!r} "
                "does not declare (the read must be parameterisable by the handle)"
            )
        existing = self._by_write.get(pairing.write_tool)
        if existing is not None:
            raise SchemaPolicyLoadError(
                f"state_pairings: write tool {pairing.write_tool!r} is already "
                f"paired with {existing.read_tool!r} (the paired read must be "
                "deterministic)"
            )
        self._by_id[pairing.pairing_id] = pairing
        self._by_write[pairing.write_tool] = pairing
        return pairing

    def pairing_for_write(self, tool: str) -> StatePairing | None:
        """The pairing bound to a write tool, or None when uncovered."""
        return self._by_write.get(tool)

    def pairing(self, pairing_id: str) -> StatePairing | None:
        """The pairing with this entry id, or None."""
        return self._by_id.get(pairing_id)

    def rows(self) -> dict[str, dict[str, Any]]:
        """Every pairing's bounded row, keyed by entry id (sorted for
        stable output)."""
        return {pid: pairing.row() for pid, pairing in sorted(self._by_id.items())}
