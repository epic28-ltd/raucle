"""O2: machine-readable retry guidance derived from a deny's own authority.

When the gate denies a call, the deny receipt already carries the
authority chain, the violated constraint and the reason. What an agent
retry loop needs on top is the QUESTION the reason leaves open: what
would the delegated authority actually have ALLOWED?

This module derives that answer deterministically from the capability
token the adapter already holds - the same signed policy object the gate
enforced. No inference, no model, no round-trip: whitelist constraints
(``allowed_values``), required fields (``required_present``) and numeric
bounds (``min_value``/``max_value``) are positive statements about what
would have been permitted; they are copied into the guidance shape
(intent constraints, where present, are merged in the
fail-closed-narrowing direction: the intersection of whitelists, the
union of required fields, the tighter bound).

Honesty rules, test-pinned:

- ADDITIVE: the guidance rides alongside a deny and never touches the
  verdict. A deny with guidance attached has the same ``decision``,
  ``reason`` and every other field byte-identical to a deny without;
  allow and escalate responses are returned UNCHANGED (the key is never
  added to them).
- HONEST ABSENCE: a deny whose constraints carry no positive,
  derivable alternative (denylists only, rate limits, expiry windows)
  yields NO guidance - the caller sees no ``retry_guidance`` key, not a
  null-shaped guessing licence. Naming absence honestly is the whole
  point: the absence itself is the signal "nothing deterministic to
  say, do not retry blind".

The shape is schema-documented (``raucle/retry-guidance/v1``); the
schema lives in :data:`RETRY_GUIDANCE_SCHEMA` and is written out with
worked examples in ``docs/spec/retry-guidance-v1.md``.
"""

from __future__ import annotations

from typing import Any

SCHEMA_NAME = "raucle/retry-guidance/v1"

RETRY_GUIDANCE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "raucle/retry-guidance/v1",
    "title": "raucle deny retry guidance",
    "description": (
        "Machine-readable description of what a denied call's own "
        "delegated authority WOULD have allowed, derived deterministically "
        "from the capability token the gate enforced. Additive on deny, "
        "absent when nothing deterministic can be said."
    ),
    "type": "object",
    "additionalProperties": False,
    "required": ["schema", "permitted_actions"],
    "properties": {
        "schema": {"const": SCHEMA_NAME},
        "permitted_actions": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["tool", "criteria"],
                "properties": {
                    "tool": {"type": "string", "minLength": 1},
                    "criteria": {
                        "type": "object",
                        "additionalProperties": False,
                        "minProperties": 1,
                        "properties": {
                            "allowed_values": {
                                "description": (
                                    "field -> value whitelist: the retry "
                                    "must pick a value from the list"
                                ),
                                "type": "object",
                                "minProperties": 1,
                                "additionalProperties": {
                                    "type": "array",
                                    "minItems": 1,
                                },
                            },
                            "required_present": {
                                "description": ("fields the retried args must carry"),
                                "type": "array",
                                "minItems": 1,
                                "items": {"type": "string", "minLength": 1},
                            },
                            "bounds": {
                                "description": (
                                    "field -> numeric bounds the retried args must satisfy"
                                ),
                                "type": "object",
                                "minProperties": 1,
                                "additionalProperties": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "minProperties": 1,
                                    "properties": {
                                        "min": {"type": ["integer", "number"]},
                                        "max": {"type": ["integer", "number"]},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


def _normalise_constraints(c: dict[str, Any]) -> dict[str, Any]:
    from raucle.capability import _normalise_constraints as _n

    return _n(dict(c))


def retry_guidance(token_dict: dict[str, Any]) -> dict[str, Any] | None:
    """Deterministically derive what the token's authority would allow.

    ``token_dict`` is the signed capability dict the adapter holds for the
    call being denied (the same object sent as ``X-Capability-Token``).
    Returns the ``raucle/retry-guidance/v1`` shape, or ``None`` when no
    deterministic alternative can be derived - the caller must then omit
    the ``retry_guidance`` key entirely (named absence, never null).
    """
    if not isinstance(token_dict, dict):
        return None
    tool = token_dict.get("tool")
    if not isinstance(tool, str) or not tool:
        return None
    constraints = token_dict.get("constraints")
    if not isinstance(constraints, dict):
        constraints = {}
    constraints = _normalise_constraints(constraints)

    # The approved task intent narrows the authority: merge its
    # constraints in the narrowing direction. If the intent lists a tool
    # set and the token's own tool is outside it, no retry under this
    # authority can be described deterministically.
    intent = token_dict.get("intent")
    if isinstance(intent, dict):
        intent_tools = intent.get("tools")
        if isinstance(intent_tools, list) and intent_tools and tool not in intent_tools:
            return None
        intent_constraints = intent.get("constraints")
        if isinstance(intent_constraints, dict) and intent_constraints:
            constraints = _merge(constraints, _normalise_constraints(dict(intent_constraints)))

    allowed = constraints.get("allowed_values")
    # An intersection that emptied a whitelist means this authority
    # permits nothing for that field: no honest retry exists at all.
    if isinstance(allowed, dict) and any(isinstance(v, list) and not v for v in allowed.values()):
        return None
    required = constraints.get("required_present")
    bounds: dict[str, dict[str, Any]] = {}
    for field, bound in (constraints.get("min_value") or {}).items():
        bounds.setdefault(str(field), {})["min"] = bound
    for field, bound in (constraints.get("max_value") or {}).items():
        bounds.setdefault(str(field), {})["max"] = bound

    criteria: dict[str, Any] = {}
    if isinstance(allowed, dict) and allowed:
        criteria["allowed_values"] = {
            str(f): list(v) for f, v in allowed.items() if isinstance(v, list) and v
        }
    if isinstance(required, list) and required:
        criteria["required_present"] = [str(f) for f in required]
    if bounds:
        criteria["bounds"] = bounds
    if not criteria:
        # Denylist-only, rate-limited or time-bound authority: nothing
        # deterministic to say about what WOULD be allowed. Honest absence.
        return None
    return {"schema": SCHEMA_NAME, "permitted_actions": [{"tool": tool, "criteria": criteria}]}


def attach_retry_guidance(response: dict[str, Any], token_dict: dict[str, Any]) -> dict[str, Any]:
    """Additively attach the guidance to a DENY response.

    The verdict is untouched: ``decision`` and every existing field pass
    through byte-identical; allow/escalate responses are returned
    unchanged; a deny without derivable guidance gains no key at all.
    """
    if not isinstance(response, dict) or response.get("decision") != "deny":
        return response
    guidance = retry_guidance(token_dict)
    if guidance is None:
        return response
    out = dict(response)
    out["retry_guidance"] = guidance
    return out


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """Merge two constraint sets in the NARROWING direction.

    Intersection of whitelists, union of required fields, tighter of the
    two bounds - matching ``_merge_narrowing`` semantics in
    raucle.capability, so the derived guidance can never describe an
    authority broader than the one the gate enforced.
    """
    out = dict(base)
    merged_allowed: dict[str, list[Any]] = {}
    for source in (base.get("allowed_values"), extra.get("allowed_values")):
        if isinstance(source, dict) and source:
            for field, values in source.items():
                values = [v for v in values if isinstance(v, (str, int, bool))]
                if field in merged_allowed:
                    merged_allowed[field] = [v for v in merged_allowed[field] if v in values]
                else:
                    merged_allowed[field] = values
    if merged_allowed:
        out["allowed_values"] = merged_allowed

    req: list[str] = []
    for source in (base.get("required_present"), extra.get("required_present")):
        if isinstance(source, list):
            for f in source:
                if isinstance(f, str) and f not in req:
                    req.append(f)
    if req:
        out["required_present"] = req

    bounds = dict(base.get("min_value") or {})
    for field, bound in (extra.get("min_value") or {}).items():
        bounds[field] = max(bounds.get(field, bound), bound)
    if bounds:
        out["min_value"] = bounds
    bounds = dict(base.get("max_value") or {})
    for field, bound in (extra.get("max_value") or {}).items():
        bounds[field] = min(bounds.get(field, bound), bound)
    if bounds:
        out["max_value"] = bounds
    return out
