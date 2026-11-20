"""Policy DSL for non-developers.

Risk officers and compliance teams author policies in YAML without touching
Python. The DSL compiles to the constraint dicts that
:meth:`CapabilityIssuer.mint` already accepts.

Example policy file::

    version: 1
    issuer: acme.bank.payments
    policies:
      - tool: transfer_money
        agent_id: agent:payments-bot
        ttl_seconds: 300
        constraints:
          allow:
            from_account: ["ACC-001", "ACC-002"]
            to_account: ["ACC-003"]
          max:
            amount: 10000
          require_approval_when:
            amount_gt: 5000
        description: "Internal transfers, max 10k, escalate over 5k"

Compile and mint::

    from raucle.policy import PolicyFile, mint_from_policy

    policy = PolicyFile.load("policies.yaml")
    tokens = mint_from_policy(policy, issuer)
    # Returns {tool_name: Capability} dict
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from raucle.capability import Capability, CapabilityIssuer


def _validate_allow_destination_classes(allow_classes: Any) -> None:
    """Fail-closed validation of the optional allow-list in
    ``deny_from_chain_taint``: when set, it must be a non-empty list of
    non-empty strings."""
    if allow_classes is None:
        return
    if not isinstance(allow_classes, list) or not allow_classes:
        raise ValueError("deny_from_chain_taint.allow_destination_classes must be a non-empty list")
    if any(not isinstance(v, str) or not v for v in allow_classes):
        raise ValueError(
            "deny_from_chain_taint.allow_destination_classes must be non-empty strings"
        )


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ChainTaintDeny:
    """Data-flow constraint binding chain taint to a destination-class deny.

    Semantics (deterministic, fail-closed): when any prior tool output in
    the SAME task/delegation chain (identified by ``trace_id``) carries one
    of ``taint_tags``, a call whose ``destination_class`` matches this kind
    is denied. ``allow_destination_classes`` optionally allow-lists the
    destination classes the deny does NOT cover; when it is set, every
    destination class NOT on the allow-list denies (fail-closed). The kind
    only ever denies - it can never widen the authority a capability
    token grants.
    """

    taint_tags: list[str] = field(default_factory=list)
    destination_classes: list[str] = field(default_factory=list)
    allow_destination_classes: list[str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChainTaintDeny:
        if not isinstance(data, dict):
            raise ValueError(f"deny_from_chain_taint must be a mapping, got {type(data).__name__}")
        tags = data.get("taint_tags")
        dest_classes = data.get("destination_classes") or []
        allow_classes = data.get("allow_destination_classes")
        if not isinstance(tags, list) or not tags:
            raise ValueError("deny_from_chain_taint.taint_tags must be a non-empty list")
        for name, values in (("taint_tags", tags), ("destination_classes", dest_classes)):
            if any(not isinstance(v, str) or not v for v in values):
                raise ValueError(f"deny_from_chain_taint.{name} must be non-empty strings")
        _validate_allow_destination_classes(allow_classes)
        if not dest_classes and allow_classes is None:
            raise ValueError(
                "deny_from_chain_taint requires 'destination_classes' or "
                "'allow_destination_classes'"
            )
        return cls(
            taint_tags=list(tags),
            destination_classes=list(dest_classes),
            allow_destination_classes=list(allow_classes) if allow_classes is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"taint_tags": list(self.taint_tags)}
        if self.destination_classes:
            data["destination_classes"] = list(self.destination_classes)
        if self.allow_destination_classes is not None:
            data["allow_destination_classes"] = list(self.allow_destination_classes)
        return data


@dataclass
class PolicyRule:
    """A single policy rule for one tool."""

    tool: str
    agent_id: str
    ttl_seconds: int = 300
    constraints: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    # Stable rule identifier for audit rows (A2): explicit `id:` in the YAML
    # wins; otherwise derived at load as "<tool>/<agent_id>/<index>".
    id: str = ""
    require_approval_when: dict[str, Any] | None = None
    # Data-flow rule kind (EPIC O1): deny calls whose destination class
    # matches whenever a prior output in the same task chain carries a
    # listed taint tag. See :class:`ChainTaintDeny`.
    deny_from_chain_taint: ChainTaintDeny | None = None
    # Evidence Quality Requirement (N6): gate input declaring the minimum
    # evidence quality the authority depends on, and the narrowing-side
    # behaviour when the evidence is degraded. See :class:`raucle.eqr.EQR`.
    eqr: Any = None
    # Participant matcher (EPIC Q lane Q-3): which observable participant
    # the rule scopes to, one of ``tool_call`` (default, the gate's own
    # decision surface) or ``tool_response_taint``. Empty string keeps the
    # historical behaviour byte-compatibly.
    participant: str = ""
    # Source/destination matching: the policy only applies when the
    # inbound source and outbound destination match these patterns.
    # Empty string or "*" means "match anything".
    source: str = ""
    destination: str = ""
    # The file this rule was loaded from (for admin panel display).
    source_file: str = ""

    def matches(self, source: str, destination: str) -> bool:
        """Check if this rule applies to the given source/destination.

        ``fnmatchcase`` rather than ``fnmatch``: the latter normalises case on
        Windows only, so the same policy would match differently per host and
        a rule that holds in CI could silently not apply in production.
        """
        import fnmatch

        if (
            self.source
            and self.source != "*"
            and not fnmatch.fnmatchcase(source or "", self.source)
        ):
            return False
        if self.destination and self.destination != "*":
            return fnmatch.fnmatchcase(destination or "", self.destination)
        return True

    def to_mint_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs for CapabilityIssuer.mint()."""
        return {
            "agent_id": self.agent_id,
            "tool": self.tool,
            "constraints": self._compile_constraints(),
            "ttl_seconds": self.ttl_seconds,
        }

    def _compile_constraints(self) -> dict[str, Any]:
        """Compile DSL constraint syntax to the gate's native format."""
        return compile_constraint_dsl(self.constraints)

    @staticmethod
    def _expand_wildcards(
        values: dict[str, Any],
    ) -> dict[str, Any]:
        """Pass through values. Wildcard expansion happens at gate time
        via starts_with constraints, not in allowed_values.

        If a value contains "*", it should use starts_with instead.
        We detect and warn about this.
        """
        for field_name, field_values in values.items():
            if isinstance(field_values, list):
                for v in field_values:
                    if isinstance(v, str) and "*" in v:
                        raise ValueError(
                            f"Wildcard '*' in allowed_values for field "
                            f"'{field_name}'. Use 'starts_with' constraint "
                            f"instead: starts_with: {{{field_name}: ['ACC-']}}"
                        )
        return values


def _load_eqr_class() -> Any:
    """Lazy import of :class:`raucle.eqr.EQR` (eqr imports this module)."""
    from raucle.eqr import EQR

    return EQR


# ---------------------------------------------------------------------------
# Session behavioural rules (EPIC Q lane Q-2)
# ---------------------------------------------------------------------------

#: The closed v1 rule-kind vocabulary: deterministic rules evaluated over
#: the gateway's session window state (bounded decision summaries). v1
#: actions are deny-only; escalation is a named v1.1 follow-up.
SESSION_RULE_KINDS = (
    "repeated_deny_storm",
    "runaway_tool_loop",
    "gradual_extraction",
    "forbidden_tool_chain",
    "scope_drift",
)

# ---------------------------------------------------------------------------
# Participant matchers (EPIC Q lane Q-3): per-participant traffic tagging
# ---------------------------------------------------------------------------

#: The closed participant vocabulary: the two participants whose traffic
#: the gate actually observes. ``tool_call`` is the gate's own decision
#: surface (the default; semantics unchanged when omitted).
#: ``tool_response_taint`` marks rules that additionally consider the
#: recorded chain taint (``record_chain_output`` state) for the rule's
#: tool. User, assistant and tool-definition participants deliberately do
#: not exist here: the gateway never sees that content, and the DSL must
#: not pretend to match it. Unknown values fail closed at load with a
#: named error, never a silently skipped rule.
PARTICIPANTS = ("tool_call", "tool_response_taint")


def _validate_participant(value: Any, *, context: str) -> str:
    """Validate one ``participant`` matcher value; empty means the default."""
    if value is None:
        return ""
    if not isinstance(value, str) or value not in ("",) + PARTICIPANTS:
        raise ValueError(
            f"{context}: unknown participant {value!r}; use one of "
            + ", ".join(PARTICIPANTS)
            + " (unknown participants fail closed at load; the gateway "
            "observes only tool calls and recorded tool-response taint)"
        )
    return value


_KINDS_NEEDING_THRESHOLD = frozenset(
    {"repeated_deny_storm", "runaway_tool_loop", "gradual_extraction", "scope_drift"}
)


def _session_rule_int(data: dict[str, Any], key: str, *, minimum: int = 1) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"session rule field '{key}' must be an integer >= {minimum}")
    return value


def _session_rule_str_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"session rule field '{key}' must be a non-empty list")
    if any(not isinstance(v, str) or not v for v in value):
        raise ValueError(f"session rule field '{key}' must be non-empty strings")
    return list(value)


@dataclass
class SessionRule:
    """One deterministic session rule (EPIC Q lane Q-2).

    Rules are evaluated over the session window state: bounded, content-free
    summaries of the session's RECEIPTED decisions (see
    :class:`raucle.gateway.SessionWindowState`). A rule never sees tool
    arguments or any content, only decision, tool name, timestamps, trace
    and the caller-declared destination_class.

    v1 actions are deny-only: a session rule participates in the gate's
    only-ever-DENY pre-check tier. Escalation to approval is a named v1.1
    follow-up and is refused at parse time for now.
    """

    id: str
    kind: str
    window_seconds: int
    threshold: int = 0
    tools: list[str] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)
    destination_class: str = ""
    tool_patterns: list[str] = field(default_factory=list)
    # Participant matcher (EPIC Q lane Q-3): one of ``tool_call`` or
    # ``tool_response_taint``; empty means the default (tool_call). A
    # ``tool_response_taint`` session rule counts only window entries whose
    # trace has recorded chain taint (``record_chain_output`` state).
    participant: str = ""
    action: str = "deny"
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionRule:
        if not isinstance(data, dict):
            raise ValueError("a session rule must be a mapping")
        rule_id = data.get("id", "")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("session rule field 'id' is required")
        kind = data.get("kind", "")
        if kind not in SESSION_RULE_KINDS:
            raise ValueError(
                f"unknown session rule kind {kind!r}; use one of " + ", ".join(SESSION_RULE_KINDS)
            )
        action = data.get("action", "deny") or "deny"
        if action != "deny":
            raise ValueError(
                f"session rule action {action!r} is not supported in v1; only 'deny' is allowed"
            )
        window_seconds = _session_rule_int(data, "window_seconds")
        threshold = 0
        if kind in _KINDS_NEEDING_THRESHOLD:
            threshold = _session_rule_int(data, "threshold")
        tools: list[str] = []
        if kind == "scope_drift":
            tools = _session_rule_str_list(data, "tools")
        sequence: list[str] = []
        if kind == "forbidden_tool_chain":
            sequence = _session_rule_str_list(data, "sequence")
        destination_class = ""
        if kind == "gradual_extraction":
            destination_class = data.get("destination_class", "")
            if not isinstance(destination_class, str) or not destination_class:
                raise ValueError(
                    "session rule field 'destination_class' is required for gradual_extraction"
                )
        patterns_raw = data.get("tool_patterns", [])
        if patterns_raw is None:
            patterns_raw = []
        if not isinstance(patterns_raw, list) or any(
            not isinstance(p, str) or not p for p in patterns_raw
        ):
            raise ValueError(
                "session rule field 'tool_patterns' must be a list of non-empty strings"
            )
        description = data.get("description", "")
        if not isinstance(description, str):
            raise ValueError("session rule field 'description' must be a string")
        participant = _validate_participant(
            data.get("participant"), context="session rule field 'participant'"
        )
        return cls(
            id=rule_id,
            kind=kind,
            window_seconds=window_seconds,
            threshold=threshold,
            tools=tools,
            sequence=sequence,
            destination_class=destination_class,
            tool_patterns=list(patterns_raw),
            participant=participant,
            action=action,
            description=description,
        )

    def to_dict(self) -> dict[str, Any]:
        """The canonical dict form: round-trips through :meth:`from_dict`
        and is the content the gateway binds into a session-rule deny
        receipt's ruleset_hash."""
        data: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "window_seconds": self.window_seconds,
        }
        if self.threshold:
            data["threshold"] = self.threshold
        if self.tools:
            data["tools"] = list(self.tools)
        if self.sequence:
            data["sequence"] = list(self.sequence)
        if self.destination_class:
            data["destination_class"] = self.destination_class
        if self.tool_patterns:
            data["tool_patterns"] = list(self.tool_patterns)
        if self.participant:
            data["participant"] = self.participant
        if self.action != "deny":
            data["action"] = self.action
        if self.description:
            data["description"] = self.description
        return data


def _parse_session_rules(raw: Any) -> tuple[list[SessionRule], list[str]]:
    """Parse the optional ``session_rules:`` block, capturing named errors.

    Never raises and never silently skips: a malformed rule is returned as
    a NAMED error so the gateway can deny fail-closed. A session rule that
    cannot be evaluated must not become an unenforced rule.
    """
    rules: list[SessionRule] = []
    errors: list[str] = []
    if raw is None:
        return rules, errors
    if not isinstance(raw, list):
        return [], ["session_rules must be a list of rule mappings"]
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            errors.append(f"session rule {i}: expected a mapping")
            continue
        named = entry.get("id")
        label = named if isinstance(named, str) and named else "unnamed"
        try:
            rules.append(SessionRule.from_dict(entry))
        except ValueError as exc:
            errors.append(f"session rule {i} ({label}): {exc}")
    return rules, errors


def compile_constraint_dsl(constraints: dict[str, Any]) -> dict[str, Any]:
    """Compile DSL constraint syntax to the gate's native format.

    Module-level so other policy-input kinds (e.g. the EQR reduced scope in
    :mod:`raucle.eqr`) compile through the same path as
    :meth:`PolicyRule._compile_constraints`.
    """
    compiled: dict[str, Any] = {}

    # allow -> allowed_values
    if "allow" in constraints:
        compiled["allowed_values"] = PolicyRule._expand_wildcards(constraints["allow"])

    # deny -> forbidden_values
    if "deny" in constraints:
        compiled["forbidden_values"] = PolicyRule._expand_wildcards(constraints["deny"])

    # max -> max_value
    if "max" in constraints:
        compiled["max_value"] = constraints["max"]

    # min -> min_value
    if "min" in constraints:
        compiled["min_value"] = constraints["min"]

    # require -> required_present
    if "require" in constraints:
        compiled["required_present"] = constraints["require"]

    # starts_with
    if "starts_with" in constraints:
        compiled["starts_with"] = constraints["starts_with"]

    # forbidden_combinations
    if "forbidden_combinations" in constraints:
        compiled["forbidden_field_combinations"] = constraints["forbidden_combinations"]

    return compiled


@dataclass
class PolicyFile:
    """A loaded policy file."""

    version: int
    issuer: str
    policies: list[PolicyRule] = field(default_factory=list)
    # Session behavioural rules (EPIC Q lane Q-2): deterministic, deny-only
    # rules the gateway evaluates over its session window state. Parsing
    # captures a malformed rule as a NAMED error instead of raising, so a
    # bad session rule can never silently vanish from enforcement.
    session_rules: list[SessionRule] = field(default_factory=list)
    session_rule_errors: list[str] = field(default_factory=list)
    # EPIC W lane W1: operator-declared write-to-read pairings (raw rows;
    # shape is validated here, the tool-reference bind runs at gateway
    # load against the tool schema registry, SchemaPolicyLoadError).
    state_pairings: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> PolicyFile:
        """Load and validate a policy file from YAML."""
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyFile:
        """Create a PolicyFile from a parsed dict."""
        version = data.get("version", 1)
        if version != 1:
            raise ValueError(f"Unsupported policy version: {version}")

        issuer = data.get("issuer", "")
        if not issuer:
            raise ValueError("Policy file must specify 'issuer'")

        policies: list[PolicyRule] = []
        for i, rule_data in enumerate(data.get("policies", [])):
            rule = PolicyRule(
                tool=rule_data.get("tool", ""),
                agent_id=rule_data.get("agent_id", ""),
                ttl_seconds=rule_data.get("ttl_seconds", 300),
                constraints=rule_data.get("constraints", {}),
                description=rule_data.get("description", ""),
                id=rule_data.get("id") or "",
                require_approval_when=rule_data.get("require_approval_when"),
                deny_from_chain_taint=(
                    ChainTaintDeny.from_dict(rule_data["deny_from_chain_taint"])
                    if rule_data.get("deny_from_chain_taint") is not None
                    else None
                ),
                eqr=(
                    _load_eqr_class().from_dict(rule_data["eqr"])
                    if rule_data.get("eqr") is not None
                    else None
                ),
                source=rule_data.get("source", ""),
                destination=rule_data.get("destination", ""),
                participant=_validate_participant(
                    rule_data.get("participant"), context=f"Policy rule {i}"
                ),
            )
            if not rule.id:
                rule.id = f"{rule.tool}/{rule.agent_id}/{i}"
            if not rule.tool:
                raise ValueError(f"Policy rule {i}: 'tool' is required")
            if not rule.agent_id:
                raise ValueError(f"Policy rule {i}: 'agent_id' is required")
            # Validate constraint syntax
            rule.to_mint_kwargs()  # raises on invalid
            policies.append(rule)

        session_rules, session_rule_errors = _parse_session_rules(data.get("session_rules"))
        state_pairings = _parse_state_pairings(data.get("state_pairings"))
        return cls(
            version=version,
            issuer=issuer,
            policies=policies,
            session_rules=session_rules,
            session_rule_errors=session_rule_errors,
            state_pairings=state_pairings,
        )

    def to_yaml(self) -> str:
        """Serialise back to YAML (round-trip for editing)."""
        data = {
            "version": self.version,
            "issuer": self.issuer,
            **(
                {"session_rules": [r.to_dict() for r in self.session_rules]}
                if self.session_rules
                else {}
            ),
            **({"state_pairings": self.state_pairings} if self.state_pairings else {}),
            "policies": [
                {
                    "tool": r.tool,
                    "agent_id": r.agent_id,
                    "ttl_seconds": r.ttl_seconds,
                    "constraints": r.constraints,
                    "description": r.description,
                    **(
                        {"require_approval_when": r.require_approval_when}
                        if r.require_approval_when
                        else {}
                    ),
                    **(
                        {"deny_from_chain_taint": r.deny_from_chain_taint.to_dict()}
                        if r.deny_from_chain_taint
                        else {}
                    ),
                    **({"eqr": r.eqr.to_dict()} if r.eqr is not None else {}),
                    **({"source": r.source} if r.source else {}),
                    **({"destination": r.destination} if r.destination else {}),
                    **({"participant": r.participant} if r.participant else {}),
                }
                for r in self.policies
            ],
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


def _parse_state_pairings(entries: Any) -> list[dict[str, Any]]:
    """EPIC W lane W1: the state_pairings policy-file section, raw rows.

    Shape errors refuse the config load here with a named ValueError; the
    tool-reference validation (unknown tool, undeclared id field) runs at
    gateway load against the tool schema registry, raising
    ``SchemaPolicyLoadError`` (the X1 fail-closed bind, never at call
    time). An absent section is an empty list: no pairings, no coverage
    claims, byte-identical behaviour.
    """
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ValueError("state_pairings must be a list of pairing entries")
    rows: list[dict[str, Any]] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"state_pairings entry {i} must be a JSON object")
        for field_name in ("write_tool", "read_tool", "id_pointer"):
            value = entry.get(field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"state_pairings entry {i}: {field_name!r} must be a non-empty string"
                )
        classes = entry.get("require_field_classes")
        if classes is None:
            classes = []
        if not isinstance(classes, list) or any(not isinstance(c, str) or not c for c in classes):
            raise ValueError(
                f"state_pairings entry {i}: require_field_classes must be a list of "
                "non-empty strings"
            )
        rows.append(
            {
                "write_tool": str(entry["write_tool"]),
                "read_tool": str(entry["read_tool"]),
                "id_pointer": str(entry["id_pointer"]),
                "require_field_classes": [str(c) for c in classes],
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Approval thresholds (human-in-the-loop)
# ---------------------------------------------------------------------------


_THRESHOLD_OPERATORS = frozenset({"gt", "lt", "gte", "lte", "eq"})


def _threshold_value(value: Any) -> tuple[str, Any]:
    """Classify an approval-threshold operand as ``number``, ``string`` or
    ``incomparable`` (RED-031).

    Booleans are excluded from numbers (``bool`` subclasses ``int``) and
    non-finite floats are rejected, so an argument cannot slip a bound by
    arriving as ``True`` or ``NaN``.
    """
    if isinstance(value, bool):
        return ("incomparable", None)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return ("incomparable", None)
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    return ("incomparable", None)


@dataclass
class ApprovalThreshold:
    """A threshold that requires human approval before execution.

    When a gate check matches an approval threshold, the decision is
    ESCALATE instead of ALLOW. The caller must obtain human approval
    before proceeding.
    """

    field: str
    operator: str  # "gt", "lt", "gte", "lte", "eq"
    value: Any

    def matches(self, args: dict[str, Any]) -> bool:
        """Check if the given args trigger this approval threshold.

        Fail-closed (RED-031): a threshold is a human check, so an argument
        that cannot be shown to sit *below* it must escalate. Comparisons
        run on normalised values, never on raw caller types: a bare
        ``str > int`` raised `TypeError` out of the gate (HTTP 500, no
        receipt) and a type-mismatched ``eq`` silently skipped escalation,
        which allowed a call the policy meant a human to see.
        """
        if self.field not in args:
            return False
        actual_kind, actual = _threshold_value(args[self.field])
        expected_kind, expected = _threshold_value(self.value)
        if actual_kind == "incomparable" or expected_kind == "incomparable":
            return True
        if actual_kind != expected_kind:
            # Numeric text against a numeric threshold compares numerically,
            # so "10000" and 10000 mean the same thing. Any other mixed pair
            # cannot be compared meaningfully, so it escalates.
            if {actual_kind, expected_kind} != {"number", "string"}:
                return True
            try:
                actual = float(actual)
                expected = float(expected)
            except (TypeError, ValueError):
                return True
        if self.operator not in _THRESHOLD_OPERATORS:
            return True
        if self.operator == "gt":
            return actual > expected
        if self.operator == "lt":
            return actual < expected
        if self.operator == "gte":
            return actual >= expected
        if self.operator == "lte":
            return actual <= expected
        return actual == expected

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> list[ApprovalThreshold]:
        """Parse DSL approval syntax like {amount_gt: 5000}."""
        thresholds: list[ApprovalThreshold] = []
        for key, value in data.items():
            # Parse field_operator pattern: amount_gt, amount_lt, etc.
            m = re.match(r"^(\w+)_(gt|lt|gte|lte|eq)$", key)
            if m:
                thresholds.append(
                    cls(
                        field=m.group(1),
                        operator=m.group(2),
                        value=value,
                    )
                )
        return thresholds


# ---------------------------------------------------------------------------
# Minting from policy
# ---------------------------------------------------------------------------


def mint_from_policy(
    policy: PolicyFile,
    issuer: CapabilityIssuer,
) -> dict[str, Capability]:
    """Mint capability tokens for all rules in a policy file.

    Returns a dict mapping tool_name -> Capability token.
    Each token is signed by the issuer (local or KMS-backed).
    """
    tokens: dict[str, Capability] = {}
    for rule in policy.policies:
        if rule.tool in tokens:
            raise ValueError(
                f"Duplicate tool '{rule.tool}' in policy file. "
                f"Each tool may have only one policy rule."
            )
        kwargs = rule.to_mint_kwargs()
        tokens[rule.tool] = issuer.mint(**kwargs)
    return tokens


def check_approval_needed(
    rule: PolicyRule,
    args: dict[str, Any],
) -> bool:
    """Check if a gate decision requires human approval.

    Returns True if the args match any approval threshold in the rule.
    The caller should hold the call, notify a human approver, and only
    proceed when approval is received.
    """
    if not rule.require_approval_when:
        return False
    thresholds = ApprovalThreshold.from_dict(rule.require_approval_when)
    return any(t.matches(args) for t in thresholds)


def evaluate_chain_taint_deny(
    deny: ChainTaintDeny,
    prior_outputs: list[dict[str, Any]],
    destination_class: str,
) -> str:
    """Evaluate a data-flow rule against the replayed chain state.

    *prior_outputs* is the ordered list of tool outputs recorded for the
    SAME task/delegation chain (``{"tool": str, "taint_tags": list[str]}``),
    excluding the call under decision. Returns the deny REASON string, or
    "" when the call is not covered.

    Semantics, in evaluation order (fail-closed with named reasons):
      1. a malformed (non-string or empty) taint tag anywhere in the chain
         state is UNKNOWN and denies the call outright;
      2. no listed taint tag in the chain state allows the call (every
         call alone stays allowed) - regardless of destination class;
      3. with chain taint present, an UNKNOWN (empty) destination class
         denies;
      4. with an allow-list, any destination class not on it denies;
         otherwise a destination class in the denied list denies.

    The function is pure: the same (deny, prior_outputs, destination_class)
    triple always yields the same verdict - no side-channel state.
    """
    # Unknown taint tags anywhere in the chain state deny outright: an
    # unclassifiable taint cannot be proven NOT to reach this call.
    for output in prior_outputs:
        for tag in output.get("taint_tags") or []:
            if not isinstance(tag, str) or not tag:
                return "data-flow rule: unknown taint tag in chain state (fail-closed deny)"
    matching_tags = sorted(
        {
            tag
            for output in prior_outputs
            for tag in output.get("taint_tags") or []
            if tag in deny.taint_tags
        }
    )
    if not matching_tags:
        return ""
    if not isinstance(destination_class, str) or not destination_class:
        return "data-flow rule: unknown destination class (fail-closed deny)"
    allow = deny.allow_destination_classes
    if allow is not None:
        covered = destination_class not in allow
        basis = "not on data-flow allow-list"
    else:
        covered = destination_class in deny.destination_classes
        basis = "in denied destination classes"
    if not covered:
        return ""
    return (
        f"data-flow rule: taint tag '{matching_tags[0]}' in chain state with destination class "
        f"'{destination_class}' {basis} (fail-closed deny)"
    )


__all__ = [
    "PolicyFile",
    "PolicyRule",
    "ChainTaintDeny",
    "PARTICIPANTS",
    "compile_constraint_dsl",
    "ApprovalThreshold",
    "mint_from_policy",
    "check_approval_needed",
    "evaluate_chain_taint_deny",
]
