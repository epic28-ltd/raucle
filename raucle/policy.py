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

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from raucle.capability import Capability, CapabilityIssuer

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


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
    # Source/destination matching: the policy only applies when the
    # inbound source and outbound destination match these patterns.
    # Empty string or "*" means "match anything".
    source: str = ""
    destination: str = ""
    # The file this rule was loaded from (for admin panel display).
    source_file: str = ""

    def matches(self, source: str, destination: str) -> bool:
        """Check if this rule applies to the given source/destination."""
        import fnmatch

        if self.source and self.source != "*" and not fnmatch.fnmatch(source or "", self.source):
            return False
        if self.destination and self.destination != "*":
            return fnmatch.fnmatch(destination or "", self.destination)
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
        compiled: dict[str, Any] = {}

        # allow -> allowed_values
        if "allow" in self.constraints:
            compiled["allowed_values"] = self._expand_wildcards(self.constraints["allow"])

        # deny -> forbidden_values
        if "deny" in self.constraints:
            compiled["forbidden_values"] = self._expand_wildcards(self.constraints["deny"])

        # max -> max_value
        if "max" in self.constraints:
            compiled["max_value"] = self.constraints["max"]

        # min -> min_value
        if "min" in self.constraints:
            compiled["min_value"] = self.constraints["min"]

        # require -> required_present
        if "require" in self.constraints:
            compiled["required_present"] = self.constraints["require"]

        # starts_with
        if "starts_with" in self.constraints:
            compiled["starts_with"] = self.constraints["starts_with"]

        # forbidden_combinations
        if "forbidden_combinations" in self.constraints:
            compiled["forbidden_field_combinations"] = self.constraints["forbidden_combinations"]

        return compiled

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


@dataclass
class PolicyFile:
    """A loaded policy file."""

    version: int
    issuer: str
    policies: list[PolicyRule] = field(default_factory=list)

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
                source=rule_data.get("source", ""),
                destination=rule_data.get("destination", ""),
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

        return cls(version=version, issuer=issuer, policies=policies)

    def to_yaml(self) -> str:
        """Serialise back to YAML (round-trip for editing)."""
        data = {
            "version": self.version,
            "issuer": self.issuer,
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
                    **({"source": r.source} if r.source else {}),
                    **({"destination": r.destination} if r.destination else {}),
                }
                for r in self.policies
            ],
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Approval thresholds (human-in-the-loop)
# ---------------------------------------------------------------------------


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
        """Check if the given args trigger this approval threshold."""
        if self.field not in args:
            return False
        actual = args[self.field]
        expected = self.value
        if self.operator == "gt":
            return actual > expected
        if self.operator == "lt":
            return actual < expected
        if self.operator == "gte":
            return actual >= expected
        if self.operator == "lte":
            return actual <= expected
        if self.operator == "eq":
            return actual == expected
        return False

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


__all__ = [
    "PolicyFile",
    "PolicyRule",
    "ApprovalThreshold",
    "mint_from_policy",
    "check_approval_needed",
]
