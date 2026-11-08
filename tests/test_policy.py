"""Tests for the policy DSL."""

import os
import tempfile

import pytest
import yaml

from raucle.audit import Ed25519Signer
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.kms import KMSSigner
from raucle.policy import (
    ApprovalThreshold,
    PolicyFile,
    PolicyRule,
    check_approval_needed,
    mint_from_policy,
)


class TestPolicyFile:
    """Loading and validating policy files."""

    def test_load_from_yaml(self):
        yaml_content = """
version: 1
issuer: acme.bank
policies:
  - tool: transfer_money
    agent_id: agent:payments
    ttl_seconds: 300
    constraints:
      allow:
        from_account: ["ACC-001"]
        to_account: ["ACC-002"]
      max:
        amount: 10000
    description: "Internal transfers"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            policy = PolicyFile.load(f.name)
        os.unlink(f.name)

        assert policy.version == 1
        assert policy.issuer == "acme.bank"
        assert len(policy.policies) == 1
        assert policy.policies[0].tool == "transfer_money"
        assert policy.policies[0].description == "Internal transfers"

    def test_from_dict(self):
        data = {
            "version": 1,
            "issuer": "test.bank",
            "policies": [
                {
                    "tool": "lookup",
                    "agent_id": "agent:svc",
                    "ttl_seconds": 60,
                    "constraints": {"allow": {"account": ["ACC-001"]}},
                }
            ],
        }
        policy = PolicyFile.from_dict(data)
        assert policy.policies[0].tool == "lookup"
        assert policy.policies[0].ttl_seconds == 60

    def test_missing_issuer_raises(self):
        with pytest.raises(ValueError, match="issuer"):
            PolicyFile.from_dict({"version": 1, "policies": []})

    def test_missing_tool_raises(self):
        with pytest.raises(ValueError, match="tool"):
            PolicyFile.from_dict(
                {
                    "version": 1,
                    "issuer": "test",
                    "policies": [{"agent_id": "agent:x", "constraints": {}}],
                }
            )

    def test_missing_agent_id_raises(self):
        with pytest.raises(ValueError, match="agent_id"):
            PolicyFile.from_dict(
                {
                    "version": 1,
                    "issuer": "test",
                    "policies": [{"tool": "lookup", "constraints": {}}],
                }
            )

    def test_round_trip_yaml(self):
        data = {
            "version": 1,
            "issuer": "test.bank",
            "policies": [
                {
                    "tool": "lookup",
                    "agent_id": "agent:svc",
                    "ttl_seconds": 60,
                    "constraints": {"allow": {"account": ["ACC-001"]}},
                    "description": "Test policy",
                }
            ],
        }
        policy = PolicyFile.from_dict(data)
        yaml_str = policy.to_yaml()
        restored = PolicyFile.from_dict(yaml.safe_load(yaml_str))
        assert restored.issuer == "test.bank"
        assert restored.policies[0].tool == "lookup"

    def test_unsupported_version_raises(self):
        with pytest.raises(ValueError, match="version"):
            PolicyFile.from_dict({"version": 2, "issuer": "x", "policies": []})


class TestConstraintCompilation:
    """DSL constraint syntax compiles to gate-native format."""

    def test_allow_compiles_to_allowed_values(self):
        rule = PolicyRule(
            tool="lookup",
            agent_id="agent:x",
            constraints={"allow": {"account": ["ACC-001", "ACC-002"]}},
        )
        compiled = rule._compile_constraints()
        assert compiled["allowed_values"] == {"account": ["ACC-001", "ACC-002"]}

    def test_deny_compiles_to_forbidden_values(self):
        rule = PolicyRule(
            tool="lookup",
            agent_id="agent:x",
            constraints={"deny": {"account": ["ACC-999"]}},
        )
        compiled = rule._compile_constraints()
        assert compiled["forbidden_values"] == {"account": ["ACC-999"]}

    def test_max_compiles_to_max_value(self):
        rule = PolicyRule(
            tool="transfer",
            agent_id="agent:x",
            constraints={"max": {"amount": 10000}},
        )
        compiled = rule._compile_constraints()
        assert compiled["max_value"] == {"amount": 10000}

    def test_min_compiles_to_min_value(self):
        rule = PolicyRule(
            tool="transfer",
            agent_id="agent:x",
            constraints={"min": {"amount": 1}},
        )
        compiled = rule._compile_constraints()
        assert compiled["min_value"] == {"amount": 1}

    def test_starts_with_compiles(self):
        rule = PolicyRule(
            tool="lookup",
            agent_id="agent:x",
            constraints={"starts_with": {"account": ["ACC-"]}},
        )
        compiled = rule._compile_constraints()
        assert compiled["starts_with"] == {"account": ["ACC-"]}

    def test_wildcard_in_allow_raises(self):
        rule = PolicyRule(
            tool="lookup",
            agent_id="agent:x",
            constraints={"allow": {"account": ["ACC-*"]}},
        )
        with pytest.raises(ValueError, match="Wildcard"):
            rule._compile_constraints()

    def test_multiple_constraints_compile(self):
        rule = PolicyRule(
            tool="transfer",
            agent_id="agent:x",
            constraints={
                "allow": {"from_account": ["ACC-001"], "to_account": ["ACC-002"]},
                "max": {"amount": 5000},
                "min": {"amount": 1},
            },
        )
        compiled = rule._compile_constraints()
        assert "allowed_values" in compiled
        assert "max_value" in compiled
        assert "min_value" in compiled


class TestMintFromPolicy:
    """Minting capability tokens from a policy file."""

    def test_mint_all_policies(self):
        issuer = CapabilityIssuer.generate(issuer="test.bank")
        policy = PolicyFile.from_dict(
            {
                "version": 1,
                "issuer": "test.bank",
                "policies": [
                    {
                        "tool": "lookup",
                        "agent_id": "agent:svc",
                        "ttl_seconds": 60,
                        "constraints": {"allow": {"account": ["ACC-001"]}},
                    },
                    {
                        "tool": "transfer",
                        "agent_id": "agent:pay",
                        "ttl_seconds": 300,
                        "constraints": {
                            "allow": {"from": ["ACC-001"]},
                            "max": {"amount": 5000},
                        },
                    },
                ],
            }
        )
        tokens = mint_from_policy(policy, issuer)
        assert "lookup" in tokens
        assert "transfer" in tokens
        assert tokens["lookup"].token_id.startswith("cap:")
        assert tokens["transfer"].token_id.startswith("cap:")

    def test_minted_tokens_verify_in_gate(self):
        issuer = CapabilityIssuer.generate(issuer="test.bank")
        policy = PolicyFile.from_dict(
            {
                "version": 1,
                "issuer": "test.bank",
                "policies": [
                    {
                        "tool": "transfer",
                        "agent_id": "agent:pay",
                        "ttl_seconds": 300,
                        "constraints": {
                            "allow": {"from": ["ACC-001"], "to": ["ACC-002"]},
                            "max": {"amount": 10000},
                        },
                    }
                ],
            }
        )
        tokens = mint_from_policy(policy, issuer)
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

        # Allowed
        d = gate.check(
            tokens["transfer"],
            tool="transfer",
            agent_id="agent:pay",
            args={"from": "ACC-001", "to": "ACC-002", "amount": 5000},
        )
        assert d.allowed

        # Over limit
        d = gate.check(
            tokens["transfer"],
            tool="transfer",
            agent_id="agent:pay",
            args={"from": "ACC-001", "to": "ACC-002", "amount": 50000},
        )
        assert not d.allowed

        # Wrong account
        d = gate.check(
            tokens["transfer"],
            tool="transfer",
            agent_id="agent:pay",
            args={"from": "ACC-999", "to": "ACC-002", "amount": 100},
        )
        assert not d.allowed

    def test_mint_with_kms_signer(self):
        """Policy DSL works with KMS-backed issuers."""
        local = Ed25519Signer.generate()
        kms = KMSSigner(sign_fn=local.sign, public_key_pem=local.public_key_pem())
        issuer = CapabilityIssuer.from_signer("enterprise.bank", kms)
        policy = PolicyFile.from_dict(
            {
                "version": 1,
                "issuer": "enterprise.bank",
                "policies": [
                    {
                        "tool": "transfer",
                        "agent_id": "agent:prod",
                        "ttl_seconds": 3600,
                        "constraints": {"allow": {"account": ["ACC-001"]}},
                    }
                ],
            }
        )
        tokens = mint_from_policy(policy, issuer)
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        d = gate.check(
            tokens["transfer"], tool="transfer", agent_id="agent:prod", args={"account": "ACC-001"}
        )
        assert d.allowed

    def test_duplicate_tool_raises(self):
        issuer = CapabilityIssuer.generate(issuer="test")
        policy = PolicyFile.from_dict(
            {
                "version": 1,
                "issuer": "test",
                "policies": [
                    {"tool": "lookup", "agent_id": "agent:a", "constraints": {}},
                    {"tool": "lookup", "agent_id": "agent:b", "constraints": {}},
                ],
            }
        )
        with pytest.raises(ValueError, match="Duplicate tool"):
            mint_from_policy(policy, issuer)


class TestApprovalThreshold:
    """Human-in-the-loop approval thresholds."""

    def test_gt_threshold(self):
        t = ApprovalThreshold(field="amount", operator="gt", value=5000)
        assert t.matches({"amount": 6000})
        assert not t.matches({"amount": 5000})
        assert not t.matches({"amount": 4000})
        assert not t.matches({})  # missing field

    def test_lt_threshold(self):
        t = ApprovalThreshold(field="amount", operator="lt", value=100)
        assert t.matches({"amount": 50})
        assert not t.matches({"amount": 100})

    def test_from_dict_parses_gt(self):
        thresholds = ApprovalThreshold.from_dict({"amount_gt": 5000})
        assert len(thresholds) == 1
        assert thresholds[0].field == "amount"
        assert thresholds[0].operator == "gt"
        assert thresholds[0].value == 5000

    def test_from_dict_parses_multiple(self):
        thresholds = ApprovalThreshold.from_dict(
            {
                "amount_gt": 5000,
                "risk_score_gte": 80,
            }
        )
        assert len(thresholds) == 2

    def test_from_dict_ignores_unknown(self):
        thresholds = ApprovalThreshold.from_dict({"unknown_field": 100})
        assert len(thresholds) == 0

    @pytest.mark.parametrize("value", ["99999", None, {"a": 1}, [1], object()])
    def test_incomparable_value_escalates_fail_closed(self, value):
        """RED-031: an argument whose type cannot be compared must ESCALATE.

        Before the fix a string raised TypeError out of the gate (HTTP 500
        with no receipt) and a mismatched type on an ``eq`` threshold
        silently skipped escalation, which allowed the call.
        """
        t = ApprovalThreshold(field="amount", operator="gt", value=5000)
        assert t.matches({"amount": value}) is True

    def test_eq_threshold_matches_across_numeric_spellings(self):
        """RED-031: numeric text matches a numeric threshold instead of
        falling through the comparison and quietly passing the call."""
        t = ApprovalThreshold(field="amount", operator="eq", value=10000)
        assert t.matches({"amount": "10000"}) is True
        assert t.matches({"amount": 10000}) is True
        assert t.matches({"amount": "10000.0"}) is True
        assert t.matches({"amount": 10001}) is False

    def test_boolean_is_not_a_number(self):
        """bool is an int subclass; True must not satisfy a numeric threshold."""
        t = ApprovalThreshold(field="amount", operator="gt", value=0)
        assert t.matches({"amount": True}) is True

    def test_gte_and_lte_still_work(self):
        assert ApprovalThreshold(field="n", operator="gte", value=10).matches({"n": 10})
        assert ApprovalThreshold(field="n", operator="lte", value=10).matches({"n": 10})
        assert not ApprovalThreshold(field="n", operator="lte", value=10).matches({"n": 11})


class TestCheckApprovalNeeded:
    """The check_approval_needed function."""

    def test_no_threshold_returns_false(self):
        rule = PolicyRule(tool="x", agent_id="agent:x", constraints={})
        assert not check_approval_needed(rule, {"amount": 999999})

    def test_threshold_met_returns_true(self):
        rule = PolicyRule(
            tool="transfer",
            agent_id="agent:x",
            constraints={},
            require_approval_when={"amount_gt": 5000},
        )
        assert check_approval_needed(rule, {"amount": 10000})

    def test_threshold_not_met_returns_false(self):
        rule = PolicyRule(
            tool="transfer",
            agent_id="agent:x",
            constraints={},
            require_approval_when={"amount_gt": 5000},
        )
        assert not check_approval_needed(rule, {"amount": 100})


class TestEndToEndPolicyFlow:
    """Full flow: load policy YAML, mint tokens, gate checks, approval escalation."""

    def test_full_enterprise_scenario(self):
        """Simulate a bank's payments policy end-to-end."""
        yaml_content = """
version: 1
issuer: acme.bank.payments
policies:
  - tool: transfer_money
    agent_id: agent:payments-bot
    ttl_seconds: 300
    constraints:
      allow:
        from_account: ["ACC-001", "ACC-002"]
        to_account: ["ACC-003", "ACC-004"]
      max:
        amount: 10000
      min:
        amount: 1
    require_approval_when:
      amount_gt: 5000
    description: "Internal transfers, max 10k, escalate over 5k"

  - tool: lookup_balance
    agent_id: agent:customer-service
    ttl_seconds: 600
    constraints:
      allow:
        account: ["ACC-001", "ACC-002", "ACC-003", "ACC-004"]
    description: "Customer service balance lookup"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            policy = PolicyFile.load(f.name)
        os.unlink(f.name)

        # Mint tokens
        issuer = CapabilityIssuer.generate(issuer="acme.bank.payments")
        tokens = mint_from_policy(policy, issuer)
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

        # Test 1: Small transfer - allowed, no approval needed
        assert not check_approval_needed(
            policy.policies[0], {"from_account": "ACC-001", "to_account": "ACC-003", "amount": 500}
        )
        d = gate.check(
            tokens["transfer_money"],
            tool="transfer_money",
            agent_id="agent:payments-bot",
            args={"from_account": "ACC-001", "to_account": "ACC-003", "amount": 500},
        )
        assert d.allowed

        # Test 2: Large transfer - needs approval
        assert check_approval_needed(
            policy.policies[0], {"from_account": "ACC-001", "to_account": "ACC-003", "amount": 7500}
        )
        d = gate.check(
            tokens["transfer_money"],
            tool="transfer_money",
            agent_id="agent:payments-bot",
            args={"from_account": "ACC-001", "to_account": "ACC-003", "amount": 7500},
        )
        # Gate still allows (amount < max), but approval is required separately
        assert d.allowed
        assert check_approval_needed(
            policy.policies[0], {"from_account": "ACC-001", "to_account": "ACC-003", "amount": 7500}
        )

        # Test 3: Over max - denied by gate
        d = gate.check(
            tokens["transfer_money"],
            tool="transfer_money",
            agent_id="agent:payments-bot",
            args={"from_account": "ACC-001", "to_account": "ACC-003", "amount": 50000},
        )
        assert not d.allowed

        # Test 4: Wrong account - denied
        d = gate.check(
            tokens["transfer_money"],
            tool="transfer_money",
            agent_id="agent:payments-bot",
            args={"from_account": "ACC-999", "to_account": "ACC-003", "amount": 100},
        )
        assert not d.allowed

        # Test 5: Balance lookup works
        d = gate.check(
            tokens["lookup_balance"],
            tool="lookup_balance",
            agent_id="agent:customer-service",
            args={"account": "ACC-001"},
        )
        assert d.allowed

        # Test 6: Balance lookup wrong account
        d = gate.check(
            tokens["lookup_balance"],
            tool="lookup_balance",
            agent_id="agent:customer-service",
            args={"account": "ACC-999"},
        )
        assert not d.allowed
