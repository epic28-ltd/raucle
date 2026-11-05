"""Tests for the mcp-cap:v1 binding helpers (MCP capability annotations + receipts)."""

from __future__ import annotations

import pytest

from raucle.mcp_auth import (
    MCP_CAP_VERSION,
    receipt_meta,
    tool_capability_annotation,
    verify_tool_annotation,
)


class TestToolAnnotation:
    def test_basic_annotation(self):
        a = tool_capability_annotation(
            issuer_key_id="abc123def4567890",
            required_constraints=["allowed_values", "max_value"],
        )
        assert a["version"] == MCP_CAP_VERSION
        assert a["gated"] is True
        assert a["issuer_key_id"] == "abc123def4567890"
        assert a["required_constraints"] == ["allowed_values", "max_value"]

    def test_constraints_are_sorted_and_deduped(self):
        a = tool_capability_annotation(
            issuer_key_id="k",
            required_constraints=["max_value", "allowed_values", "max_value"],
        )
        assert a["required_constraints"] == ["allowed_values", "max_value"]

    def test_unknown_constraint_rejected_fail_closed(self):
        with pytest.raises(ValueError, match="unknown cap:v1 constraint"):
            tool_capability_annotation(
                issuer_key_id="k", required_constraints=["allowed_values", "sql_injection_ok"]
            )

    def test_policy_proof_hash_optional(self):
        a = tool_capability_annotation(
            issuer_key_id="k", required_constraints=[], policy_proof_hash="sha256:deadbeef"
        )
        assert a["policy_proof_hash"] == "sha256:deadbeef"


class TestReceiptMeta:
    def test_allow_receipt(self):
        r = receipt_meta(decision="ALLOW", receipt_id="sha256:aaa", token_id="cap:1234")
        assert r["version"] == MCP_CAP_VERSION
        assert r["decision"] == "ALLOW"
        assert r["receipt_id"] == "sha256:aaa"
        assert r["token_id"] == "cap:1234"
        assert "reason" not in r  # reasons only on denials

    def test_deny_receipt_carries_reason(self):
        r = receipt_meta(decision="DENY", receipt_id="sha256:bbb", reason="amount over max")
        assert r["decision"] == "DENY"
        assert r["reason"] == "amount over max"

    def test_invalid_decision_rejected(self):
        with pytest.raises(ValueError):
            receipt_meta(decision="MAYBE", receipt_id="x")


class TestVerifyAnnotation:
    def test_ungated_tool_accepted(self):
        ok, _ = verify_tool_annotation({"name": "t"}, trusted_key_ids={"k"})
        assert ok

    def test_gated_by_trusted_anchor_accepted(self):
        tool = {
            "name": "transfer_funds",
            "_meta": {
                "raucle": tool_capability_annotation(
                    issuer_key_id="trusted-key", required_constraints=["max_value"]
                )
            },
        }
        ok, reason = verify_tool_annotation(tool, trusted_key_ids={"trusted-key"})
        assert ok
        assert "trusted issuer" in reason

    def test_gated_by_untrusted_anchor_rejected(self):
        tool = {
            "name": "transfer_funds",
            "_meta": {
                "raucle": tool_capability_annotation(
                    issuer_key_id="rogue-key", required_constraints=["max_value"]
                )
            },
        }
        ok, reason = verify_tool_annotation(tool, trusted_key_ids={"trusted-key"})
        assert not ok
        assert "untrusted" in reason

    def test_malformed_gated_annotation_rejected_fail_closed(self):
        tool = {"_meta": {"raucle": {"version": MCP_CAP_VERSION, "gated": True}}}  # no key_id
        ok, reason = verify_tool_annotation(tool, trusted_key_ids={"k"})
        assert not ok
        assert "issuer_key_id" in reason

    def test_unknown_binding_version_rejected(self):
        tool = {
            "_meta": {"raucle": {"version": "mcp-cap:v99", "gated": True, "issuer_key_id": "k"}}
        }
        ok, reason = verify_tool_annotation(tool, trusted_key_ids={"k"})
        assert not ok
        assert "unknown binding version" in reason
