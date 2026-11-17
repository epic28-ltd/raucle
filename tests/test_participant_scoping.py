"""Per-participant traffic tagging (EPIC Q lane Q-3): the optional
``participant`` matcher on PolicyRule and SessionRule.

Vocabulary is the two participants the gate actually observes:
``tool_call`` (the gate's own decision surface; default, semantics
unchanged when omitted) and ``tool_response_taint`` (rules that consider
chain taint recorded via ``record_chain_output``). User, assistant and
tool-definition participants deliberately do not exist: the gateway
never sees that content. Unknown participant values fail closed at
policy load with a named error, never a skipped rule.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.policy import PolicyFile


def policy_yaml(policies: str, session_rules: str = "") -> str:
    out = "version: 1\nissuer: test.bank\n"
    if session_rules:
        out += f"session_rules:\n{session_rules}"
    out += f"policies:\n{policies}"
    return out


def make_gateway(tmp_path, *, policy_text: str, **overrides) -> RaucleGateway:
    policy = tmp_path / "policies.yaml"
    policy.write_text(policy_text)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        receipt_store_dir=str(tmp_path / "segments"),
        receipt_index_path=str(tmp_path / "index.sqlite"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
        session_window_ttl_seconds=900,
        session_window_max_keys=1024,
        session_window_max_entries=10000,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return RaucleGateway(config)


def call(
    client,
    tool,
    args=None,
    *,
    trace_id="",
    session_id="",
    destination_class="",
    headers=None,
):
    body: dict = {"tool": tool, "args": args or {}, "agent_id": "agent:svc", "source": ""}
    hdrs = dict(headers or {})
    if trace_id:
        hdrs["X-Trace-Id"] = trace_id
    if session_id:
        body["session_id"] = session_id
    if destination_class:
        body["destination_class"] = destination_class
    return client.post("/gate", json=body, headers=hdrs).json()


def allow_args(*accounts):
    return {"account": accounts[0] if accounts else "ACC-001"}


# ---------------------------------------------------------------------------
# Acceptance (c): v-current policy with no participant field is unchanged
# ---------------------------------------------------------------------------


class TestParticipantDefaultUnchanged:
    def test_old_policy_parses_with_empty_participant(self):
        pf = PolicyFile.from_dict(
            {
                "version": 1,
                "issuer": "i",
                "policies": [{"tool": "t1", "agent_id": "agent:a"}],
            }
        )
        assert pf.policies[0].participant == ""
        assert pf.session_rules == []

    def test_round_trip_has_no_participant_field(self):
        """Byte-compat: a v-current policy file round-trips without any
        participant key appearing."""
        pf = PolicyFile.from_dict(
            {
                "version": 1,
                "issuer": "i",
                "policies": [{"tool": "t1", "agent_id": "agent:a"}],
            }
        )
        assert "participant" not in pf.to_yaml()

    def test_tool_call_participant_behaves_as_today(self, tmp_path):
        """participant=tool_call is the existing decision surface end to end:
        constraints allow and deny exactly as before."""
        text = policy_yaml(
            """
  - tool: lookup_balance
    agent_id: agent:svc
    participant: tool_call
    constraints:
      allow:
        account: ["ACC-001"]
"""
        )
        gw = make_gateway(tmp_path, policy_text=text)
        client = TestClient(create_gateway_app(gw))
        r1 = call(client, "lookup_balance", {"account": "ACC-001"}, trace_id="tr-1")
        r2 = call(client, "lookup_balance", {"account": "ACC-999"}, trace_id="tr-1")
        assert r1["decision"] == "allow"
        assert r2["decision"] == "deny"


# ---------------------------------------------------------------------------
# Acceptance (b): unknown participant fails closed at load
# ---------------------------------------------------------------------------


class TestUnknownParticipantFailsClosed:
    def test_unknown_participant_on_policy_rule_named_error(self):
        with pytest.raises(ValueError) as exc:
            PolicyFile.from_dict(
                {
                    "version": 1,
                    "issuer": "i",
                    "policies": [{"tool": "t1", "agent_id": "agent:a", "participant": "assistant"}],
                }
            )
        msg = str(exc.value)
        assert "participant" in msg
        assert "assistant" in msg

    def test_non_observable_participant_value_named_error(self):
        with pytest.raises(ValueError) as exc:
            PolicyFile.from_dict(
                {
                    "version": 1,
                    "issuer": "i",
                    "policies": [{"tool": "t1", "agent_id": "agent:a", "participant": "user"}],
                }
            )
        assert "user" in str(exc.value)

    def test_unknown_participant_on_session_rule_named_error(self):
        pf = PolicyFile.from_dict(
            {
                "version": 1,
                "issuer": "i",
                "session_rules": [
                    {
                        "id": "sr-bad",
                        "kind": "repeated_deny_storm",
                        "window_seconds": 60,
                        "threshold": 2,
                        "participant": "tool_definition",
                    }
                ],
                "policies": [{"tool": "t1", "agent_id": "agent:a"}],
            }
        )
        assert pf.session_rules == []
        assert len(pf.session_rule_errors) == 1
        assert "sr-bad" in pf.session_rule_errors[0]
        assert "participant" in pf.session_rule_errors[0]

    def test_broken_session_rule_denies_sessioned_calls_fail_closed(self, tmp_path):
        """A participant value the policy cannot compile is a NAMED load
        error, and a rule that cannot be evaluated never silently skips:
        session'd traffic denies fail-closed until the config is fixed."""
        text = policy_yaml(
            """
  - tool: t1
    agent_id: agent:svc
""",
            """
  - id: sr-bad
    kind: repeated_deny_storm
    window_seconds: 60
    threshold: 2
    participant: assistant
""",
        )
        gw = make_gateway(tmp_path, policy_text=text)
        client = TestClient(create_gateway_app(gw))
        r = call(client, "t1", session_id="s1", trace_id="tr-9")
        assert r["decision"] == "deny"
        assert "session rule config malformed" in r["reason"]


# ---------------------------------------------------------------------------
# Acceptance (a): tool_response_taint overlay denies only with recorded taint
# ---------------------------------------------------------------------------

TWO_RULE_POLICY = """
  - tool: lookup_balance
    agent_id: agent:svc
    constraints:
      allow:
        account: ["ACC-001"]
  - tool: lookup_balance
    agent_id: agent:svc
    participant: tool_response_taint
    id: taint-overlay/lookup_balance
"""


class TestToolResponseTaintOverlay:
    def test_denies_once_taint_recorded_for_the_tool(self, tmp_path):
        gw = make_gateway(tmp_path, policy_text=policy_yaml(TWO_RULE_POLICY))
        client = TestClient(create_gateway_app(gw))
        r1 = call(
            client,
            "lookup_balance",
            {"account": "ACC-001"},
            trace_id="tr-1",
            session_id="s1",
        )
        assert r1["decision"] == "allow", r1["reason"]
        gw.record_chain_output("tr-1", "lookup_balance", ["taint:customer-email"])
        r2 = call(
            client,
            "lookup_balance",
            {"account": "ACC-001"},
            trace_id="tr-1",
            session_id="s1",
        )
        assert r2["decision"] == "deny"
        assert "participant=tool_response_taint" in r2["reason"]
        assert "taint-overlay/lookup_balance" in r2["reason"]
        assert r2["rule_id"] == "taint-overlay/lookup_balance"

    def test_identical_call_without_recorded_taint_not_denied(self, tmp_path):
        gw = make_gateway(tmp_path, policy_text=policy_yaml(TWO_RULE_POLICY))
        client = TestClient(create_gateway_app(gw))
        r1 = call(
            client,
            "lookup_balance",
            {"account": "ACC-001"},
            trace_id="tr-fresh",
            session_id="s1",
        )
        assert r1["decision"] == "allow", r1["reason"]
        r2 = call(
            client,
            "lookup_balance",
            {"account": "ACC-001"},
            trace_id="tr-fresh",
            session_id="s1",
        )
        assert r2["decision"] == "allow", r2["reason"]

    def test_other_tool_chain_taint_does_not_leak(self, tmp_path):
        """Taint recorded for a DIFFERENT tool in the chain does not trigger
        the overlay: the recorded state must be for the rule's tool."""
        gw = make_gateway(tmp_path, policy_text=policy_yaml(TWO_RULE_POLICY))
        client = TestClient(create_gateway_app(gw))
        gw.record_chain_output("tr-2", "fs.write", ["taint:customer-email"])
        r = call(client, "lookup_balance", {"account": "ACC-001"}, trace_id="tr-2")
        assert r["decision"] == "allow", r["reason"]

    def test_overlay_with_deny_from_chain_taint_delegates_tag_matching(self, tmp_path):
        """A taint-participant rule carrying deny_from_chain_taint denies
        through the existing tag/class evaluation, scoped to its tool."""
        text = policy_yaml(
            """
  - tool: lookup_balance
    agent_id: agent:svc
    constraints:
      allow:
        account: ["ACC-001"]
  - tool: lookup_balance
    agent_id: agent:svc
    participant: tool_response_taint
    id: taint-deny/lookup_balance
    deny_from_chain_taint:
      taint_tags: ["taint:customer-email"]
      destination_classes: ["external"]
"""
        )
        gw = make_gateway(tmp_path, policy_text=text)
        client = TestClient(create_gateway_app(gw))
        # recorded but non-matching tag: the overlay does not deny (the
        # rule's own taint conditions decide once taint is recorded)
        gw.record_chain_output("tr-3", "lookup_balance", ["taint:unrelated"])
        r1 = call(
            client,
            "lookup_balance",
            {"account": "ACC-001"},
            trace_id="tr-3",
            destination_class="external",
        )
        assert r1["decision"] == "allow", r1["reason"]
        # matching tag + denied destination class: overlay deny
        gw.record_chain_output("tr-4", "lookup_balance", ["taint:customer-email"])
        r2 = call(
            client,
            "lookup_balance",
            {"account": "ACC-001"},
            trace_id="tr-4",
            destination_class="external",
        )
        assert r2["decision"] == "deny", r2["reason"]
        assert "participant=tool_response_taint" in r2["reason"]
        assert "taint-deny/lookup_balance" in r2["reason"]


# ---------------------------------------------------------------------------
# Session rules: participant scoping over the window
# ---------------------------------------------------------------------------


class TestSessionRuleParticipant:
    def test_session_rule_taint_participant_counts_only_tainted_traces(self, tmp_path):
        """A session rule with participant=tool_response_taint counts only
        window entries whose trace has recorded chain taint."""
        session_rules = """
  - id: sr-taint
    kind: repeated_deny_storm
    window_seconds: 300
    threshold: 1
    participant: tool_response_taint
    tool_patterns: ["lookup_balance"]
"""
        policies = """
  - tool: lookup_balance
    agent_id: agent:svc
    constraints:
      allow:
        account: ["NOTHING-MATCHES-THIS"]
"""
        gw = make_gateway(tmp_path, policy_text=policy_yaml(policies, session_rules))
        client = TestClient(create_gateway_app(gw))
        # two denied attempts, but the traces carry no recorded taint: the
        # taint-scoped rule does not fire
        for trace in ("tr-a", "tr-b"):
            r = call(
                client,
                "lookup_balance",
                {"account": "ACC-999"},
                trace_id=trace,
                session_id="s1",
            )
            assert r["decision"] == "deny"
            assert "sr-taint" not in r["reason"]
        # one of the denied attempts' traces now has recorded taint: the
        # rule fires with the participant named in the reason
        gw.record_chain_output("tr-b", "lookup_balance", ["taint:customer-email"])
        r3 = call(
            client,
            "lookup_balance",
            {"account": "ACC-999"},
            trace_id="tr-b",
            session_id="s1",
        )
        assert r3["decision"] == "deny"
        assert "sr-taint" in r3["reason"]
        assert "participant=tool_response_taint" in r3["reason"]


# ---------------------------------------------------------------------------
# Receipt index: acting_for query helper (trivially index-backed, v3)
# ---------------------------------------------------------------------------


def _b64url(obj) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jws_record(receipt_hash: str, payload: dict) -> dict:
    """A minimal unsigned JWS envelope; the index decoder does not verify."""
    header_payload_sig = f"{_b64url({'alg': 'none'})}.{_b64url(payload)}."
    return {"receipt_hash": receipt_hash, "jws": header_payload_sig}


class TestReceiptIndexActingForQuery:
    def test_query_filters_by_acting_for(self, tmp_path):
        """acting_for is an indexed v3 column; the query helper filters on it."""
        from raucle.receipt_index import ReceiptIndex

        idx = ReceiptIndex(str(tmp_path / "idx.sqlite"))
        body = {
            "iat": int(time.time()),
            "x_gate": {
                "decision": "allow",
                "tool": "t1",
                "agent_id": "agent:a",
            },
        }
        idx.index_receipt(
            _jws_record("r1", {**body, "x_gate": {**body["x_gate"], "acting_for": "user:alice"}})
        )
        idx.index_receipt(
            _jws_record("r2", {**body, "x_gate": {**body["x_gate"], "acting_for": "user:bob"}})
        )
        got = idx.query(acting_for="user:alice")
        assert [r["receipt_hash"] for r in got] == ["r1"]
        got_all = idx.query()
        assert len(got_all) == 2
