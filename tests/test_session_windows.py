"""Session window engine tests (EPIC Q lane Q-2): stateful session windows
plus deterministic session rules, enforced deny-only in the gate pre-check
tier, findings receipted.

The window is a bounded projection of RECEIPTED decisions: summaries carry
decision, tool, iat, trace_id, rule_id and destination_class only - never
args, never content. Session rules are policy-side (``session_rules:`` in
the policy file), evaluated only for calls that declare a session_id, and
can only ever deny.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, SessionWindowState
from raucle.gateway_app import create_gateway_app
from raucle.policy import PolicyFile, SessionRule
from raucle.provenance import ProvenanceVerifier, _canonical_json, _sha256_hex

TOOL_POLICIES = """
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
  - tool: web.fetch
    agent_id: agent:svc
    ttl_seconds: 60
    constraints: {}
  - tool: fs.write
    agent_id: agent:svc
    ttl_seconds: 60
    constraints: {}
  - tool: shell.exec
    agent_id: agent:svc
    ttl_seconds: 60
    constraints: {}
"""


def policy_yaml(session_rules: str = "", policies: str = TOOL_POLICIES) -> str:
    """A complete policy file; session rules ride the same sealed file."""
    out = "version: 1\nissuer: test.bank\n"
    if session_rules:
        out += f"session_rules:\n{session_rules}"
    out += f"policies:\n{policies}"
    return out


def make_gateway(
    tmp_path, session_rules: str = "", *, policy_text: str = "", **overrides
) -> RaucleGateway:
    policy = tmp_path / "policies.yaml"
    policy.write_text(policy_text or policy_yaml(session_rules))
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
    client, tool, args=None, *, session_id="", destination_class="", agent="agent:svc", source=""
):
    body: dict = {
        "tool": tool,
        "args": args or {},
        "agent_id": agent,
        "source": source,
    }
    if session_id:
        body["session_id"] = session_id
    if destination_class:
        body["destination_class"] = destination_class
    return client.post("/gate", json=body).json()


def _decode(jws: str) -> dict:
    b = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(b + "=" * ((4 - len(b) % 4) % 4)))


def envelope(gw, receipt_hash) -> dict:
    """The decoded JWS payload of one stored receipt envelope."""
    rec = gw._receipt_store.find_by_hash(receipt_hash)  # noqa: SLF001
    assert rec is not None, f"receipt {receipt_hash} not in store"
    return _decode(rec["jws"])


def all_payloads(gw):
    for seg in gw._receipt_store.segments():  # noqa: SLF001
        with open(seg, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield _decode(json.loads(line)["jws"])


def session_findings(gw, rule_id) -> list[dict]:
    """Every session-monitor finding receipt for one rule id."""
    return [
        p["x_finding"]
        for p in all_payloads(gw)
        if p.get("x_finding", {}).get("harness") == "session-monitor"
        and p["x_finding"].get("test_id") == rule_id
    ]


def assert_chain_verifies(gw) -> None:
    """The whole chain, session-monitor findings included, verifies offline
    through ProvenanceVerifier (the anti-fabrication re-check runs on every
    x_finding: cited receipt exists, actual decision matches)."""
    verifier = ProvenanceVerifier(
        public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
    )
    for seg in gw._receipt_store.segments():  # noqa: SLF001
        report = verifier.verify_chain(str(seg))
        assert report.valid, report.errors


# ---------------------------------------------------------------------------
# Window state: bounded, content-free
# ---------------------------------------------------------------------------


class TestSessionWindowState:
    def test_record_and_entries_roundtrip(self):
        state = SessionWindowState(ttl_seconds=900, max_keys=64, max_entries=100)
        now = int(time.time())
        state.record("s1", "agent:a", "allow", "t1", now, "trace-1", "r1", "external")
        entries = state.entries("s1", "agent:a")
        assert len(entries) == 1
        assert entries[0] == {
            "decision": "allow",
            "tool": "t1",
            "iat": now,
            "trace_id": "trace-1",
            "rule_id": "r1",
            "destination_class": "external",
        }

    def test_summaries_carry_no_content(self):
        """The window is decision summaries only: no args, no content, ever."""
        state = SessionWindowState(ttl_seconds=900, max_keys=64, max_entries=100)
        state.record("s1", "agent:a", "deny", "t1", int(time.time()), "", "", "")
        entry = state.entries("s1", "agent:a")[0]
        assert set(entry) == {
            "decision",
            "tool",
            "iat",
            "trace_id",
            "rule_id",
            "destination_class",
        }

    def test_ttl_prunes_old_entries(self):
        state = SessionWindowState(ttl_seconds=900, max_keys=64, max_entries=100)
        now = int(time.time())
        state.record("s1", "agent:a", "deny", "t1", now - 1000, "", "", "")
        state.record("s1", "agent:a", "deny", "t1", now, "", "", "")
        assert len(state.entries("s1", "agent:a")) == 1
        assert state.entries("s1", "agent:a")[0]["iat"] == now

    def test_max_keys_evicts_least_recently_used(self):
        """Bounded keys: a new session beyond max_keys evicts the least
        recently touched one (ChainTaintState's unbounded growth is a known
        wart; the window state must not replicate it)."""
        state = SessionWindowState(ttl_seconds=900, max_keys=2, max_entries=100)
        now = int(time.time())
        state.record("s1", "agent:a", "allow", "t1", now, "", "", "")
        state.record("s2", "agent:a", "allow", "t1", now, "", "", "")
        # touching s1 again makes s2 the LRU key
        state.record("s1", "agent:a", "deny", "t1", now, "", "", "")
        state.record("s3", "agent:a", "allow", "t1", now, "", "", "")
        assert state.key_count() == 2
        assert state.entries("s1", "agent:a"), "recently touched key must survive"
        assert state.entries("s2", "agent:a") == [], "LRU key must be evicted"

    def test_per_key_entry_cap_bounds_a_hot_session(self):
        """TTL alone does not bound a runaway session; the per-key cap does."""
        state = SessionWindowState(ttl_seconds=900, max_keys=64, max_entries=3)
        now = int(time.time())
        for _ in range(5):
            state.record("s1", "agent:a", "deny", "t1", now, "", "", "")
        assert len(state.entries("s1", "agent:a")) == 3

    def test_keys_are_per_agent(self):
        """The window is keyed (session_id, agent_id): one agent's storm
        never denies another agent's calls in the same session."""
        state = SessionWindowState(ttl_seconds=900, max_keys=64, max_entries=100)
        now = int(time.time())
        state.record("s1", "agent:a", "deny", "t1", now, "", "", "")
        assert state.entries("s1", "agent:b") == []


# ---------------------------------------------------------------------------
# SessionRule parsing (policy side)
# ---------------------------------------------------------------------------


class TestSessionRuleParsing:
    def test_five_kinds_parse_and_roundtrip(self):
        rules = [
            SessionRule.from_dict(
                {"id": "r1", "kind": "repeated_deny_storm", "threshold": 3, "window_seconds": 600}
            ),
            SessionRule.from_dict(
                {"id": "r2", "kind": "runaway_tool_loop", "threshold": 3, "window_seconds": 600}
            ),
            SessionRule.from_dict(
                {
                    "id": "r3",
                    "kind": "gradual_extraction",
                    "threshold": 3,
                    "window_seconds": 600,
                    "destination_class": "external",
                }
            ),
            SessionRule.from_dict(
                {
                    "id": "r4",
                    "kind": "forbidden_tool_chain",
                    "window_seconds": 600,
                    "sequence": ["a.b", "c.d"],
                }
            ),
            SessionRule.from_dict(
                {
                    "id": "r5",
                    "kind": "scope_drift",
                    "threshold": 2,
                    "window_seconds": 600,
                    "tools": ["a.b"],
                }
            ),
        ]
        for rule in rules:
            assert rule.action == "deny"  # v1: deny only
            assert SessionRule.from_dict(rule.to_dict()) == rule

    def test_unknown_kind_is_refused(self):
        with pytest.raises(ValueError, match="kind"):
            SessionRule.from_dict(
                {"id": "r", "kind": "nonsense", "threshold": 1, "window_seconds": 60}
            )

    def test_non_deny_action_is_refused_v1(self):
        with pytest.raises(ValueError, match="deny"):
            SessionRule.from_dict(
                {
                    "id": "r",
                    "kind": "runaway_tool_loop",
                    "threshold": 1,
                    "window_seconds": 60,
                    "action": "alert",
                }
            )

    def test_missing_threshold_is_refused(self):
        with pytest.raises(ValueError, match="threshold"):
            SessionRule.from_dict({"id": "r", "kind": "repeated_deny_storm", "window_seconds": 60})

    def test_chain_without_sequence_is_refused(self):
        with pytest.raises(ValueError, match="sequence"):
            SessionRule.from_dict({"id": "r", "kind": "forbidden_tool_chain", "window_seconds": 60})

    def test_drift_without_known_tools_is_refused(self):
        with pytest.raises(ValueError, match="tools"):
            SessionRule.from_dict(
                {"id": "r", "kind": "scope_drift", "threshold": 2, "window_seconds": 60}
            )

    def test_extraction_without_destination_class_is_refused(self):
        with pytest.raises(ValueError, match="destination_class"):
            SessionRule.from_dict(
                {"id": "r", "kind": "gradual_extraction", "threshold": 2, "window_seconds": 60}
            )

    def test_malformed_rule_is_captured_never_raised_never_skipped(self):
        """A malformed session rule must not break the whole policy file
        (tool rules keep loading) and must not be silently skipped either:
        the named error rides the PolicyFile so the gateway can deny
        fail-closed."""
        data = {
            "version": 1,
            "issuer": "test.bank",
            "session_rules": [
                {"id": "good", "kind": "runaway_tool_loop", "threshold": 2, "window_seconds": 60},
                {"id": "bad-rule", "kind": "nonsense", "threshold": 1, "window_seconds": 60},
            ],
            "policies": [{"tool": "lookup_balance", "agent_id": "agent:svc", "constraints": {}}],
        }
        pf = PolicyFile.from_dict(data)
        assert [r.id for r in pf.session_rules] == ["good"]
        assert len(pf.session_rule_errors) == 1
        assert "bad-rule" in pf.session_rule_errors[0]


# ---------------------------------------------------------------------------
# repeated_deny_storm through the real gateway
# ---------------------------------------------------------------------------


STORM_RULE = """
  - id: sr-storm
    kind: repeated_deny_storm
    threshold: 3
    window_seconds: 600
"""


class TestRepeatedDenyStorm:
    @pytest.fixture
    def gw(self, tmp_path):
        return make_gateway(tmp_path, STORM_RULE)

    @pytest.fixture
    def client(self, gw):
        return TestClient(create_gateway_app(gw))

    def test_storm_fires_on_fourth_attempt(self, gw, client):
        """Three receipted denies for the tool, then the rule cuts the next
        attempt: an otherwise-allowable call is denied, so only the session
        rule could have denied it."""
        for _ in range(3):
            body = call(client, "lookup_balance", {"account": "ACC-999-SECRET"}, session_id="run-1")
            assert body["decision"] == "deny"  # policy deny, receipted
            assert "sr-storm" not in body["reason"]
        trip = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-1")
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-storm"
        assert "sr-storm" in trip["reason"]
        assert "repeated_deny_storm" in trip["reason"]
        assert "lookup_balance" in trip["reason"]
        assert "3" in trip["reason"]
        # content-free: the arg value never enters the reason
        assert "ACC-999-SECRET" not in trip["reason"]

    def test_storm_deny_receipts_and_finding(self, gw, client):
        for _ in range(3):
            call(client, "lookup_balance", {"account": "ACC-999"}, session_id="run-2")
        trip = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-2")
        # the deny is receipted and binds the session + rule id
        payload = envelope(gw, trip["receipt_id"])
        assert payload["guardrail_verdict"] == "deny"
        assert payload["x_gate"]["session_id"] == "run-2"
        assert payload["x_gate"]["rule_id"] == "sr-storm"
        # a session-monitor finding cites the triggering deny receipt
        findings = session_findings(gw, "sr-storm")
        assert len(findings) == 1
        assert findings[0]["cited_receipt"] == trip["receipt_id"]
        assert findings[0]["repro"]["actual_decision"] == "deny"
        assert findings[0]["verdict"] == "confirmed"
        # and the whole chain, finding included, verifies offline
        assert_chain_verifies(gw)

    def test_no_session_id_refuses_named_when_rules_configured(self, gw, client):
        """Q17 gate hardening (close 3): with rules configured, an omitted
        session id refuses by name instead of silently skipping the
        configured control - and no session rule finding is minted from
        the refusal (rules never fire from trace continuity; continuity is
        still never fabricated)."""
        for _ in range(5):
            body = call(client, "lookup_balance", {"account": "ACC-999"})
            assert body["decision"] == "deny"
            assert "session_binding_required" in body["reason"], body
        ok = call(client, "lookup_balance", {"account": "ACC-001"})
        assert "session_binding_required" in ok["reason"], ok
        assert session_findings(gw, "sr-storm") == []

    def test_other_agent_same_session_is_separate(self, tmp_path):
        """The window is keyed (session_id, agent_id): one agent's storm
        never denies another agent's calls in the same session."""
        two_agents = """
  - tool: lookup_balance
    agent_id: agent:other
    ttl_seconds: 60
    source: "other-host"
    constraints:
      allow:
        account: ["ACC-001"]
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""
        gw = make_gateway(tmp_path, STORM_RULE, policy_text=policy_yaml(STORM_RULE, two_agents))
        client = TestClient(create_gateway_app(gw))
        for _ in range(3):
            body = call(client, "lookup_balance", {"account": "ACC-999"}, session_id="run-3")
            assert body["decision"] == "deny"
        # same session, different agent: a separate window, so the storm
        # rule does not apply (the call matches this agent's own rule)
        ok = call(
            client,
            "lookup_balance",
            {"account": "ACC-001"},
            session_id="run-3",
            agent="agent:other",
            source="other-host",
        )
        assert ok["decision"] == "allow", ok
        # and the storming agent's next attempt is still cut off
        trip = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-3")
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-storm"


# ---------------------------------------------------------------------------
# runaway_tool_loop: the acceptance rule
# ---------------------------------------------------------------------------


LOOP_RULE = """
  - id: sr-loop
    kind: runaway_tool_loop
    threshold: 3
    window_seconds: 600
"""


class TestRunawayToolLoop:
    @pytest.fixture
    def gw(self, tmp_path):
        return make_gateway(tmp_path, LOOP_RULE)

    @pytest.fixture
    def client(self, gw):
        return TestClient(create_gateway_app(gw))

    def test_loop_acceptance(self, gw, client):
        """A mix of allow then repeated fails: the threshold-th call of the
        same tool without a receipted success between them is denied
        fail-closed; the reason names the rule id plus window counters; a
        session-monitor finding receipt cites the deny; verify_chain
        validates the chain through ProvenanceVerifier."""
        first = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="loop-1")
        assert first["decision"] == "allow"
        for _ in range(2):
            body = call(client, "lookup_balance", {"account": "ACC-999"}, session_id="loop-1")
            assert body["decision"] == "deny"
            assert "sr-loop" not in body["reason"]  # policy deny, not the rule
        # the third call without receipted success would be allowable; the
        # rule denies it
        trip = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="loop-1")
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-loop"
        assert "sr-loop" in trip["reason"]
        assert "runaway_tool_loop" in trip["reason"]
        assert "lookup_balance" in trip["reason"]
        assert "ACC-999" not in trip["reason"]
        # window counters in the reason: 2 prior, threshold 3
        assert "2" in trip["reason"] and "3" in trip["reason"]
        # receipted deny + session-monitor finding citing it
        assert trip["receipt_id"]
        findings = session_findings(gw, "sr-loop")
        assert len(findings) == 1
        assert findings[0]["cited_receipt"] == trip["receipt_id"]
        assert findings[0]["repro"]["actual_decision"] == "deny"
        assert_chain_verifies(gw)

    def test_receipted_success_resets_the_loop(self, client):
        call(client, "lookup_balance", {"account": "ACC-001"}, session_id="loop-2")
        call(client, "lookup_balance", {"account": "ACC-999"}, session_id="loop-2")
        # a receipted allow between failures resets the loop count
        call(client, "lookup_balance", {"account": "ACC-001"}, session_id="loop-2")
        body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="loop-2")
        assert body["decision"] == "allow", body

    def test_loop_denies_are_counted_so_the_rule_stays_fired(self, client):
        """Once fired, the rule's own denies keep the loop count above the
        threshold: the intervention does not flap."""
        call(client, "lookup_balance", {"account": "ACC-999"}, session_id="loop-3")
        call(client, "lookup_balance", {"account": "ACC-999"}, session_id="loop-3")
        for _ in range(3):
            body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="loop-3")
            assert body["decision"] == "deny"
            assert body["rule_id"] == "sr-loop"


# ---------------------------------------------------------------------------
# gradual_extraction (content-free, classification rides destination_class)
# ---------------------------------------------------------------------------


EXTRACTION_RULE = """
  - id: sr-extraction
    kind: gradual_extraction
    threshold: 3
    window_seconds: 600
    destination_class: external
"""


class TestGradualExtraction:
    @pytest.fixture
    def gw(self, tmp_path):
        return make_gateway(tmp_path, EXTRACTION_RULE)

    @pytest.fixture
    def client(self, gw):
        return TestClient(create_gateway_app(gw))

    def test_counts_allow_and_deny_decisions_by_class(self, gw, client):
        """The class counter counts receipted decisions (allow or deny):
        gradual extraction is about many touches, not many failures."""
        for i in range(3):
            body = call(
                client,
                "web.fetch",
                {"url": f"http://ext.example/{i}"},
                session_id="ext-1",
                destination_class="external",
            )
            assert body["decision"] == "allow", body
        trip = call(
            client,
            "web.fetch",
            {"url": "http://ext.example/4"},
            session_id="ext-1",
            destination_class="external",
        )
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-extraction"
        assert "sr-extraction" in trip["reason"]
        assert "external" in trip["reason"]
        assert "ext.example" not in trip["reason"]
        findings = session_findings(gw, "sr-extraction")
        assert findings and findings[0]["cited_receipt"] == trip["receipt_id"]
        assert_chain_verifies(gw)

    def test_other_classes_do_not_count(self, client):
        for i in range(5):
            body = call(
                client,
                "web.fetch",
                {"url": f"http://int.example/{i}"},
                session_id="ext-2",
                destination_class="internal",
            )
            assert body["decision"] == "allow", body


# ---------------------------------------------------------------------------
# forbidden_tool_chain (exact trailing sequence)
# ---------------------------------------------------------------------------


CHAIN_RULE = """
  - id: sr-chain
    kind: forbidden_tool_chain
    window_seconds: 600
    sequence: [lookup_balance, web.fetch]
"""


class TestForbiddenToolChain:
    @pytest.fixture
    def gw(self, tmp_path):
        return make_gateway(tmp_path, CHAIN_RULE)

    @pytest.fixture
    def client(self, gw):
        return TestClient(create_gateway_app(gw))

    def test_chain_fires_on_exact_completion(self, gw, client):
        first = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="chain-1")
        assert first["decision"] == "allow"
        trip = call(client, "web.fetch", {"url": "http://x.example"}, session_id="chain-1")
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-chain"
        assert "sr-chain" in trip["reason"]
        assert "lookup_balance" in trip["reason"] and "web.fetch" in trip["reason"]
        findings = session_findings(gw, "sr-chain")
        assert findings and findings[0]["cited_receipt"] == trip["receipt_id"]
        assert_chain_verifies(gw)

    def test_interleaved_tools_do_not_complete_the_chain(self, client):
        call(client, "lookup_balance", {"account": "ACC-001"}, session_id="chain-2")
        body = call(client, "fs.write", {"path": "/tmp/x"}, session_id="chain-2")
        assert body["decision"] == "allow", body
        body = call(client, "web.fetch", {"url": "http://x.example"}, session_id="chain-2")
        assert body["decision"] == "allow", body

    def test_partial_sequence_alone_does_not_fire(self, client):
        body = call(client, "web.fetch", {"url": "http://x.example"}, session_id="chain-3")
        assert body["decision"] == "allow", body


# ---------------------------------------------------------------------------
# scope_drift (declared known-tools set)
# ---------------------------------------------------------------------------


DRIFT_RULE = """
  - id: sr-drift
    kind: scope_drift
    threshold: 2
    window_seconds: 600
    tools: [lookup_balance, web.fetch]
"""


class TestScopeDrift:
    @pytest.fixture
    def gw(self, tmp_path):
        return make_gateway(tmp_path, DRIFT_RULE)

    @pytest.fixture
    def client(self, gw):
        return TestClient(create_gateway_app(gw))

    def test_drift_fires_on_second_unknown_tool_call(self, gw, client):
        first = call(
            client, "shell.exec", {"cmd": "cat /etc/shadow-SECRETVAL"}, session_id="drift-1"
        )
        assert first["decision"] == "allow"  # strike one, below threshold
        trip = call(
            client, "shell.exec", {"cmd": "cat /etc/shadow-SECRETVAL"}, session_id="drift-1"
        )
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-drift"
        assert "sr-drift" in trip["reason"]
        assert "shell.exec" in trip["reason"]
        # content-free: the argument value never enters the reason
        assert "SECRETVAL" not in trip["reason"]
        findings = session_findings(gw, "sr-drift")
        assert findings and findings[0]["cited_receipt"] == trip["receipt_id"]
        assert_chain_verifies(gw)

    def test_known_tools_do_not_strike(self, client):
        for tool, args in (
            ("lookup_balance", {"account": "ACC-001"}),
            ("web.fetch", {"url": "http://x.example"}),
        ):
            body = call(client, tool, args, session_id="drift-2")
            assert body["decision"] == "allow", body

    def test_drift_does_not_cut_declared_tools(self, client):
        """Once drifted, the session keeps its declared tools: the rule
        cuts off-the-list calls, it does not kill the session."""
        call(client, "shell.exec", {"cmd": "cat /etc/x"}, session_id="drift-3")
        call(client, "shell.exec", {"cmd": "cat /etc/x"}, session_id="drift-3")
        body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="drift-3")
        assert body["decision"] == "allow", body


# ---------------------------------------------------------------------------
# tool_patterns scoping (optional fnmatch)
# ---------------------------------------------------------------------------


PATTERN_RULE = """
  - id: sr-pattern-loop
    kind: runaway_tool_loop
    threshold: 2
    window_seconds: 600
    tool_patterns: ["db.*"]
"""

PATTERN_TOOL_POLICIES = """
  - tool: db.query
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        q: ["ok"]
  - tool: web.fetch
    agent_id: agent:svc
    ttl_seconds: 60
    constraints: {}
"""


class TestToolPatterns:
    def test_pattern_scopes_the_rule_to_matching_tools(self, tmp_path):
        gw = make_gateway(
            tmp_path, PATTERN_RULE, policy_text=policy_yaml(PATTERN_RULE, PATTERN_TOOL_POLICIES)
        )
        client = TestClient(create_gateway_app(gw))
        # db.query matches the pattern: a first failed call, then the rule
        # cuts the second (1 prior + this call = threshold 2)
        first = call(client, "db.query", {"q": 1}, session_id="p-1")
        assert first["decision"] == "deny"  # policy deny, receipted
        trip = call(client, "db.query", {"q": "ok"}, session_id="p-1")
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-pattern-loop"
        # web.fetch does not match: the rule never applies to it, even as
        # an unrecoverable loop
        for _ in range(3):
            body = call(client, "web.fetch", {"url": "u"}, session_id="p-2")
            assert body["decision"] == "allow", body


# ---------------------------------------------------------------------------
# fail-closed: malformed config, window-state faults
# ---------------------------------------------------------------------------


BAD_KIND_RULE = """
  - id: bad-rule
    kind: nonsense_kind
    threshold: 1
    window_seconds: 60
"""


class TestFailClosedConfig:
    def test_malformed_session_rule_denies_session_calls_with_named_reason(self, tmp_path):
        gw = make_gateway(tmp_path, BAD_KIND_RULE)
        client = TestClient(create_gateway_app(gw))
        body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-1")
        assert body["decision"] == "deny"
        assert "malformed" in body["reason"].lower()
        assert "bad-rule" in body["reason"]
        assert body["receipt_id"], "the fail-closed deny must be receipted"

    def test_malformed_config_does_not_touch_session_free_calls(self, tmp_path):
        """A session rule cannot fire without continuity: even a malformed
        config is skipped entirely for calls with no session_id."""
        gw = make_gateway(tmp_path, BAD_KIND_RULE)
        client = TestClient(create_gateway_app(gw))
        body = call(client, "lookup_balance", {"account": "ACC-001"})
        assert body["decision"] == "allow", body

    def test_rule_window_beyond_state_ttl_is_a_config_error(self, tmp_path):
        """A window wider than the retained state would silently
        undercount; the load refuses it as malformed instead."""
        wide = """
  - id: wide-window
    kind: repeated_deny_storm
    threshold: 2
    window_seconds: 3600
"""
        gw = make_gateway(tmp_path, wide, session_window_ttl_seconds=600)
        client = TestClient(create_gateway_app(gw))
        body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-1")
        assert body["decision"] == "deny"
        assert "wide-window" in body["reason"]

    def test_window_state_error_denies(self, tmp_path, monkeypatch):
        """A window-state error denies, never skips (fail-closed)."""
        gw = make_gateway(tmp_path, STORM_RULE)
        client = TestClient(create_gateway_app(gw))

        def _boom(*_args, **_kwargs):
            raise RuntimeError("window corrupted")

        monkeypatch.setattr(gw._session_windows, "entries", _boom)  # noqa: SLF001
        body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-1")
        assert body["decision"] == "deny"
        assert "session rule evaluation fault" in body["reason"]
        assert "RuntimeError" in body["reason"]
        assert "window corrupted" not in body["reason"]  # type only, never the message


# ---------------------------------------------------------------------------
# bounded keys through the real gateway
# ---------------------------------------------------------------------------


class TestBoundedStateThroughGateway:
    def test_keys_evicted_per_config(self, tmp_path):
        gw = make_gateway(tmp_path, "", session_window_max_keys=2)
        client = TestClient(create_gateway_app(gw))
        for session in ("s1", "s2", "s3"):
            body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id=session)
            assert body["decision"] == "allow"
        assert gw._session_windows.key_count() == 2  # noqa: SLF001
        assert gw._session_windows.entries("s1", "agent:svc") == []  # noqa: SLF001


# ---------------------------------------------------------------------------
# boot replay: the index is the durable authority for window state
# ---------------------------------------------------------------------------


class TestBootReplay:
    def test_replay_rebuilds_counts_from_the_index(self, tmp_path):
        """A restart mid-session does not silently reset counters: the new
        gateway rebuilds the window from the receipt index within the TTL
        window (the index is the durable authority, memory the fast path)."""
        config_shared = {
            "receipt_store": str(tmp_path / "receipts.jsonl"),
            "receipt_store_dir": str(tmp_path / "segments"),
            "receipt_index_path": str(tmp_path / "index.sqlite"),
        }
        gw_a = make_gateway(tmp_path, STORM_RULE, **config_shared)
        client_a = TestClient(create_gateway_app(gw_a))
        for _ in range(3):
            body = call(client_a, "lookup_balance", {"account": "ACC-999"}, session_id="replay-1")
            assert body["decision"] == "deny"
        # a FRESH gateway over the same store + index replays the session
        gw_b = make_gateway(tmp_path, STORM_RULE, **config_shared)
        client_b = TestClient(create_gateway_app(gw_b))
        trip = call(client_b, "lookup_balance", {"account": "ACC-001"}, session_id="replay-1")
        assert trip["decision"] == "deny"
        assert trip["rule_id"] == "sr-storm"
        assert "3" in trip["reason"]

    def test_replay_is_bounded_by_the_ttl_window(self, tmp_path):
        """Receipts older than the TTL window are not replayed: they are
        outside every configured rule window anyway."""
        config_shared = {
            "receipt_store": str(tmp_path / "receipts.jsonl"),
            "receipt_store_dir": str(tmp_path / "segments"),
            "receipt_index_path": str(tmp_path / "index.sqlite"),
        }
        gw_a = make_gateway(tmp_path, STORM_RULE, **config_shared)
        client_a = TestClient(create_gateway_app(gw_a))
        for session in ("fresh", "stale"):
            for _ in range(3):
                call(client_a, "lookup_balance", {"account": "ACC-999"}, session_id=session)
        conn = sqlite3.connect(config_shared["receipt_index_path"])
        conn.execute("UPDATE receipts SET iat = iat - 100000 WHERE session_id = 'stale'")
        conn.commit()
        conn.close()
        gw_b = make_gateway(tmp_path, STORM_RULE, **config_shared)
        client_b = TestClient(create_gateway_app(gw_b))
        assert (
            call(client_b, "lookup_balance", {"account": "ACC-001"}, session_id="fresh")["decision"]
            == "deny"
        )
        assert (
            call(client_b, "lookup_balance", {"account": "ACC-001"}, session_id="stale")["decision"]
            == "allow"
        )

    def test_replay_honest_residual_class_dimensions_undercount(self, tmp_path):
        """destination_class is not indexed (index v3), so replayed
        summaries carry no class: gradual_extraction undercounts after a
        restart. It can never fabricate a deny from partial data."""
        config_shared = {
            "receipt_store": str(tmp_path / "receipts.jsonl"),
            "receipt_store_dir": str(tmp_path / "segments"),
            "receipt_index_path": str(tmp_path / "index.sqlite"),
        }
        gw_a = make_gateway(tmp_path, EXTRACTION_RULE, **config_shared)
        client_a = TestClient(create_gateway_app(gw_a))
        for i in range(3):
            body = call(
                client_a,
                "web.fetch",
                {"url": f"http://ext.example/{i}"},
                session_id="class-replay",
                destination_class="external",
            )
            assert body["decision"] == "allow"
        gw_b = make_gateway(tmp_path, EXTRACTION_RULE, **config_shared)
        client_b = TestClient(create_gateway_app(gw_b))
        body = call(
            client_b,
            "web.fetch",
            {"url": "http://ext.example/4"},
            session_id="class-replay",
            destination_class="external",
        )
        assert body["decision"] == "allow"  # the documented residual


# ---------------------------------------------------------------------------
# tamper sealing: session rules ride the policy-bytes seal
# ---------------------------------------------------------------------------


class TestSessionRulesRideTheSeal:
    def test_out_of_band_session_rule_edit_denies_fail_closed(self, tmp_path):
        """Session rules live in the sealed policy file: an out-of-band edit
        trips the policy_tampered gate-entry check before any evaluation."""
        gw = make_gateway(tmp_path, STORM_RULE, policy_seal_file=str(tmp_path / "seal.json"))
        assert gw.seal_policy_bytes()["sealed"] is True
        client = TestClient(create_gateway_app(gw))
        body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-1")
        assert body["decision"] == "allow"
        # out-of-band edit of the session rule bytes
        policy = tmp_path / "policies.yaml"
        policy.write_text(policy_yaml(STORM_RULE.replace("threshold: 3", "threshold: 2")))
        body = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="run-1")
        assert body["decision"] == "deny"
        assert body["reason"].startswith("policy_tampered")


# ---------------------------------------------------------------------------
# ruleset_hash: a session-rule deny binds the session rule content
# ---------------------------------------------------------------------------


class TestRulesetHashBinding:
    def test_session_deny_receipt_binds_the_session_rule_digest(self, tmp_path):
        gw = make_gateway(tmp_path, STORM_RULE)
        client = TestClient(create_gateway_app(gw))
        for _ in range(3):
            call(client, "lookup_balance", {"account": "ACC-999"}, session_id="hash-1")
        trip = call(client, "lookup_balance", {"account": "ACC-001"}, session_id="hash-1")
        payload = envelope(gw, trip["receipt_id"])
        rule = gw._session_rules[0]  # noqa: SLF001
        assert payload["ruleset_hash"] == _sha256_hex(_canonical_json(rule.to_dict()))
        # and a policy deny on the SAME tool binds the tool rule digest, so
        # the two digests differ (the binding is decision-specific). The
        # policy deny runs in its own session: the storm stays fired in
        # hash-1, so its next call would be another session-rule deny.
        policy_deny = call(client, "lookup_balance", {"account": "ACC-999"}, session_id="hash-2")
        assert policy_deny["decision"] == "deny"
        deny_payload = envelope(gw, policy_deny["receipt_id"])
        assert deny_payload["ruleset_hash"] != payload["ruleset_hash"]
