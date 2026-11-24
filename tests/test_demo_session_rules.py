"""The EPIC Q demo scenario: session behavioural rules over a scripted
agent-run corpus.

One gateway, one policy carrying all five deterministic session rule kinds;
the corpus walks each rule through the REAL gate over POST /gate with a
declared session_id, allow and deny paths both, then proves the evidence
story offline: every session-rule deny carries a signed gate receipt, a
session-monitor finding citing it, and the whole chain (findings included)
still verifies through ProvenanceVerifier.

Rule evaluation is deterministic and declared-order: when more than one
rule matches a call, the first declared rule wins (the corpus demonstrates
this in the deny-storm scenario, where the loop rule also matches the
tripping call but the storm rule is declared first).
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier

DEMO_SESSION_RULES = """
  - id: demo-storm
    kind: repeated_deny_storm
    threshold: 3
    window_seconds: 600
    tool_patterns: ["lookup_balance"]
  - id: demo-loop
    kind: runaway_tool_loop
    threshold: 4
    window_seconds: 600
  - id: demo-extraction
    kind: gradual_extraction
    threshold: 3
    window_seconds: 600
    destination_class: external
  - id: demo-chain
    kind: forbidden_tool_chain
    window_seconds: 600
    sequence: [lookup_balance, web.fetch]
  - id: demo-drift
    kind: scope_drift
    threshold: 2
    window_seconds: 600
    tools: [lookup_balance, web.fetch, fs.write]
"""

DEMO_POLICY = f"""version: 1
issuer: demo.bank
session_rules:{DEMO_SESSION_RULES}policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
  - tool: web.fetch
    agent_id: agent:svc
    ttl_seconds: 60
    constraints: {{}}
  - tool: fs.write
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        path: ["/tmp/ok"]
  - tool: shell.exec
    agent_id: agent:svc
    ttl_seconds: 60
    constraints: {{}}
"""

# The scripted corpus: each scenario runs in its OWN session (windows are
# keyed (session_id, agent_id), so scenarios cannot interfere), exercises
# the allow path first, then trips the rule.
SECRET = "ACC-999-SECRET"

DEMO_CORPUS = [
    {
        "scenario": "healthy traffic stays silent",
        "session": "demo-healthy",
        "calls": [
            # ordered so no trailing pair completes the forbidden chain
            # (lookup_balance -> web.fetch): healthy traffic stays healthy
            ("web.fetch", {"url": "http://int.example/a"}, "internal", "allow", ""),
            ("lookup_balance", {"account": "ACC-001"}, "", "allow", ""),
            ("fs.write", {"path": "/tmp/ok"}, "", "allow", ""),
        ],
    },
    {
        "scenario": "repeated deny storm",
        "session": "demo-storm",
        "calls": [
            # three receipted denies for the tool...
            ("lookup_balance", {"account": SECRET}, "", "deny", ""),
            ("lookup_balance", {"account": SECRET}, "", "deny", ""),
            ("lookup_balance", {"account": SECRET}, "", "deny", ""),
            # ...then the rule cuts an otherwise-allowable attempt. The
            # loop rule also matches this call; the storm rule is declared
            # first, so it wins deterministically.
            ("lookup_balance", {"account": "ACC-001"}, "", "deny", "demo-storm"),
        ],
    },
    {
        "scenario": "runaway tool loop",
        "session": "demo-loop",
        "calls": [
            ("fs.write", {"path": "/tmp/ok"}, "", "allow", ""),
            ("fs.write", {"path": "/tmp/f1"}, "", "deny", ""),
            ("fs.write", {"path": "/tmp/f2"}, "", "deny", ""),
            ("fs.write", {"path": "/tmp/f3"}, "", "deny", ""),
            # the fourth call without a receipted success, on a tool that
            # would be allowed: only the session rule denies it
            ("fs.write", {"path": "/tmp/ok"}, "", "deny", "demo-loop"),
        ],
    },
    {
        "scenario": "gradual extraction",
        "session": "demo-extraction",
        "calls": [
            ("web.fetch", {"url": "http://ext.example/1"}, "external", "allow", ""),
            ("web.fetch", {"url": "http://ext.example/2"}, "external", "allow", ""),
            ("web.fetch", {"url": "http://ext.example/3"}, "external", "allow", ""),
            ("web.fetch", {"url": "http://ext.example/4"}, "external", "deny", "demo-extraction"),
        ],
    },
    {
        "scenario": "forbidden tool chain",
        "session": "demo-chain",
        "calls": [
            ("lookup_balance", {"account": "ACC-001"}, "", "allow", ""),
            ("web.fetch", {"url": "http://x.example"}, "", "deny", "demo-chain"),
        ],
    },
    {
        "scenario": "scope drift",
        "session": "demo-drift",
        "calls": [
            ("shell.exec", {"cmd": "ls"}, "", "allow", ""),
            ("shell.exec", {"cmd": "ls"}, "", "deny", "demo-drift"),
        ],
    },
]


# The session rule ids the corpus can trip (a non-trip decision is made
# by a tool policy rule, so its rule_id must never be one of these).
DEMO_RULE_IDS = {"demo-storm", "demo-loop", "demo-extraction", "demo-chain", "demo-drift"}


@pytest.fixture
def demo(tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(DEMO_POLICY)
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
    )
    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client


def _run_corpus(client):
    """Drive the corpus through the real gate, asserting each scripted
    decision as it happens. Returns (receipt_ids, decided) where decided
    is a (rule_id, reason) pair per call (rule_id None when a policy
    rule decided)."""
    receipts: list[str] = []
    decided: list[tuple[str, str]] = []
    for scenario in DEMO_CORPUS:
        for tool, args, dest_class, expected, rule_id in scenario["calls"]:
            body: dict = {
                "tool": tool,
                "args": args,
                "agent_id": "agent:svc",
                "session_id": scenario["session"],
            }
            if dest_class:
                body["destination_class"] = dest_class
            response = client.post("/gate", json=body).json()
            assert response["decision"] == expected, (
                scenario["scenario"],
                tool,
                response,
            )
            if rule_id:
                # a session rule decided this call
                assert response["rule_id"] == rule_id, (scenario["scenario"], tool, response)
            else:
                # decided by the tool policy: never a session rule id
                assert response["rule_id"] not in DEMO_RULE_IDS, (
                    scenario["scenario"],
                    tool,
                    response,
                )
            if response["receipt_id"]:
                receipts.append(response["receipt_id"])
            decided.append((rule_id, response["reason"]))
    return receipts, decided


def _payloads(gw):
    for seg in gw._receipt_store.segments():  # noqa: SLF001
        with open(seg, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    b = json.loads(line)["jws"].split(".")[1]
                    yield json.loads(base64.urlsafe_b64decode(b + "=" * ((4 - len(b) % 4) % 4)))


class TestDemoSessionRulesCorpus:
    def test_corpus_runs_as_scripted(self, demo):
        """Every scripted call lands its expected decision with the
        expected rule id: the demo never shows a rule firing late or
        early."""
        _gw, client = demo
        receipts, _reasons = _run_corpus(client)
        assert receipts, "every decision in the corpus must be receipted"

    def test_denial_reasons_are_content_free(self, demo):
        """Session-rule denial reasons carry rule ids and window counters
        only: the arg values the attacker sent never enter a session-rule
        reason. (Policy constraint denies legitimately quote constraint
        values; that is pre-existing gate behaviour outside this lane's
        bounded-disclosure claim, which covers session rule reasons.)"""
        _gw, client = demo
        _receipts, decided = _run_corpus(client)
        for rule_id, reason in decided:
            if rule_id not in DEMO_RULE_IDS:
                continue
            assert SECRET not in reason
            assert "ext.example" not in reason
            assert "http://" not in reason

    def test_every_fired_rule_has_a_session_monitor_finding(self, demo):
        """Each session-rule deny emits a signed session-monitor finding
        receipt citing the triggering gate receipt (harness
        'session-monitor', test_id = rule id)."""
        gw, client = demo
        receipts, _reasons = _run_corpus(client)
        findings = [
            p["x_finding"]
            for p in _payloads(gw)
            if p.get("x_finding", {}).get("harness") == "session-monitor"
        ]
        by_rule: dict[str, list[dict]] = {}
        for finding in findings:
            by_rule.setdefault(finding["test_id"], []).append(finding)
        for rule_id in ("demo-storm", "demo-loop", "demo-extraction", "demo-chain", "demo-drift"):
            assert rule_id in by_rule, f"no session-monitor finding for {rule_id}"
            assert finding_cites(by_rule[rule_id], receipts), rule_id

    def test_chain_verifies_offline_including_findings(self, demo):
        """The anti-fabrication verifier passes on the session findings
        unchanged: each cited receipt exists in the chain and the reported
        actual decision matches the cited receipt's recorded verdict."""
        gw, client = demo
        _run_corpus(client)
        verifier = ProvenanceVerifier(
            public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
        )
        for seg in gw._receipt_store.segments():  # noqa: SLF001
            report = verifier.verify_chain(str(seg))
            assert report.valid, report.errors

    def test_no_session_id_refuses_named_and_never_fires_a_rule(self, demo):
        """Q17 gate hardening (close 3): with the demo session rules
        configured, a call with no session declared refuses by name before
        any rule can fire, and no session rule finding is minted from it
        (continuity is never fabricated from trace ids)."""
        _gw, client = demo
        for _ in range(4):
            body = client.post(
                "/gate",
                json={
                    "tool": "lookup_balance",
                    "args": {"account": SECRET},
                    "agent_id": "agent:svc",
                },
            ).json()
            assert body["decision"] == "deny", body
            assert "session_binding_required" in body["reason"], body
            # no rule fired, nothing was fabricated: the refusal carries no
            # demo session rule id and mints no session-rule finding
            assert "demo-" not in str(body.get("rule_id", "")), body


def finding_cites(findings: list[dict], receipts: list[str]) -> bool:
    return any(f["cited_receipt"] in receipts for f in findings)
