"""Consumer policy regression runner: exact policy binding and bounded reports."""

import hashlib
import json

import pytest

from raucle.policy_regression import (
    MAX_INPUT_BYTES,
    RegressionInputError,
    _read_bounded,
    run_regression,
)

POLICY_A = b"""version: 1
issuer: regression.test
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""

POLICY_B = b"""version: 1
issuer: regression.test
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-002"]
"""

SCENARIOS = json.dumps(
    {
        "version": 1,
        "scenarios": [
            {
                "id": "allowed-account",
                "tool": "lookup_balance",
                "agent_id": "agent:svc",
                "args": {"account": "ACC-001"},
                "expected": "allow",
            },
            {
                "id": "unlisted-account",
                "tool": "lookup_balance",
                "agent_id": "agent:svc",
                "args": {"account": "SENSITIVE-ACCOUNT-999"},
                "expected": "deny",
            },
        ],
    },
    separators=(",", ":"),
).encode()


def test_consumer_scenarios_run_against_exact_policy_bytes():
    report = run_regression(POLICY_A, SCENARIOS)
    assert report["status"] == "passed"
    assert report["policy_sha256"] == hashlib.sha256(POLICY_A).hexdigest()
    assert report["scenarios_sha256"] == hashlib.sha256(SCENARIOS).hexdigest()
    assert report["summary"] == {"total": 2, "passed": 2, "failed": 0}
    assert [row["actual"] for row in report["executed"]] == ["allow", "deny"]
    assert report["engine_commit"] == "unavailable"
    assert report["suite_manifest_sha256"]
    assert report["unsupported_suites"]


def test_changed_policy_bytes_change_hash_and_outcome():
    first = run_regression(POLICY_A, SCENARIOS)
    second = run_regression(POLICY_B, SCENARIOS)
    assert first["policy_sha256"] != second["policy_sha256"]
    assert first["executed"][0]["actual"] == "allow"
    assert second["executed"][0]["actual"] == "deny"
    assert second["status"] == "failed"


def test_report_does_not_include_argument_values_or_free_text_reasons():
    report = run_regression(POLICY_A, SCENARIOS)
    rendered = json.dumps(report)
    assert "SENSITIVE-ACCOUNT-999" not in rendered
    assert all("reason" not in row for row in report["executed"])


@pytest.mark.parametrize(
    "scenarios",
    [
        b'{"version":2,"scenarios":[]}',
        b'{"version":1,"scenarios":[]}',
        b'{"version":1,"scenarios":[{"id":"x","tool":"t","agent_id":"agent:a","args":{},"expected":"allow","extra":true}]}',
        b'{"version":1,"scenarios":[{"id":"x","tool":"t","agent_id":"agent:a","args":{},"expected":"maybe"}]}',
        b'{"version":1,"scenarios":[{"id":"x","tool":"t","agent_id":"agent:a","args":{},"expected":"allow"},{"id":"x","tool":"t","agent_id":"agent:a","args":{},"expected":"allow"}]}',
        b'{"version":1,"scenarios":[{"id":"x","tool":"t","agent_id":"agent:a","args":NaN,"expected":"allow"}]}',
    ],
)
def test_malformed_scenario_documents_fail_closed(scenarios):
    with pytest.raises(RegressionInputError):
        run_regression(POLICY_A, scenarios)


def test_invalid_policy_fails_closed():
    with pytest.raises(RegressionInputError, match="policy_invalid"):
        run_regression(b"version: 1\npolicies: [broken", SCENARIOS)


def test_empty_policy_fails_closed():
    with pytest.raises(RegressionInputError, match="policy_invalid"):
        run_regression(b"version: 1\nissuer: empty.test\npolicies: []\n", SCENARIOS)


POLICY_ESCALATE = b"""version: 1
issuer: regression.test
policies:
  - tool: transfer_money
    agent_id: agent:pay
    ttl_seconds: 60
    constraints:
      allow:
        from_account: ["ACC-001"]
        to_account: ["ACC-002"]
      max:
        amount: 10000
    require_approval_when:
      amount_gt: 5000
"""


def test_escalate_decision_is_supported():
    scenarios = json.dumps(
        {
            "version": 1,
            "scenarios": [
                {
                    "id": "high-value-transfer",
                    "tool": "transfer_money",
                    "agent_id": "agent:pay",
                    "args": {
                        "from_account": "ACC-001",
                        "to_account": "ACC-002",
                        "amount": 7500,
                    },
                    "expected": "escalate",
                }
            ],
        }
    ).encode()
    report = run_regression(POLICY_ESCALATE, scenarios, engine_commit="a" * 40)
    assert report["status"] == "passed"
    assert report["engine_commit"] == "a" * 40
    assert report["executed"][0]["actual"] == "escalate"


def test_invalid_engine_commit_refuses():
    with pytest.raises(RegressionInputError, match="engine_commit_invalid"):
        run_regression(POLICY_A, SCENARIOS, engine_commit="main")


def test_read_bounded_refuses_missing_empty_directory_and_oversized(tmp_path):
    with pytest.raises(RegressionInputError, match="policy_not_a_file"):
        _read_bounded(tmp_path / "missing.yaml", "policy")
    empty = tmp_path / "empty.yaml"
    empty.write_bytes(b"")
    with pytest.raises(RegressionInputError, match="policy_empty"):
        _read_bounded(empty, "policy")
    with pytest.raises(RegressionInputError, match="policy_not_a_file"):
        _read_bounded(tmp_path, "policy")
    oversized = tmp_path / "oversized.yaml"
    oversized.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
    with pytest.raises(RegressionInputError, match="policy_too_large"):
        _read_bounded(oversized, "policy")
