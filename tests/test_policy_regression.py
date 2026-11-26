"""Consumer policy regression runner: exact policy binding and bounded reports."""

import hashlib
import json

import pytest

import raucle.policy_regression as policy_regression
from raucle.policy_regression import (
    MAX_INPUT_BYTES,
    RegressionExecutionError,
    RegressionInputError,
    _error_report,
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
    assert report["engine_version"]
    assert report["dependency_versions"]["raucle"] == report["engine_version"]
    assert {
        "PyYAML",
        "cryptography",
        "cffi",
        "pycparser",
    }.issubset(report["dependency_versions"])
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


def test_error_report_preserves_manifest_boundaries_and_completed_scenarios():
    completed = [
        {
            "suite_id": "consumer-policy-v1",
            "scenario_id": "first",
            "tool": "lookup_balance",
            "expected": "allow",
            "actual": "allow",
            "passed": True,
        }
    ]
    dependency_versions = {
        "raucle": "test-engine-version",
        "PyYAML": "6.0.2",
        "cryptography": "48.0.0",
        "cffi": "2.1.1",
        "pycparser": "3.12",
    }
    report = _error_report(
        "a" * 40,
        "engine_error",
        completed,
        policy_sha256=hashlib.sha256(POLICY_A).hexdigest(),
        scenarios_sha256=hashlib.sha256(SCENARIOS).hexdigest(),
        engine_version="test-engine-version",
        dependency_versions=dependency_versions,
    )
    assert report["status"] == "error"
    assert report["error_code"] == "engine_error"
    assert report["executed"] == completed
    assert report["skipped"] == []
    assert report["unsupported_suites"]
    assert report["suite_manifest_sha256"]

def test_partial_execution_error_report_binds_exact_inputs_and_dependencies(monkeypatch):
    from raucle.gateway import RaucleGateway

    original = RaucleGateway.check_tool_call
    calls = 0

    def fail_second_call(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic engine failure")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(RaucleGateway, "check_tool_call", fail_second_call)
    with pytest.raises(RegressionExecutionError) as caught:
        run_regression(POLICY_A, SCENARIOS)

    error = caught.value
    assert len(error.results) == 1
    assert error.policy_sha256 == hashlib.sha256(POLICY_A).hexdigest()
    assert error.scenarios_sha256 == hashlib.sha256(SCENARIOS).hexdigest()
    assert error.engine_version
    assert error.dependency_versions["cryptography"]


@pytest.mark.parametrize(
    ("scenario", "error_code"),
    [
        (None, "scenario_0_invalid_fields"),
        ({"id": " ", "tool": "t", "agent_id": "a", "args": {}, "expected": "allow"}, "scenario_0_invalid_id"),
        ({"id": "x", "tool": " ", "agent_id": "a", "args": {}, "expected": "allow"}, "scenario_0_invalid_tool"),
        ({"id": "x", "tool": "t", "agent_id": " ", "args": {}, "expected": "allow"}, "scenario_0_invalid_agent_id"),
        ({"id": "x", "tool": "t", "agent_id": "a", "args": [], "expected": "allow"}, "scenario_0_invalid_args"),
        ({"id": "x", "tool": "t", "agent_id": "a", "args": {}, "expected": "allow", "source": 1}, "scenario_0_invalid_source"),
        ({"id": "x", "tool": "t", "agent_id": "a", "args": {}, "expected": "allow", "destination": 1}, "scenario_0_invalid_destination"),
    ],
)
def test_scenario_validation_rejects_each_invalid_field(scenario, error_code):
    raw = json.dumps({"version": 1, "scenarios": [scenario]}).encode()
    with pytest.raises(RegressionInputError, match=error_code):
        policy_regression._parse_scenarios(raw)


@pytest.mark.parametrize(
    ("raw", "error_code"),
    [
        (b"not-json", "scenarios_invalid_json"),
        (b"[]", "scenarios_unsupported_version"),
        (b'{"version":1,"scenarios":null}', "scenarios_required"),
    ],
)
def test_scenario_validation_rejects_invalid_document(raw, error_code):
    with pytest.raises(RegressionInputError, match=error_code):
        policy_regression._parse_scenarios(raw)


def test_scenario_count_is_bounded():
    raw = json.dumps(
        {
            "version": 1,
            "scenarios": [
                {
                    "id": str(index),
                    "tool": "t",
                    "agent_id": "a",
                    "args": {},
                    "expected": "allow",
                }
                for index in range(policy_regression.MAX_SCENARIOS + 1)
            ],
        }
    ).encode()
    with pytest.raises(RegressionInputError, match="scenarios_too_many"):
        policy_regression._parse_scenarios(raw)


def test_error_report_keeps_input_bindings_if_suite_manifest_is_unavailable(monkeypatch):
    def unavailable():
        raise RuntimeError("manifest unavailable")

    monkeypatch.setattr(policy_regression, "_load_suite_manifest", unavailable)
    report = _error_report(
        "a" * 40,
        "engine_error",
        [],
        policy_sha256=hashlib.sha256(POLICY_A).hexdigest(),
        scenarios_sha256=hashlib.sha256(SCENARIOS).hexdigest(),
    )
    assert report["policy_sha256"] == hashlib.sha256(POLICY_A).hexdigest()
    assert report["scenarios_sha256"] == hashlib.sha256(SCENARIOS).hexdigest()
    assert "unsupported_suites" not in report


def test_cli_success_writes_machine_report(tmp_path, monkeypatch):
    policy_file = tmp_path / "policy.yaml"
    scenarios_file = tmp_path / "scenarios.json"
    report_file = tmp_path / "nested" / "report.json"
    policy_file.write_bytes(POLICY_A)
    scenarios_file.write_bytes(SCENARIOS)
    monkeypatch.setattr(
        policy_regression,
        "run_regression",
        lambda *args, **kwargs: {
            "status": "passed",
            "summary": {"passed": 1, "total": 1},
            "policy_sha256": hashlib.sha256(POLICY_A).hexdigest(),
        },
    )
    result = policy_regression.main(
        [
            "--policy",
            str(policy_file),
            "--scenarios",
            str(scenarios_file),
            "--output",
            str(report_file),
        ]
    )
    assert result == 0
    assert json.loads(report_file.read_text())["status"] == "passed"


def test_cli_refusal_writes_error_report(tmp_path, monkeypatch):
    policy_file = tmp_path / "policy.yaml"
    scenarios_file = tmp_path / "scenarios.json"
    report_file = tmp_path / "report.json"
    policy_file.write_bytes(POLICY_A)
    scenarios_file.write_bytes(SCENARIOS)

    def refuse(*args, **kwargs):
        raise RegressionInputError("policy_invalid")

    monkeypatch.setattr(policy_regression, "_read_bounded", lambda path, label: POLICY_A)
    monkeypatch.setattr(policy_regression, "run_regression", refuse)
    result = policy_regression.main(
        ["--policy", str(policy_file), "--scenarios", str(scenarios_file), "--output", str(report_file)]
    )
    assert result == 2
    assert json.loads(report_file.read_text())["error_code"] == "policy_invalid"


def test_cli_engine_error_preserves_partial_hashes(tmp_path, monkeypatch):
    policy_file = tmp_path / "policy.yaml"
    scenarios_file = tmp_path / "scenarios.json"
    report_file = tmp_path / "report.json"
    policy_file.write_bytes(POLICY_A)
    scenarios_file.write_bytes(SCENARIOS)
    partial = [
        {
            "suite_id": "consumer-policy-v1",
            "scenario_id": "allowed-account",
            "tool": "lookup_balance",
            "expected": "allow",
            "actual": "allow",
            "passed": True,
        }
    ]

    def fail(*args, **kwargs):
        raise RegressionExecutionError(
            partial,
            policy_sha256=hashlib.sha256(POLICY_A).hexdigest(),
            scenarios_sha256=hashlib.sha256(SCENARIOS).hexdigest(),
            engine_version="0.23.9",
            dependency_versions={"cryptography": "48.0.0"},
        )

    monkeypatch.setattr(policy_regression, "_read_bounded", lambda path, label: POLICY_A)
    monkeypatch.setattr(policy_regression, "run_regression", fail)
    result = policy_regression.main(
        ["--policy", str(policy_file), "--scenarios", str(scenarios_file), "--output", str(report_file)]
    )
    report = json.loads(report_file.read_text())
    assert result == 2
    assert report["executed"] == partial
    assert report["policy_sha256"] == hashlib.sha256(POLICY_A).hexdigest()
    assert report["scenarios_sha256"] == hashlib.sha256(SCENARIOS).hexdigest()

