"""EPIC O1: data-flow-aware policy rule kinds.

``deny_from_chain_taint`` denies a call whose destination class matches
whenever a prior tool output in the SAME task/delegation chain carries a
listed taint tag - evaluated against the replayed chain state,
deterministic, fail-closed (unknown taint tags / destination classes deny
with a named reason), and deny-only (never widens authority).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.policy import ChainTaintDeny, PolicyFile, evaluate_chain_taint_deny

VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "standards"
    / "test-vectors"
    / "dataflow_v1_01_taint_denies_destination.json"
)

# ---------------------------------------------------------------------------
# Policy DSL: parsing, validation, round-trip
# ---------------------------------------------------------------------------


def _policy_path(tmp_path: Path, data: dict[str, Any]) -> str:
    path = tmp_path / "policies.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return str(path)


def test_deny_from_chain_taint_parses(tmp_path: Path) -> None:
    path = _policy_path(
        tmp_path,
        {
            "version": 1,
            "issuer": "acme.bank",
            "policies": [
                {
                    "tool": "transfer_money",
                    "agent_id": "agent:pay",
                    "deny_from_chain_taint": {
                        "taint_tags": ["untrusted_user"],
                        "destination_classes": ["payment:external"],
                    },
                }
            ],
        },
    )
    policy = PolicyFile.load(path)
    deny = policy.policies[0].deny_from_chain_taint
    assert deny is not None
    assert deny.taint_tags == ["untrusted_user"]
    assert deny.destination_classes == ["payment:external"]
    assert deny.allow_destination_classes is None


def test_deny_from_chain_taint_yaml_round_trip(tmp_path: Path) -> None:
    path = _policy_path(
        tmp_path,
        {
            "version": 1,
            "issuer": "acme.bank",
            "policies": [
                {
                    "tool": "transfer_money",
                    "agent_id": "agent:pay",
                    "deny_from_chain_taint": {
                        "taint_tags": ["t1", "t2"],
                        "destination_classes": ["d1"],
                        "allow_destination_classes": ["internal:d1"],
                    },
                }
            ],
        },
    )
    policy = PolicyFile.load(path)
    as_yaml = policy.to_yaml()
    reloaded = PolicyFile.from_dict(yaml.safe_load(as_yaml))
    assert reloaded.policies[0].deny_from_chain_taint == policy.policies[0].deny_from_chain_taint


@pytest.mark.parametrize(
    "deny_body",
    [
        {"destination_classes": ["d1"]},  # no taint tags
        {"taint_tags": []},  # empty taint tags
        {"taint_tags": ["t"], "destination_classes": []},  # no class scope at all
        {"taint_tags": ["t"], "destination_classes": ["d1"], "allow_destination_classes": []},
        {"taint_tags": ["t"], "destination_classes": [""]},  # empty class string
        {"taint_tags": ["t"], "destination_classes": [3]},  # non-string class
    ],
)
def test_deny_from_chain_taint_load_fail_closed(tmp_path: Path, deny_body: dict) -> None:
    path = _policy_path(
        tmp_path,
        {
            "version": 1,
            "issuer": "acme.bank",
            "policies": [
                {
                    "tool": "transfer_money",
                    "agent_id": "agent:pay",
                    "deny_from_chain_taint": deny_body,
                }
            ],
        },
    )
    with pytest.raises(ValueError):
        PolicyFile.load(path)


# ---------------------------------------------------------------------------
# Pure evaluation: deterministic per-call semantics
# ---------------------------------------------------------------------------


def _deny() -> ChainTaintDeny:
    return ChainTaintDeny.from_dict(
        {"taint_tags": ["untrusted_user"], "destination_classes": ["payment:external"]}
    )


def test_acceptance_two_call_chain() -> None:
    """Backlog acceptance: call 1 output taint T, call 2 target D under
    'T denies D': call 2 denies while each call alone is allowed."""
    # Call 1 alone: no prior outputs - allowed.
    assert evaluate_chain_taint_deny(_deny(), [], "payment:internal") == ""
    # Call 2 has call 1's output in the chain: prior taint T + dest D -> deny
    # with a named reason.
    reason = evaluate_chain_taint_deny(
        _deny(), [{"tool": "fetch_document", "taint_tags": ["untrusted_user"]}], "payment:external"
    )
    assert "untrusted_user" in reason
    assert "payment:external" in reason
    assert reason.startswith("data-flow rule:")
    # Each call alone (fresh chain, no prior outputs) is allowed - even at D.
    assert evaluate_chain_taint_deny(_deny(), [], "payment:external") == ""


def test_evaluation_is_deterministic() -> None:
    chain = [{"tool": "fetch_document", "taint_tags": ["untrusted_user"]}]
    verdicts = {evaluate_chain_taint_deny(_deny(), chain, "payment:external") for _ in range(10)}
    assert len(verdicts) == 1
    assert list(verdicts)[0].startswith("data-flow rule:")


def test_deny_list_other_class_allows() -> None:
    chain = [{"tool": "fetch_document", "taint_tags": ["untrusted_user"]}]
    assert evaluate_chain_taint_deny(_deny(), chain, "payment:internal") == ""


def test_untainted_chain_allows_any_class() -> None:
    chain = [{"tool": "fetch_document", "taint_tags": []}]
    d = ChainTaintDeny.from_dict(
        {"taint_tags": ["untrusted_user"], "allow_destination_classes": ["internal:*"]}
    )
    assert evaluate_chain_taint_deny(d, chain, "anything") == ""
    assert evaluate_chain_taint_deny(d, chain, "") == ""


def test_allow_list_mode() -> None:
    d = ChainTaintDeny.from_dict(
        {"taint_tags": ["untrusted_user"], "allow_destination_classes": ["payment:internal"]}
    )
    chain = [{"tool": "fetch_document", "taint_tags": ["untrusted_user"]}]
    # Allow-listed destination stays allowed under a tainted chain.
    assert evaluate_chain_taint_deny(d, chain, "payment:internal") == ""
    # Everything else (including an unrecognised class) denies - allow-listing
    # is itself fail-closed.
    assert "not on data-flow allow-list" in evaluate_chain_taint_deny(d, chain, "email:external")


def test_unknown_destination_class_denies_when_tainted() -> None:
    chain = [{"tool": "fetch_document", "taint_tags": ["untrusted_user"]}]
    reason = evaluate_chain_taint_deny(_deny(), chain, "")
    assert "unknown destination class" in reason
    non_string_reason = evaluate_chain_taint_deny(_deny(), chain, 123)  # type: ignore[arg-type]
    assert "unknown destination class" in non_string_reason


def test_unknown_taint_tag_in_chain_denies_named() -> None:
    chain = [{"tool": "fetch_document", "taint_tags": [None]}]
    assert "unknown taint tag" in evaluate_chain_taint_deny(_deny(), chain, "payment:external")
    # Unusable tags deny even when the destination class is not in scope.
    assert (
        evaluate_chain_taint_deny(_deny(), chain, "anything")
        == "data-flow rule: unknown taint tag in chain state (fail-closed deny)"
    )


# ---------------------------------------------------------------------------
# Gateway enforcement: the real public surface
# ---------------------------------------------------------------------------


@pytest.fixture
def dataflow_policy(tmp_path: Path) -> str:
    data = {
        "version": 1,
        "issuer": "acme.bank",
        "policies": [
            {"tool": "fetch_document", "agent_id": "agent:reader", "ttl_seconds": 300},
            {
                "tool": "transfer_money",
                "agent_id": "agent:pay",
                "ttl_seconds": 300,
                "constraints": {"allow": {"from_account": ["ACC-001"], "to_account": ["ACC-002"]}},
                "deny_from_chain_taint": {
                    "taint_tags": ["untrusted_user"],
                    "destination_classes": ["payment:external"],
                },
            },
        ],
    }
    return _policy_path(tmp_path, data)


@pytest.fixture
def gateway(dataflow_policy: str, tmp_path: Path) -> RaucleGateway:
    config = GatewayConfig(
        policy_file=dataflow_policy,
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
    )
    return RaucleGateway(config)


def _call_transfer(
    gateway: RaucleGateway, trace_id: str, destination_class: str = "payment:external"
) -> dict[str, Any]:
    return gateway.check_tool_call(
        "transfer_money",
        {"from_account": "ACC-001", "to_account": "ACC-002"},
        agent_id="agent:pay",
        trace_id=trace_id,
        destination_class=destination_class,
    )


def test_gateway_acceptance_two_call_chain(gateway: RaucleGateway) -> None:
    trace = "task-chain-1"
    # Call 1: allowed on its own.
    first = gateway.check_tool_call("fetch_document", {"q": "a"}, trace_id=trace)
    assert first["decision"] == "allow"
    # Call 1's output comes back carrying taint T; recorded on the chain.
    gateway.record_chain_output(trace, "fetch_document", ["untrusted_user"])
    # Call 2: same chain, destination class D - DENIED while each call alone
    # is allowed.
    second = _call_transfer(gateway, trace)
    assert second["decision"] == "deny"
    assert second["rule_id"] == "transfer_money/agent:pay/1"
    assert "untrusted_user" in second["reason"]
    # A receipt exists for the data-flow deny (attributable).
    assert second["receipt_id"]
    # Same call WITHOUT the tainted prior output (fresh gateway, alone) allows.
    solo = RaucleGateway(gateway.config)
    assert _call_transfer(solo, "fresh-trace")["decision"] == "allow"


def test_gateway_dataflow_is_deterministic(gateway: RaucleGateway) -> None:
    def run() -> list[str]:
        trace = "determinism"
        gateway.clear_chain_state()
        decisions = [
            gateway.check_tool_call("fetch_document", {"q": "a"}, trace_id=trace)["decision"]
        ]
        gateway.record_chain_output(trace, "fetch_document", ["untrusted_user"])
        decisions.append(_call_transfer(gateway, trace)["decision"])
        decisions.append(_call_transfer(gateway, trace, "payment:internal")["decision"])
        return decisions

    assert run() == ["allow", "deny", "allow"] == run()


def test_gateway_composition_never_widens_authority(gateway: RaucleGateway) -> None:
    trace = "compose"
    gateway.record_chain_output(trace, "fetch_document", ["untrusted_user"])
    # Constraint deny still denies even when the data-flow rule would allow.
    outside = gateway.check_tool_call(
        "transfer_money",
        {"from_account": "ACC-999", "to_account": "ACC-002"},
        trace_id=trace,
        destination_class="payment:internal",
    )
    assert outside["decision"] == "deny"
    # An unconstrained class the rule does not cover stays within the token's
    # authority: data-flow adds no allowance of its own (denies only).
    covered = _call_transfer(gateway, trace)
    assert covered["decision"] == "deny"


def test_gateway_missing_trace_fails_closed(gateway: RaucleGateway) -> None:
    result = gateway.check_tool_call(
        "transfer_money",
        {"from_account": "ACC-001", "to_account": "ACC-002"},
        trace_id="",
        destination_class="payment:internal",
    )
    assert result["decision"] == "deny"
    assert "trace_id missing" in result["reason"]


def test_gateway_unknown_class_fails_closed_when_tainted(gateway: RaucleGateway) -> None:
    trace = "uc"
    gateway.record_chain_output(trace, "fetch_document", ["untrusted_user"])
    result = _call_transfer(gateway, trace, destination_class="")
    assert result["decision"] == "deny"
    assert "unknown destination class" in result["reason"]


def test_gateway_unknown_taint_tag_in_chain_fails_closed(gateway: RaucleGateway) -> None:
    trace = "ut"
    # The harness records an output whose tag is unusable (empty string).
    gateway.record_chain_output(trace, "fetch_document", [""])
    result = _call_transfer(gateway, trace, destination_class="payment:internal")
    assert result["decision"] == "deny"
    assert "unknown taint tag" in result["reason"]


def test_gateway_rules_without_the_kind_unchanged(tmp_path: Path) -> None:
    """Composes without changing per-call semantics of existing rules."""
    policy = _policy_path(
        tmp_path,
        {
            "version": 1,
            "issuer": "acme.bank",
            "policies": [
                {"tool": "fetch_document", "agent_id": "agent:reader"},
            ],
        },
    )
    config = GatewayConfig(
        policy_file=policy,
        receipt_store=str(tmp_path / "r.jsonl"),
        audit_chain=str(tmp_path / "a.jsonl"),
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    trace = "x"
    gateway.record_chain_output(trace, "fetch_document", ["untrusted_user"])
    assert (
        gateway.check_tool_call("fetch_document", {"q": "a"}, trace_id=trace, destination_class="")[
            "decision"
        ]
        == "allow"
    )


def test_gateway_http_destination_class(gateway: RaucleGateway) -> None:
    app = create_gateway_app(gateway)
    client = TestClient(app)
    trace = "http-trace"
    gateway.record_chain_output(trace, "fetch_document", ["untrusted_user"])
    resp = client.post(
        "/gate",
        headers={"X-Trace-Id": trace},
        json={
            "tool": "transfer_money",
            "args": {"from_account": "ACC-001", "to_account": "ACC-002"},
            "agent_id": "agent:pay",
            "trace_id": trace,
            "destination_class": "payment:external",
        },
    )
    body = resp.json()
    assert resp.status_code == 200
    assert body["decision"] == "deny"
    assert "untrusted_user" in body["reason"]
    # Deterministic: the same replay gives the same verdict via HTTP.
    resp2 = client.post(
        "/gate",
        headers={"X-Trace-Id": trace},
        json={
            "tool": "transfer_money",
            "args": {"from_account": "ACC-001", "to_account": "ACC-002"},
            "agent_id": "agent:pay",
            "trace_id": trace,
            "destination_class": "payment:external",
        },
    )
    assert resp2.json()["decision"] == "deny"


# ---------------------------------------------------------------------------
# Corpus vector: the acceptance scenario replayed from JSON
# ---------------------------------------------------------------------------


def test_corpus_vector_replays() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    deny = vector["rule"]["deny_from_chain_taint"]
    rule = ChainTaintDeny.from_dict(deny)
    decisions = vector["decisions"]
    chain_state: list[dict[str, Any]] = []
    # Replay: call 1 (allow, records its output taint), call 2 (deny).
    step1 = vector["calls"][0]
    assert evaluate_chain_taint_deny(rule, chain_state, step1["destination_class"]) == ""
    chain_state.append(step1["output"])
    step2 = vector["calls"][1]
    reason = evaluate_chain_taint_deny(rule, chain_state, step2["destination_class"])
    assert reason == decisions[1]["reason"]
    # Solo replay (fresh chain state) allows call 2 again.
    assert evaluate_chain_taint_deny(rule, [], step2["destination_class"]) == ""
