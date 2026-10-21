"""The public live-pulse endpoint must carry aggregates only.

The login screen's field counter reads /api/live-pulse without credentials,
so the endpoint must expose no per-agent, per-tool or payload detail under
any circumstance, and must report the same totals the authenticated
dashboard shows.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app

POLICY = """
version: 1
issuer: pulse.test
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""

PAYLOAD = {
    "tool": "lookup_balance",
    "args": {"account": "ACC-001"},
    "agent_id": "agent:svc",
    "source": "agent:svc",
    "destination": "banking-core",
}


@pytest.fixture()
def gw(tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
    )
    return RaucleGateway(config)


@pytest.fixture()
def client(gw) -> TestClient:
    return TestClient(create_gateway_app(gw))


def _gate(client: TestClient, n: int) -> None:
    for _ in range(n):
        resp = client.post("/gate", json=PAYLOAD)
        assert resp.status_code == 200


def test_pulse_keys_are_aggregate_only(client: TestClient) -> None:
    resp = client.get("/api/live-pulse")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) <= {"live", "rpm_1m", "uptime_s", "avg_latency_us", "totals"}
    assert set(body["totals"].keys()) == {"requests", "allowed", "denied", "escalated"}
    text = resp.text
    assert "agent:" not in text
    assert "lookup_balance" not in text


def test_pulse_counts_follow_real_traffic(client: TestClient) -> None:
    _gate(client, 40)
    first = client.get("/api/live-pulse").json()
    assert first["totals"]["requests"] == 40
    time.sleep(1.3)
    _gate(client, 40)
    second = client.get("/api/live-pulse").json()
    assert second["totals"]["requests"] == 80
    assert second["rpm_1m"] > 0
    assert second["totals"]["allowed"] == 80


def test_pulse_rate_estimate_converges_from_deltas(client: TestClient) -> None:
    first = client.get("/api/live-pulse").json()  # seeds the window
    _gate(client, 120)
    time.sleep(1.3)
    body = client.get("/api/live-pulse").json()
    # 120 calls inside a ~1s poll window projects to thousands per minute,
    # and the endpoint must report that projection without inventing detail
    assert body["totals"]["requests"] > first["totals"]["requests"]
    assert body["rpm_1m"] > 60
    assert body["uptime_s"] >= 0
