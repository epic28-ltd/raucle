"""Final coverage-gap round: learning mode, MFA, SIEM senders, server endpoints.

Fills the behavioural gaps that remained after the CLI harness, RED
regressions, and integrations-contract rounds:

- Gateway learn mode (`RAUCLE_LEARN_MODE`): observe unmatched calls,
  aggregate, draft policy, clear.
- UserManager MFA lifecycle (setup/verify/verify_totp/disable) and expiry.
- SIEM senders (Azure Log Analytics shape).
- REST server endpoints the suite hadn't driven: batch cap, output scan,
  verdict-receipt verification, outcome classification, audit/SSE streaming
  helpers.
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")


from raucle.gateway import GatewayConfig, RaucleGateway, UserManager  # noqa: E402

# ---------------------------------------------------------------------------
# UserManager MFA + user lifecycle
# ---------------------------------------------------------------------------


def test_usermanager_mfa_lifecycle(tmp_path):
    users = UserManager()
    users.add_user("u-key", "operator", "Op")
    setup = users.setup_mfa("u-key")
    assert setup
    assert set(setup) >= {"secret", "uri"}
    code = pytest.importorskip("pyotp").TOTP(setup["secret"]).now()
    assert users.verify_totp(users.get_user("u-key"), code) is True
    assert users.verify_mfa("u-key", "000000") is False
    assert users.verify_mfa("u-key", code) is True  # valid code enables MFA
    assert users.disable_mfa("u-key") is True
    assert users.get_user("u-key").mfa_enabled is False
    assert users.setup_mfa("missing-key") is None
    assert users.disable_mfa("missing-key") is False
    assert users.remove_user("u-key") is True
    assert users.remove_user("u-key") is False
    assert users.get_user("u-key") is None


def test_usermanager_expired_user_returns_none(tmp_path):
    users = UserManager()
    users.add_user("u-key", "operator", "Op")
    user = users.get_user("u-key")
    user.expires_at = 1  # long past
    assert users.get_user("u-key") is None


# ---------------------------------------------------------------------------
# SIEM: Azure Log Analytics sender
# ---------------------------------------------------------------------------


def _azure_forwarder(monkeypatch):
    from raucle.gateway import SIEMForwarder

    config = GatewayConfig(
        siem_enabled=True,
        siem_backend="sentinel",
        siem_url="",
        siem_token="",
    )
    return SIEMForwarder(config)


def test_azure_siem_sends_when_configured(monkeypatch):
    import base64
    import hashlib
    import hmac as _hmac

    shared_key = base64.b64encode(b"k" * 32).decode()
    monkeypatch.setenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "ws-123")
    monkeypatch.setenv("AZURE_LOG_ANALYTICS_SHARED_KEY", shared_key)
    sent: list[tuple[str, dict]] = []
    event = {"decision": "DENY", "tool": "t"}

    class _FakeRequests:
        @staticmethod
        def post(url, data=None, headers=None, timeout=None):
            sent.append((url, headers))
            return None

    monkeypatch.setitem(sys.modules, "requests", _FakeRequests)
    _azure_forwarder(monkeypatch).forward(event)
    assert sent, "expected a Log Analytics post"
    url, headers = sent[0]
    assert "ods.opinsights.azure.com" in url
    auth = headers["Authorization"]
    assert auth.startswith("SharedKey ws-123:")
    sig = auth.split(":", 1)[1]
    date = headers["x-ms-date"]
    string_to_sign = f"POST\n{len(json.dumps(event))}\napplication/json\n{date}/api/logs"
    expected = base64.b64encode(
        _hmac.new(base64.b64decode(shared_key), string_to_sign.encode(), hashlib.sha256).digest()
    ).decode()
    assert sig == expected


def test_azure_siem_noop_without_creds(monkeypatch):
    monkeypatch.delenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID", raising=False)
    monkeypatch.delenv("AZURE_LOG_ANALYTICS_SHARED_KEY", raising=False)
    sent: list = []

    class _FakeRequests:
        @staticmethod
        def post(*a, **k):  # pragma: no cover - must not be called
            sent.append(1)

    monkeypatch.setitem(sys.modules, "requests", _FakeRequests)
    _azure_forwarder(monkeypatch).forward({"decision": "DENY"})
    assert not sent


# ---------------------------------------------------------------------------
# Learning mode
# ---------------------------------------------------------------------------


@pytest.fixture
def learn_gateway(tmp_path) -> RaucleGateway:
    policy = tmp_path / "policies.yaml"
    policy.write_text(
        "version: 1\nissuer: test.bank\npolicies:\n  - tool: known_tool\n"
        "    agent_id: agent:svc\n    ttl_seconds: 60\n    constraints:\n"
        "      allow:\n        account: ['ACC-001']\n",
        encoding="utf-8",
    )
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_backend="local",
        learn_mode=True,
    )
    return RaucleGateway(config)


def test_learn_mode_observes_and_drafts(learn_gateway):
    gateway = learn_gateway
    for account in ("ACC-001", "ACC-002"):
        gateway.check_tool_call(
            "unknown_tool",
            {"account": account, "retries": 3},
            "agent:learner",
            source="src",
            destination="dst",
            trace_id="t",
        )
    summary = gateway.learn_summary()
    assert summary["learn_mode"] is True
    assert summary["tools"]["unknown_tool"]["calls"] == 2
    draft = gateway.draft_policy()
    assert "unknown_tool" in draft
    gateway._learn_clear()  # noqa: SLF001 - exercising the reset contract
    assert gateway.learn_summary()["tools"] == {}


def test_learn_mode_off_records_nothing(tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text("version: 1\nissuer: test.bank\npolicies: []\n", encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    gateway.check_tool_call(
        "other_tool", {"x": 1}, "agent:x", source="", destination="", trace_id="t"
    )
    assert gateway.learn_summary()["tools"] == {}


# ---------------------------------------------------------------------------
# REST server endpoints
# ---------------------------------------------------------------------------


def _server(monkeypatch):
    for key in ("RAUCLE_DETECT_API_KEY", "RAUCLE_DETECT_RATE_LIMIT", "RAUCLE_DETECT_BURST_LIMIT"):
        monkeypatch.delenv(key, raising=False)
    sys.modules.pop("raucle.server", None)
    return importlib.import_module("raucle.server")


def test_server_batch_cap_rejects(monkeypatch):
    server = _server(monkeypatch)
    with pytest.raises(ValidationError) as excinfo:
        server.BatchScanRequest(prompts=["x"] * 1001)
    assert "1000" in str(getattr(excinfo.value, "detail", excinfo.value))


def test_server_verify_receipt_endpoint(monkeypatch, tmp_path):
    from raucle.verdicts import VerdictSigner

    signer = VerdictSigner.generate()
    receipt = signer.issue(
        input_text="hello world",
        verdict="MALICIOUS",
        confidence=0.9,
        ruleset_hash="ab" * 32,
    )
    server = _server(monkeypatch)
    body = server.verify_receipt(
        server.VerifyReceiptRequest(
            receipt=receipt, public_key_pem=signer.public_key_pem().decode()
        )
    )
    assert body["valid"] is True
    assert body["payload"]["verdict"] == "MALICIOUS"
    bad = server.VerifyReceiptRequest(
        receipt="a.b.c", public_key_pem=signer.public_key_pem().decode()
    )
    with pytest.raises(HTTPException) as excinfo:
        server.verify_receipt(bad)
    assert "Invalid receipt" in str(getattr(excinfo.value, "detail", excinfo.value))


def test_server_outcome_and_audit_status(monkeypatch, tmp_path):
    server = _server(monkeypatch)
    outcome = server.verify_outcome(
        server.OutcomeVerifyRequest(prompt="prompt", response="response", tool_calls=[])
    )
    assert "uncertain" in json.dumps(outcome).lower() or '"status"' in json.dumps(outcome)
    report = server.audit_status()
    assert report == {"enabled": False}


def test_server_audit_stream_sse_frames(monkeypatch, tmp_path):
    """_audit_line_to_frame and _follow_audit_stream yield SSE for real events."""
    server = _server(monkeypatch)
    chain = tmp_path / "audit.jsonl"
    chain.write_text(
        json.dumps({"chain_meta": {"v": 1}})
        + "\n"
        + json.dumps({"event": {"decision": "DENY", "tool": "t", "timestamp": "x"}})
        + "\n"
        + "garbage\n",
        encoding="utf-8",
    )
    frames = [server._audit_line_to_frame(line) for line in chain.read_text().splitlines()]
    assert frames[0] is None  # meta skipped
    assert frames[1].startswith("data: ")
    assert "DENY" in frames[1]
    assert frames[2] is None  # garbage skipped
    with open(chain, encoding="utf-8") as fh:  # noqa: SIM115 - generator holds the handle by design
        follow = server._follow_audit_stream(fh)
        frames = []
        for i, frame in enumerate(follow):
            frames.append(frame)
            if i == 0:
                break
    assert frames
