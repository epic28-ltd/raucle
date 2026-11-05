"""Tests for the AWS Egress Gate (raucle.broker).

Covers: SigV4 correctness against the published AWS test vector, the gate
ALLOW/DENY paths, the receipt binding to the exact wire request, and the
custody invariant that the agent never receives signed material.
"""

from __future__ import annotations

import pytest

cryptography = pytest.importorskip("cryptography")

from raucle.broker import AWSEgressGate, CapabilityDenied, sigv4
from raucle.capability import CapabilityGate, CapabilityIssuer


# ---------------------------------------------------------------------------
# SigV4 — validate against the AWS aws-sig-v4-test-suite "get-vanilla" vector
# ---------------------------------------------------------------------------
def test_sigv4_matches_aws_get_vanilla_vector():
    """The canonical AWS SigV4 KAT: GET / with the example credentials must
    produce the published signature. Proves the signing algorithm is correct."""
    signed = sigv4.sign(
        method="GET",
        service="service",
        region="us-east-1",
        host="example.amazonaws.com",
        path="/",
        headers={},
        body=b"",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        amz_date="20150830T123600Z",
    )
    expected_sig = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    assert f"Signature={expected_sig}" in signed.headers["authorization"]
    assert "SignedHeaders=host;x-amz-date" in signed.headers["authorization"]


def test_sigv4_binds_body_and_date():
    """Different body or date must change the signature — the receipt binding
    depends on this."""

    def _sig(body: bytes, date: str) -> str:
        return sigv4.sign(
            method="POST",
            service="dynamodb",
            region="us-east-1",
            host="dynamodb.us-east-1.amazonaws.com",
            path="/",
            headers={"content-type": "application/x-amz-json-1.0"},
            body=body,
            access_key="AKIDEXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            amz_date=date,
        ).canonical_hash

    base = _sig(b'{"TableName":"t"}', "20150830T123600Z")
    assert base != _sig(b'{"TableName":"u"}', "20150830T123600Z")  # body bound
    assert base != _sig(b'{"TableName":"t"}', "20150830T123601Z")  # date bound


# ---------------------------------------------------------------------------
# The gate: ALLOW / DENY / binding / no credential leak
# ---------------------------------------------------------------------------
class _FakeTransport:
    """Captures the signed request and returns a canned DynamoDB response."""

    def __init__(self):
        self.calls = []

    def __call__(self, req: sigv4.SignedRequest):
        self.calls.append(req)
        return 200, b'{"Item":{"customer_id":{"S":"C-123"}}}'


def _gate_and_token(constraints, tool="dynamodb.GetItem"):
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool=tool,
        constraints=constraints,
        ttl_seconds=300,
    )
    return gate, token


def _egress(gate, transport, *, clock=lambda: 1_700_000_000):
    return AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        transport=transport,
        clock=clock,
    )


def test_allow_signs_forwards_and_receipts():
    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    tx = _FakeTransport()
    egress = _egress(gate, tx)

    result = egress.get_item(
        token,
        table="customers",
        key={"customer_id": {"S": "C-123"}},
        agent_id="agent:kyc-prod",
    )

    assert result.status == 200
    assert result.json()["Item"]["customer_id"]["S"] == "C-123"
    assert len(tx.calls) == 1  # exactly one wire request
    # Receipt is bound to the exact signed request.
    assert result.receipt["decision"] == "ALLOW"
    assert result.receipt["request_binding"]["canonical_request_hash"] == tx.calls[0].canonical_hash
    assert result.receipt["request_binding"]["service"] == "dynamodb"


def test_deny_never_signs_or_forwards():
    # Constrain to a different table; the requested one is not allowed.
    gate, token = _gate_and_token({"allowed_values": {"TableName": ["other_table"]}})
    tx = _FakeTransport()
    egress = _egress(gate, tx)

    with pytest.raises(CapabilityDenied):
        egress.get_item(
            token,
            table="customers",
            key={"customer_id": {"S": "C-123"}},
            agent_id="agent:kyc-prod",
        )
    assert tx.calls == []  # never reached AWS


def test_agent_never_receives_signed_material():
    """The custody invariant: the EgressResult returned to the agent must carry
    NO Authorization header and NO credentials."""
    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    tx = _FakeTransport()
    egress = _egress(gate, tx)

    result = egress.get_item(
        token,
        table="customers",
        key={"customer_id": {"S": "C-123"}},
        agent_id="agent:kyc-prod",
    )

    blob = repr(result).lower()
    assert "authorization" not in blob
    assert "aws4-hmac-sha256" not in blob
    assert "akidexample" not in blob
    assert "wjalrxutnfemi" not in blob  # the secret key must never surface


def test_receipt_emitted_before_dispatch_survives_transport_failure():
    """no receipt = no action: a request that reaches the transport must already
    have a receipt, even if the transport then fails (timeout after AWS received
    it). The receipt is emitted to the sink BEFORE forwarding."""

    class _RecordingSink:
        def __init__(self):
            self.events = []

        def append(self, event):
            self.events.append(event)
            return event

    class _FailingTransport:
        def __call__(self, req):
            raise RuntimeError("connection reset after request was sent")

    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    sink = _RecordingSink()
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        sink=sink,
        transport=_FailingTransport(),
        clock=lambda: 1_700_000_000,
    )

    with pytest.raises(RuntimeError):
        egress.get_item(
            token,
            table="customers",
            key={"customer_id": {"S": "C-123"}},
            agent_id="agent:kyc-prod",
        )
    # The receipt for the signed, about-to-be-dispatched request was recorded
    # before the transport failed — the dispatch is never receipt-less.
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "ALLOW"
    assert sink.events[0]["request_binding"]["canonical_request_hash"].startswith("sha256:")


# ---------------------------------------------------------------------------
# S3 — SigV4 KAT (AWS-documented GetObject example) + gate behaviour
# ---------------------------------------------------------------------------
def test_sigv4_matches_aws_s3_get_object_vector():
    """AWS-documented S3 GetObject SigV4 example (service=s3, with Range and
    x-amz-content-sha256 signed headers). Validates S3-mode signing."""
    empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    signed = sigv4.sign(
        method="GET",
        service="s3",
        region="us-east-1",
        host="examplebucket.s3.amazonaws.com",
        path="/test.txt",
        headers={"range": "bytes=0-9", "x-amz-content-sha256": empty_sha},
        body=b"",
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        amz_date="20130524T000000Z",
    )
    expected_sig = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    assert f"Signature={expected_sig}" in signed.headers["authorization"]
    assert (
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"
        in (signed.headers["authorization"])
    )


class _S3GetTransport:
    """Returns raw (binary) object bytes, as S3 GetObject does."""

    def __init__(self, content: bytes):
        self.content = content
        self.calls = []

    def __call__(self, req):
        self.calls.append(req)
        return 200, self.content


def test_s3_get_object_returns_raw_bytes_and_binds_receipt():
    gate, token = _gate_and_token(
        {"allowed_values": {"Bucket": ["statements"]}}, tool="s3.GetObject"
    )
    tx = _S3GetTransport(b"\x89PNG\r\n\x1a\n binary object bytes")
    egress = _egress(gate, tx)

    result = egress.get_object(
        token, bucket="statements", key="2026/06/stmt.pdf", agent_id="agent:kyc-prod"
    )

    assert result.status == 200
    assert result.body == b"\x89PNG\r\n\x1a\n binary object bytes"  # raw bytes
    assert result.receipt["decision"] == "ALLOW"
    assert result.receipt["request_binding"]["service"] == "s3"
    assert result.receipt["request_binding"]["path"] == "/2026/06/stmt.pdf"
    # The signed request carries the S3-required payload-hash header.
    assert "x-amz-content-sha256" in tx.calls[0].headers


def test_s3_put_object_binds_body_to_receipt():
    gate, token = _gate_and_token({"allowed_values": {"Bucket": ["uploads"]}}, tool="s3.PutObject")

    def _put_hash(body: bytes) -> str:
        tx = _S3GetTransport(b"")
        egress = _egress(gate, tx)
        r = egress.put_object(
            token, bucket="uploads", key="a.txt", body=body, agent_id="agent:kyc-prod"
        )
        return r.receipt["request_binding"]["canonical_request_hash"]

    # Different bodies must produce different receipts (the body is bound).
    assert _put_hash(b"hello") != _put_hash(b"world")


def test_s3_deny_never_forwards():
    gate, token = _gate_and_token({"allowed_values": {"Bucket": ["allowed"]}}, tool="s3.GetObject")
    tx = _S3GetTransport(b"x")
    egress = _egress(gate, tx)
    with pytest.raises(CapabilityDenied):
        egress.get_object(token, bucket="secret-bucket", key="k", agent_id="agent:kyc-prod")
    assert tx.calls == []


def test_s3_put_object_size_can_be_gated():
    """ContentLength is a gated arg, so a capability can PREVENT (not just audit)
    an oversized write."""
    gate, token = _gate_and_token(
        {
            "allowed_values": {"Bucket": ["uploads"]},
            "max_value": {"ContentLength": 8},
        },
        tool="s3.PutObject",
    )
    tx = _S3GetTransport(b"")
    egress = _egress(gate, tx)

    # Within the size limit: allowed.
    egress.put_object(
        token, bucket="uploads", key="a.txt", body=b"small", agent_id="agent:kyc-prod"
    )
    assert len(tx.calls) == 1

    # Over the size limit: denied, never forwarded.
    with pytest.raises(CapabilityDenied):
        egress.put_object(
            token,
            bucket="uploads",
            key="a.txt",
            body=b"this body is far too large",
            agent_id="agent:kyc-prod",
        )
    assert len(tx.calls) == 1  # no new wire request


def test_json_helper_does_not_crash_on_binary_body():
    """EgressResult.json() must never crash on binary S3 object bytes."""
    gate, token = _gate_and_token(
        {"allowed_values": {"Bucket": ["statements"]}}, tool="s3.GetObject"
    )
    tx = _S3GetTransport(b"\x89PNG\r\n\xff\xfe not utf-8")
    egress = _egress(gate, tx)
    result = egress.get_object(token, bucket="statements", key="x.png", agent_id="agent:kyc-prod")
    parsed = result.json()  # must not raise
    assert "_raw" in parsed


# ---------------------------------------------------------------------------
# Custody → evidence loop: gate-emitted JWS receipts feed `raucle audit-export`
# ---------------------------------------------------------------------------
def test_gate_jws_receipts_feed_audit_export_end_to_end(tmp_path):
    """The portable-provable-custody wedge: when the gate is given a
    ProvenanceLogger, every gated action (ALLOW and DENY) emits a per-action,
    Ed25519-signed JWS provenance receipt that `audit-export` ingests and that
    verifies OFFLINE from the broker's public key alone — no AWS, no network.
    This is the property AgentCore's CloudWatch trail structurally cannot give a
    regulator."""
    from raucle.audit_export import _load_receipts, build_report
    from raucle.provenance import (
        AgentIdentity,
        ProvenanceLogger,
        ProvenanceVerifier,
    )

    broker = AgentIdentity.generate(agent_id="agent:raucle-aws-egress-broker")
    chain = tmp_path / "custody.jsonl"
    writer = ProvenanceLogger(broker, sink_path=chain)

    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        provenance_writer=writer,
        transport=_FakeTransport(),
        clock=lambda: 1_700_000_000,
    )

    # ALLOW — the returned receipt links to the signed provenance receipt hash.
    res = egress.get_item(
        token,
        table="customers",
        key={"customer_id": {"S": "C-123"}},
        agent_id="agent:kyc-prod",
    )
    assert res.receipt["provenance_receipt_hash"].startswith("sha256:")

    # DENY — a refused action is cryptographically attested too.
    with pytest.raises(CapabilityDenied):
        egress.get_item(
            token,
            table="forbidden_table",
            key={"customer_id": {"S": "C-9"}},
            agent_id="agent:kyc-prod",
        )
    writer.close()

    # audit-export ingests the gate-produced chain (the loop is closed). Each
    # action is a mini-chain rooted at its gate-decision guardrail_scan:
    # ALLOW = scan + tool_call (2), DENY = scan only (1) → 3 receipts total.
    receipts = _load_receipts(chain)
    assert len(receipts) == 3

    # The signed payloads carry the gate decisions and the performed AWS action.
    from raucle.provenance import Operation

    decoded = [r for _, r in receipts]
    scans = [r for r in decoded if r.operation is Operation.GUARDRAIL_SCAN]
    tool_calls = [r for r in decoded if r.operation is Operation.TOOL_CALL]
    assert {s.guardrail_verdict for s in scans} == {"ALLOW", "DENY"}
    assert len(tool_calls) == 1  # only the ALLOW produced an AWS call
    assert tool_calls[0].tool == "dynamodb.GetItem"
    assert tool_calls[0].parents  # descends from its decision receipt

    # Every receipt verifies OFFLINE from the broker public key alone — no AWS.
    verifier = ProvenanceVerifier(public_keys={broker.key_id: broker.public_key_pem()})
    verdict = verifier.verify_chain(chain)
    assert verdict.valid, verdict
    assert verdict.receipt_count == 3
    assert verdict.signature_failures == 0

    # And the full audit-export report builds clean over the gate chain.
    report = build_report(
        chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        generated_at=1_700_000_000,
    )
    assert report.body()["chain_verdict"]["valid"] is True


def test_require_durable_receipt_refuses_construction_without_a_sink():
    """Fail-closed custody: a gate that requires a durable receipt cannot be
    built without somewhere to durably record it (Codex High)."""
    gate, _ = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    with pytest.raises(ValueError, match="durable"):
        AWSEgressGate(
            gate,
            region="us-east-1",
            access_key="AKIDEXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            require_durable_receipt=True,  # no sink, no provenance_writer
        )
    # With a durable sink it constructs fine.
    AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        sink=type("S", (), {"append": staticmethod(lambda e: e)})(),
        require_durable_receipt=True,
    )


def test_receipt_binds_exact_signed_request_not_just_canonical_hash():
    """Codex High: the receipt must pin the EXACT signed request (incl. the
    Authorization signature), not only the canonical-request hash — so a
    different principal signing the same canonical request can't match it."""
    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    egress = _egress(gate, _FakeTransport())
    res = egress.get_item(
        token,
        table="customers",
        key={"customer_id": {"S": "C-123"}},
        agent_id="agent:kyc-prod",
    )
    binding = res.receipt["request_binding"]
    assert binding["signed_request_hash"].startswith("sha256:")
    # It is distinct from the canonical-request hash (binds more: the signature).
    assert binding["signed_request_hash"] != binding["canonical_request_hash"]
    # And it leaks no credential/signature material (it is only a hash).
    blob = repr(res.receipt).lower()
    assert "aws4-hmac-sha256" not in blob
    assert "akidexample" not in blob


# ---------------------------------------------------------------------------
# SQS SendMessage — the custody model on an action/messaging surface
# ---------------------------------------------------------------------------
_Q = "https://sqs.us-east-1.amazonaws.com/123456789012/kyc-events"


def test_sqs_send_message_allows_and_binds_body():
    gate, token = _gate_and_token({"allowed_values": {"QueueUrl": [_Q]}}, tool="sqs.SendMessage")
    tx = _FakeTransport()
    egress = _egress(gate, tx)
    result = egress.send_message(
        token,
        queue_url=_Q,
        message_body='{"event":"kyc.verified","id":"C-123"}',
        agent_id="agent:kyc-prod",
    )
    assert result.receipt["decision"] == "ALLOW"
    assert result.receipt["request_binding"]["service"] == "sqs"
    assert len(tx.calls) == 1  # exactly one wire request
    # The exact message is bound into the signed wire request body.
    assert b"kyc.verified" in tx.calls[0].body
    assert b'"QueueUrl"' in tx.calls[0].body


def test_sqs_denies_unallowed_queue():
    gate, token = _gate_and_token(
        {"allowed_values": {"QueueUrl": ["https://sqs.us-east-1.amazonaws.com/1/allowed"]}},
        tool="sqs.SendMessage",
    )
    tx = _FakeTransport()
    egress = _egress(gate, tx)
    with pytest.raises(CapabilityDenied):
        egress.send_message(token, queue_url=_Q, message_body="x", agent_id="agent:kyc-prod")
    assert tx.calls == []  # never reached AWS


def test_sqs_message_size_can_be_gated():
    gate, token = _gate_and_token(
        {"allowed_values": {"QueueUrl": [_Q]}, "max_value": {"MessageBytes": 16}},
        tool="sqs.SendMessage",
    )
    tx = _FakeTransport()
    egress = _egress(gate, tx)
    with pytest.raises(CapabilityDenied):
        egress.send_message(token, queue_url=_Q, message_body="x" * 64, agent_id="agent:kyc-prod")
    assert tx.calls == []


# ---------------------------------------------------------------------------
# Secrets Manager GetSecretValue — custody of secrets
# ---------------------------------------------------------------------------
_SECRET = "prod/kyc/api-key"


class _FakeSecretsTransport:
    def __init__(self):
        self.calls = []

    def __call__(self, req):
        self.calls.append(req)
        return 200, b'{"Name":"prod/kyc/api-key","SecretString":"s3cr3t"}'


def test_secrets_get_allows_and_receipts():
    gate, token = _gate_and_token(
        {"allowed_values": {"SecretId": [_SECRET]}}, tool="secretsmanager.GetSecretValue"
    )
    tx = _FakeSecretsTransport()
    egress = _egress(gate, tx)
    result = egress.get_secret_value(token, secret_id=_SECRET, agent_id="agent:kyc-prod")
    assert result.receipt["decision"] == "ALLOW"
    assert result.receipt["request_binding"]["service"] == "secretsmanager"
    assert result.json()["SecretString"] == "s3cr3t"
    assert len(tx.calls) == 1
    # Agent still never sees the AWS credential / Authorization signature.
    assert "akidexample" not in repr(result).lower()


def test_secrets_denies_unallowed_secret():
    gate, token = _gate_and_token(
        {"allowed_values": {"SecretId": ["prod/other/secret"]}},
        tool="secretsmanager.GetSecretValue",
    )
    tx = _FakeSecretsTransport()
    egress = _egress(gate, tx)
    with pytest.raises(CapabilityDenied):
        egress.get_secret_value(token, secret_id=_SECRET, agent_id="agent:kyc-prod")
    assert tx.calls == []  # never reached AWS — the secret was never fetched
