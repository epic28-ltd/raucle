"""Credential, trust-root and revocation freshness: fail-closed regressions
(depends issue #344 items 1 and 5, ADR 0010).

Contract under test, all at the authenticated gateway boundary, not at
store internals:

1. A ROTATED api key's predecessor stops verifying the moment the
   replacement is issued; the revoked key stops verifying; both deny
   pre-gate by name with no receipt (identity stage).
2. A capability token signed by an issuer key that is not an ACTIVE
   entry in the trust registry is refused pre-gate ("unknown key_id").
3. A genuinely expired capability token is refused pre-gate.
4. A token whose id is named in the revocation registry is refused
   pre-gate (current classification: unattributable identity-stage
   denial, receipt_id None).
5. A corrupt revocation registry must refuse token calls BY NAME rather
   than raising an unaudited exception into the HTTP layer (PR #360 made
   the parser fail closed; this pins the live refusal surface).
6. A revocation registry that was read once and then vanishes must
   refuse token calls rather than quietly re-opening revoked tokens;
   restoring the file ends the refusal without a gateway restart.
7. A configured registry that has not been created yet must keep
   serving: the registry file is created lazily by the first
   revocation, so absent-before-first-read is a legitimate steady state.
8. A receipt-signer (KMS) outage after a policy match downgrades the
   allow to a named deny ("receipt emission failed"); an unaudited allow
   is never returned, and recovery restores receipted decisions.
"""

import json

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.trust_registry import TrustRegistry

POLICY = """
version: 1
issuer: freshness.test
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 600
    constraints:
      allow:
        account: ["ACC-001"]
"""

TOOL_ARGS = {"tool": "lookup_balance", "args": {"account": "ACC-001"}, "agent_id": "agent:svc"}


def _base_config(tmp_path, *, gate_auth: str = "token", revocations: bool = True):
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(POLICY)
    config.gate_auth = gate_auth
    if revocations:
        config.revocations_file = str(tmp_path / "revocations.jsonl")
    return config


def _publish_issuer(config, issuer, issuer_name="test-issuer"):
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=config.registry_path).publish(pem, issuer=issuer_name)


def _mint(issuer, account="ACC-001", ttl_seconds=600):
    return issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        constraints={"allowed_values": {"account": [account]}},
        ttl_seconds=ttl_seconds,
    )


def _token_call(client, token):
    return client.post(
        "/gate", json=TOOL_ARGS, headers={"X-Capability-Token": json.dumps(token.to_dict())}
    )


def _assert_pre_gate_deny(response_body):
    """The identity-stage refusal shape: deny without a receipted chain."""
    assert response_body["decision"] == "deny"
    assert response_body["receipt_id"] is None


# ---------------------------------------------------------------------------
# Credentials: rotation and revocation cut through at the gate
# ---------------------------------------------------------------------------


class TestCredentialFreshness:
    def test_rotated_apikey_old_key_denies_pre_gate_new_key_receipted(self, tmp_path):
        config = _base_config(tmp_path, gate_auth="apikey", revocations=False)
        config.delegations_file = ""
        # The gateway owns the credential store: credentials are issued
        # through the gateway's own instance so the boot-time store sees
        # them (single-writer, in-process rotation cut-over).
        gw = RaucleGateway(config)
        store = gw._agent_creds
        assert store is not None
        first = store.issue("agent:svc")
        client = TestClient(create_gateway_app(gw))

        def api_call(key):
            return client.post("/gate", json=TOOL_ARGS, headers={"X-Api-Key": key})

        assert api_call(first).json()["decision"] == "allow"
        rotated = store.issue("agent:svc")
        old = api_call(first).json()
        _assert_pre_gate_deny(old)
        assert old["reason"] == "unauthenticated: invalid or revoked api key"
        fresh = api_call(rotated).json()
        assert fresh["decision"] == "allow"
        assert fresh["receipt_id"]

    def test_revoked_apikey_denies_pre_gate(self, tmp_path):
        config = _base_config(tmp_path, gate_auth="apikey", revocations=False)
        config.delegations_file = ""
        gw = RaucleGateway(config)
        store = gw._agent_creds
        key = store.issue("agent:svc")
        client = TestClient(create_gateway_app(gw))

        def api_call(k):
            return client.post("/gate", json=TOOL_ARGS, headers={"X-Api-Key": k})

        assert api_call(key).json()["decision"] == "allow"
        store.revoke("agent:svc")
        body = api_call(key).json()
        _assert_pre_gate_deny(body)
        assert body["reason"] == "unauthenticated: invalid or revoked api key"


# ---------------------------------------------------------------------------
# Trust root and token freshness: untrusted issuer, expiry, revocation
# ---------------------------------------------------------------------------


class TestTrustRootAndTokenFreshness:
    def test_foreign_issuer_token_refused_pre_gate(self, tmp_path):
        config = _base_config(tmp_path)
        config.delegations_file = ""
        gw = RaucleGateway(config)
        trusted = CapabilityIssuer.generate(issuer="test-issuer")
        _publish_issuer(config, trusted)
        client = TestClient(create_gateway_app(gw))

        assert _token_call(client, _mint(trusted)).json()["decision"] == "allow"
        foreign = CapabilityIssuer.generate(issuer="foreign")
        body = _token_call(client, _mint(foreign)).json()
        _assert_pre_gate_deny(body)
        assert "unknown key_id" in body["reason"]

    def test_expired_capability_token_refused_pre_gate(self, tmp_path):
        config = _base_config(tmp_path)
        config.delegations_file = ""
        gw = RaucleGateway(config)
        trusted = CapabilityIssuer.generate(issuer="test-issuer")
        _publish_issuer(config, trusted)
        client = TestClient(create_gateway_app(gw))

        expired = _mint(trusted, ttl_seconds=1)
        import time

        time.sleep(1.1)
        body = _token_call(client, expired).json()
        _assert_pre_gate_deny(body)
        assert "token expired" in body["reason"]

    def test_revoked_token_id_refused_pre_gate(self, tmp_path):
        config = _base_config(tmp_path)
        config.delegations_file = ""
        gw = RaucleGateway(config)
        trusted = CapabilityIssuer.generate(issuer="test-issuer")
        _publish_issuer(config, trusted)
        client = TestClient(create_gateway_app(gw))

        token = _mint(trusted)
        assert _token_call(client, token).json()["decision"] == "allow"
        (tmp_path / "revocations.jsonl").write_text(
            json.dumps({"token_id": token.token_id, "reason": "compromise"}) + "\n"
        )
        body = _token_call(client, token).json()
        _assert_pre_gate_deny(body)
        assert f"token {token.token_id} is revoked" in body["reason"]


# ---------------------------------------------------------------------------
# Revocation registry freshness: corrupt and vanished state refuses by name
# ---------------------------------------------------------------------------


class TestRevocationRegistryFreshness:
    def test_corrupt_revocation_registry_refused_by_name(self, tmp_path):
        config = _base_config(tmp_path)
        config.delegations_file = ""
        gw = RaucleGateway(config)
        trusted = CapabilityIssuer.generate(issuer="test-issuer")
        _publish_issuer(config, trusted)
        client = TestClient(create_gateway_app(gw))

        (tmp_path / "revocations.jsonl").write_text('{"token_id": "x"}\nnot-json\n')
        body = _token_call(client, _mint(trusted)).json()
        _assert_pre_gate_deny(body)
        assert "gate identity dependency unavailable (fail closed)" in body["reason"]
        assert "revocation registry contains invalid JSON on line 2" in body["reason"]
        # recovery: restoring a well-formed registry resumes normal service
        (tmp_path / "revocations.jsonl").write_text("")
        assert _token_call(client, _mint(trusted)).json()["decision"] == "allow"

    def test_revocation_registry_vanishing_refuses_until_restored(self, tmp_path):
        config = _base_config(tmp_path)
        config.delegations_file = ""
        gw = RaucleGateway(config)
        trusted = CapabilityIssuer.generate(issuer="test-issuer")
        _publish_issuer(config, trusted)
        client = TestClient(create_gateway_app(gw))

        token = _mint(trusted)
        registry = tmp_path / "revocations.jsonl"
        registry.write_text(json.dumps({"token_id": token.token_id}) + "\n")
        body = _token_call(client, token).json()
        _assert_pre_gate_deny(body)
        assert "is revoked" in body["reason"]

        # The registry vanishes after having been read: the revoked id
        # must NOT silently re-open.
        registry.unlink()
        body = _token_call(client, token).json()
        _assert_pre_gate_deny(body)
        assert "gate identity dependency unavailable (fail closed)" in body["reason"]
        assert "now missing" in body["reason"]

        # Restoring the registry ends the refusal without a restart, and
        # the recorded revocation still holds it.
        registry.write_text(json.dumps({"token_id": token.token_id}) + "\n")
        assert _token_call(client, token).json()["decision"] == "deny"

    def test_registry_absent_before_first_revocation_still_serves(self, tmp_path):
        """Configured-but-never-created stays the lazy pre-revocation state."""
        config = _base_config(tmp_path)  # revocation file NOT created yet
        config.delegations_file = ""
        gw = RaucleGateway(config)
        trusted = CapabilityIssuer.generate(issuer="test-issuer")
        _publish_issuer(config, trusted)
        client = TestClient(create_gateway_app(gw))
        assert _token_call(client, _mint(trusted)).json()["decision"] == "allow"


# ---------------------------------------------------------------------------
# Receipt signer (KMS) outage after a policy match
# ---------------------------------------------------------------------------


class TestReceiptSignerOutage:
    def test_signer_outage_downgrades_allow_to_deny_and_recovery_is_receipted(self, tmp_path):
        config = _base_config(tmp_path)
        config.delegations_file = ""
        gw = RaucleGateway(config)
        trusted = CapabilityIssuer.generate(issuer="test-issuer")
        _publish_issuer(config, trusted)
        client = TestClient(create_gateway_app(gw))

        token = _mint(trusted)
        assert _token_call(client, token).json()["decision"] == "allow"

        original_sign = gw._gate_identity.sign

        def _kms_outage(*_args, **_kwargs):
            raise RuntimeError("simulated KMS outage")

        gw._gate_identity.sign = _kms_outage
        try:
            body = _token_call(client, _mint(trusted)).json()
            assert body["decision"] == "deny"
            assert body["reason"] == "receipt emission failed"
        finally:
            gw._gate_identity.sign = original_sign
        body = _token_call(client, _mint(trusted)).json()
        assert body["decision"] == "allow"
        assert body["receipt_id"]


@pytest.mark.parametrize(
    "registry_bytes,expected_line",
    [
        (b'{"token_id": "x"}\nnot-json\n', "invalid JSON on line 2"),
        (b'{"token_id": "x"}\n[]\n', "line 2 must be an object"),
        (b'{"token_id": "x"}\n{"token_id": ""}\n', "line 2 has no valid token_id"),
    ],
)
def test_corrupt_registry_variants_all_refuse_by_name(tmp_path, registry_bytes, expected_line):
    config = _base_config(tmp_path)
    config.delegations_file = ""
    gw = RaucleGateway(config)
    trusted = CapabilityIssuer.generate(issuer="test-issuer")
    _publish_issuer(config, trusted)
    client = TestClient(create_gateway_app(gw))
    (tmp_path / "revocations.jsonl").write_bytes(registry_bytes)
    body = _token_call(client, _mint(trusted)).json()
    _assert_pre_gate_deny(body)
    assert "gate identity dependency unavailable (fail closed)" in body["reason"]
    assert expected_line in body["reason"]
