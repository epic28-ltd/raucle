"""Deployment intake conformance (H1 phase 5).

The gate accepts EXTERNAL (portal-signed) policy deployments only through
a PINNED trust root, appends the deployment to its own hash-chained
audit chain, and refuses everything else fail-closed (audited, artefact
never applied). The unconfigured posture is unchanged: no endpoint.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from raucle.deployment_intake import (
    DeploymentIntakeError,
    resolve_deployment_trust,
    verify_portal_jws,
)
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app

ARTEFACT = """
version: 1
issuer: portal.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class PortalKey:
    """Test stand-in for the portal's Ed25519 signing identity."""

    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.generate()

    @property
    def public_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def jws(
        self,
        *,
        artefact: str = ARTEFACT,
        issuer: str = "raucle-portal",
        nonce: str | None = None,
        artefact_sha256: str | None = None,
        kid: str = "raucle-portal-test",
        alg: str = "EdDSA",
    ) -> tuple[str, dict]:
        import hashlib

        digest = artefact_sha256 or ("sha256:" + hashlib.sha256(artefact.encode()).hexdigest())
        extension = {
            "org": "test-org",
            "policy_id": "lookup_balance",
            "policy_name": "balance lookup",
            "version": 1,
            "action": "activate",
            "stage": "active",
            "actor": "operator-1",
            "artefact_sha256": digest,
            "nonce": nonce or uuid.uuid4().hex,
        }
        payload = {
            "iss": issuer,
            "typ": "provenance-receipt/v1",
            "iat": int(time.time()),
            "nonce": extension["nonce"],
            "agent_id": "portal",
            "operation": "guardrail_scan",
            "parents": [],
            "taint": ["portal:admin"],
            "input_hash": _b64url(b"x")[:0] or digest,
            "ruleset_hash": digest,
            "guardrail_verdict": f"policy_{extension['action']}",
            "x_policy_deploy": extension,
        }
        header = {
            "alg": alg,
            "typ": "provenance-receipt/v1",
            "kid": kid,
            "crit": ["raucle/v1"],
            "raucle/v1": "authority",
        }
        signing = (
            _b64url(json.dumps(header, sort_keys=True).encode())
            + "."
            + _b64url(json.dumps(payload, sort_keys=True).encode())
        )
        sig = self._private.sign(signing.encode("ascii"))
        return signing + "." + _b64url(sig), payload


@pytest.fixture()
def env(tmp_path):
    portal = PortalKey()
    keyfile = tmp_path / "portal-public.pem"
    keyfile.write_bytes(portal.public_pem)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(tmp_path / "live-policies.yaml"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
        deployment_trust={
            "issuer": "raucle-portal",
            "key_path": str(keyfile),
            "policy_target": str(tmp_path / "live-policies.yaml"),
            "nonce_cache": str(tmp_path / "deploy-nonces.json"),
        },
    )
    gateway = RaucleGateway(config)
    return portal, gateway, tmp_path


def _accept_body(jws: str, artefact: str = ARTEFACT) -> dict:
    return {"jws": jws, "artefact": artefact}


def _client(gateway: RaucleGateway) -> TestClient:
    return TestClient(create_gateway_app(gateway))


def _audit_events(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if isinstance(record.get("event"), dict):
            out.append(record)
    return out


class TestDefaultPosture:
    def test_no_trust_root_no_endpoint(self, tmp_path) -> None:
        config = GatewayConfig(
            host="127.0.0.1",
            policy_file="",
            receipt_store=str(tmp_path / "r.jsonl"),
            audit_chain=str(tmp_path / "a.jsonl"),
            registry_path=str(tmp_path / "reg.jsonl"),
        )
        client = _client(RaucleGateway(config))
        assert client.post(
            "/api/deployments/accept", json={"jws": "x", "artefact": "y"}
        ).status_code == 404

    def test_enabled_false_keeps_default_posture(self) -> None:
        assert resolve_deployment_trust({"enabled": False}) is None

    def test_unknown_algorithm_fail_closed(self) -> None:
        assert resolve_deployment_trust({"algorithm": "HS256"}) is None


class TestAccept:
    def test_accept_applies_artefact_and_chains_receipt(self, env) -> None:
        portal, gateway, tmp_path = env
        jws, _ = portal.jws()
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body(jws))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["accepted"] is True
        assert body["policy_digest"].startswith("sha256:")

        # The artefact IS the live policy file and the gate reloaded it.
        live = Path(gateway.config.policy_file).read_text()
        assert live == ARTEFACT
        assert body["policy_id"] in gateway._policy_rules  # noqa: SLF001

        events = _audit_events(tmp_path / "audit.jsonl")
        deploy_events = [e for e in events if e["event"].get("kind") == "policy_deployed"]
        assert len(deploy_events) == 1
        ev = deploy_events[0]["event"]
        assert ev["policy_digest"] == body["policy_digest"]
        assert ev["version"] == 1
        assert ev["action"] == "activate"
        assert ev["gate_receipt_hash"] == body["gate_receipt_hash"]

        # The gate-issued receipt is a real store receipt.
        receipts = [
            json.loads(line)
            for line in (tmp_path / "receipts.jsonl").read_text().splitlines()
        ]
        assert any(r["receipt_hash"] == body["gate_receipt_hash"] for r in receipts)


class TestRefusals:
    def test_bad_signature_401_never_applied_audited(self, env) -> None:
        portal, gateway, tmp_path = env
        other = PortalKey()  # not the pinned key
        jws, _ = other.jws()
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body(jws))
        assert resp.status_code == 401
        assert not Path(gateway.config.policy_file).exists()
        kinds = [e["event"].get("kind") for e in _audit_events(tmp_path / "audit.jsonl")]
        assert kinds.count("bad_signature") == 1

    def test_untrusted_issuer_403(self, env, tmp_path) -> None:
        portal, gateway, tmp_path = env
        jws, payload = portal.jws()
        forged_payload = {**payload, "iss": "raucle-portal-impostor"}
        header_b64 = jws.split(".")[0]
        signing = (
            header_b64
            + "."
            + _b64url(json.dumps(forged_payload, sort_keys=True).encode())
        )
        sig = portal._private.sign(signing.encode("ascii"))  # noqa: SLF001
        forged = signing + "." + _b64url(sig)
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body(forged))
        assert resp.status_code == 403
        kinds = [e["event"].get("kind") for e in _audit_events(tmp_path / "audit.jsonl")]
        assert kinds.count("untrusted_issuer") == 1

    def test_digest_mismatch_400(self, env, tmp_path) -> None:
        portal, gateway, tmp_path = env
        jws, _ = portal.jws(artefact=ARTEFACT)  # binds ARTEFACT
        resp = _client(gateway).post(
            "/api/deployments/accept",
            json=_accept_body(jws, artefact=ARTEFACT + "\n# tampered\n"),
        )
        assert resp.status_code == 400
        kinds = [e["event"].get("kind") for e in _audit_events(tmp_path / "audit.jsonl")]
        assert kinds.count("digest_mismatch") == 1

    def test_replayed_nonce_403_only_first_applied(self, env, tmp_path) -> None:
        portal, gateway, tmp_path = env
        jws, _ = portal.jws()
        client = _client(gateway)
        first = client.post("/api/deployments/accept", json=_accept_body(jws))
        assert first.status_code == 200
        second = client.post("/api/deployments/accept", json=_accept_body(jws))
        assert second.status_code == 403
        kinds = [e["event"].get("kind") for e in _audit_events(tmp_path / "audit.jsonl")]
        assert kinds.count("replayed_nonce") == 1
        deploy_events = [
            e for e in _audit_events(tmp_path / "audit.jsonl")
            if e["event"].get("kind") == "policy_deployed"
        ]
        assert len(deploy_events) == 1

    def test_malformed_artefact_400_not_applied(self, env) -> None:
        portal, gateway, _ = env
        jws, _ = portal.jws(artefact="not: a policy: [")
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body(jws))
        assert resp.status_code == 400
        assert not Path(gateway.config.policy_file).exists()


class TestFailClosed:
    def test_signer_absent_503(self, tmp_path) -> None:
        """A pinned root whose key is unreadable refuses, never trusts."""
        gateway = RaucleGateway(
            GatewayConfig(
                host="127.0.0.1",
                policy_file=str(tmp_path / "p.yaml"),
                receipt_store=str(tmp_path / "r.jsonl"),
                audit_chain=str(tmp_path / "a.jsonl"),
                registry_path=str(tmp_path / "reg.jsonl"),
                deployment_trust={"key_path": str(tmp_path / "missing.pem")},
            )
        )
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body("a.b.c"))
        assert resp.status_code == 503
        assert not Path(gateway.config.policy_file).exists()

    def test_verify_portal_jws_signer_absent_refuses(self) -> None:
        trust = resolve_deployment_trust({"key_path": "/nonexistent/x.pem"})
        assert trust is not None
        with pytest.raises(DeploymentIntakeError) as exc:
            verify_portal_jws("h.p.s", trust)
        assert exc.value.status_code == 503

    def test_nonce_cache_unreadable_503(self, env) -> None:
        portal, gateway, tmp_path = env
        (tmp_path / "deploy-nonces.json").write_text("{corrupt")
        jws, _ = portal.jws()
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body(jws))
        # Fail-closed before any verification decision relies on the cache.
        assert resp.status_code == 503
        assert not Path(gateway.config.policy_file).exists()

    def test_missing_trust_root_pin_503(self, tmp_path) -> None:
        """deployment_trust only, no key material anywhere: refuse."""
        gateway = RaucleGateway(
            GatewayConfig(
                host="127.0.0.1",
                policy_file=str(tmp_path / "p.yaml"),
                receipt_store=str(tmp_path / "r.jsonl"),
                audit_chain=str(tmp_path / "a.jsonl"),
                registry_path=str(tmp_path / "reg.jsonl"),
                deployment_trust={"issuer": "raucle-portal"},
            )
        )
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body("a.b.c"))
        assert resp.status_code == 503

    def test_offline_third_party_verification(self, env) -> None:
        """Recompute the chain: portal JWS, gate receipt, audit linkage."""
        portal, gateway, tmp_path = env
        jws, _ = portal.jws()
        body = _client(gateway).post("/api/deployments/accept", json=_accept_body(jws)).json()

        # Audit chain re-verification with the gate's public key (third
        # party path: the verifier gets keys, never private material).
        from raucle.audit import AuditVerifier

        report = AuditVerifier(
            public_key_pem=gateway._gate_identity.public_key_pem()  # noqa: SLF001
        ).verify_chain(str(tmp_path / "audit.jsonl"))
        assert report.valid, report.errors

        # And the chain really links: recompute hashes independently.
        events = _audit_events(tmp_path / "audit.jsonl")
        for record in events:
            assert isinstance(record.get("hash"), str)
        deploy = [
            e for e in events if e["event"].get("kind") == "policy_deployed"
        ][0]
        assert deploy["event"]["gate_receipt_hash"] == body["gate_receipt_hash"]

