"""C1: lease receipts in the evidence layer (receipts v1.2 lease extension).

A credential lease binds: the delegated-authority chain that authorised it
(capability_id + chain_digest, v1.1), the vault secret by HASH (never the
secret), the scopes narrowed from the capability's constraints, and a TTL.
Every lease event - granted, denied, redeemed, revoked - is a receipt the
verifier re-checks offline:

1. A redemption must cite a grant that exists in the chain.
2. The redemption's time must fall inside the grant's TTL window.
3. The redemption's scopes must be a subset of the grant's (never wider).
4. A denied lease is receipted like every other attributable denial.

The minting workflows, vault and injection live in raucle-cloud (the 16.3
split); this file pins the evidence contract they emit against.
"""

import time

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.provenance import ProvenanceVerifier


def _lease_receipt(gw, action, **overrides):
    """Emit a lease receipt through the authority-receipt machinery with an
    x_lease extension (the shape the cloud lease manager emits)."""
    block = {
        "action": action,
        "lease_id": "lease:abc123",
        "capability_id": "cap:child",
        "chain_digest": "deadbeef" * 8,
        "secret_ref_hash": "sha256:" + "ab" * 32,
        "scopes": {"allowed_values": {"account": ["ACC-001"]}},
        "ttl_seconds": 300,
        "granted_at": int(time.time()) - 60,
    }
    block.update(overrides)
    receipt_id = gw._emit_authority_receipt(
        verdict=f"lease_{action}",
        extension_key="x_lease",
        extension=block,
    )
    return receipt_id


def _emitter(tmp_path):
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
    return RaucleGateway(config)


def _verify(gw, tmp_path):
    pem = gw._gate_identity.public_key_pem()
    return ProvenanceVerifier(public_keys={gw._gate_identity.key_id: pem}).verify_chain(
        tmp_path / "receipts.jsonl"
    )


def test_lease_grant_and_redemption_verify(tmp_path):
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted")
    # redemption inside the window, matching scope (the receipt's own iat is
    # the redemption moment; the verifier checks it against the grant window)
    _lease_receipt(
        gw,
        "redeemed",
        scopes={"allowed_values": {"account": ["ACC-001"]}},
    )
    report = _verify(gw, tmp_path)
    assert report.valid, report.errors
    assert report.receipt_count == 2


def test_redemption_after_expiry_is_invalid(tmp_path):
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", ttl_seconds=1, granted_at=int(time.time()) - 600)
    # redeemed past the window: the lease was dead
    _lease_receipt(
        gw,
        "redeemed",
        scopes={"allowed_values": {"account": ["ACC-001"]}},
    )
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert any("lease expired" in e for e in report.errors), report.errors


def test_redemption_with_wider_scope_is_invalid(tmp_path):
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", scopes={"allowed_values": {"account": ["ACC-001"]}})
    # the redemption claims a scope the grant never allowed
    _lease_receipt(
        gw,
        "redeemed",
        scopes={"allowed_values": {"account": ["ACC-001", "ACC-999"]}},
    )
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert any("scope" in e for e in report.errors), report.errors


def test_redemption_without_grant_is_invalid(tmp_path):
    gw = _emitter(tmp_path)
    _lease_receipt(
        gw,
        "redeemed",
        lease_id="lease:never-granted",
    )
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert any("no lease grant" in e for e in report.errors), report.errors


def test_lease_denial_is_receipted(tmp_path):
    """A lease request outside the delegated authority denies, receipted -
    the same attributable-deny doctrine as every other gate decision."""
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "denied", capability_id="cap:child", reason="outside authority")
    report = _verify(gw, tmp_path)
    assert report.valid, report.errors  # the denial is VALID evidence


def test_lease_revocation_verifies(tmp_path):
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", ttl_seconds=300)
    _lease_receipt(gw, "revoked")
    report = _verify(gw, tmp_path)
    assert report.valid, report.errors
