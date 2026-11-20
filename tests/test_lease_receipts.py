"""C1: lease receipts in the evidence layer (receipts v1.2 lease extension).

A credential lease binds: the delegated-authority chain that authorised it
(capability_id + chain_digest, v1.1), the vault secret by HASH (never the
secret), the scopes narrowed from the capability's constraints, and a TTL.
Every lease event - granted, denied, redeemed, revoked - is a receipt the
verifier re-checks offline:

1. A redemption must cite a grant from an earlier line in the chain
   (pairing_absent otherwise).
2. The redemption's time must fall inside the grant's TTL window
   (lease_expired otherwise).
3. The redemption's scopes must be a subset of the grant's (never wider,
   scope_exceeded otherwise).
4. A redemption after the lease's revocation is invalid (lease_revoked),
   whatever its TTL window; a redemption before it stays valid evidence.
5. A denied lease is receipted like every other attributable denial.
6. The block carries handles, the grant pairing, scope names and digests
   only: the shared forbidden-field sweep rejects content anywhere
   inside it.

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


def _lease_revocation_receipt(gw, lease_id):
    """The second revocation source: a v1.0-shape x_revocation block
    citing the lease id (the shape revoke_capability emits)."""
    gw._emit_authority_receipt(
        verdict="authority_revoked",
        extension_key="x_revocation",
        extension={
            "revoked_ids": [lease_id],
            "root": None,
            "actor": "operator",
            "reason": "lease revoked",
        },
    )


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
    # redemption inside the window, matching scope (the receipt's own iat is
    # the redemption moment; the verifier checks it against the grant window)
    _lease_receipt(gw, "granted")
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
    assert any("lease_expired" in e for e in report.errors), report.errors


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
    assert any("scope_exceeded" in e for e in report.errors), report.errors


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
    assert any("pairing_absent" in e for e in report.errors), report.errors


def test_redemption_before_grant_is_invalid(tmp_path):
    """The pairing is temporal: grants collect from EARLIER lines only,
    so a redemption minted before its grant line has no grant to pair
    with (pairing_absent, the same refusal as an unknown lease)."""
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "redeemed", scopes={"allowed_values": {"account": ["ACC-001"]}})
    _lease_receipt(gw, "granted", ttl_seconds=300)
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert any("pairing_absent" in e for e in report.errors), report.errors


def test_redemption_after_revocation_is_invalid(tmp_path):
    """C1 remainder: a redemption minted after the lease's revocation
    event is invalid (lease_revoked), whatever its TTL window."""
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", ttl_seconds=300)
    _lease_receipt(gw, "revoked")
    _lease_receipt(gw, "redeemed", scopes={"allowed_values": {"account": ["ACC-001"]}})
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert any("lease_revoked" in e for e in report.errors), report.errors


def test_redemption_after_x_revocation_is_invalid(tmp_path):
    """The second revocation source: an x_revocation block citing the
    lease id stops later redemptions exactly like an x_lease revoked
    event (one shared revocation collector)."""
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", ttl_seconds=300)
    _lease_revocation_receipt(gw, "lease:abc123")
    _lease_receipt(gw, "redeemed", scopes={"allowed_values": {"account": ["ACC-001"]}})
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert any("lease_revoked" in e for e in report.errors), report.errors


def test_redemption_before_revocation_stays_valid(tmp_path):
    """Temporal doctrine (A3): revocations collect as the walk proceeds,
    so a revocation only bites later lines; a redemption minted before
    the revocation line stays valid evidence."""
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", ttl_seconds=300)
    _lease_receipt(gw, "redeemed", scopes={"allowed_values": {"account": ["ACC-001"]}})
    _lease_receipt(gw, "revoked")
    report = _verify(gw, tmp_path)
    assert report.valid, report.errors


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


def test_lease_block_forbidden_field_fails(tmp_path):
    """Bounded disclosure: the shared forbidden-field sweep covers the
    x_lease block, so a content-like field anywhere inside it fails with
    the sweep's named error (handles and digests, never content)."""
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", secret="hunter2")
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert any("content-like field" in e for e in report.errors), report.errors


def test_report_body_keeps_v10_shape(tmp_path):
    """The named refusals ride the existing errors list: no new report
    keys, so every consumer pinning the v1.0 report body (digests,
    fixture packs) is byte-preserved, failing chains included."""
    gw = _emitter(tmp_path)
    _lease_receipt(gw, "granted", ttl_seconds=1, granted_at=int(time.time()) - 600)
    _lease_receipt(gw, "redeemed", scopes={"allowed_values": {"account": ["ACC-001"]}})
    report = _verify(gw, tmp_path)
    assert not report.valid
    assert set(report.to_dict()) == {
        "valid",
        "receipt_count",
        "signature_failures",
        "parent_link_failures",
        "taint_monotonicity_failures",
        "capability_violations",
        "unauthorised_sanitisations",
        "tampered_receipts",
        "errors",
    }
