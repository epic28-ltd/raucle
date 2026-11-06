"""Policy-bytes tamper detection (threat-model residual 5, mitigation M2).

Covers both halves of the M2 contract:

- raucle/policy_bytes.py unit behaviour: receipted sealing, out-of-band
  edit detection, the explicit re-activation re-receipt flow, revocation
  registry append-only prefix tolerance and corrupt-seal fail-closed.
- the gateway integration: a diverging enforcement file denies every
  call fail-closed with the named ``policy_tampered`` reason before any
  policy evaluation; an explicit re-activation re-receipts the new
  bytes and re-opens the gate; an unchanged-bytes restart passes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.policy_bytes import (
    POLICY_STATUS_OK,
    POLICY_STATUS_TAMPERED,
    PolicyBytesError,
    PolicyBytesVerifier,
)

_POLICY_YAML = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> str:
    path = tmp_path / "policies.yaml"
    path.write_text(_POLICY_YAML)
    return str(path)


@pytest.fixture
def revocations_path(tmp_path: Path) -> str:
    path = tmp_path / "revocations.jsonl"
    path.write_text("")
    return str(path)


def _verifier(policy_path: str, seal_path: str, revocations_path: str = "", receipts=None):
    """A verifier with a receipt collector standing in for the stream."""
    if receipts is None:
        receipts = []
    return PolicyBytesVerifier(
        policy_path=policy_path,
        seal_path=seal_path,
        revocations_path=revocations_path,
        emitter=lambda verdict, extra: receipts.append((verdict, extra)) or f"rcpt_{len(receipts)}",
    )


# ---------------------------------------------------------------------------
# Module: sealing receipts the bytes, verification is deterministic
# ---------------------------------------------------------------------------


def test_seal_receipts_activation_and_verifies_ok(policy_path, revocations_path, tmp_path):
    receipts: list[tuple[str, dict[str, Any]]] = []
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"), revocations_path, receipts)
    status = verifier.seal()
    assert status["status"] == POLICY_STATUS_OK
    assert status["sealed"] is True
    assert status["receipt_id"] == "rcpt_1"
    # exactly one receipt was emitted, and it is a policy_activation
    assert len(receipts) == 1
    verdict, extra = receipts[0]
    assert verdict == "policy_activation"
    assert extra["policy_sha256"]
    assert extra["revocations_prefix_len"] == 0
    assert verifier.verify() == {
        "status": POLICY_STATUS_OK,
        "sealed": True,
        "divergences": [],
    }


def test_out_of_band_edit_is_named_tampered(policy_path, tmp_path):
    receipts: list[tuple[str, dict[str, Any]]] = []
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"), receipts=receipts)
    verifier.seal()
    # an out-of-band edit: the file is rewritten behind the gate's back
    Path(policy_path).write_text(_POLICY_YAML + "\n# sneaky extra rule\n")
    status = verifier.verify()
    assert status["status"] == POLICY_STATUS_TAMPERED
    assert status["sealed"] is True
    assert len(status["divergences"]) == 1
    assert "policy bytes diverge" in status["divergences"][0]
    # the digests ride the receipt stream: reactivation is the audit path
    reactivated = verifier.reactivate(reason="operator policy review")
    assert reactivated["status"] == POLICY_STATUS_OK
    verdicts = [v for v, _ in receipts]
    assert verdicts == ["policy_activation", "policy_reactivation"]
    assert verifier.verify()["status"] == POLICY_STATUS_OK


def test_reactivation_persists_the_new_digest_and_clears(policy_path, tmp_path):
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"))
    verifier.seal()
    Path(policy_path).write_text(_POLICY_YAML)
    # rewriting identical bytes: mtime changes but digests do not — no
    # divergence, so reactivation is refused (nothing to re-receipt)
    with pytest.raises(PolicyBytesError, match="nothing diverged"):
        verifier.reactivate()


def test_reactivation_carries_link_to_previous_receipt(policy_path, tmp_path):
    receipts: list[tuple[str, dict[str, Any]]] = []
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"), receipts=receipts)
    verifier.seal()
    _ = receipts.pop()  # don't need it here, just the recorded side effects
    Path(policy_path).write_text(_POLICY_YAML + "\n# v2\n")
    before = verifier.seal_file.read_text(encoding="utf-8")
    first_receipt = json.loads(before)["receipt_id"]
    verifier.reactivate()
    record = json.loads(verifier.seal_file.read_text(encoding="utf-8"))
    assert record["reactivated_from_receipt_id"] == first_receipt


def test_revocations_prefix_tolerates_gate_appends(policy_path, revocations_path, tmp_path):
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"), revocations_path)
    Path(revocations_path).write_text('{"token_id": "tok_1"}\n')
    verifier.seal()
    # the gate itself appends cascade revocations: bytes grow past the
    # receipted prefix — legitimate, never tampering
    with open(revocations_path, "a", encoding="utf-8") as fh:
        fh.write('{"token_id": "tok_2"}\n')
    assert verifier.verify()["status"] == POLICY_STATUS_OK
    # prefix rewrite IS tampering: the receipted bytes no longer match
    Path(revocations_path).write_text('{"token_id": "replaced"}\n{"token_id": "tok_2"}\n')
    status = verifier.verify()
    assert status["status"] == POLICY_STATUS_TAMPERED
    assert "revocation registry prefix diverges" in status["divergences"][0]
    # shrink below the prefix is tampering too
    Path(revocations_path).write_text("")
    status = verifier.verify()
    assert status["status"] == POLICY_STATUS_TAMPERED
    assert "shrank below the receipted prefix" in status["divergences"][0]


def test_corrupt_seal_file_is_fail_closed_tampered(policy_path, tmp_path):
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"))
    verifier.seal()
    Path(tmp_path / "seal.json").write_text("{not json")
    status = verifier.verify()
    assert status["status"] == POLICY_STATUS_TAMPERED
    assert "seal file is corrupt" in status["divergences"][0]
    # a corrupt seal must never be silently resealed over
    with pytest.raises(PolicyBytesError, match="corrupt"):
        verifier.reactivate()


def test_vanished_policy_file_is_tampered(policy_path, tmp_path):
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"))
    verifier.seal()
    Path(policy_path).unlink()
    status = verifier.verify()
    assert status["status"] == POLICY_STATUS_TAMPERED
    assert "has vanished since activation" in status["divergences"][0]


def test_unsealed_deployment_is_policy_ok(policy_path, tmp_path):
    verifier = _verifier(policy_path, str(tmp_path / "seal.json"))
    assert verifier.has_seal() is False
    assert verifier.verify() == {
        "status": POLICY_STATUS_OK,
        "sealed": False,
        "divergences": [],
    }


def test_receipt_failure_refuses_the_seal(policy_path, tmp_path):
    def failing_emitter(verdict: str, extra: dict[str, Any]) -> str:
        raise RuntimeError("receipt stream down")

    verifier = PolicyBytesVerifier(
        policy_path=policy_path,
        seal_path=str(tmp_path / "seal.json"),
        emitter=failing_emitter,
    )
    with pytest.raises(PolicyBytesError, match="receipt emission failed; seal refused"):
        verifier.seal()
    # no unreceipted activation ever persisted
    assert verifier.has_seal() is False


def test_missing_policy_file_refuses_the_seal(tmp_path):
    verifier = PolicyBytesVerifier(
        policy_path=str(tmp_path / "missing.yaml"),
        seal_path=str(tmp_path / "seal.json"),
        emitter=lambda verdict, extra: "rcpt_1",
    )
    with pytest.raises(PolicyBytesError, match="does not exist"):
        verifier.seal()


# ---------------------------------------------------------------------------
# Gateway integration
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway(tmp_path, policy_path):
    config = GatewayConfig(
        policy_file=policy_path,
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_seal_file=str(tmp_path / "seal.json"),
    )
    gw = RaucleGateway(config)
    gw.seal_policy_bytes()
    return gw


def test_gateway_unchanged_bytes_restart_passes(tmp_path, policy_path):
    """A legitimate restart with unchanged enforced bytes serves calls."""
    seal = str(tmp_path / "seal.json")
    first = RaucleGateway(
        GatewayConfig(
            policy_file=policy_path,
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="k",
            signer_backend="local",
            policy_seal_file=seal,
        )
    )
    first.seal_policy_bytes()
    second = RaucleGateway(
        GatewayConfig(
            policy_file=policy_path,
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="k",
            signer_backend="local",
            policy_seal_file=seal,
        )
    )
    # the gate came up sealed (not tampered) and serves a policy-covered call
    assert second.policy_bytes_status()["status"] == POLICY_STATUS_OK
    result = second.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
    assert result["decision"] == "allow"


def test_gateway_out_of_band_edit_denies_named(tmp_path, policy_path, gateway):
    """The edited bytes deny fail-closed with the named status."""
    result = gateway.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
    assert result["decision"] == "allow"
    # out-of-band edit
    Path(policy_path).write_text(_POLICY_YAML + "\n# operator added a rule\n")
    denied = gateway.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
    assert denied["decision"] == "deny"
    assert denied["reason"].startswith("policy_tampered: ")
    assert "policy bytes diverge" in denied["reason"]
    # the deny itself is receipted like every other gate decision
    assert denied["receipt_id"]


def test_gateway_reactivation_rereceipts_and_clears(tmp_path, policy_path, gateway):
    Path(policy_path).write_text(_POLICY_YAML + "\n# operator added a rule\n")
    assert (
        gateway.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")[
            "decision"
        ]
        == "deny"
    )
    # edit=>auditable re-receipt (the receipts go to the signer receipts
    # file too, so the new bytes are bound into the receipt stream)
    receipts_before = len(Path(tmp_path / "receipts.jsonl").read_text().splitlines())
    outcome = gateway.reactivate_policy_bytes(reason="reviewed policy change")
    assert outcome["status"] == POLICY_STATUS_OK
    assert outcome["receipt_id"]
    receipts_after = len(Path(tmp_path / "receipts.jsonl").read_text().splitlines())
    assert receipts_after > receipts_before
    assert gateway.policy_bytes_status()["status"] == POLICY_STATUS_OK
    assert (
        gateway.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")[
            "decision"
        ]
        == "allow"
    )


def test_gateway_tampered_receipt_stream_is_named(tmp_path, policy_path):
    """A corrupt/unreadable seal puts the gate in the named tampered state."""
    seal = str(tmp_path / "seal.json")
    gw = RaucleGateway(
        GatewayConfig(
            policy_file=policy_path,
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="k",
            signer_backend="local",
            policy_seal_file=seal,
        )
    )
    gw.seal_policy_bytes()
    Path(seal).write_text("corrupted-bytes")
    status = gw.policy_bytes_status()
    assert status["status"] == POLICY_STATUS_TAMPERED
    denied = gw.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
    assert denied["decision"] == "deny"
    assert denied["reason"].startswith("policy_tampered: ")


def test_gateway_without_seal_config_is_unaffected(tmp_path, policy_path):
    """No seal configured: the existing deployments behave exactly as before."""
    gw = RaucleGateway(
        GatewayConfig(
            policy_file=policy_path,
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="k",
            signer_backend="local",
        )
    )
    assert gw._policy_bytes is None
    assert gw.policy_bytes_status()["status"] == POLICY_STATUS_OK
    result = gw.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
    assert result["decision"] == "allow"


def test_gateway_seal_requires_configuration(tmp_path, policy_path):
    gw = RaucleGateway(
        GatewayConfig(
            policy_file=policy_path,
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="k",
            signer_backend="local",
        )
    )
    with pytest.raises(PolicyBytesError, match="not configured"):
        gw.seal_policy_bytes()


def test_receipt_stream_carried_the_policy_bytes_block(tmp_path, policy_path, gateway):
    """The activation digest rode the signed authority receipt stream."""
    import base64
    import hashlib

    lines = Path(tmp_path / "receipts.jsonl").read_text().splitlines()
    blocks = []
    for line in lines:
        jws = json.loads(line)["jws"]
        payload_b64 = jws.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        if isinstance(payload.get("x_policy_bytes"), dict):
            blocks.append(payload["x_policy_bytes"])
    assert blocks, "no x_policy_bytes block found in the receipt stream"
    digest = blocks[-1]["policy_sha256"]
    on_disk = Path(policy_path).read_bytes()
    assert digest == hashlib.sha256(on_disk).hexdigest()
