"""P4.A v0: receipted containment (emergency authority stop).

Acceptance criteria (P4.A lane):

- hold => further gate calls deny (named deny reason) for the held scope;
- resume => the pre-hold bytes are restored byte-exactly (sha256 both sides);
- the hold and the resume are each a signed, offline-verifiable receipt
  (a halt without its receipt is a bug);
- hostile paths: a hold during a concurrent activation that locks the
  target file fails named (exit 1, flock); a malformed scope fails named
  (exit 1).
"""

import base64
import fcntl
import hashlib
import json
import os

import pytest

from raucle.capability import CapabilityGate, CapabilityIssuer, DelegationLedger
from raucle.cli import main as cli_main
from raucle.containment import (
    VERDICT_HOLD,
    VERDICT_RESUME,
    ContainmentConfig,
    ContainmentError,
    ContainmentManager,
)
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.verdicts import VerdictSigner, VerdictVerifier

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _config(tmp_path) -> ContainmentConfig:
    return ContainmentConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        revocations_file=str(tmp_path / "revocations.jsonl"),
        delegations_file=str(tmp_path / "delegations.jsonl"),
        receipts_path=str(tmp_path / "containment-receipts.jsonl"),
        state_dir=str(tmp_path / "containment"),
        actor="op",
    )


@pytest.fixture
def gw(tmp_path):
    """A live gateway on the same policy file the CLI will hold."""
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "gateway-receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
    )
    return RaucleGateway(config)


def _read_receipts(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _verdict_payload(jws: str) -> dict:
    part = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _export_signer_pem(signer) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return signer._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


class TestOperatorKeypin:
    """RED-028 honest mitigation: the operator keypair fingerprint is
    pinned at hold-request time; a post-hold re-anchor is DETECTABLE
    (operator_key_changed), not silently accepted. The pre-hold swap
    window stays a documented limit (R3-L1)."""

    def test_resume_after_unchanged_operator_key_succeeds(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        policy = tmp_path / "policies.yaml"
        original = policy.read_bytes()
        mgr.hold(scope="global", reason="pin drill")
        resumed = mgr.resume(reason="done")
        assert resumed["status"] == "resumed"
        assert policy.read_bytes() == original

    def test_hold_receipt_and_state_carry_the_pinned_fingerprint(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        held = mgr.hold(scope="global", reason="pin drill")
        fp = held["operator_key_fingerprint"]
        expected = hashlib.sha256(
            (tmp_path / "containment" / "containment-operator-pubkey.pem").read_bytes()
        ).hexdigest()
        assert fp == expected
        # the hold receipt pins the same fingerprint
        receipts = _read_receipts(cfg.receipts_path)
        payload = _verdict_payload(receipts[0]["jws"])
        assert payload["extra"]["operator_key_fingerprint"] == expected
        # the held state carries it too
        state = json.loads((tmp_path / "containment" / "containment-state.json").read_text())
        assert state["operator_key_fingerprint"] == expected

    def test_post_hold_keypair_swap_refuses_named(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.hold(scope="global", reason="incident")
        state_dir = tmp_path / "containment"
        # the attacker swaps the anchor AFTER the hold (RED-028 shape)
        attacker = VerdictSigner.generate()
        (state_dir / "containment-operator-key.pem").write_bytes(_export_signer_pem(attacker))
        with pytest.raises(ContainmentError, match="operator_key_changed"):
            mgr.resume(reason="try the swap")
        # fail-closed: the policy bytes were NOT restored
        assert (state_dir / "containment-state.json").exists()

    def test_removed_keypair_refuses_without_minting_a_new_anchor(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.hold(scope="global", reason="incident")
        key_path = tmp_path / "containment" / "containment-operator-key.pem"
        key_path.unlink()
        with pytest.raises(ContainmentError, match="operator_key_changed"):
            mgr.resume(reason="try again")
        assert not key_path.exists()  # no fresh anchor minted by the failed resume

    def test_pre_keypin_held_state_refuses_named(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.hold(scope="global", reason="incident")
        state_path = tmp_path / "containment" / "containment-state.json"
        state = json.loads(state_path.read_text())
        del state["operator_key_fingerprint"]
        state_path.write_text(json.dumps(state, sort_keys=True))
        with pytest.raises(ContainmentError, match="operator_key_unpinned"):
            mgr.resume(reason="legacy")


class TestGlobalHoldResume:
    def test_hold_denies_then_resume_restores_bytes(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        policy = tmp_path / "policies.yaml"
        original = policy.read_bytes()
        original_sha = _sha(original)

        held = mgr.hold(scope="global", reason="drill")
        assert held["status"] == "held"
        assert held["receipt_id"]

        # the gate's existing deny machinery enforces the stop
        gw.reload_policies()
        result = gw.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
        assert result["decision"] == "deny"
        assert "no policy configured for tool" in result["reason"]

        # the deny-all policy is a valid, loadable zero-rule policy
        assert gw._policy_rules == {}

        resumed = mgr.resume(reason="drill over")
        assert resumed["status"] == "resumed"
        assert resumed["restored_sha256"] == original_sha
        # byte-exact restore, sha256-verified both sides
        assert policy.read_bytes() == original
        gw.reload_policies()
        ok = gw.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
        assert ok["decision"] == "allow"

    def test_hold_and_resume_receipts_verify_offline(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.hold(scope="global", reason="incident")
        mgr.resume(reason="incident closed")

        receipts = _read_receipts(cfg.receipts_path)
        verdicts = [_verdict_payload(r["jws"])["verdict"] for r in receipts]
        assert verdicts == [VERDICT_HOLD, VERDICT_RESUME]

        pubkey = (tmp_path / "containment" / "containment-operator-pubkey.pem").read_bytes()
        verifier = VerdictVerifier(public_key_pem=pubkey)
        for receipt, verdict in zip(receipts, verdicts, strict=False):
            payload = verifier.verify(receipt["jws"])
            assert payload.verdict == verdict
            assert payload.extra["actor"] == "op"
        # each receipt's envelope hash binds the JWS
        for receipt in receipts:
            assert (
                "sha256:" + hashlib.sha256(receipt["jws"].encode("ascii")).hexdigest()
                == receipt["receipt_hash"]
                or hashlib.sha256(receipt["jws"].encode("ascii")).hexdigest()
                == receipt["receipt_hash"]
            )

    def test_resume_after_restore_digest_mismatch_refuses(self, tmp_path, gw):
        """Tampering with the snapshot digest blocks the resume (fail-closed)."""
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.hold(scope="global")
        state = json.loads((tmp_path / "containment" / "containment-state.json").read_text())
        state["original_sha256"] = "0" * 64
        (tmp_path / "containment" / "containment-state.json").write_text(json.dumps(state))
        with pytest.raises(ContainmentError, match="digest mismatch"):
            mgr.resume()
        # still held
        assert mgr.status()["held"] is True

    def test_double_hold_refused(self, tmp_path, gw):
        mgr = ContainmentManager(_config(tmp_path))
        mgr.hold(scope="global")
        with pytest.raises(ContainmentError, match="already held"):
            mgr.hold(scope="global")

    def test_resume_without_hold_refused(self, tmp_path, gw):
        mgr = ContainmentManager(_config(tmp_path))
        with pytest.raises(ContainmentError, match="not held"):
            mgr.resume()

    def test_receipt_emission_failure_rolls_back_the_hold(self, tmp_path, gw, monkeypatch):
        """No unreceipted halt: receipt failure rolls the policy back."""
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        policy = tmp_path / "policies.yaml"
        original = policy.read_bytes()

        def boom(*a, **k):
            raise OSError("receipt stream unavailable")

        monkeypatch.setattr(ContainmentManager, "_emit_receipt", boom)
        with pytest.raises(ContainmentError, match="receipt emission failed"):
            mgr.hold(scope="global")
        # rolled back: the gate still allows
        assert policy.read_bytes() == original


class TestScopedHolds:
    @pytest.fixture
    def chains(self, tmp_path):
        issuer = CapabilityIssuer.generate(issuer="test-issuer")
        ledger = DelegationLedger(tmp_path / "delegations.jsonl")
        root = issuer.mint(
            agent_id="agent:svc",
            tool="lookup_balance",
            constraints={"allowed_values": {"account": ["ACC-001"]}},
            ttl_seconds=600,
        )
        child = issuer.attenuate(root)
        ledger.register(root, "agent:svc", verifying_key=issuer)
        ledger.register(child, "agent:svc", verifying_key=issuer)
        other = issuer.mint(
            agent_id="agent:other",
            tool="other_tool",
            constraints={},
            ttl_seconds=600,
        )
        ledger.register(other, "agent:other", verifying_key=issuer)
        return issuer, root, child, other

    def test_agent_hold_revokes_subtree_and_resume_restores_revocations(self, tmp_path, chains):
        issuer, root, child, other = chains
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        rev_path = tmp_path / "revocations.jsonl"
        assert not rev_path.exists()

        held = mgr.hold(scope="agent", scope_id="agent:svc", reason="agent compromise")
        assert held["status"] == "held"
        assert set(held["revoked_ids"]) == {root.token_id, child.token_id}

        # the gate's revocation machinery refuses the held chain
        gate = CapabilityGate(
            trusted_issuers={issuer.key_id: issuer.public_key_pem},
            parent_resolver=DelegationLedger(cfg.delegations_file).resolver(),
            revoked_token_ids={r["token_id"] for r in _read_receipts_of(rev_path)},
        )
        denied = gate.check(
            child,
            tool="lookup_balance",
            agent_id="agent:svc",
            args={"account": "ACC-001"},
        )
        assert not denied.allowed
        # an untouched agent's chain is not collateral
        assert "agent:other" not in json.dumps(held)

        resumed = mgr.resume()
        assert resumed["status"] == "resumed"
        # byte-exact restore: the revocations file did not exist before
        assert not rev_path.exists() or rev_path.read_bytes() == b""
        # the chain is live again
        gate2 = CapabilityGate(
            trusted_issuers={issuer.key_id: issuer.public_key_pem},
            parent_resolver=DelegationLedger(cfg.delegations_file).resolver(),
            revoked_token_ids=set(),
        )
        allowed = gate2.check(
            child,
            tool="lookup_balance",
            agent_id="agent:svc",
            args={"account": "ACC-001"},
        )
        assert allowed.allowed

    def test_chain_hold_scopes_to_subtree(self, tmp_path, chains):
        issuer, root, child, other = chains
        mgr = ContainmentManager(_config(tmp_path))
        held = mgr.hold(scope="chain", scope_id=root.token_id)
        assert held["revoked_ids"] == [root.token_id, child.token_id]
        mgr.resume()

    def test_agent_hold_receipted(self, tmp_path, chains):
        mgr = ContainmentManager(_config(tmp_path))
        mgr.hold(scope="agent", scope_id="agent:svc")
        mgr.resume()
        receipts = _read_receipts(_config(tmp_path).receipts_path)
        assert [_verdict_payload(r["jws"])["verdict"] for r in receipts] == [
            VERDICT_HOLD,
            VERDICT_RESUME,
        ]
        assert receipts[0]
        assert receipts[1]


def _read_receipts_of(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class TestHostilePaths:
    def test_concurrent_activation_lock_blocks_hold(self, tmp_path, gw):
        """A concurrent activation holding the policy file's flock fails
        the hold with a named error (no interleaving, no half-written policy)."""
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        policy = tmp_path / "policies.yaml"
        fd = os.open(policy, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(ContainmentError, match="concurrent activation"):
                mgr.hold(scope="global")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        # the policy was not touched
        assert _sha(policy.read_bytes()) == _sha(POLICY.encode())
        assert mgr.status()["held"] is False

    def test_malformed_scope_via_cli_exit_1(self, tmp_path, capsys):
        # unknown scope is argparse-level (exit 2); malformed agent id is ours (exit 1)
        rc = cli_main(
            [
                "containment",
                "hold",
                "agent",
                "not-an-agent",
                "--policy-file",
                str(tmp_path / "p.yaml"),
                "--delegations-file",
                str(tmp_path / "d.jsonl"),
                "--revocations-file",
                str(tmp_path / "r.jsonl"),
                "--receipts",
                str(tmp_path / "c.jsonl"),
                "--state-dir",
                str(tmp_path / "state"),
            ]
        )
        assert rc == 1
        assert "malformed scope" in capsys.readouterr().err

    def test_unknown_chain_token_exit_1(self, tmp_path, capsys):
        (tmp_path / "d.jsonl").write_text("")
        rc = cli_main(
            [
                "containment",
                "hold",
                "chain",
                "tok-nonexistent",
                "--delegations-file",
                str(tmp_path / "d.jsonl"),
                "--revocations-file",
                str(tmp_path / "r.jsonl"),
                "--receipts",
                str(tmp_path / "c.jsonl"),
                "--state-dir",
                str(tmp_path / "state"),
            ]
        )
        assert rc == 1
        assert "delegation ledger" in capsys.readouterr().err

    def test_agent_hold_without_delegations_exit_1(self, tmp_path, capsys):
        rc = cli_main(
            [
                "containment",
                "hold",
                "agent",
                "agent:svc",
                "--receipts",
                str(tmp_path / "c.jsonl"),
                "--state-dir",
                str(tmp_path / "state"),
            ]
        )
        assert rc == 1
        assert (
            "revocations_file" in capsys.readouterr().err
            or "delegations_file" in capsys.readouterr().err
        )

    def test_global_hold_reported_by_status(self, tmp_path, gw, capsys):
        rc = cli_main(
            [
                "containment",
                "hold",
                "global",
                "--reason",
                "drill",
                "--policy-file",
                str(tmp_path / "policies.yaml"),
                "--receipts",
                str(tmp_path / "c.jsonl"),
                "--state-dir",
                str(tmp_path / "state"),
            ]
        )
        assert rc == 0
        rc = cli_main(
            [
                "containment",
                "status",
                "--receipts",
                str(tmp_path / "c.jsonl"),
                "--state-dir",
                str(tmp_path / "state"),
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "HELD" in out
        assert "scope=global" in out
        assert "drill" in out
        rc = cli_main(
            [
                "containment",
                "resume",
                "--receipts",
                str(tmp_path / "c.jsonl"),
                "--state-dir",
                str(tmp_path / "state"),
            ]
        )
        assert rc == 0
        assert "resumed" in capsys.readouterr().out
