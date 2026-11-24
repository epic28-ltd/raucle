"""E (Q11): capability revocation depth: ancestry required for production
delegation.

Pre-Q11: CapabilityGate documents that without a parent_resolver, revoking
a grandparent may not revoke grandchildren. With a resolver the full-chain
revocation walk exists (REVOKE-DEPTH at the gate level); what was missing
is the production strict mode: when delegation depth beyond one level is
in use and no parent_resolver is configured, the deployment must refuse
to serve delegation-affected calls by name instead of silently depending
on short TTLs. These tests pin:

- strict mode + delegation-affected call + no resolver = a named refusal
  at the affected call (the gate surfaces refusals as GateDecision),
- strict mode + a configured delegation ledger that cannot back a
  resolver = a named boot refusal (the stronger form when the config
  unambiguously enables delegation),
- with the ancestry resolver configured, root/child/grandchild revocation
  each deny the descendant tree through the gateway's own paths,
- the resolver is read-only: racing resolver fetches stay consistent and
  a ledger append is visible on the next call (no stale cached ancestry
  beyond the registry's refresh cadence),
- the deep revocation survives a gateway restart.
"""

from __future__ import annotations

import json
import threading

import pytest

from raucle.capability import CapabilityGate, CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.trust_registry import TrustRegistry

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: transfer_funds
    agent_id: agent:billing
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""


def _issuer_and_chain():
    """A root, a child and a grandchild minted from one issuer."""
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    root = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
        ttl_seconds=3600,
    )
    child = issuer.attenuate(root, extra_constraints={"max_value": {"amount": 50}})
    grandchild = issuer.attenuate(child, extra_constraints={"max_value": {"amount": 10}})
    return issuer, root, child, grandchild


def _write_revocation(path, token_id: str, reason: str = "test") -> None:
    row = {"token_id": token_id, "reason": reason, "actor": "operator", "timestamp": "2026"}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


class TestStrictAncestryGate:
    def test_strict_gate_refuses_child_token_by_name(self):
        issuer, root, child, _ = _issuer_and_chain()
        pem = _issuer_public_pem(issuer)
        gate = CapabilityGate(
            trusted_issuers={issuer.key_id: pem},
            require_ancestry_resolver=True,
        )
        decision = gate.check(child, tool="transfer_funds", args={"amount": 5})
        assert decision.denied
        assert "RAUCLE_REQUIRE_ANCESTRY_RESOLVER" in decision.reason
        assert "parent_resolver" in decision.reason
        # The root token is NOT delegation-affected: it stays servable.
        root_decision = gate.check(root, tool="transfer_funds", args={"amount": 5})
        assert root_decision.allowed

    def test_non_strict_gate_keeps_the_existing_message(self):
        """Development affordance guard: without the strict flag the
        refusal stays the established no-resolver deny (unchanged)."""
        issuer, _root, child, _ = _issuer_and_chain()
        pem = _issuer_public_pem(issuer)
        gate = CapabilityGate(trusted_issuers={issuer.key_id: pem})
        decision = gate.check(child, tool="transfer_funds", args={"amount": 5})
        assert decision.denied
        assert "RAUCLE_REQUIRE_ANCESTRY_RESOLVER" not in decision.reason
        assert "no parent_resolver" in decision.reason


class TestStrictAncestryGatewayBoot:
    def test_boot_refuses_when_delegation_ledger_missing_under_strict(self, tmp_path):
        config = GatewayConfig(
            host="127.0.0.1",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
        )
        config.require_ancestry_resolver = True
        config.delegations_file = str(tmp_path / "delegations.jsonl")
        with pytest.raises(Exception) as excinfo:
            RaucleGateway(config)
        msg = str(excinfo.value)
        assert "RAUCLE_REQUIRE_ANCESTRY_RESOLVER" in msg
        assert "delegations.jsonl" in msg

    def test_boot_survives_when_the_ledger_backs_a_resolver(self, tmp_path):
        """The happy strict boot: the ledger exists, the resolver is
        configured, the gateway serves."""
        issuer, root, child, grandchild = _issuer_and_chain()
        paths = _seed_fleet(tmp_path, issuer, [root, child, grandchild])
        gw = RaucleGateway(paths["config"])
        agent_id, reason, decision = gw.authenticate_caller(
            capability_token=grandchild.to_dict(),
            tool="transfer_funds",
            args={"amount": 5},
        )
        assert agent_id == "agent:billing"
        assert reason == ""
        assert decision is None


class TestDeepRevocationThroughGateway:
    def test_root_and_child_revocation_each_deny_the_grandchild(self, tmp_path):
        issuer, root, child, grandchild = _issuer_and_chain()
        paths = _seed_fleet(tmp_path, issuer, [root, child, grandchild])
        gw = RaucleGateway(paths["config"])

        # Baseline: the grandchild is served with its full chain resolved.
        agent_id, reason, _ = gw.authenticate_caller(
            capability_token=grandchild.to_dict(),
            tool="transfer_funds",
            args={"amount": 5},
        )
        assert agent_id == "agent:billing", reason

        # Revoke the CHILD (depth 2): the grandchild is denied.
        _write_revocation(paths["revocations"], child.token_id)
        agent_id, reason, decision = gw.authenticate_caller(
            capability_token=grandchild.to_dict(),
            tool="transfer_funds",
            args={"amount": 5},
        )
        assert agent_id is None
        assert "revoked" in reason
        assert child.token_id in reason
        assert decision is None  # identity stage: not attributable

        # Revoke the ROOT (depth 3): the grandchild is still denied.
        _write_revocation(paths["revocations"], root.token_id)
        agent_id, reason, _ = gw.authenticate_caller(
            capability_token=grandchild.to_dict(),
            tool="transfer_funds",
            args={"amount": 5},
        )
        assert agent_id is None
        assert "revoked" in reason

    def test_deep_revocation_survives_a_gateway_restart(self, tmp_path):
        issuer, root, child, grandchild = _issuer_and_chain()
        paths = _seed_fleet(tmp_path, issuer, [root, child, grandchild])
        gw = RaucleGateway(paths["config"])
        _write_revocation(paths["revocations"], root.token_id)
        agent_id, reason, _ = gw.authenticate_caller(
            capability_token=grandchild.to_dict(),
            tool="transfer_funds",
            args={"amount": 5},
        )
        assert agent_id is None

        # A restarted gateway (fresh caches over the same files) denies
        # the same descendant: the revocation state is durable.
        gw2 = RaucleGateway(paths["config"])
        agent_id2, reason2, _ = gw2.authenticate_caller(
            capability_token=grandchild.to_dict(),
            tool="transfer_funds",
            args={"amount": 5},
        )
        assert agent_id2 is None, reason2
        assert "revoked" in reason2

    def test_unrelated_chain_is_unaffected(self, tmp_path):
        """Revoking one chain never denies an unrelated sibling chain."""
        issuer, root, child, grandchild = _issuer_and_chain()
        other_root, other_child = _second_chain(issuer)
        # The sibling chain registers in full (root and child): a
        # half-registered sibling would fail the resolver walk on the
        # missing ancestor, which is the unresolved-chain deny, not the
        # revocation isolation this test pins.
        paths = _seed_fleet(tmp_path, issuer, [root, child, grandchild, other_root, other_child])
        gw = RaucleGateway(paths["config"])
        _write_revocation(paths["revocations"], root.token_id)
        agent_id, reason, _ = gw.authenticate_caller(
            capability_token=other_child.to_dict(),
            tool="transfer_funds",
            args={"amount": 5},
        )
        assert agent_id == "agent:billing", reason


class TestResolverFreshness:
    def test_racing_resolver_fetches_stay_consistent(self, tmp_path):
        """The resolver is read-only: concurrent fetches return identical
        material and never mutate the ledger under them."""
        issuer, root, child, grandchild = _issuer_and_chain()
        recs = [root, child, grandchild]
        paths = _seed_fleet(tmp_path, issuer, recs, gateway=False)
        ledger = DelegationLedger(paths["delegations"])
        resolver = ledger.resolver()

        token_ids = [t.token_id for t in recs]
        results: list[list] = []
        errors: list[Exception] = []

        def fetch_round():
            try:
                out = []
                for _ in range(50):
                    for tid in token_ids:
                        cap = resolver(tid)
                        out.append((tid, cap.body() if cap is not None else None))
                results.append(out)
            except Exception as exc:  # pragma: no cover - surfaced by assert
                errors.append(exc)

        threads = [threading.Thread(target=fetch_round) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert errors == []
        assert results[0] == results[1], "racing resolver fetches diverged"

    def test_ledger_append_is_visible_on_the_resolver_next_call(self, tmp_path):
        """No stale cached ancestry beyond the registry refresh cadence:
        an appended delegation record resolves on the next fetch."""
        issuer, root, child, grandchild = _issuer_and_chain()
        paths = _seed_fleet(tmp_path, issuer, [root, child], gateway=False)
        ledger = DelegationLedger(paths["delegations"])
        resolver = ledger.resolver()
        assert resolver(grandchild.token_id) is None

        ledger.register(grandchild, verifying_key=_issuer_public_pem(issuer))
        assert resolver(grandchild.token_id) is not None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _issuer_public_pem(issuer: CapabilityIssuer) -> str:
    pem = issuer.public_key_pem
    return pem.decode() if isinstance(pem, bytes) else pem


def _seed_fleet(tmp_path, issuer, tokens, *, gateway=True) -> dict:
    """Publish trust, register the tokens in the delegation ledger and
    return the gateway config + surface paths."""
    registry_path = tmp_path / "registry.jsonl"
    TrustRegistry(path=registry_path).publish(_issuer_public_pem(issuer), issuer="platform.test")
    delegations_path = tmp_path / "delegations.jsonl"
    revocations_path = tmp_path / "revocations.jsonl"
    ledger = DelegationLedger(delegations_path)
    for token in tokens:
        ledger.register(token, verifying_key=_issuer_public_pem(issuer))
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        host="127.0.0.1",
        signer_backend="local",
        policy_file=str(policy_path),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(registry_path),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
        delegations_file=str(delegations_path),
        revocations_file=str(revocations_path),
    )
    if gateway:
        config.gate_auth = "token"
    return {
        "config": config,
        "delegations": delegations_path,
        "revocations": revocations_path,
    }


def _second_chain(issuer: CapabilityIssuer):
    """An unrelated root/child pair from the same issuer."""
    other_root = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 7}},
        ttl_seconds=3600,
    )
    other_child = issuer.attenuate(other_root, extra_constraints={"max_value": {"amount": 5}})
    return other_root, other_child
