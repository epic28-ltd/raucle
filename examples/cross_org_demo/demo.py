"""Cross-org agent handshake — two companies, one shared registry, no prior key swap.

No API key, no network. Two organisations (a bank "Org A" and a payments gateway
"Org B") each publish their issuer key to ONE shared Trust Registry. Org A's
agent then calls Org B's agent. Org B has never held Org A's key: it resolves it
from the registry, capability-gates the call, and signs an acknowledgement that
Org A verifies the same way. This is the interop primitive for multi-agent
ecosystems — trust comes from the shared registry, not a bilateral key exchange.

    pip install 'raucle[compliance]'
    python examples/cross_org_demo/demo.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from raucle.audit import Ed25519Signer
from raucle.capability import CapabilityIssuer
from raucle.handshake import accept_call, build_request, verify_ack
from raucle.replay_store import SqliteReplayStore
from raucle.trust_registry import TrustRegistry


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="raucle-cross-org-"))
    reg_path = workdir / "registry.jsonl"
    replay_store = SqliteReplayStore(workdir / "replay.sqlite3")

    print("=" * 72)
    print("Setup — one shared Trust Registry; two orgs publish their keys")
    print("=" * 72)
    operator = Ed25519Signer.generate()  # whoever runs the registry
    registry = TrustRegistry(reg_path, operator_signer=operator)

    org_a = CapabilityIssuer.generate(issuer="org-a.bank")  # Org A's issuer
    org_b = Ed25519Signer.generate()  # Org B's responder key
    ka = registry.publish(org_a.public_key_pem, issuer=org_a.issuer)  # canonical issuer id
    kb = registry.publish(org_b.public_key_pem().decode(), issuer="org-b.gateway")
    print(f"  Org A published key_id {ka}")
    print(f"  Org B published key_id {kb}")
    print("  (A and B have NEVER exchanged keys directly)\n")

    # Org A mints a token scoped to exactly what its task may do.
    token = org_a.mint(
        agent_id="agent:a.invoice-bot",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}, "allowed_values": {"to": ["acct:b-co"]}},
        ttl_seconds=300,
    )

    print("=" * 72)
    print("Scene 1 — Org A's agent calls Org B with a legitimate $50 transfer")
    print("=" * 72)
    req = build_request(
        token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50}, nonce="h1"
    )
    res = accept_call(req, registry=registry, responder_signer=org_b, responder_id="org-b.gateway", replay=replay_store)
    print(
        f"  Org B resolved Org A from the registry, then: {'ACCEPT' if res.accepted else 'REJECT'}"
    )
    ok, why = verify_ack(res.ack_receipt, registry=registry, expected_nonce="h1")
    print(f"  Org A verifies Org B's signed ack (resolving B from the registry): {ok} ({why})\n")

    print("=" * 72)
    print("Scene 2 — a prompt-injected $9,900 transfer to an attacker")
    print("=" * 72)
    bad = build_request(
        token, tool="transfer_funds", args={"to": "acct:attacker", "amount": 9900}, nonce="h2"
    )
    res2 = accept_call(bad, registry=registry, responder_signer=org_b, responder_id="org-b.gateway", replay=replay_store)
    print(f"  Org B decision: {'ACCEPT' if res2.accepted else 'REJECT'} ({res2.reason})")
    ack2_ok = verify_ack(res2.ack_receipt, registry=registry)[0]
    print(f"  The signed REJECT ack still verifies: {ack2_ok}\n")

    print("=" * 72)
    print("Scene 3 — Org A's key is revoked in the registry")
    print("=" * 72)
    registry.revoke(ka, reason="key compromised")
    req3 = build_request(
        token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50}, nonce="h3"
    )  # a fresh nonce: scene 1's nonce is consumed and its replay would be refused
    res3 = accept_call(
        req3,
        registry=registry,
        responder_signer=org_b,
        responder_id="org-b.gateway",
        replay=replay_store,
    )
    verdict3 = "ACCEPT" if res3.accepted else "REJECT"
    print(f"  Org B rejects BEFORE the gate even runs: {verdict3} ({res3.reason})")

    print(f"\nRegistry left at: {reg_path}")

    ok_all = (
        res.accepted
        and verify_ack(res.ack_receipt, registry=registry, expected_nonce="h1")[0]
        and not res2.accepted
        and not res3.accepted
    )
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
