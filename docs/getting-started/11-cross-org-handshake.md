# 11. Cross-org agent handshake

Two agents from different companies can establish a verifiable, capability-gated
call **without exchanging keys beforehand** — they resolve each other from the
shared [Trust Registry](10-trust-registry.md). This is the interop primitive for
multi-agent ecosystems: trust comes from the registry, not a bilateral key swap.

```bash
pip install 'raucle[compliance]'
```

## The flow

```python
from raucle.handshake import build_request, accept_call, verify_ack

# Org A (initiator): present a minted capability token + the concrete call.
request = build_request(
    token, tool="transfer_funds", args={"to": "acct:b-co", "amount": 50}, nonce="h1"
)

# Org B (responder): resolve A's key_id from the SHARED registry (fail-closed on
# unknown/revoked), capability-gate the call, return a SIGNED acknowledgement.
result = accept_call(
    request, registry=shared_registry, responder_signer=org_b_signer, responder_id="org-b.gateway"
)

# Org A: verify B's ack by resolving B's key from the SAME registry.
ok, why = verify_ack(result.ack_receipt, registry=shared_registry, expected_nonce="h1")
```

Org B never held Org A's key. It resolved `token.key_id` from the registry,
checked revocation, ran the gate, and signed an ACCEPT/REJECT. Org A verifies
that ack the same way. The result is a cross-org receipt pair anchored in the
registry.

## What it guarantees

- **No prior key exchange.** A and B trust each other only via the shared
  registry. Each new publisher makes the next cross-org call trivial.
- **Fail-closed.** An initiator key that is unknown or revoked in the registry
  is rejected *before the gate runs*. Revocation propagates to every verifier
  through the registry, with no bilateral coordination.
- **Mutual evidence.** Both the call decision and the acknowledgement are
  signed and registry-verifiable, so each side holds proof of the other's
  action.
- **Anti-replay.** The `nonce` binds an ack to a specific handshake; a replayed
  ack with a different nonce is rejected.

See the runnable [examples/cross_org_demo](../../examples/cross_org_demo/)
(no API key): legitimate call accepted, injection rejected, revoked-key rejected.

---

This is P2 of the ecosystem-infrastructure track, built on the
[Trust Registry](10-trust-registry.md) (P1).
