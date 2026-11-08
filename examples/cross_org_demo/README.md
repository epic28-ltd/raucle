# Cross-org agent handshake — trust from a shared registry

A **runnable** demo (no API key, no network) of the interop primitive for
multi-agent ecosystems: two organisations establish a verifiable, capability-gated
call **without any prior key exchange between them.**

```bash
pip install 'raucle[compliance]'
python examples/cross_org_demo/demo.py
```

Two orgs (a bank and a payments gateway) each publish their issuer key to ONE
shared [Trust Registry](../../docs/getting-started/10-trust-registry.md). Then:

1. **Org A calls Org B with a legitimate $50 transfer.** Org B has never held
   Org A's key — it resolves it from the registry, capability-gates the call,
   and returns a signed ACCEPT that Org A verifies the same way (resolving B).
2. **A prompt-injected $9,900 transfer to an attacker is REJECTED** at Org B's
   gate. The signed REJECT ack still verifies.
3. **Org A's key is revoked in the registry** → Org B rejects *before the gate
   even runs*. Revocation propagates to every verifier through the shared
   registry, with no bilateral coordination.

The point: trust comes from the shared registry, not a per-pair key swap. That
is the network effect — each org that publishes makes the next cross-org
verification trivial. The exit code is a CI self-test
([tests/test_handshake.py](../../tests/test_handshake.py)).

## The receipt-bound bilateral policy diff (EPIC S2)

`policy_diff_demo.py` — same two-org setting, after the incident review:

```bash
pip install 'raucle[server,compliance]'
python examples/cross_org_demo/policy_diff_demo.py
```

Org A replays its incident chain against the stricter alternative policy,
SIGNS the resulting diff (chain head + both policy digests + the verdict),
and Org B verifies it OFFLINE with a key resolved from the shared registry:
the replay is re-run and must match the signed summary exactly. The demo
ends with the dishonesty check — a retyped verdict fails closed.

[EPIC S2 details in `raucle/policy_diff.py`.]
