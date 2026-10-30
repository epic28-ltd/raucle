# Receipts v1.2: credential-lease extension

Status: accepted 30 October 2026. Backwards compatible: receipts without
the extension are unaffected.

## What it binds

A credential LEASE is a gate-minted, time-limited grant of a vault secret's
USE, scoped by the delegated authority that authorised it. The agent holds
only a placeholder credential; the raw secret never traverses the agent
process. Every lease event is a receipt carrying an `x_lease` extension:

```
x_lease = {
    "action": "granted" | "denied" | "redeemed" | "revoked",
    "lease_id": "lease:<hex>",
    "capability_id": "<the authority of record>",
    "chain_digest": "<the v1.1 delegated-authority digest>",
    "secret_ref_hash": "sha256:<hash of the vault reference, never the secret>",
    "scopes": { <the standard constraint vocabulary, narrowed from the
                capability's constraints> },
    "ttl_seconds": 300,
    "granted_at": <epoch seconds>,
}
```

## Enforcement

- **granted**: the lease exists; the receipt cites the capability chain
  (v1.1) and the secret by hash only. The vault ref itself is not in the
  receipt unless the deployment opts in.
- **denied**: a lease request outside the delegated authority, or for a
  ref the capability's narrowing does not cover, denies - receipted like
  every other attributable denial.
- **redeemed**: the injection proxy swapped the placeholder for the real
  secret. The redemption's scopes must be a subset of the grant's and its
  moment (the receipt's own iat) must fall inside the grant's TTL window.
- **revoked**: the lease was revoked (cascade or explicit); like a
  revocation event, later redemptions are invalid.

## Verification rules (offline, no vault access required)

The verifier collects grants by `lease_id` as it walks the chain, then:

1. A `redeemed` receipt must cite a grant present in the chain ("redeemed
   with no lease grant" otherwise).
2. The redemption's iat must not exceed `granted_at + ttl_seconds`
   ("redeemed after lease expired" otherwise).
3. The redemption's scopes must be a subset of the grant's, checked with
   the standard narrowing rules - a wider scope is "redeemed beyond its
   granted scope".

A third party can therefore prove: which chain leased which secret (by
hash), when, for how long, with what scope, how many redemptions, and that
revocation stopped them - without ever seeing the secret.

## Homes (the 16.3 split)

- Evidence layer (this document, the verifier rules, the test vectors):
  OSS, public.
- Vault, lease manager (minting/redeeming/revocation workflows), injection
  proxy, admin surfaces: raucle-cloud, private.
- External-vault adapters: a later interface behind the built-in store.

## Test fixtures

tests/test_lease_receipts.py: grant + redemption verify; redemption after
expiry invalid; redemption with wider scope invalid; redemption without a
grant invalid; lease denial receipted; revocation verifies.