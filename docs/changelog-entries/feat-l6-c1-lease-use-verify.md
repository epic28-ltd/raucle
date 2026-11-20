- Lease-use verification (C1 remainder, spec
  docs/spec/provenance/v1.2/lease-extension.md): a lease-use receipt now
  verifies only while the lease is valid and its use is scope-matched. The
  offline verifier rejects a redemption whose lease was revoked at an
  earlier line (`lease_revoked`), on the same temporal doctrine as the A3
  cascade: an `x_lease` `revoked` event and an `x_revocation` block citing
  the lease id are both revocation evidence, and a redemption before the
  revocation line stays valid evidence.
- The lease redemption refusals are named in the verifier errors:
  `pairing_absent` (no grant from an earlier line in the chain),
  `lease_expired` (the redemption's iat past the grant's TTL window),
  `scope_exceeded` (a redemption wider than its grant, the narrowing
  invariant) and `lease_revoked`. Each failure names its class, never a
  generic invalid.
- The shared forbidden-field sweep now covers the `x_lease` block: lease
  receipts carry handles, the grant pairing, scope names and digests only,
  never content; a content-like field anywhere inside the block fails with
  the sweep's named error.
- The verification report body is unchanged: the named errors ride the
  existing `errors` list and no new report keys are added, so the v1.0
  byte shape is preserved and the digest pins and fixture packs stand as
  they were (pinned by test).
