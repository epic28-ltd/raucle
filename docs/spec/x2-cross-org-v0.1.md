# X2 slice 3: cross-org receipt verification (v0.1)

Status: implemented (`raucle/cross_org.py`, the cross-org mode in
`assets/verifier/x2-verifier.html`, fixture set
`assets/verifier/fixtures/cross-org/`, tests `tests/test_cross_org_verify.py`
plus the extended node harness `tests/verifier_harness/x2_harness.mjs`).

## The acceptance

A third party verifies ANOTHER organisation's receipt in a browser with no
raucle install and no prior key exchange, holding exactly two artefacts and
one out-of-band pin:

- the receipt chain (envelope lines signed by org A's agent key),
- the registry artifact (the Trust Registry's operator-signed JSONL log),
- the registry operator's public key, pinned out of band.

No trust is placed in either organisation's operator: org A's key is never
taken from org A, and the verifier resolves it through the registry alone.
The registry operator is the single trust anchor, and only through the
pinned key, never through anything riding the artifact.

## The four legs

1. **The registry leg** (`verifyRegistryArtifact` in the page,
   `TrustRegistry.verify_integrity` with the pinned anchor in Python). The
   artifact must be operator-signed: an unsigned log cannot anchor trust
   and is refused by name. The hash chain is recomputed entry by entry,
   every operator signature is verified against the PINNED key, register
   entries must bind `key_id` to the SHA-256 of their public key, and
   active issuer names are unique per algorithm namespace.
2. **The receipt leg.** Every `agent_key_id` the chain names is resolved
   through the registry: an unknown key or a revoked key is a named,
   fail-closed refusal. The signatures are then verified by the same
   machinery an auditor runs (Python: `ProvenanceVerifier`; the page: the
   shipped `verifyChainText`, unchanged).
3. **The scope leg (what was allowed).** When the registry record's
   metadata carries the org's published capability statement, the receipt
   is held to it: the statement must bind the SAME key (a statement for
   another key is substitutable scope material and is refused), its
   signature must verify against the registry-resolved key, the receipt's
   agent identity must match, the statement must not have expired, and the
   receipt's tool/model must be within the published allowances. When no
   statement is published the leg reads UNSTATED by name, never green.
4. **The registration leg (when it was registered).** The transparency
   log's inclusion proof (X2 slice 2) binds the chain's LEAF receipt
   (the last envelope) to a signed epoch checkpoint, verified against a
   separately pinned log operator key. The key riding the proof is
   convenience material, never verification input: a proof without a pin
   is refused as LOG-UNPINNED rather than verified self-attested. The
   verdict surfaces `registered_at` (the committed entry) and the signed
   checkpoint `iat`, the operator-independent point in time.

## What the browser page ships

The cross-org section of `x2-verifier.html` takes the receipt (envelope
lines or a bare compact JWS), the registry artifact, the pinned anchor,
optional freshness pins (minimum head index, expected head hash, maximum
artifact age), and the optional inclusion proof with its pinned log key.
It renders one verdict line plus the four legs with named reasons. The
no-network discipline is unchanged and still test-pinned: no external
references, no network-capable API literals, exactly two inline script
blocks, all vendored bytes hash-pinned in `ASSET-HASHES.json`.

The node harness proves the BROWSER implementation against the committed
fixture: clean cross-org green, tampered registry refused, wrong anchor
refused with the operator-signature reason, stale freshness pins refused,
a proof pinned to the wrong log key refused, a doctored proof refused,
and an unpinned proof refused. A render probe runs the shipped UI wiring
against a stub document and asserts the verdict text and the four rendered
legs, so the click path a human uses is exercised, not just the core.

## Honest limits

- **The anchor is the whole trust model.** Pin the wrong operator key and
  the artifact refuses; pin nothing and the page refuses. But the pin
  itself is out-of-band by construction: nothing here can tell you whether
  the pinned key is the RIGHT registry operator. That judgement is the
  human's, same doctrine as the audit-pack custodian pin.
- **Freshness pins are caller-supplied.** Without any pin, a chain-valid,
  fully signed but STALE snapshot still verifies. A rollback that hides a
  later revocation is only caught when the consumer pins the head (index
  or hash) or a maximum age. The page exposes all three pins; using them
  is the verifier's discipline, not the page's.
- **The scope leg is only as strong as the publication.** An org that
  publishes no capability statement gets UNSTATED scope, and the verdict
  stays green on the signature and hash legs alone. The statement is the
  org's own claim about its agent, carried in registry metadata: it is
  authoritative for scope only because the registry operator countersigned
  the record that carries it.
- **The registration leg binds the leaf.** The inclusion proof names the
  LAST envelope's digest. A third party registering a different line must
  target it explicitly (the Python API's `expect_digest` path through
  `verify_log_inclusion`).
- **The log proves what was registered, not that everything was.**
  Withholding remains the operator's residual (the slice-2 doctrine,
  unchanged).
- **PQ hybrids stay refused in-browser.** Receipts declaring `raucle/pq1`
  are denied with that named reason, exactly as in slice 1: a partially
  verified hybrid must never be reported as verified.
- **The registry text and network loaders now reject duplicate JSON keys**
  (the file path always did). A crafted entry with duplicate keys must not
  smuggle a `key_id` past integrity checks.

## Regenerating the fixture

`scripts/x2_cross_org_fixtures.py` rebuilds
`assets/verifier/fixtures/cross-org/` from the real production paths
(`TrustRegistry`, `ProvenanceLogger`, `compute_log_entry_hash`); the
generator round-trips through `verify_receipt_cross_org` in the test
suite, then `scripts/x2_asset_hashes.py` re-pins the bytes. The two
committed `.pem` files are the out-of-band anchors, committed so the
acceptance tests can pin them; in a real verification each anchor travels
out of band, never inside the artifact it authenticates.
