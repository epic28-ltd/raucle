# Receipts v1.2: revocation-event receipts (x_revocation)

Status: draft 18 November 2026 for the v1.2 kind specified here. The
shipped emitter (cascade revocation, accepted 30 October 2026) mints
the v1.0 shape; both are valid, because revocation is a new link in the
chain, never an edit.

## What it binds

A revocation event: a prior receipt, lease or capability was revoked,
by whom, when, and why by class. A revocation receipt testifies to the
revocation WITHOUT trusting the revoker: it carries chain linkage back
to the revoked object, the revoking identity, the reason class and the
timestamp, and no content. A third party holding the chain and the
revoked object verifies the linkage by hash: the revoker's word is
evidence, not authority.

Every receipt kind before this one records an action the system took. A
revocation receipt records that an authority ended. That is why its
shape is stricter than a deny: a deny says this call was refused; a
revocation says every future call on this authority is refused, and the
record must stand for the life of the archive.

## The block

    x_revocation = {
      "version": "revocation/v1",
      "kind": "capability" | "lease" | "receipt",
      "revoked_ids": ["<the revoked objects' identifiers>"],
      "revoked_hashes": {"<revoked id>": "sha256:<hash of that object>"},
      "actor": "<the revoking identity>",
      "reason_class": "<closed vocabulary>",
      "reason": "<optional free-text detail>",
      "revoked_at": <epoch seconds>
    }

Mandatory: `version`, `kind`, `revoked_ids`, `revoked_hashes`, `actor`,
`reason_class`, `revoked_at`. Optional: `reason`.

Field rules:

- **kind** is the closed vocabulary of revocable objects: `capability`
  (a delegated authority subtree), `lease` (a credential lease) or
  `receipt` (a prior receipt).
- **revoked_hashes** is the chain linkage: for a capability, the hash
  of the revoked token; for a lease, the grant receipt's receipt_hash;
  for a receipt, the cited receipt_hash. Its keys MUST exactly equal
  the `revoked_ids` set. A third party hashes the object it holds and
  matches the digest: the linkage verifies without trusting the
  revoker.
- **actor** is the revoking identity, the admin-plane actor on record.
- **reason_class** is the closed vocabulary: `compromise` (suspected or
  confirmed compromise of the identity, key or token),
  `owner_departure` (the owning identity left; the owner-departure
  operation), `scope_correction` (the authority was wider than
  intended), `policy_change` (the policy no longer authorises the
  object), `operational` (routine retirement: rotation, maintenance).
  Unknown classes fail verification.
- **reason** is optional free-text detail. A revocation receipt is
  retained for the life of the archive, so the reason SHOULD stay at
  class level and MUST NOT quote secret material, credentials or
  constraint values.
- **revoked_at** is an integer epoch, the revocation's effective
  moment. It MUST NOT be later than the receipt's own `iat`: the
  receipt is minted at revocation, and a post-dated timestamp is
  editorial, not evidence.

What the block does NOT carry:

- No secret material: no vault references, no secret digests, no key
  material. Lease revocations cite the grant receipt by hash; the
  secret never enters the revocation.
- No capability replay content: the revoked capability's constraints,
  scopes, expiry or token bytes never appear. Ids and hashes only: a
  revocation receipt is evidence of an ending, not a replayable
  capability.
- No content: no arguments, no values, no denial reasons. A revocation
  that quoted what it revoked would turn an ending into a disclosure.

## Verification rules (offline, no revoker trust)

1. Structure: closed field set; `kind` and `reason_class` inside their
   closed vocabularies; digests sha256-shaped; integer epochs;
   `revoked_at` not later than `iat`; `revoked_hashes` keys exactly
   equal to `revoked_ids`.
2. Version gate: a block carrying `version: "revocation/v1"` gets the
   mandatory-field check above. An unknown version string refuses with
   a named error, never a skip. A block with no version field is the
   shipped v1.0 shape and keeps the shipped semantics.
3. Chain linkage: for `kind = "receipt"`, every cited receipt_hash MUST
   exist in the chain (a ghost citation fails with a named error, the
   same membership rule every extension citation obeys). For
   `capability` and `lease`, a third party holding the object verifies
   the digest match; a verifier holding the delegation ledger or the
   grant receipt re-derives it.
4. New link, never an edit: the revoked object's own receipt is never
   modified, re-signed or removed. The revocation appends. Because the
   chain is tamper-evident, an edit to a revoked receipt after the
   revocation line breaks the chain at the recomputed hash: the
   revocation and the tamper evidence do the work together.
5. Effect, stated normatively: receipts minted after the revocation
   line that cite a revoked authority are INVALID with a named error;
   receipts before the line stay valid. Revocation is not retroactive:
   it ends an authority going forward, and the pre-revocation span
   keeps its verdict.

## Fail-closed consumer rule

A consumer (gate, verifier, replay tool) that meets a revocation block
it does not understand, an unknown version, an unknown kind or an
unknown reason class refuses with a named error. A revocation is the
one record whose silent loss converts a containment operation into a
window of authority, so ignoring it is never acceptable behaviour.

## Homes (the 16.3 split)

- Evidence layer (this document, the verifier rules, the future test
  vectors): OSS, public.
- The shipped emitter surface (`revoke_capability`,
  `revoke_agent_chains`, the cascade walk) is OSS gateway code; the
  admin-plane operations that trigger it are the operator portal.
- A signed, distributable revocation feed for multi-gate fleets remains
  the named follow-up the provenance v1 spec records (appendix C): this
  kind is the receipt format such a feed carries.

## Shipped surface today

The accepted 30 October 2026 emitter writes `revoked_ids`, `root`,
`actor` and a free-text `reason` under verdict `authority_revoked`, and
the verifier marks post-revocation citations invalid with a named
error. The v1.2 kind specified here adds `version`, `kind`,
`revoked_hashes`, `reason_class` and `revoked_at`. Revocations minted
before this document are valid and stay valid (rule 4); the
implementing Q lane extends the emitter, and until it does the shipped
shape is what the chain holds.

## Fixture targets for the implementation lane

The shipped contract is pinned today in `tests/test_cascade_revocation.py`
(subtree revocation verifies offline; the gate refuses revoked ids;
post-revocation citations fail with a named error; pre-revocation
receipts stay valid). The v1.2 kind adds, spec preceding
implementation:

- An unknown `version` refuses with a named error, never ignored.
- An unknown `reason_class` or `kind` fails verification.
- `revoked_hashes` keys must exactly equal `revoked_ids`.
- `revoked_at` later than `iat` fails with a named error.
- A `kind = "receipt"` revocation citing a receipt not in the chain
  fails with a named error.
- A reason quoting a constraint value fails the bounded-disclosure
  rule.

## Rationale

Revocation is the control every framework claims and few can prove. A
revocation you must trust (an operator's word, a mutable status file, a
directory entry) is not containment evidence: an auditor cannot
distinguish revoked from deleted. A revocation receipt is the primitive
the rest of the system already trusts, applied to endings: signed,
offline-verifiable, append-only, and strict enough that the archive
carries proof of who ended what, when and under which stated class,
without carrying the authority's material.
