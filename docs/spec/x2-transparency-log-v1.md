# X2 slice 2: the hosted transparency log, verifier side

Status: implemented (`raucle/transparency.py`, `tests/test_transparency_log_verify.py`,
fixture `tests/fixtures/transparency-log/cloud-roundtrip.json`). The log itself is
the operator surface (raucle-cloud, branch feat/x2-transparency-log); this document
specifies only what the licence split (17 Nov) makes OSS: the verifier-side contract,
meaning what a third party recomputes, with no trust in the operator.

## What the log proves, and what it does not

Registering a receipt digest with the operator appends one entry to the org's
hash-chained log and immediately closes a signed epoch over the head. That proves
one thing: the digest was registered with this operator, in this org, at a point in
time provable against a signature. It does not upgrade the quality of the underlying
receipt, does not attest the truth of any decision, and is not a compliance claim.
The same doctrine as transparency anchoring (`transparency-v1.md`): proof of
registration, nothing else.

## The entry profile (closed)

An entry carries exactly seven fields:

| field | shape |
|---|---|
| `org` | non-empty string, the org whose chain holds the entry |
| `sequence` | positive integer, monotonic from 1 within the org's chain |
| `prev_hash` | `sha256:<64 hex>`, the previous entry's hash (genesis for entry 1) |
| `receipt_digest` | `sha256:<64 hex>`, the registered receipt digest |
| `payload_digest` | `sha256:<64 hex>` or null (optional) |
| `registered_at` | non-negative integer, seconds since the epoch |
| `entry_hash` | `sha256:<64 hex>`, the covering value |

The entry hash is sha256 over the OSS canonical JSON of the six public fields
(everything but `entry_hash` itself), so a third party recomputes every hash offline
from the proof alone: `compute_log_entry_hash`. The profile is closed; an entry with
unknown fields is refused, not partially read. Chains are per org and each starts
from its own genesis, `LOG_GENESIS_PREV_HASH = sha256:` followed by 64 zeros.
Re-registering a digest appends a new entry; it is never a rewrite.

## The epoch checkpoint (the signed tree head)

Every append closes an epoch, so a registered digest is provable against a signed
head immediately. The checkpoint is a compact JWS, Ed25519:

- header (closed set): `alg` `EdDSA`, `typ` `transparency-epoch/v1`, `kid`, `crit`
  `["raucle/v1"]`, and `"raucle/v1": "transparency"`;
- payload (closed set): `iss`, `org`, `epoch`, `size`, `head_hash`, `iat`, `nonce`.

In this v1 profile `epoch == size`: each append closes one epoch, numbered by the
chain size it closed. Unknown header or payload fields are refused, never ignored.

## The proof surfaces (output contracts)

The operator serves three surfaces; the verifier consumes these fields of each:

- **latest**: the org's current signed head, or an honest empty (`size` 0);
- **inclusion proof**: `org`, `sequence` (the target), `entries` (every entry from
  the target to the head, in order), `size`, `head_hash`, `checkpoint_jws`, and
  convenience material the verifier ignores (`receipt_digest`, `payload_digest`,
  `epoch`, `key_id`, `operator_public_key_pem`);
- **consistency proof**: `org`, `from_size`, `to_size`, `entries` (the appended
  segment, `from_size + 1` to `to_size`), `from_checkpoint_jws`,
  `to_checkpoint_jws`, plus the same convenience material.

## What a third party recomputes

1. Recompute every entry hash from the proof alone (`compute_log_entry_hash`) and
   hold each entry to its stated hash: a doctored entry does not bind.
2. Check the segment: contiguous sequences, each entry linking the previous
   entry's hash, and a segment beginning at sequence 1 naming the genesis link.
3. Check the target: the segment begins at the stated sequence; the target entry
   registers the expected digest (`expect_digest`); the proof is for the expected
   org (`org`).
4. Verify the Ed25519 checkpoint against the **pinned** operator key. The public
   key riding the proof is convenience material for humans, never verification
   input: a proof verified against its own key would be self-attested. Pinning the
   key out of band is the trust anchor, the same doctrine the audit-pack verifier
   documents.
5. Check the head bindings: the last entry's hash is the head the checkpoint
   signs, the stated size matches, the checkpoint's org matches.

The consistency check adds the growth binding: the first appended entry must link
the from-checkpoint's signed head, and the last entry must be the to-checkpoint's
signed head. An operator who rewrites history cannot produce a segment that grows
from the head it signed before.

## The named statuses

`verify_log_inclusion` and `verify_log_consistency` return a `LogVerification`
carrying a named status, every refusal reason found (never just the first), and
the size and head hash the proof claims.

| status | meaning |
|---|---|
| `LOG-INCLUDED` / `LOG-CONSISTENT` | every check passed |
| `LOG-MALFORMED` | the proof is not shaped like a proof: missing fields, bad digest shapes, bad sizes or ranges, entries that are not log entries |
| `LOG-BAD-SIGNATURE` | the checkpoint cannot be verified: the signature fails against the pinned key, or the checkpoint does not follow the profile (typ, crit, header or payload field sets, epoch not equal to size, a non-Ed25519 pinned key) |
| `LOG-CHAIN-BROKEN` | the chain math fails: an entry does not bind its stated hash, linkage or contiguity breaks, the genesis link is misnamed, or (consistency) the segment does not grow from the signed old head |
| `LOG-HEAD-MISMATCH` | a binding to the expected material fails: the expected org or digest differs, the stated head is not the segment's head, the segment does not reach the signed head |

Precedence when several families fire at once: MALFORMED, then BAD-SIGNATURE, then
CHAIN-BROKEN, then HEAD-MISMATCH, with every reason still reported.

## Honest limits

- An inclusion proof re-verifies the segment it carries in full; the prefix before
  the target is bound through the segment's linkage and the signed head only. A
  verifier who wants the whole chain asks for the sequence 1 proof, which carries
  every entry from genesis.
- The log proves what was registered, not that everything was. Withholding is the
  operator's residual; the consistency proof between two sizes is the control that
  the log grew only by appending between those heads.
- `registered_at` is operator-claimed but committed (hashed into the entry); the
  operator-independent point in time is the checkpoint's signed `iat`.

## The cross-repo dogfood

The committed fixture was generated by the cloud implementation from a live log: the
OSS verifier accepts the log's real proofs, and doctored copies refuse with the
named statuses. Regeneration is a cloud-side exercise (the operator half), never a
hand edit. The paired PRs, raucle-cloud feat/x2-transparency-log and this branch,
disclose each other in their bodies.
