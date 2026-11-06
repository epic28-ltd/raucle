# Transparency anchoring v1: SCITT registration of receipt-chain heads

Status: proposed 6 November 2026. Profile semantics follow the IETF
SCITT registration flow (draft-noa-scitt-ai-agent-receipt entry profile
for receipt-chain heads) as realised in `raucle/transparency.py`. No
vendor SDK; standard-library HTTP only.

## What anchoring proves — and what it does not

Anchoring proves **non-equivocation of the receipt-chain head**. Once
the head digest (final event index plus its record hash) is registered
with a Transparency Service, the service holds a signed statement that
this exact head existed at registration time; the writer cannot later
present a different chain history for the same chain without that
discrepancy being nameable.

Anchoring proves nothing more than that, and this document claims
nothing more. It does not upgrade the quality of the underlying
records, does not attest the truth of any decision, and is not a
compliance claim of any kind.

## The registration flow (client side)

`SCITTAnchorClient` implements the well-known SCITT flow against any
service implementing it:

1. **Submit** — `POST {base}/entries` with the receipt-chain-head entry
   (`entry_profile`, `chain_id`, `chain_head {index, hash}`). A `201`
   with a `Location` header naming the operation status URL (absolute
   or relative; relative references are resolved RFC 3986-style).
2. **Poll** — `GET` the operation URL until `status` is `complete`
   (carrying a `signed_statement_url`), `failed`, or until the poll
   budget is exhausted, in which case the named `PENDING` status is
   returned with the recorded location so the caller may resume. A
   `Retry-After` header (RFC 9110 delta-seconds or HTTP-date) is
   honoured, bounded to 30 s.
3. **Fetch** — `GET` the signed-statement URL. The statement must echo
   the exact head that was submitted; any other digest yields the named
   `DIGEST-MISMATCH` status, never a success.

Strict header handling: an unparseable `Date` header raises rather than
being ignored. Bearer tokens are constructor/method parameters, never
environment globals or module state. The client never mutates the chain
file — anchoring is read-only over the chain bytes.

## Named statuses

- `TRANSPARENCY-ANCHORED` — statement received, digest confirmed.
- `PENDING` — service has not finished; resumable.
- `TRANSPARENCY-FAILED` — service reported the operation failed (or an
  unmodelled status; the client fails closed).
- `DIGEST-MISMATCH` — the statement anchors different material than was
  submitted (client side) or than the recomputed chain head (verifier side).
- `SELF-SIGNED-ONLY` — no transparency statement is available: the chain
  stands on its own signatures and no non-equivocation guarantee for the
  head has been established.

## The offline verifier-side check

`verify_transparency_anchor(chain_path, signed_statement=None, ...)`
recomputes the chain head (re-verifying every event record's hash over
its canonical bytes — a tampered chain refuses to be anchored) and
compares it against a cached or fetched signed statement:

- digest match: anchored `chain_head` equals the recomputed head;
- signature path present: the statement carries a signature element
  (`signature`, `signatures` or `cose`). Full COSE verification against
  a transparency root is verifier wiring for a follow-up; an absent
  signature path can never count as anchored.

The check is **optional and OFF by default**: callers that never invoke
it keep the plain self-signed verification story. When the transparency
root is absent, the result is the honestly named `SELF-SIGNED-ONLY`
status with the reason recorded in `reasons` — a named fail-open, never
a silent pass and never a silent skip. A statement whose digest differs
from the recomputed head yields `DIGEST-MISMATCH` with the reason
recorded.

## Test posture

All transparency tests run against a loopback HTTP double (a local
`http.server` fixture implementing submit/poll/fetch). No test in
`tests/test_transparency.py` performs an external network call, and the
canonical-bytes invariant (the chain file's SHA-256 is unchanged across
anchoring and verification) is pinned by test.
