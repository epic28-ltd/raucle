# X3 Slice 4: Single-Writer Receipt Sidecar v0.1 (Spec)

Status: Accepted 2026-11-23 (lane L15, X3 slice 4). The scale answer is the
one decided by the approved X3 programme and recorded in
[x3-oidc-admin-v1.md](x3-oidc-admin-v1.md) (scale posture): a single-writer
receipt sidecar owns the chain append so several gateway replicas can serve
traffic. This slice is that sidecar. Slices 1 to 3 (identity federation,
admin-plane OIDC, key rotation) are unchanged by it.

## Purpose

Today one gateway process owns the receipt chain and the index projection,
which pins every deployment to a single writer per chain (the chart
constraint). With the sidecar, THE append path moves into one small
service:

- the MINT stays in the gateway (signing, receipt_hash computation),
- the APPEND (chain segment write) and the INDEX write go through the
  sidecar,
- the gate decision completes before submission, so a sidecar failure can
  never un-decide an enforcement outcome.

One process writes the chain and the SQLite index; several gateway
replicas read, decide and submit. The SQLite WAL file never has two
writers.

## Deployment shape

```
gateway replica 1 --\
gateway replica 2 --- submit (local HTTP, shared secret) --> receipt sidecar --> chain + index (single writer)
gateway replica N --/
```

The sidecar is a process in this repo (`raucle sidecar`, stdlib only, no
new mandatory dependency). It binds a local address and owns the receipt
store directory and the index file. Gateways mount the store read-only;
they never open the store or the index for writing. The Helm chart gains a
sidecar Deployment (single replica, Recreate, owns the data volume) and the
gateway Deployment lifts its single-replica constraint when the sidecar is
enabled. The sidecar itself remains pinned to one replica: it is the
single writer, and the honest note in the chart README says so.

## The submit protocol

`POST /submit` on the sidecar, body the exact envelope the gateway minted:
`{"receipt_hash": "sha256:...", "jws": "..."}`.

Authentication is a shared-secret handshake, following the existing
`RAUCLE_*` env-name patterns:

| Env var | Side | Meaning |
| --- | --- | --- |
| `RAUCLE_RECEIPT_SIDECAR_SECRET` | both | the deployment's shared secret; the sidecar refuses to boot without it, the gateway refuses sidecar mode without it |
| `RAUCLE_RECEIPT_SIDECAR_URL` | gateway | sidecar base URL, e.g. `http://raucle-gateway-sidecar:8092` |
| `RAUCLE_RECEIPT_SIDECAR_TIMEOUT` | gateway | HTTP timeout in seconds (default `2.0`) |
| `RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE` | sidecar | bound on the submit queue (default `4096`) |

The handshake: the client sends `X-Raucle-Nonce` (fresh random lowercase
hex, 16 to 128 characters), `X-Raucle-Sidecar-Sent-At` (its unix time in
seconds) and `X-Raucle-Sidecar-Auth: <hex HMAC-SHA256(secret, nonce +
"\n" + sent_at + "\n" + body)>`. The sidecar recomputes and compares in
constant time. A missing or wrong authenticator is a named 401 refusal
and nothing is appended; a sent-at that is not an integer is a named 401;
a sent-at outside the accepted clock-skew window (default plus or minus
300 seconds) is a named 400 `stale_timestamp` and burns no nonce record.
The secret never enters argv, a config document or a receipt. Because the
timestamp is under the HMAC, a captured request cannot be re-signalled
into a fresh-looking one.

Submit anti-replay (issue #340, on the ADR 0008 section 5 contract): the
first submit of a nonce-and-body identity is consumed atomically into a
persistent SQLite store (`<store_dir>/submit_nonces.sqlite`) BEFORE the
envelope is enqueued, and answers 202 `status: queued`. An identical
resubmission of that nonce and body gets the named duplicate answer (200
`status: duplicate`, carrying the first accepted receipt hash) and is
never appended again. The same nonce over a different body is refused as
409 `nonce_reuse_mismatch` and the first digest stays. The store is
single-host only, like `SqliteReplayStore`: one file, one writer sidecar
process, its own namespace separate from any handshake replay keys.
Consumed nonces survive a sidecar restart. Retention of consumed records
defaults to forever; a configured `retention_seconds` must be at least
twice the skew window (enforced at boot), and expiry is then honest:
within retention a replay is the duplicate answer, beyond it the
HMAC-bound sent-at window still refuses it, so a captured submit is never
appended a second time. If the nonce store cannot serve a decision, the
submit is refused fail-closed by name (503 `nonce_store_unavailable`,
nothing enqueued) and the receipt loss is recorded by the caller. This is
at-most-once ingest of one request identity; it is not an exactly-once
claim, and gateway and sidecar must run the same protocol version (an
older client's HMAC no longer matches).

Fail-closed misconfiguration guard: a gateway configured with BOTH a
sidecar URL and a local write projection (`receipt_store_dir` or
`receipt_index_path`) refuses to boot with a named error. Two writers are
the failure this slice exists to prevent; the chart gates its store env
rows on the sidecar being disabled.

## Ordering

The sidecar assigns chain order: submissions enter a bounded FIFO queue
and one writer thread drains it, appending to the chain segment and then
projecting into the index. Arrival order is chain order. Gateways mint
concurrently; the chain is strictly ordered because only one thread ever
writes it. A mint-order versus chain-order divergence under concurrency is
expected and harmless (the chain is the record, the iat inside the
receipt preserves mint time).

## The overflow contract (named, never silent)

The submit queue is bounded. When it is full the sidecar answers `503`
with the named error `receipt_sink_overflow` and no request-supplied
value is reflected back in the response body (S5131): the refused
envelope's hash stays with the gateway, which already holds the envelope
it minted. The gateway then mints ONE advisory receipt, signed by the
same
gate identity as every other receipt, with an `x_sidecar` extension
(bounded disclosure: the refused hash, the named reason, the queue depth,
the time; never content):

```
"x_sidecar": {
  "action": "refused",
  "refused_receipt": "sha256:...",
  "reason": "receipt_sink_overflow",
  "refused_at": 1760000000
}
```

The refused receipt is lost by name; the advisory is the receipted record
of that loss, in the claim-then-verify spirit of the harness finding
pattern (emission states the claim; offline verification re-reads the
chain). If the advisory's own submission is also refused, it waits in a
bounded gateway-side pending list (128 entries) and rides the next
successful submit; a pending-list overflow drops the oldest advisory with
a named error log. This is fail-open for receipt persistence only: the
enforcement decision was already made and stands. An unreachable sidecar
or any other transport failure is a named per-receipt loss (ERROR log),
never an exception into the gate path.

## Restart and recovery

The sidecar owns the same on-disk shapes the gateway owned, so no new
recovery path exists:

- the `SegmentedReceiptStore` reopens the last unsealed segment and
  continues appending;
- the `ReceiptIndex` constructor runs the unchanged J2 interrupted
  migration recovery;
- on boot the sidecar reconciles the projection against the chain and
  rebuilds the index from the store when the index is behind (a crash
  between the append and the index write). `rebuild_from_store` is the
  repair contract, exactly as before.

## Byte compatibility

Chains written through the sidecar are byte-identical to single-writer
ones. The sidecar appends `json.dumps({"receipt_hash": ..., "jws": ...},
ensure_ascii=False)`, the same serialisation the gateway's local path
uses, so segments remain pure receipt chains: `ProvenanceVerifier`, the
audit pack and the offline verifier page consume them with no changes
and no new record kinds.

## Security posture and residuals (named)

- The shared secret authenticates the sidecar's callers as this
  deployment's own gateways (the same signing identity). It does not
  authenticate the sidecar to the gateway and it is not a capability: a
  holder can append arbitrary envelopes to the chain. Deployments must
  keep the sidecar on a loopback or in-cluster address, never behind the
  public ingress. The chart never exposes it.
- The handshake is HMAC over the body, so tamper-evident per request, but
  the transport is plaintext HTTP on a trusted network segment. mTLS is
  a named follow-up, not an assumption.
- Submit replay is now refused by name instead of appended twice: the
  duplicate answer, the mismatch refusal and the stale refusals are
  named (see the protocol above). A duplicate envelope can still reach
  the chain when the caller mints a fresh nonce for a repeat of the
  same receipt: anti-replay scope is the REQUEST identity, and
  duplicate SUPPRESSION by receipt hash stays out of the sidecar (the
  index keeps every attempt by design). The multi-host shared replay
  backend (PostgreSQL unique-constraint transactions) is a named
  follow-up slice requiring a deployment decision and ADR acceptance;
  no multi-host or exactly-once claim is made.
- No duplicate suppression at the sidecar: byte-identical same-second
  attempts are legitimate mint events and the derived index keeps every
  attempt by design, so the sidecar keeps them too.
- In sidecar mode the gateway's receipt query surfaces have no local
  index and answer as any no-index deployment does; the chain and the
  index live on the sidecar's volume. A read-only gateway index view is
  a named follow-up.
- The gateway-side pending advisory list is in-memory: a gateway crash
  loses at most 128 advisories. The refused receipts they describe are
  already lost by name in the sidecar's overflow events and logs.

## Test contract

Red-first, in `tests/test_receipt_sidecar.py`:

1. Two gateway processes submitting concurrently through one sidecar
   produce a strictly ordered, intact chain: every line parses, counts
   match, no interleaving corruption, and the chain verifies through the
   standard verifier.
2. Overflow: the sidecar returns the named `receipt_sink_overflow`
   refusal; the gateway mints the `x_sidecar` advisory naming the refused
   hash; the advisory lands when the queue drains; the refused receipt is
   absent and the chain still verifies.
3. Sidecar restart: same store directory, resume appending, counts
   contiguous, and an index left behind by a crash is rebuilt from the
   chain (J2 recovery unchanged, no new recovery code).
4. The offline verifier is unchanged: chains built through the sidecar
   verify exactly as single-writer ones do.
5. Byte-compat pin: the same envelope written through the sidecar and
   through the gateway's local path produces identical bytes on disk.
6. The handshake: no or wrong authenticator is a named 401 with nothing
   appended; the misconfiguration guard refuses the two-writer boot.
7. The chart contract: sidecar rows in values, env wiring, read-only
   gateway mount, single-replica Recreate sidecar, prod.env.example names.
8. Submit anti-replay, pinned in `tests/test_sidecar_submit_antireplay.py`:
   the named duplicate answer (serial use, a verbatim captured replay and
   concurrent duplicates with exactly one winner), the
   `nonce_reuse_mismatch` refusal with the first digest preserved, the
   clock-skew window both ways with no nonce burned, restart persistence
   of consumed nonces, retention expiry with the HMAC-bound sent-at still
   blocking the replay, the retention floor (at least twice the skew), a
   nonce-store write failure answered fail-closed by name with the receipt
   ledger byte-identical and enforcement untouched, recovery clean after
   the fault, a corrupt nonce store failing the boot, and a failing chain
   append contained by the sink with no partial line and no index row.

## Non-goals (named, deferred)

Gateway query surfaces over the shared volume (read-only index view),
mTLS between gateway and sidecar, sidecar HA (a standby is a follow-up;
the single writer is the constraint by design), envelope-level duplicate
suppression across distinct nonces (receipt-sequencing, separate
contract), a multi-host shared replay backend, and any change to receipt
formats or the verifier.
