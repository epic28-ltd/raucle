- Receipt sidecar submit anti-replay (issue 340 items 1 and 2, on the ADR
  0008 section 5 contract): the sidecar's HMAC request nonce is now
  persisted and replay checked before the envelope is enqueued. The HMAC
  covers the nonce, a client sent-at timestamp and the exact body; the
  first submit of a nonce and body answers 202 queued, an identical
  resubmission gets the named duplicate answer (200, status duplicate,
  first accepted receipt hash) and is never appended again, the same
  nonce over a different body is refused as 409 nonce_reuse_mismatch, a
  submit whose signed sent-at lies outside the clock-skew window (default
  plus or minus 300 seconds, constructor opt-in) is refused as 400
  stale_timestamp without burning the nonce record, and captured verbatim
  replays are refused either as duplicates (nonce retained) or as stale
  (nonce expired, timestamp HMAC-bound), so a captured submit is never
  appended a second time.
- The submit nonce store (raucle/sidecar_nonce_store.py) builds on the
  existing replay-store machinery: the same file-backed SQLite idiom
  (WAL, busy_timeout, primary key uniqueness, BEGIN IMMEDIATE
  serialisation, retain-forever default, operator purge) with the payload
  digest bound in the same atomic step. It is single-host only, one file
  and one writer in its own namespace, separate from any handshake replay
  keys. A configured retention must cover at least twice the skew window,
  enforced at boot. The multi-host shared backend (PostgreSQL
  unique-constraint transactions) is a named follow-up requiring a
  deployment decision; no multi-host or exactly-once claim is made, and
  gateway and sidecar must run the same protocol version.
- Sidecar persistence failures fail closed and corrupt nothing (issue 344
  item 3, sidecar part): a nonce-store write failure refuses the submit
  by name (503 nonce_store_unavailable, nothing enqueued, receipt ledger
  byte-identical, enforcement untouched), a corrupt nonce store fails the
  sidecar boot, a failing chain append is contained by the sink with no
  partial line and no index row, and recovery after the fault is clean.
  Regression tests pin all of it in
  tests/test_sidecar_submit_antireplay.py.
