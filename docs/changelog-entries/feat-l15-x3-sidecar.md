- X3 slice 4: the single-writer receipt sidecar (`raucle sidecar`, a
  stdlib-only service in the same repo) owns the receipt chain append and
  the index projection. Gateway replicas submit their minted envelopes to
  it over local HTTP with a shared-secret handshake
  (RAUCLE_RECEIPT_SIDECAR_URL/SECRET/TIMEOUT/MAX_QUEUE), so several
  gateways can serve traffic while one process writes and the SQLite WAL
  never has two writers. The mint stays in the gateway; the sidecar
  assigns chain order.
- Receipt loss is named, never silent: submit goes through a bounded
  queue, overflow is a named `receipt_sink_overflow` refusal, and the
  gateway receipts the loss as a signed `x_sidecar` advisory (the
  harness-finding pattern, bounded disclosure: refused hash, reason,
  time). The enforcement decision completed before submission and
  stands; this is fail-open for receipt persistence only. A gateway
  configured with a sidecar URL plus a local write projection is a named
  two-writer boot refusal.
- Restart resume is unchanged: the store reopens the last unsealed
  segment, the J2 interrupted-migration recovery still runs in the index
  constructor, and an index left behind by a crash is rebuilt from the
  chain of record. Chains written through the sidecar are byte-identical
  to single-writer ones and verify through the unchanged offline
  verifier.
- The Helm chart gains the sidecar Deployment and Service (replicas
  pinned to 1 with a Recreate strategy, owns the data volume; the
  gateways mount it read-only and their single-replica constraint lifts),
  with the honest notes in the chart README and
  docs/deployment-topologies.md. New spec first:
  docs/spec/x3-sidecar-v0.1.md.
