# ADR 0009: Receipt ledger durability and transparency proof strategy

- **Status:** Proposed
- **Date:** 2026-11-26
- **Owners:** Raucle engineering
- **Parent programme:** [Enterprise Readiness Programme #107](https://github.com/epic28-ltd/raucle-agent-assurance/issues/107)
- **Implementation tracking:** [Raucle issue #342](https://github.com/epic28-ltd/raucle/issues/342)

## Context

The enterprise proposal suggests a new append-only receipt ledger backed by PostgreSQL/TimescaleDB,
with Merkle roots anchored through RFC 3161 or a transparency log. Raucle already has several
relevant mechanisms. The correct next step is to map their guarantees and gaps, not introduce a
second ledger by default.

### Existing mechanisms

1. **Signed provenance receipts.** Each receipt is independently signed and has a content hash.
   Offline verification validates the receipt and its signature. This proves the signed content,
   not that no other receipt was omitted from the presented collection.
2. **Segmented receipt storage.** `raucle/receipt_store.py` writes JSONL segments, flushes and
   fsyncs each append, rotates segments at a configured size and writes seal metadata in a
   separate `.meta` sidecar. A configured signer can sign the canonical seal metadata; without
   one the segment is explicitly marked unsigned. Sealed read-only permissions are a local
   operational measure, not a WORM guarantee against a privileged host operator.
3. **SCITT chain-head anchoring.** `raucle/transparency.py` can register a hash-chain head with a
   Transparency Service and verify the returned statement offline. The documented claim is
   non-equivocation of the anchored head, not truth/completeness of the underlying events.
   This client path is optional and off by default; the spec records residual verification
   wiring for the transparency root.
4. **Hosted transparency log.** The OSS verifier validates per-organisation hash-linked log
   entries, signed Ed25519 epoch checkpoints, inclusion proofs and consistency proofs. This is a
   hash chain with linear proof segments, not a Merkle tree. The verifier uses a pinned operator
   public key, never a key supplied by the proof.

These mechanisms cover more than a simple local JSONL append log, but their trust surfaces are
not interchangeable. In particular, the chain-head anchoring client and hosted log verifier
must be mapped to the exact artifact they anchor: receipt chain, audit hash chain or individual
receipt digest. Do not use "receipt ledger anchored" as a blanket description until this mapping
is explicit for each deployment path.

## Decision

### 1. Preserve the existing receipt format and storage path

Do not change canonical receipt bytes or add database metadata into the receipt chain. Keep
query/index state as a rebuildable projection. Keep signed segment seals as a separate sidecar
artifact. Any new evidence format must be additive and versioned, with offline test vectors.

PostgreSQL/TimescaleDB may be appropriate for query/index or hosted multi-tenant ingestion,
but it must not become the sole trust anchor for the receipt history. The verifiable record
remains the signed receipt material plus independently held checkpoints/proofs.

### 2. Do not add a Merkle tree until a measured requirement justifies it

The existing hosted hash-chain log already supports offline inclusion and consistency checks
against signed checkpoints. A Merkle tree could reduce inclusion proof size and support
efficient append-only transparency at scale, but it would introduce a new tree-head format,
proof algorithm, consistency logic, key/checkpoint lifecycle and cross-implementation burden.

Before selecting Merkle, measure:
- proof bytes and verification time at realistic log sizes;
- proof-generation and append cost;
- operational cost of checkpoint publication and witness monitoring;
- compatibility/interoperability demand from external auditors or customer systems.

If the linear proof size is acceptable for the expected enterprise scale, retain the simpler
hash-chain contract. If it is not, propose a separately versioned Merkle transparency profile;
do not retrofit a tree into the existing v1 proof format.

### 3. Make external checkpointing and archive retention explicit

A local signed receipt or signed segment seal does not prevent a privileged writer from
deleting the entire store, withholding a tail or presenting an older valid snapshot. The control
for those threats is an independently retained checkpoint or witness, combined with a
repeatable archive process.

Define a deployment policy for:
- checkpoint cadence and maximum unanchored interval;
- independent retention of signed statements/checkpoints and the corresponding chain digest;
- immutable/offline archive of sealed segments, seal metadata, trust roots and verifier version;
- key rotation and retired-key retention;
- restore verification and reconciliation against the latest independently held checkpoint;
- alerting when an expected checkpoint is missing or a chain head rolls back.

RFC 3161 timestamps can attest that a digest existed at a time; they do not prove append-only
completeness by themselves. A transparency log consistency proof can show growth between two
signed heads, provided the verifier pins the correct operator key and retains prior checkpoints.
A timestamp and a transparency proof therefore solve related but different problems.

### 4. State the guarantee boundaries

| Threat | Existing control | Residual / required follow-up |
|---|---|---|
| Receipt content modification | Receipt signature/hash verification | Compromised signing key remains a trust-boundary risk |
| Local segment tail corruption | Parse checks, fsync, signed seal where configured | Disk/controller failure and privileged tampering require backup/restore |
| Segment rewrite after sealing | Read-only seal posture; optional signed metadata | Not equivalent to immutable/WORM storage |
| Entire-chain deletion or rollback | External anchored head / retained prior checkpoint | Must be enabled, retained independently and monitored |
| Equivocation between presented histories | Signed checkpoint plus consistency proof | Verifier must compare against a previously retained trusted checkpoint |
| Omission/withholding before first checkpoint | None from a later checkpoint alone | Shorten anchor interval; independent witnesses/expected-volume monitoring |
| Missing or unsigned seal metadata | Explicit unsigned state | Production policy should decide whether unsigned seals are permitted |
| Database/index tampering | Index is a rebuildable projection from the chain | The index is not evidence and must never override the chain |

## Consequences

- No duplicate Merkle ledger is introduced before evidence shows it is needed.
- Existing receipt bytes and offline verifier compatibility remain stable.
- Enterprise assurance work focuses on checkpoint cadence, independent retention,
  key lifecycle, restore exercises and precise artifact-to-proof mapping.
- A future Merkle profile remains possible without weakening v1 compatibility.

## Required validation

- Test signed and unsigned segment seals, tampered metadata and retired-key verification.
- Demonstrate restore from archived segments and verify against an independently retained head.
- Demonstrate rollback detection when the presented head is older than a retained checkpoint.
- Document exactly which chain artifact each SCITT and hosted transparency integration anchors.
- Benchmark hash-chain proof size and verification cost at increasing log sizes before deciding
  whether Merkle is necessary.
- Ensure all public descriptions distinguish local tamper evidence, externally anchored
  non-equivocation, timestamp existence proofs and durable archive retention.

## References

- `raucle/receipt_store.py`
- `raucle/transparency.py`
- `docs/spec/transparency-v1.md`
- `docs/spec/x2-transparency-log-v1.md`
- `docs/deployment-topologies.md`
- [Raucle issue #342](https://github.com/epic28-ltd/raucle/issues/342)
