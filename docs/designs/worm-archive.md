# WORM receipt archive (H3)

Status: design only, not yet implemented. Draft 30 October 2026.
Companion to the records management semantics work (G3, `raucle/records.py`),
the time-source model (G1, `docs/spec/time-source-v1.md`), the audit-chain
projection (H1b-1), and the pq1 hybrid signature design
(`docs/spec/provenance/v1/pq1-hybrid.md`). No code in this document; it is
the design a WORM archive build must satisfy.

## Problem

Receipt chains are currently self-custody artefacts: the operator's ledger
and exported chains live on storage the operator controls and can, in
principle, modify. The cryptography already makes tampering detectable
(any edit breaks the chain digest), but the evidence surface a regulator
asks about is not the cryptography in the abstract, it is the questions:

  Can a record be written once and then never silently altered or deleted?
  Can retention and disposal be demonstrated against a fixed, non-custodial
  copy?

The archive answers both with a storage primitive the industry already
accredits: S3 Object Lock in compliance mode.

## 1. Object Lock compliance mode

### Why compliance mode, not Governance mode

Object Lock compliance mode is write-once retention enforced by the
service: no principal, including the root account, can shorten or remove
the retention period or delete the object before it expires. Governance
mode has a bypass permission (`BypassGovernanceRetention`) and therefore
relies on procedural controls the raucle trust model does not want to
assume. The archive takes the stronger mode and accepts the operational
consequence: retention set in error is stuck until expiry.

Legal hold is the escape valve for exactly this. Compliance mode fixes the
time window; legal hold (variable, no end date) extends protection beyond
it. Deletion requires both the retention period expired and the hold
cleared.

### The Cohasset assessment, and its limits

Amazon's S3 compliance assessment, prepared by Cohasset Associates, covers
SEC 17a-4(f)(2) and 18a-6(e)(2), FINRA 4511(c), and CFTC 1.31(c)-(d). A
2026 revision of the assessment is published (scope extended to 18a-6(e)
alongside the original rules). Raucle's receipt chains are records the
assessment shape is designed to hold: non-rewriteable, non-erasable,
time-based retention.

Two caveats, which must stand in any document that quotes the assessment:

- The assessment covers the hosted AWS platform in commercial regions. It
  does NOT cover the AWS partitions: Object Lock compliance-mode
  availability in the EU sovereign cloud (aws-eusc) or AWS GovCloud is
  unconfirmed in public documentation, and H5 makes partition portability a
  requirement. Re-verify at deployment time, per H5.
- Assessments are revised. Verify the current revision and its exact rule
  list before quoting it in any buyer-facing or G-Cloud material, and
  re-date the citation.

The seller's compliance obligation under SEC 17a-4(f)(3)(iii) and
CFTC 1.31(c) (the audit-trail and readability clauses) is the regulated
entity's; the archive supplies the storage half of that proof and states
the boundary honestly. Raucle's design role is narrower: tamper-evident
signed receipts that let any verifier reconstruct the trail offline. The
WORM layer preserves the raw evidence so the re-derivation has a pristine
input.

## 2. The write path

### Bucket shape

One bucket per operator instance (`raucle-archive-<instance>`), versioning
enabled at creation (Object Lock requires it), default retention set to
compliance mode so an object that arrives without explicit retention is
still locked (this satisfies the 24-hour control-application guidance).

### Keys: content-addressed, append-only by version

Receipt chains are append-only. That fact, not Object Lock, decides the
key scheme:

- Chain segments: `chain/<tenant>/<year>/<month>/<chain-slug>/seg-<n>.jsonl`,
  written once per segment close (rotation by size or span). Each object is
  self-contained JSONL. Content address (SHA-256) rides in object metadata
  and in the segment's parent linkage, so a re-written segment at the same
  key is provably not the original even before the lock test fires.
- Pack bundles: `pack/<tenant>/<pack-id>/bundle.json` plus its manifest,
  written once per pack publication.
- Destruction receipts: `destruction/<tenant>/<receipt-id>/receipt.json`,
  written once at disposal time.
- Time anchors (G1): `anchor/<tenant>/<chain-slug>/<horizon-date>.json`,
  written once per anchoring run.

Because Object Lock protects object VERSIONS, not keys, mis-writing a key
would create a second version under the same name rather than silently
destroy the first. The archive's read contract therefore always pins a
version ID (carried in manifests and in the audit-chain projection), never
"latest". The design question resolves as: single-key-per-artefact with
version pinning; no mutable pointer objects inside the WORM bucket. Any
index or directory listing lives in a non-WORM metadata store and is
rebuildable from the bucket (see section 5). Rebuildability is the invariant
that keeps an accidental or malicious re-write detectable and correctable.

### When objects land

The write path is a projection, not a fork. The operator's ledger remains
the primary record; the archive receives artefacts at defined moments so
the WORM copy is independent of ledger state:

1. On chain segment rotation: the closed segment goes to the archive.
2. On evidence-pack publication: the bundle and its signed manifest.
3. On destruction: the signed `x_destruction` receipt, after disposition.
4. On anchoring: the G1 anchor artefact.

Each archive write carries metadata: artifact type, chain slug, span,
SHA-256, retention category, and the ledger position it was cut from, so
the archive can be reconciled against the ledger in one pass.

### Retention category defaults

Retention on each object is derived, not hand-tuned:

- Receipt chains: the chain's own archive horizon (`retention_until`, below),
  floored at the operator's configured minimum (regulatory minimums are
  per-regime; the archive takes the operator's declared minimum and states
  it in the evidence pack).
- Pack bundles and destruction receipts: the same horizon as the chains they
  attest. A destruction receipt must outlive the chain segment it re-anchors.
- Anchors: longest of the horizons they cover.

## 3. Retention interplay with G3

G3 (records management semantics) is where the archive hooks into existing
semantics. Retention is already stamped into gate receipts when
`config.retention_days` is set: `retention_until = iat + retention_days`
(`raucle/gateway.py`, the receipt's `x_gate` block, zero when unset). The
time-source model (G1) already uses the latest `retention_until` across a
chain as the chain's archive horizon. H3 generalises that horizon from a
timestamping scheduling value into the WORM retention value.

### Mapping `retention_until` to Object Lock retention

- Compliance-mode `RetainUntilDate` on a chain segment is set to the chain's
  horizon, with margin for anchoring and re-anchoring (the G1 retimestamp cadence
  must be able to touch artefacts in place; if a horizon needs extension, Object
  Lock allows extending a compliance-mode period, never shortening, which is
  exactly the permitted direction).
- The three-mode time-source model means receipts may carry internal, TSA, or
  OpenTimestamps time. The archive does not care which mode minted the horizon;
  it locks to the value already in the receipts and preserves whatever
  `x_timestamp` evidence accompanies the chain.
- Legal hold is the archive-side expression of an open investigation,
  dispute, or regulator freeze. A legal hold is recorded as an operator-plane
  event (who, when, why, authority) and applied as S3 Legal Hold on the
  affected objects; the receipt of the hold decision is itself archived, so
  the hold's provenance is on WORM too.
- Destruction versus compliance mode is the one place the two regimes collide
  and the design must be explicit:
  - The WORM archive never deletes. Destruction (G3) removes records from
    the operator ledger and escrow; the destruction receipt, the escrow
    reference, and the re-anchored surviving chain are archived.
  - What is destroyed is "the removed records" (the ledger rows and escrow
    payload), not the receipt chain segments. The segments themselves
    contain the audit trail of what was removed, bound by span/count/digest,
    and are precisely what regulation (FOI/DSAR/SEC) wants preserved.
  - Therefore no compliance-mode deletion is ever required by the destruction
    flow, and the archive's own retention floor for destruction receipts is
    the horizon of the re-anchored surviving chain (which the escrow copy the
    destruction receipt carries can outlast as well, subject to the operator's
    own judgment call, see open questions).
  - If an operator ever needs an artefact to disappear from the archive
    (GDPR erasure of an agent principal, say) the honest answer is that
    compliance mode prevents it until expiry. Options are Governance mode
    for that one bucket or not putting the disputed payload in the archive
    in the first place; the archive's default is not to ingest anything a
    regulator has not asked to see retained.

## 4. Recovery posture

### What the archive is, and is not

The WORM bucket is the durable evidence copy, not the operator's primary
store. Losing the primary ledger (a database, an operator estate) with the
archive intact is recoverable: the chain segments, pack manifests,
destruction receipts, and anchors reconstruct every evidential claim.
Losing the archive with the primary intact is also recoverable (re-project
the archive from the ledger), but the archive should be treated as a
restoration-of-last-resort copy for exactly this case, and its loss window
is bounded by the write-lag below.

### Durability, availability, RTO/RPO, stated honestly

- Storage durability: S3 promises 99.999999999% (11x9s) average annual
  durability over multi-AZ deployment within a region by default; this is
  the vendor figure, not raucle-measured. The design assumes one region,
  three AZs minimum for the primary archive.
- Cross-region replication (CRR) to a second region is the answer to a
  regional outage and the mechanism the Cohasset assessment names for the
  off-site-copy requirement under 17a-4. CRR replicates retention controls
  (mode, RetainUntilDate, legal hold) alongside the objects. Recommended
  but a cost decision; the design allows the archive to be configured
  either way and requires the configuration to be stated in the deployment
  documentation. Object Lock availability on the replication target must
  be verified per region (and per partition, H5).
- RPO: for artifacts already written, effectively zero within CRR
  propagation delay (seconds to minutes, AWS does not guarantee a bound).
  Between ledger and archive, RPO is the segment- and pack-cadence lag, so
  an in-flight (not yet rotated) chain span is the loss window. If the
  ledger's own backup cadence is tighter than the archive's, the effective
  RPO is the max of the two; the runbook must state the actual number, not
  the aspiration. A target number cannot honestly be claimed until the
  operator deployment is measured; the design goal is minutes, with the
  in-flight segment as the known and documented residual.
- RTO: restoring read access to the archive from a healthy replica is
  minutes to hours. Rebuilding the operator's primary ledger from the
  archive is the slow path (replaying chain segments and the H1b-1
  projection) and has not been measured. The runbook requirement is
  therefore: a restore drill, timed, per deployment, recorded into the
  evidence pack. Until one has been run, no RTO number is asserted.

### Runbook shape

A one-page runbook per deployment, in the operator portal (H1), with:

1. Preconditions: the reconciliation procedure ("diff the ledger's chain
   inventory against the archive object inventory, expect empty"), the
   CRR status check, the legal-hold inventory.
2. Incident classes: (a) single-object corruption/drop, (b) AZ outage,
   (c) regional outage (failover reads to the replica), (d) full ledger
   loss, (e) full archive loss with ledger intact (re-project), (f)
   mis-set retention discovered within the lock window.
3. For each, a procedure a non-AWS-native on-call engineer can follow,
   with what evidence to capture (this matters for the regulated buyer:
   restore actions during an incident may themselves be audit-relevant).
4. Restore drill cadence: quarterly during early production.

## 5. The verifier never needs the archive online

This is the load-bearing property and it is worth stating plainly.

Raucle's receipts verify offline against exported chains and keys. The
archive is not part of the verification path; it is not a trust root, not a
retrieval service, and not consulted at verify time. A chain exported for
audit, the keys, and the receipt of any revocation or destruction events
verify with no connectivity to the archive at all. The verifier CLI, the
audit-export document, and conformance re-verification all already work
this way.

Consequences worth naming:

- The archive can be kept cold, restricted, and almost never read, which is
  the security posture: a bucket whose only writers are the projection
  process, which is only read during an audit pull, a restore drill, or a
  compliance inquiry.
- Verification trusts signatures and hashes, not the bucket's continued
  existence. An examiner can be handed an export today and verify it in
  five years with no raucle infrastructure online; the archive's job is
  only to preserve the raw objects so the export's inputs are provably
  pristine.
- This is what distinguishes the raucle approach from vendors whose
  evidence plane is a server: the WORM layer is storage of last resort,
  not part of the trust computation.

## 6. What stays out of scope (for this design)

- No new receipts, envelope fields, or schema changes. The archive consumes
  what v1/v1.2 already produce; retention categories and metadata on
  archive writes are archive-side, not receipt-side.
- No change to the verifier or to the audit-export artefact.
- Nothing that requires the archive for normal gate or mint operation.

## 7. Open questions for Craig

1. Retention floor: what is the operator-configurable minimum for receipt
   chain retention, and does it differ per vertical (SEC 6 years versus
   FOI/DSAR schedules versus UK common retention defaults)? This decides
   whether the archive bucket default is per-tenant or per-regime.
2. Escrow payload retention: the destruction receipt carries an escrow copy
   of the removed records. Does the escrow go to the WORM archive too
   (proving what left, but then it is itself preserved), or live outside
   the archive with only the receipt inside? Legal sensitivity: some data
   deletion regimes arguably conflict with persisting escrow payloads
   longer than the underlying records were retained.
3. Governance-mode escape hatch: is there any buyer class for whom
   compliance mode is too strict (GDPR erasure duty), and should the design
   support a per-tenant Governance-mode archive with procedural controls,
   or is compliance mode the only supported posture?
4. Cross-region replication: default on, default off, or buyer-choice
   documented either way (cost vs the Cohasset off-site-copy line)?
5. Partition support: do we commit to verifying Object Lock compliance-mode
   availability in aws-eusc (ESC) and GovCloud as part of H5, and does H3's
   design need to state a fallback (e.g. Ceph/WASABI or an on-prem S3
   gateway) for partitions where it is unavailable?
6. Cohasset citation strategy: quote the assessment in buyer-facing
   material once re-verified, or cite it only in design/deployment docs?
   If quoted, which revision's date do we pin?
7. Restore drill ownership: who runs and times the ledger-from-archive
   rebuild drill, the on-call engineer or the portal, and does the drill
   result land in the evidence pack as a control?

## References

- Backlog item: EPIC H3, WORM receipt archive (raucle-builder-backlog.md,
  H3, and the H5 partition note).
- G3 records management: `raucle/records.py` (destruction receipts,
  escrow, span digests), retention stamps in `raucle/gateway.py` x_gate.
- G1 time source model: `docs/spec/time-source-v1.md`, archive horizon in
  `raucle/timestamp.py`.
- Audit-chain projection (H1b-1): receipt chains to audit chains.
- Audit-export artefact: `docs/designs/audit-export-v1.md`.
- pq1 hybrid signatures: `docs/spec/provenance/v1/pq1-hybrid.md`.
- Cohasset Associates, "Compliance Assessment Report: Amazon S3,
  SEC 17a-4(f), 18a-6(e), FINRA 4511(c) and CFTC 1.31(c)-(d)", 2026
  revision (re-verify before quoting; commercial regions only).