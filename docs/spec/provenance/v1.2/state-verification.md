# Receipts v1.2: state verification (x_state)

Status: shipped November 2026. Backwards compatible: receipts without
the extension are byte-identical to their pre-W1 shape.

## What it binds

The Experience Rot paper's remedy is the read-back: after a write,
read the stored state back and compare it with what the caller claimed.
The gate cannot perform that read. The gate sees tool-call requests,
not tool definitions and not tool execution (the Q-spec finding that
recast this lane), so a gate-executed read-back would fabricate a read
the gate never performed. This extension therefore binds what the
system can honestly produce today: read-back evidence AT MINT,
submitted by the adapter or runtime that actually executed the write.

The flow: the gate receipts a write decision; the runtime executes the
write; the runtime executes the paired read; the runtime hashes the
read's raw response bytes (sha256) and submits digest, handle and
field names to the gateway, which mints a signed `x_state` receipt
citing the write receipt. The gate binds and verifies; it never sees
content, and it never pretends the read was its own. A
gate-executed read-back and a verified-after reconciliation mode are
named follow-ups that wait for the execution vantage (the in-path MCP
gateway), the same prerequisite as W2's served-definition diff.

After this extension, a write reported as success with NO state
evidence is a named, offline-checkable receipt class: the verifier
marks a pairing-covered write receipt INVALID when neither evidence
nor the absent sentinel is present. That is the paper's 347/348
false-success finding made checkable in the verifiable layer, at zero
model cost. Runtimes that never submit are disclosed zeros, never
folded elsewhere (ADR-0004 coverage discipline).

## The extension block

    x_state = {
      "version": "state-evidence/v1",
      "pairing_id": "<the registry entry id>",
      "read_tool": "<the read executed post-write>",
      "evidence_digest": "sha256:<digest of the read tool's response bytes>",
      "handle": "<the object handle extracted per the entry's id_pointer>",
      "field_classes": ["<field-presence names observed in the read response>"],
      "cited_receipt": "<the write receipt's hash>"
    }

Field rules:

- **version** is the version anchor. An unknown version refuses the
  receipt with a named error, never a silent skip.
- **cited_receipt** is mandatory on every x_state receipt: the
  read-back digest is bound to the write's receipt id. The cited
  receipt must exist EARLIER in the chain (evidence follows the write,
  never pre-dates it), must be sha256-shaped, and is re-checked
  offline like every other extension citation.
- **evidence_digest** is the sha256 over the read tool's response
  bytes as submitted by the runtime: raw bytes, never normalised,
  never canonicalised, because the digest is what the runtime saw.
- **handle** is the object handle extracted from the read response via
  the pairing entry's id_pointer (for example the created event's id).
  A scalar identifier, never content.
- **field_classes** are pattern-class or field-presence names observed
  in the read response: which fields the response carried, never their
  values. The Q-7a disclosure rule carries over unchanged - digests
  and names, never content.
- **state_evidence** carries the literal sentinel `absent`. Absence
  is stated, never papered over with a fake digest: a receipt
  claiming absence must carry NO evidence fields, and a receipt
  carrying neither the sentinel nor an evidence_digest fails
  verification with a named error.
- **pairing_id** is the registry entry id. Evidence is always
  registry-bound: the gateway refuses to mint evidence for a pairing
  it does not know. On the absent path the pairing_id is present when
  a pairing exists (the read failed or was skipped) and omitted when
  the tool has no registry entry at all, in which case the receipt
  honestly says `state_evidence: absent` with no pairing_id.
- **read_tool** names the read the runtime executed (the paired read
  when a pairing exists).
- The field set is closed. Unknown fields fail verification with a
  named error, and the shared forbidden-field sweep rejects
  content-like fields at any depth: read-back content never rides the
  receipt.

The block is absent when no state evidence exists and no covered
write is asserted. Receipts without the extension keep their
historical byte shape exactly (additive extension doctrine): v1.0
chains and non-W1 chains verify byte-for-byte unchanged, and the
verification report gains no new shape.

## The state-pairing registry

Pairings are operator-declared in the policy file, in a new
`state_pairings` section alongside the tool schema manifest source
paths (the recommended surface, riding the same policy file the
gateway already seals):

    state_pairings:
      - write_tool: create_event
        read_tool: get_event
        id_pointer: event_id
        require_field_classes: ["status"]   # optional

Per entry: `write_tool`, `read_tool`, `id_pointer`, optional
`require_field_classes`. The entry id (`pairing_id`) is derived
deterministically as `<write_tool>:<read_tool>`.

Load-time validation follows the ToolSchemaRegistry doctrine
(tool_schema.py): refuse configs the gate could silently
under-enforce. A pairing referencing an unknown tool or an undeclared
id field raises a `SchemaPolicyLoadError`-class error at config load,
never at call time. Concretely:

- `write_tool` and `read_tool` must both be registered in the tool
  schema registry (the MCP tools/list-shaped manifest bound at load).
  The tools are seeded from the server manifest: the operator names
  the write/read sibling the manifest already declares.
- `id_pointer` must be a field the READ tool's input schema declares:
  the read must be parameterisable by the handle it extracts, so an
  id field the read cannot name is a pairing the runtime cannot
  execute. An undeclared id field refuses the config at load.
- A second pairing for the same write tool refuses the config: the
  paired read must be deterministic.

A tool with no registry entry is uncovered: unknown pairing means no
entry, and a read-back submitted for it is minted as the honest
absent sentinel with no pairing_id. The registry binds at boot; a
`state_pairings` section changed after construction requires a
restart, the same split-brain guard as the schema manifest (receipts
must never split from the registry state the gate enforces).

## The mint path (adapter evidence lane)

The runtime submits read-back evidence after a receipted write,
bounded and best-effort (the middleware is advisory by construction;
enforcement lives in the offline verifier):

1. The integration calls the write through the gate and records the
   write receipt (the existing `record_trace_receipt` binding).
2. The integration executes the write, then executes the paired read
   and hands the RAW response bytes to
   `RaucleMiddleware.submit_state_evidence(tool_name, read_response=..., trace_id=...)`.
3. The middleware hashes the raw bytes (sha256), extracts the handle
   per the entry's id_pointer, records the observed field names, and
   submits through `RaucleGateway.emit_state_evidence(...)`, which
   mints the signed `x_state` receipt citing the write receipt.
4. Failure or skip (no read response, unparseable response, no
   handle) yields the absent sentinel PLUS an advisory finding
   through the harness findings extension:

       harness: "state-verification"
       test_id: "state_evidence_missing"
       verdict: "confirmed"
       cited_receipt: <the write receipt>

   The finding's note names the reason (bounded: no content). An
   uncited call mints nothing: the verifier refuses findings that
   cite a receipt not in the chain, so an uncited submission is
   logged locally instead of minting unverifiable evidence.

The gateway is fail-closed at mint where the middleware is fail-open
at the seam: `emit_state_evidence` refuses an unknown pairing_id, an
evidence submission without a digest, handle or field names, an
absent submission carrying evidence fields, and a non-sha256 cited
receipt. The verifier remains the enforcement point.

## The verifier

Two layers, both offline, digest-blind by design (the verifier never
saw the read-back content; it re-checks what the receipt claims):

- Per line, the block re-checks structurally: the forbidden-field
  sweep, the closed field set, the version gate, the sentinel
  semantics (absent carries no evidence fields; neither evidence nor
  sentinel refuses), the sha256 digest shapes, the field_classes
  shape (non-empty list of names), and the cited write receipt's
  existence EARLIER in the chain.
- At chain end, the coverage and linkage pass, when the verifier is
  constructed with the deployment's pairing registry
  (`ProvenanceVerifier(..., state_pairings=...)`, the same
  constructor-carried state pattern as `executor_keys`):
  - Every ALLOWED gate receipt whose tool is a registry write tool
    must have a bound x_state receipt carrying evidence or the absent
    sentinel. Neither present marks the write receipt INVALID with a
    named reason: that is the false-success class, checkable.
  - Every x_state receipt with a pairing_id re-checks the linkage:
    the pairing exists in the registry, the cited write receipt's
    tool is the pairing's write tool, the block's read tool is the
    pairing's read tool, and every `require_field_classes` name is
    present in the block's field_classes (a presence re-check,
    deliberately dumb: semantic expectations on read outputs are where
    the paper's incomplete-documentation trap lives).

A verifier constructed WITHOUT the registry performs the per-line
structural checks only. That is the documented off-deployment
residual (the verifier's host is not the deployment), mirroring the
unreadable-manifest residual of the definition-drift pins: nothing is
fabricated, linkage simply cannot be re-checked.

## Deliberately out of scope

- Gate-executed synchronous read-back and verified-after
  reconciliation: named follow-ups gated on the execution vantage
  (the in-path MCP gateway). Nothing in v1 fabricates a read the
  gate did not perform or receive.
- Escalation options (deny follow-up calls citing an unverified
  write): a named follow-up, not smuggled into v1.
- Name-heuristic auto-seeding of pairings from MCP manifests (a
  create_X/get_X guess): the operator declares the sibling pair; a
  heuristic would fabricate pairings the operator never chose.
- Semantic re-derivation of evidence_digest from response bytes: the
  verifier is digest-blind by design; the transport carries digests,
  never bytes, so no recompute exists to perform. The binding (write
  receipt id, registry linkage, coverage) is the verifiable claim.
- Value-convention drift (priority direction, weekday numbering,
  duration units): invisible in any definition; W1's state evidence
  is the only surface that can catch those, and only the runtime's
  read-back supplies it.
