# Receipts v1.2: definition drift (x_gate.tool_definition)

Status: shipped November 2026. Backwards compatible: receipts without
the block are byte-identical to their pre-W2 shape.

## What it binds

The gate sees tool-call requests, not tool definitions and not tool
execution. Tool schemas arrive operator-fed at gate construction (an
MCP tools/list-shaped manifest bound at load time, the X1 path), so
the gate CAN honestly answer "which definition was the decision made
against" and CANNOT honestly answer "which definition was the tool
serving at call time". This extension binds the first answer and
receipts changes to it; it never fabricates the second.

Every gate receipt for a tool with a registered schema carries an
`x_gate.tool_definition` block: the definition digest bound at
registration, the manifest path the definition was pinned from, and an
honest vantage. A third party holding the same manifest re-derives
which definition each decision was made against; a manifest reload
that observes a changed digest emits a receipted `definition_changed`
finding recording the transition, old and new digests only.

The block carries digests and paths only. It never carries schema
content: the extension is swept by the shared forbidden-field sweep
and its field set is closed.

## The extension block

    x_gate.tool_definition = {
      "version": "tool-definition/v1",
      "definition_digest": "sha256:<digest of the registered inputSchema>",
      "definition_manifest": "<the manifest file the schema was bound from>",
      "definition_vantage": "none"
    }

Field rules:

- **version** is the version anchor. An unknown version refuses the
  receipt with a named error, never a silent skip.
- **definition_digest** is the sha256 over the registered input
  schema's canonical JSON (sorted keys, compact separators): the
  digest is a function of the schema's content, never the manifest
  file's byte layout, so the same definition binds the same digest
  across restarts and hosts. A schema fragment the deployment cannot
  canonicalise (non-finite numbers are not valid JSON) refuses at load,
  never at receipt time.
- **definition_manifest** names the pin the verifier recomputes
  against. It is empty when the tool was registered without a source
  manifest, in which case no recompute is possible and the block stays
  structural.
- **definition_vantage** is the closed vocabulary `none` until the
  in-path MCP gateway exists. The gate sees requests, not served
  definitions, so anything else would be detection theatre; a served
  vantage is refused.
- The field set is closed. Unknown fields fail verification with a
  named error, and the shared forbidden-field sweep rejects
  content-like fields outright: schema content never rides the
  receipt.
- The block is absent when the tool has no registered schema.
  Absent-block receipts keep their historical byte shape exactly
  (additive extension doctrine).

## The verifier

Two layers, both offline:

- Per line, the block re-checks structurally: the forbidden-field
  sweep, the closed field set, the version gate, the closed vantage
  vocabulary and the sha256 digest shape.
- At chain end, the pin discipline: the LATEST block per tool must
  re-derive from the on-disk manifest it names, and a readable
  manifest must declare the tool. That is the deployment's registry
  state answering for the chain's final decisions. Earlier blocks may
  carry superseded digests: definition drift is exactly what the
  reload path receipts, and a verifier that recomputed historical
  blocks against the current manifest would refute its own drift
  evidence.

The pin discipline is fail-closed in both directions:

- A manifest whose current schema does not match the latest receipt's
  digest, with NO receipted transition, is silent drift and fails
  verification with a named error. The operator remedies it by
  reloading through the gateway (which receipts the transition) or by
  taking the next gate call (which mints a receipt against the current
  definition).
- A manifest that is readable but does not declare the receipt's tool
  fails with a named error, receipted transition or not: a definition
  the deployment no longer carries is not made legitimate by history.

An unreadable manifest (the verifier's host is not the deployment) is
the documented off-deployment residual: no recompute is possible, the
blocks stay fully structural, and nothing is fabricated.

## Reload-drift findings

A manifest reload (`POST /api/tool-schemas/reload`, the same operator
plane as the policy reload) re-reads the configured manifest and
supersedes changed definitions in place. For each tool whose digest
changed the gateway emits a receipted finding through the harness
findings extension:

    harness: "tool-schema"
    test_id: "definition_changed"
    verdict: "confirmed"
    cited_receipt: <the last gate receipt minted for that tool>

The finding's note carries the old and new digests and the manifest
path only, never schema content. Emission is the claim; the offline
verifier enforces it (the cited receipt must exist in the chain and
the reported decision must match what it recorded, the harness
findings contract).

Honest exceptions, named rather than papered over:

- No prior gate receipt for the tool means no citable evidence, and
  the x_finding contract forbids ghost citations: the drift is
  recorded in the reload result as `skipped_no_prior_receipt` and
  nothing is minted. The registry still updates; the next receipt
  carries the new digest.
- A manifest configured after construction is refused with a named
  restart-required error, never rebound: the enforcement path holds
  the registry bound at boot, and rebinding would split receipts from
  the gate's deny decisions (the split-brain guard).

A changed digest on the LOAD path (a second registration of a changed
schema at boot) keeps X1's refusal unchanged; only the explicit reload
path observes drift. X1's deny path (undeclared arguments against the
registered schema) is not duplicated: this extension instruments WHICH
definition the decision was made against and when that definition
changed, extend, not fork.

## Deliberately out of scope

- Call-time diff of a submitted served-definition digest against the
  registered digest (`schema_drift`, a deny option): waits for the
  execution vantage, the in-path MCP gateway, the same prerequisite
  as W1's gate-executed read-back. One lane future, two features.
- Value-convention drift (priority direction, weekday numbering,
  duration units): invisible in ANY definition because the definition
  is identical in both versions; only W1's state evidence catches
  those. No control here pretends otherwise.
- Removal of tools from the registry on reload (entries absent from
  the payload stay registered): a named follow-up, never a silent
  drop.
