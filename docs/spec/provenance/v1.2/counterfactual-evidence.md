# Receipts v1.2: counterfactual evidence (intent receipts)

Status: draft 18 November 2026. Backwards compatible: receipts without
the block are byte-identical to their v1.1 shape, so every existing
verifier, conformance vector and reference port is unaffected. This
document is the contract; the emission and verifier legs land with the
implementing Q lane (spec precedes implementation).

## What it binds

An intent receipt (a gate receipt carrying `x_gate.intent`, per
[intent-binding.md](intent-binding.md)) MAY carry counterfactual
evidence: the NOT-TAKEN decision under a named alternative ruleset,
evaluated at decision time by the same deterministic gate machinery that
produced the enforced decision. The question it answers is asked at
decision time rather than after the fact: under the rules we considered
running, would this call have gone through?

The counterfactual is evidence about a hypothetical, never about
enforcement. The enforced decision is the one the gate recorded; the
counterfactual block records what the alternative would have said. A
third party can replay it offline because the evaluation is
deterministic and the ruleset is named by digest.

The alternative ruleset draws only on the deterministic vocabularies
the shipped specs define: the standard policy constraint vocabulary
(the same one `intent.constraints` uses), the session-rule kinds and
window bounds specified by
[session-behavioural-rules-v1.md](../../session-behavioural-rules-v1.md),
and its `participant` matcher (`tool_call`, `tool_response_taint`). No
other rule kind may back a counterfactual: a probabilistic classifier
verdict is advisory detection, never the receipted enforcement path, so
it cannot anchor a counterfactual block.

## The block

When counterfactual evidence is carried, the gate receipt's `x_gate`
carries:

    x_gate.counterfactual = {
      "version": "counterfactual/v1",
      "ruleset_hash": "sha256:<digest of the alternative ruleset>",
      "decision": "allow" | "deny",
      "rule_id": "<present iff decision = deny: the alternative rule that fired>",
      "rule_kind": "<present iff decision = deny: closed vocabulary>",
      "session": {
          "session_id": "<the receipt's own session id>",
          "window_seconds": <the rule's declared window bound>,
          "participant": "tool_call" | "tool_response_taint",
          "window_evidence": {"<counter name>": <int>, ...}
      },
      "evaluated_at": <epoch seconds>
    }

Field rules:

- **version** is the fail-closed anchor: `counterfactual/v1`. A
  consumer that meets an unknown version refuses the receipt with a
  named error, never silently ignoring the block.
- **ruleset_hash** pins WHICH policy the counterfactual speaks about.
  The ruleset is identified by digest, not editorial: a third party
  holding the same bytes hashes them and confirms it.
- **decision** is the not-taken decision, `allow` or `deny`.
- **rule_kind** is the closed vocabulary `policy_rule` plus the five
  session-rule kinds (`repeated_deny_storm`, `runaway_tool_loop`,
  `gradual_extraction`, `forbidden_tool_chain`, `scope_drift`).
- **session** is present if and only if the firing alternative rule is
  a session rule. Its `session_id` MUST equal the receipt's own: a
  counterfactual evaluated against another session's window is
  incoherent and fails verification. `window_evidence` carries counter
  names, counts and tool names only, never arguments or content, the
  same bounded shape a session-rule denial's reason carries.
- **evaluated_at** is an integer epoch and MUST NOT be later than the
  receipt's own `iat`: counterfactual evidence is recorded at decision
  time. A post-dated block is editorial, not evidence, and fails with
  a named error.

The block carries no argument values (the arguments stay behind the
receipt's `input_hash`), no denial-reason text (rule ids, rule kinds and
counters only) and no model output material: the replay boundary is the
shipped one, policy decisions and never model decisions.

No silent schema extension: the block appears only as the named
`x_gate.counterfactual` field with the closed field set above. Receipts
without it are byte-identical to their v1.1 shape. A verifier that does
not implement counterfactual evidence and meets the block refuses with
a named error rather than skipping it.

## Verification rules (offline, no operator contact)

The chain verifier re-checks every counterfactual block structurally,
and re-runs the evaluation when it holds the pieces:

1. Structure: closed field set; `decision` and `rule_kind` inside their
   closed vocabularies; digests sha256-shaped; epochs integer;
   `evaluated_at` not later than the receipt's `iat`.
2. Version gate: an unknown `version` fails the chain with a named
   error, never a skip.
3. Session coherence, when the `session` block is present: `session_id`
   equals the receipt's own; `window_seconds` is a positive integer;
   `participant` is inside the two-value matcher vocabulary;
   `window_evidence` counters are non-negative integers and tool names
   are strings. A content-like value inside `window_evidence` fails
   verification with a named error.
4. The replay re-check is conditional, and stated honestly: a verifier
   that holds the alternative ruleset (by digest) and the stored input
   re-runs the deterministic evaluation and confirms the recorded
   decision; a verifier without either, or a receipt with no stored
   input, reports the counterfactual as not re-run. It is never guessed
   and never upgraded.

## What a third party CAN conclude

- Which alternative ruleset the counterfactual speaks about (by
  digest), which rule fired, and with what window bound and participant
  when the rule is a session rule.
- That the deterministic gate machinery, at decision time, evaluating
  that ruleset, reached the recorded not-taken decision for this call:
  same clock, same stored input, same constraint vocabulary as every
  other receipt claim.
- With the replay re-check performed: that the recorded counterfactual
  decision reproduces offline, without the operator.

## What a third party CANNOT conclude

- That the alternative policy was ever enforced. It was not; the
  enforced decision is the one the receipt records.
- That the alternative policy would have prevented an incident as a
  whole. The claim covers this call. A chain whose inputs are not
  stored speaks only for the calls it covers; the rest are
  unreplayable, never guessed.
- Anything about model outputs. The replay boundary is unchanged from
  the shipped counterfactual engine: gate and policy decisions replay,
  model decisions do not (an `output_hash` is opaque ground truth from
  the original run).
- That a session-window counterfactual rested on complete window state.
  Window state is process memory with the restart and replay limits the
  session rules spec states; the counterfactual inherits them.
- That the counterfactual is a proof. The z3 proof leg (PROVEN /
  REFUTED / UNDECIDED) belongs to the replay and simulation surfaces
  and rides their evidence-depth contract; this block carries the
  decision and the bound only.

## Homes (the 16.3 split)

- Evidence layer (this document, the verifier rules, the future test
  vectors): OSS, public.
- Minting (the at-decision-time evaluation and the alternative-ruleset
  registry): the implementing Q lane, on the OSS gate surface.
- The policy-simulate operator surface and its signed simulation
  receipt are already specified by
  [x6-policy-simulate.md](../../x6-policy-simulate.md) and shipped;
  this extension composes with that surface, it does not replace it.

## Fixture targets for the implementation lane

Spec precedes implementation: these are the contract the implementing
lane pins, and they are not tests yet.

- A receipt with a structurally valid counterfactual block verifies
  offline; the same call without the block mints a receipt
  byte-identical to its v1.1 shape.
- An unknown `version` refuses with a named error.
- `evaluated_at` later than `iat` fails with a named error.
- A `session` block citing a session id other than the receipt's own
  fails with a named error.
- A content-like value inside `window_evidence` fails with a named
  error.
- A verifier without the alternative ruleset or the stored input
  reports the counterfactual as not re-run, named in the report, and
  the chain stays valid.

## Rationale

The incident-review question is asked everywhere else after the fact,
over a stored chain, and the honest answer then is bounded by what was
recorded. Recording the not-taken decision at decision time closes the
gap between an operator saying "we considered a stricter policy" and
evidence proving what that policy would have said, with the same clock
and machinery as the enforced decision. The limits are load-bearing,
not boilerplate: a block that could be read as enforcement, as
whole-incident prevention or as a proof would overclaim exactly the
way guardrail marketing does. The spec says what the evidence proves
and stops there.
