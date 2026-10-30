# Receipts v1.2: task-intent binding (additive extension)

Status: accepted 29 October 2026. Backwards compatible with receipts v1/v1.1:
absent fields produce byte-identical receipts, so every existing verifier,
conformance vector and reference port is unaffected.

## What it binds

An approved task may now carry an INTENT: a free-text statement of purpose
plus structured constraints. The intent binds at MINT - a capability token
may carry an `intent` object:

```
intent = {
    "statement": "Check today's calendar and report conflicts",  # required, non-empty
    "tools": ["calendar_read"],           # optional: the approved resource class
    "constraints": {                      # optional: same vocabulary as token constraints
        "allowed_values": {"window": ["today"]}
    }
}
```

Tokens without an intent are byte-identical to v1.1. A delegated child
inherits its parent's intent; a child may narrow it (tool subset,
constraint intersection) and never widen it - `CapabilityIssuer.attenuate`
refuses a widening intent, the same monotonicity the chain's other
dimensions obey.

## Enforcement (gate-time, deterministic, no model involvement)

`CapabilityGate.check` enforces the intent on every call under an
intent-bearing token, after the token's own constraint stage:

1. If `intent.tools` is present, the token's tool must be in it - an
   authority minted for one purpose cannot invoke tools outside the
   approved class. The denial is attributable.
2. If `intent.constraints` is present, the call's arguments must satisfy
   them (the standard constraint vocabulary: allowed_values fail closed,
   bounds reject non-numerics, and so on). The denial is attributable.

## Receipt shape

When an intent was in force, the gate receipt's `x_gate` carries:

- `intent`: the intent block exactly as approved (signed as part of the
  receipt, so tampering breaks the signature)
- `intent_check`: a BOUNDED disclosure - `{tool, satisfied_fields}` where
  `satisfied_fields` carries only the values of the fields the intent
  constrains. Nothing else about the arguments is disclosed; the full
  arguments remain behind the receipt's `input_hash`.

## Verification rules (verifier-side, defence-in-depth)

`ProvenanceVerifier.verify_chain` re-checks every ALLOW receipt that
carries an intent:

1. The receipt's recorded tool must sit inside `intent.tools` when
   present. A chain-valid ALLOW for an out-of-scope tool is INVALID with a
   named reason - it means the gate failed to enforce (or the evidence was
   fabricated), and the verifier does not trust the gate's own enforcement
   story.
2. Each disclosed `satisfied_fields` value must satisfy
   `intent.constraints`. A violation is INVALID with a named reason.

DENY receipts are exempt from the re-check: a denial for an
out-of-intent attempt is the enforcement working, and the receipt is the
evidence of it.

## Test fixtures

- Calendar-vs-archive: an intent approving `calendar_read` for `window:
  today` cannot produce a verifying ALLOW receipt for a five-year
  `archive_export` - the gate denies it (attributable), and a forged or
  buggy ALLOW fails the verifier with "outside intent scope".
- Recipient allowlist: an intent constraining `send_email` to
  `{alice@corp.example, bob@corp.example}` rejects an ALLOW disclosing
  `to: eve@evil.example` with a named constraint violation.

Both live in `tests/test_intent_binding.py` with the token, gate, receipt
and verifier legs.

## Rationale

Purpose-scoped authorisation is what harness-side competitors approximate
with internal policy logs. Binding the intent cryptographically - approved
at mint, enforced deterministically at the gate, re-checked by any third
party against the receipt - makes "the agent did what it was approved to
do, and nothing else" an offline-verifiable claim, not a log entry. This
is the Clawvisor-shaped capability done on verifiable foundations, and it
composes with v1.1: the chain proves WHO delegated; the intent proves
WHAT FOR.