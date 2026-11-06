# Bilateral outcome extension (x_bilateral)

Status: SHIPPED (6 November 2026). Closes round-1 vulnerability 2 (N1):
today a gate or runner receipt records what the AGENT side claims happened,
with no first-class way for the tool/execution side to co-sign what it
actually did. This extension makes the outcome of an execution a
co-signed fact, verified fail-closed offline.

## The problem

A receipt's `output_hash` binds what was produced, but the verdict on the
execution — did it run, fail or get refused — is carried only by the
signing agent's own words. The executor (the tool runtime, the runner, the
agent-hosting process) is a second party with its own key and its own claim.
Nothing today lets the two sides sign one outcome so that neither can
re-characterise it alone.

## The extension block

`x_bilateral` rides the payload root, like `x_gate`/`x_finding`, so it is
inside the agent's signature envelope:

```json
"x_bilateral": {
  "outcome": "executed" | "failed" | "rejected",
  "output_hash": "<the receipt's own output_hash, bound>",
  "executor_key_id": "<the executor's key id>",
  "signature": "<base64 Ed25519 over the bilateral binding>"
}
```

The bilateral binding is canonical JSON over exactly
`{executor_key_id, outcome, output_hash}` (`raucle.bilateral.bilateral_signing_input`),
signed by the executor's Ed25519 key. Three invariants follow:

- The co-signature lives INSIDE the signed payload, attached before the
  agent signs: agent signature, output_hash and executor claim are bound by
  one JWS and cannot move independently.
- The outcome vocabulary is closed (`executed`, `failed`, `rejected`).
  Emission refuses anything else (`sign_bilateral_outcome`); verification
  treats an off-vocabulary word as a named failure.
- `x_bilateral.output_hash` MUST equal the receipt's own `output_hash`: the
  executor vouches the outcome of exactly the output the receipt records.

Additive by construction: receipts without the block are untouched and
verify byte-identically to before; the payload schema, canonical JSON and
JWS conventions are unchanged.

## The verifier's re-check (fail-closed)

`ProvenanceVerifier(executor_keys={key_id: PEM})` re-checks every
`x_bilateral` offline. A receipt carrying the block FAILS with a named
reason when:

1. the block is not an object, or its `output_hash` does not bind the
   receipt's own `output_hash`;
2. the outcome is outside the closed vocabulary;
3. the executor signature is missing — an unsigned outcome claim is never
   silently accepted, and never inferred;
4. the named executor key id is not registered (`fail-closed: unknown
   executor`) — including the default verifier that was told no executor
   keys at all;
5. the co-signature does not verify over the bilateral binding under the
   registered executor key.

Legacy receipts in the same chain verify untouched; the bilateral check
fires only for lines carrying the block.

## The QM adapter seam

`QmHarnessBridge.bilateral_outcome(executor, outcome=..., output_hash=...)`
produces the co-signed block; `QmHarnessBridge.executor_keys([...])`
produces the verifier-side key map; `wiring()` carries the exec-side block
so the harness config names the contract. The executor is an
`AgentIdentity` with its own keypair, distinct from the agent's.

## Acceptance (pinned by tests/test_x_bilateral.py)

- A receipt with a well-formed bilateral co-sign verifies, and the block
  survives parse round-trip.
- A block without the executor signature fails with a named reason.
- A co-signature over one outcome cannot vouch a re-labelled outcome.
- Mixed chains (bilateral + legacy receipts) verify end to end.
- The outcome vocabulary is closed at emission and verification; the
  block's object shape and output_hash binding are validated.
