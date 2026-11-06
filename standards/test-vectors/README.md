# Standards test vectors

Reference vectors for the three Raucle profile drafts. A conforming reimplementation MUST round-trip every vector in this directory.

## How to regenerate

```bash
PYTHONPATH=. python standards/test-vectors/generate.py
```

The generator pins the Ed25519 keypair (via fixed secret seed) and the wall-clock (via `FROZEN_NOW`), so any run produces bit-identical output. CI verifies this on every commit. If the vectors drift, either the generator changed or the canonical encoding changed — both are noteworthy events.

## `cap:v1` vectors

| File | What it verifies |
|---|---|
| `cap_v1_01_minimal.json` | The minimal valid token: no constraints, no parent, no proof binding. |
| `cap_v1_02_constraints.json` | Token with `max_value` + `allowed_values` constraints. |
| `cap_v1_03_attenuated.json` | Child of `02` with tightened `max_value`. Verify `parent_id` matches `02.token_id`. |
| `cap_v1_04_with_proof.json` | Token with non-null `policy_proof_hash`. |
| `cap_v1_05_tampered.json` | Same body as `02` with `constraints` mutated to widen the bound. Original signature retained. **MUST fail verification.** |

`cap_issuer_pubkey.pem` is the issuer public key for verifying vectors 1-4.

## `proof:v1` vectors

| File | What it verifies |
|---|---|
| `proof_v1_01_proven.json` | Trivially-PROVEN proof: the schema's enum already excludes the forbidden value. |
| `proof_v1_02_refuted.json` | REFUTED proof with concrete counterexample showing a schema-valid argument that violates a stricter policy. |

## `dataflow:v1` vectors

| File | What it verifies |
|---|---|
| `dataflow_v1_01_taint_denies_destination.json` | The data-flow acceptance scenario: call 1's output carries taint `untrusted_user` in the same task chain; call 2 targets destination class `payment:external` under `deny_from_chain_taint` — call 1 allows, call 2 denies with the named reason, and each call alone allows. |

A conforming implementation replays the recorded chain state deterministically: the
same (rule, prior outputs, destination class) triple always yields the same
verdict, and unknown taint tags / unknown destination classes deny fail-closed.

## `gate-decision:v1` schema

`gate_decision_v1_schema.json` — the field-shape reference. The reference implementation in `raucle/audit.py` emits events conforming to this shape; production deployments may add `x-`-prefixed extension fields without breaking the canonical-body hashing.

## Verifying these vectors in your reimplementation

For each vector, a conforming `cap:v1` verifier should:

1. Load the JSON.
2. Compute the canonical-JSON serialisation of the body (every field except `token_id` and `signature`).
3. Recompute `cap:` + SHA-256 of the canonical body; compare to `token_id`.
4. Verify the Ed25519 signature against the issuer's pinned public key.
5. Apply the time bounds, tool match, and constraint checks if running the full gate.

Vectors 01-04 should all verify cleanly with `cap_issuer_pubkey.pem`. Vector 05 should fail at step 3 (token_id mismatch) or step 4 (signature mismatch).

## Drift-check CI job

A standard CI job re-runs the generator and confirms the output exactly matches what's committed:

```bash
PYTHONPATH=. python standards/test-vectors/generate.py
git diff --exit-code standards/test-vectors/
```

The build fails if a code change has altered the canonical encoding without an accompanying update to the test vectors.
