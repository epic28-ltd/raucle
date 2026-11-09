# X6: Policy Simulation API — deterministic, signed, flippable

Backlog item ~1966. Slice 1: `POST /api/policy/simulate` plus the named flip
path `POST /api/policy/simulate/apply`. The operator question this answers:
*"What would THIS candidate policy have done to the traffic we actually
served?"* — answered deterministically, receipted, and appliable.

The panel tab (simulate UI) is the named follow-up; this slice is the API
everything else hangs off.

## Surface

- `POST /api/policy/simulate` — operator-plane only (admin-panel key,
  `policies` access; TOTP respected as usual for the plane).
- `POST /api/policy/simulate/apply` — the same plane and access, plus the
  verified simulation receipt.

Both live in the admin panel app (`raucle.gateway_app`,
`_register_simulate_routes`); the engine is `raucle.policy_simulate`.

## Request → response

```jsonc
// POST /api/policy/simulate
{
  "candidate_policy_yaml": "…",   // OR "policy_ref": "/path/on/server.yaml" — exactly one
  "window_ref": "/data/receipts.jsonl",     // historical window: receipt-chain JSONL
  "input_store_ref": "/data/inputs.jsonl"   // optional: replay input store alongside the window
}
```

Response: `{"result", "receipt_hash", "jws"}` where `result` is the
`policy_simulate/v1` payload (below) and `jws` is the signed receipt
envelope binding it. `result.gate` carries:

- `current` / `candidate`: `{allow, deny}` counts over the window's
  recorded gate decisions;
- `changed_decisions`: every receipt whose decision flips, bounded
  (receipt hash, tool, agent id, both decisions, evidence depth) —
  never arg values, never denial reasons (bounded disclosure, same
  contract as the I1 counterfactual);
- `chain_depth`: maximum evidence depth behind any row (see below);
- `verdict`: the counterfactual engine's sentence.

The engine path is the existing one: `raucle.counterfactual.replay_counterfactual`
re-runs every recorded decision through the gate machinery (`check_tool_call`)
against the candidate policy, with the z3 proof leg (`PROVEN / REFUTED /
UNDECIDED`) where it fires. Inputs without a stored record are
**unreplayable, never guessed** — unchanged from I1.

### Evidence depth

Per row: 1 = recorded decision only, 2 = replayed from the stored input,
3 = replayed *and* proven (the z3 leg excluded the whole recorded argument
class). `chain_depth` = max across rows: how deep the evidence behind the
simulation verdict goes.

## Signed receipt

The simulation result is receipted through the existing machinery
(`RaucleGateway._sign_and_store_receipt`): GUARDRAIL_SCAN operation,
gate identity EdDSA JWS, minimal envelope appended to the operator-plane
gateway's receipt store. The extension key is `x_sim`; the receipt's
`ruleset_hash` binds the candidate policy, `input_hash` binds the exact
result payload, `guardrail_verdict` carries the verdict sentence.

**Determinism pin:** the payload carries `iat: 0` — a simulation receipt
is a pure function of (candidate policy, window, engine), not an event.
No wall-clock field enters the signed payload; the SIEM copy (below) is
timestamped outside it. Same inputs ⇒ byte-identical `jws`, verifiable
by anyone, anywhere. Pinned in tests (`test_same_inputs_byte_identical_signed_result`,
`test_determinism_uses_no_wall_clock`).

Two implementation consequences worth knowing:

1. The operator-plane gateway keeps its own receipt store, disjoint from
   the served window, so a simulation never appends into the very chain a
   later identical simulation would replay.
2. The candidate policy is canonicalised (YAML re-serialised after schema
   validation *before* hashing), so formatting differences cannot mint two
   different verdicts for the same policy — and cannot hide a different one.

## Verification

`verify_simulation_receipt(gateway, jws)` in `raucle.policy_simulate`:
strict JOSE/structural validation (spec v1 §3.3) + Ed25519 signature check
against the gate identity's public key + the `x_sim` presence check. A
tampered, re-signed-under-another-key, or result-stripped receipt refuses
named (`invalid_simulation_receipt`).

## The flip: sim_apply

`POST /api/policy/simulate/apply` is the **named apply path** with its own
receipt (`x_sim_apply`):

1. verify the simulation receipt strictly (above);
2. re-validate the submitted candidate policy and refuse
   (`candidate_hash_mismatch`) unless its canonical hash equals the one
   the simulation receipt signed its verdict for;
3. write the canonically re-serialised policy through the standard flow:
   policy file write → hash-chained policy ledger (`sim_policy_applied`) →
   `reload_policies`;
4. emit the `x_sim_apply` authority receipt citing the simulation receipt
   it acted on (`simulation_receipt`), the actor, the candidate hash and
   the chain depth the verdict was backed by.

The apply receipt lives in the same receipt machinery, so the audit chain
shows the decision, its evidence, and the flip, all bound by signatures.

## Auth posture

- Operator-plane required: admin-panel user key + `policies` access.
- Agent-plane keys (per-agent gate credentials,
  `raucle.agent_credentials.AgentCredentialStore`) are **deny-by-default**
  and the refusal is *named*: `agent_plane_key_denied` (403), checked
  before any other auth path, on both endpoints. A leaked agent key
  probing this surface is visible as a named refusal rather than an
  ambiguous 401.
- An unknown non-operator key refuses with the plane's standard 403.

## SIEM

Every successful simulation forwards a `policy_simulate` event
(candidate hash, window ref, receipt hash, timestamp) through the
gateway's SIEM forwarder — buffered when SIEM is disabled, never
blocking the simulation on export failure.

## Error contract

All refusals are named (`reason: message` in the 400/403 detail):
`candidate_policy_required`, `invalid_candidate_policy`,
`unknown_policy_ref`, `unknown_window`, `unknown_input_store`,
`invalid_simulation_receipt`, `candidate_hash_mismatch`,
`receipt_machinery_drift` (500: a machinery signing divergence must be
loud, never returned as a receipt).

## Test pins

`tests/test_policy_simulate.py` — 14 tests: fixture-traffic simulation,
determinism (result + JWS, different callers), no-wall-clock payload,
named refusals (schema-invalid candidate, missing source, unknown window),
agent-plane deny on both endpoints, auditor-role refusal, flip round-trip
(apply receipt present and citing the sim receipt; gate now denies the
incident account), mismatched-candidate refusal, tampered-receipt refusal,
SIEM event.
