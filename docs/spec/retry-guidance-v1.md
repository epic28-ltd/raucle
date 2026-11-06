# Deny retry guidance — `raucle/retry-guidance/v1`

EPIC O2. When the gate denies a call, the deny receipt already carries the
authority chain, the violated constraint and the reason (receipts v1.1+).
What an agent retry loop still lacks is the machine-readable answer to the
question the reason leaves open: **what would this delegated authority
actually have allowed?** This spec documents the additive,
deterministic `retry_guidance` shape that the harness adapter
(`raucle.integrations.qm`) and the installed `raucle-gate` deployment
artifact attach to deny responses.

## Invariants (test-pinned)

1. **Additive, always.** The guidance rides alongside a deny and never
   touches the verdict. A deny with guidance attached has the same
   `decision`, `reason`, `receipt_id` and every other field byte-identical
   to a deny without it. Allow and escalate responses are returned
   unchanged: the key is never added to them, and the gate endpoint
   itself never emits the field — it is an adapter-layer presentation of
   the authority the caller already holds, not a second gate pass.
2. **Deterministic.** The shape is computed from the capability token the
   adapter already injected for the call (the same signed policy object
   the gate enforced) — no inference, no model involvement, no network
   round-trip. Whitelist constraints (`allowed_values`), required fields
   (`required_present`) and numeric bounds (`min_value` / `max_value`) are
   positive statements about what would be permitted, copied verbatim. An
   approved task intent merges into the criteria in the fail-closed
   narrowing direction: intersection of whitelists, union of required
   fields, tighter of the two bounds.
3. **Honest absence.** When no deterministic alternative can be derived —
   denylist-only authority (`forbidden_values`), rate limits
   (`max_calls_per_hour`), expiry windows, or an intent whose tool set
   excludes the token's tool — the `retry_guidance` key is **absent**.
   Named absence, never `null`: `null` would invite the retry loop to
   guess; absence says "nothing deterministic to say, do not retry blind".

## Shape

```json
{
  "schema": "raucle/retry-guidance/v1",
  "permitted_actions": [
    {
      "tool": "lookup_balance",
      "criteria": {
        "allowed_values": {"account": ["ACC-001", "ACC-002"]},
        "required_present": ["account"],
        "bounds": {"amount": {"min": 0, "max": 5000}}
      }
    }
  ]
}
```

`permitted_actions` has one entry — the single tool the token covers. The
criteria keys are the whitelist, required and bounds constraints the gate
enforces; a retried call satisfying **all** present criteria is within
this authority. The canonical schema (draft 2020-12) lives in
`raucle/integrations/retry_guidance.py` as `RETRY_GUIDANCE_SCHEMA` and is
exposed on the bridge as `QmHarnessBridge.retry_guidance_schema()`.

## Where it attaches

- `gate_call()` (`raucle/integrations/qm.py`): both deny paths — the
  HTTP-error body and a deny decision in a 200 body — gain `retry_guidance`
  when derivable. The `wiring()` bundle documents the field under
  `retry_guidance`.
- `examples/qm/tools/raucle-gate/raucle-gate`: the installed deployment
  artifact carries a deliberate, stdlib-only copy of the same derivation
  (the sandbox artifact cannot import raucle) and applies it to every deny
  response it prints.
- `QmHarnessBridge.deny_feedback(token_dict)`: direct access for harnesses
  that implement their own deny plumbing.

## Worked deny → retry scenario

1. A task's authority allows `lookup_balance` for exactly accounts
   `ACC-001` and `ACC-002`.
2. The agent calls with `{"account": "ACC-999"}` → deny, reason
   `constraint violated: ...`, receipted fail-closed. The deny response
   carries `retry_guidance` with `allowed_values.account = ["ACC-001",
   "ACC-002"]`.
3. A retry loop reads the shape, re-invokes the tool with an in-whitelist
   argument, and the retry is allowed by the same authority — no policy
   loosening at any point.

Provenance note: the guidance concept (deterministic, additive deny
feedback derived from already-held policy objects) is raucle's own; the
schema shape follows the repo's existing named-absence conventions rather
than any external reference.
