# Emergency authority stop — stop quorum and button posture

B1/B3 of the killswitch build wave (decisions closed 9 Nov). The containment
machinery itself (`raucle containment hold|resume|approve-hold|abort-hold`)
was already receipted end-to-end; this page documents the two deployment
posture changes that wave landed.

## Global stops are M-of-N by default (B1)

A **global**-scope stop (`containment hold global`) is an M-of-N authorisation
with a default quorum of **N=2** distinct approvers: the first invocation puts
the stop into a receipted pending state without touching any enforcement
bytes; each distinct approver (`containment approve-hold --approver <id>`)
is itself a signed receipt; the stop applies only once the quorum is met, and
the hold receipt carries the whole approver roll. Repeat approvals by the same
identity are refused; a still-pending hold can be cancelled with
`containment abort-hold` (also receipted).

Per-agent and per-chain stops stay single-approver: one operator receipt
applies them, as before. The machinery is unchanged from mitigation M3 — what
changed is the default wiring, not the design.

Both quorums are per-deployment configuration:

- `RAUCLE_GLOBAL_MIN_APPROVERS` (default `2`) or `--global-min-approvers` on
  the `hold` command sets the global floor; set `1` to restore the demo drill
  single-approver path, or a higher number for a tighter quorum.
- `min_approvers` on `ContainmentConfig` still governs non-global scopes
  (default `1`).

## The emergency stop button is default-off per deployment (B3)

The *button* — the operator-facing emergency stop, as opposed to the operator
CLI path — ships **disarmed** (`RAUCLE_GLOBAL_MIN_APPROVERS` machinery and
audit plumbing all live regardless). Arming it is itself a receipted, visible
operator transition:

```
raucle containment arm-button --approver <identity> --reason "raise posture"
```

The arm receipt (`containment_button_arm`), the persisted arm state, and the
status line (`containment status` shows the button state) make the enable
step auditable and visible. The symmetric `disarm-button` transition is
equally receipted and chains to the arm receipt it reverses. While the button
is disarmed, a button-invoked hold refuses under its own name
(`emergency_stop_button_disarmed`) — nothing is stopped, and no receipt is
minted.

Arming the button does NOT loosen the global quorum: a global stop armed via
the button still requires the same M-of-N approval as any other global stop.

## Verification

All receipts verify offline against the operator public key:
`raucle verify-receipt <jws> --pubkey <state-dir>/containment-operator-pubkey.pem`.
