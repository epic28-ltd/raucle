# QM deployment fragment: the raucle gate as an installed tool

This directory is the raucle wiring for QM-class coordination harnesses
(yc-software/qm, MIT). QM deployments consume custom tools through the
deployment-directory contract: `tools/<id>/tool.json` plus the text file
declared under `install.files`, which QM's deployment-layer sync converges
into every sandbox at `/usr/local/bin/raucle-gate` (mode 0755).

To adopt: copy `tools/raucle-gate/` into your QM deployment repository's
tools directory and set two environment values on the scopes that run gated
work:

- `RAUCLE_GATEWAY_URL` - your raucle gateway origin
- `RAUCLE_CAPABILITY_TOKEN` - the per-task capability token minted by the
  bridge (`raucle.integrations.qm.QmHarnessBridge.mint_for_task`), or by
  your own minting code against `raucle.capability`

Every gated call then crosses the raucle gate with `X-Capability-Token`:

- allow - exit 0, response JSON with `receipt_id` on stdout
- deny - exit 1, receipted where the caller is verifiable
- escalate - exit 2, approval request receipted
- gate unreachable - exit 3, fail closed: the wrapped action never proceeds

The receipts bind the delegated-authority chain (receipts v1.1) and verify
offline with the public verifier, in any of the five reference languages.

`tests/test_qm_live_integration.py` in the raucle repository proves this
fragment end to end against a real gateway socket: mint root, attenuate,
allow, attributable deny, fail-closed, offline chain verification.

## Deny retry guidance (raucle/retry-guidance/v1)

Deny responses the gate tool prints carry an additive `retry_guidance`
field when the token's own whitelist/required/bounds constraints
deterministically describe what WOULD have been allowed
(`docs/spec/retry-guidance-v1.md`). The verdict is untouched: the exit
code stays 1, the decision stays `deny`; when nothing deterministic can
be derived the key is absent, never null. An agent retry loop reads the
shape, retries within the declared alternatives, and the retry is
allowed by the same authority — no policy loosening at any point.