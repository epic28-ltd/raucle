# X3 Slice 3: Receipted Operator Key Rotation (Spec)

Status: implemented (the local signer backend; the registry discipline is
opt-in via `RAUCLE_OPERATOR_KEY_REGISTRY`).
Follow-ups named in the PR: KMS and TEE signer lifecycles keep their own
rotation paths (the boot guard binds the local backend only).

## Purpose

Rotate the operator plane's signing key (the persistent Ed25519 key behind
`agent:gate`) as one receipted, all-or-nothing command, so receipts minted
before the rotation keep verifying without re-signing history.

## Non-goals (this slice)

- No key escrow or recovery workflow (docs/security/key-operations.md
  keeps the escrow procedure).
- No KMS or TEE lifecycle changes.
- No re-signing, rewriting or migration of existing receipts or chains.

## Configuration contract

| Setting | Where | Notes |
| --- | --- | --- |
| `RAUCLE_OPERATOR_KEY_REGISTRY` | env / `operator_key_registry` | the registry both the rotation and the boot guard bind to; empty = no registry discipline, boot unchanged |
| `RAUCLE_REGISTRY_OPERATOR_KEY` | env / `--registry-key` | the registry's own signing key, required when the registry is signed |
| `RAUCLE_SIGNER_KEY_PATH` | env / `signer_key_path` | the local key store; default `gateway-signing-key.pem` beside the receipt store |
| `RAUCLE_OPERATOR` | env / `--operator` | the operator identity recorded in the rotation receipt |

## Behaviour

1. **Refusals, all before any side effect** (`KeyRotationRefusedError`,
   CLI exit 1, all-or-nothing): no operator identity; no registry
   configured; the registry file absent (fail-closed); no local signing key;
   a same-day retirement archive already present (idempotent-safe); a
   signed registry without its operator key; the signing key not
   registered; the signing key revoked.
2. **Registry transition.** The successor publishes through the registry's
   append discipline under the same issuer name; the old key RETIRES
   (append-only, still resolvable, no longer holding the issuer name). The
   registry holds both keys across the transition: retired + active.
   Retirement is additive: unset fields are omitted, so existing records
   serialise byte-identically.
3. **Key store.** The old key file renames to `<key>.retired-<date>` (never
   deleted, digest printed); the new private key lands with 0600 from
   creation.
4. **Boundary receipt.** A `GUARDRAIL_SCAN`-shaped provenance receipt
   signed by the NEW key (the first receipt pinned to it), carrying an
   `x_key_rotation` extension binding both key ids, the archived key
   digest, the registry head, the operator identity and the reason. Prior
   links are never rewritten.
5. **Verification.** The boot's own key load path returns the new key, and
   a signed canary verifies against the registry's active entry.
6. **Boot split-brain guard** (`KeyStoreRegistryMismatch`,
   restart-required, local signer backend only, when a registry is
   configured): registry missing or failing integrity verification; local
   key unregistered, revoked or retired. Each refusal names
   `raucle operator rotate-keys` and the restart. A crash between the
   registry update and the key-store move recovers by a re-run: the
   crashed attempt's public-only key retires visibly.

## Verification semantics

Every receipt stays pinned to the key id that signed it; verification
resolves key ids through the registry, retired or active. Receipts minted
before the rotation verify against the retired key; receipts after verify
against the new. Revocation of the retired key is a separate operator act
(`raucle registry revoke`) and cuts old receipts fail-closed: retire then
revoke composes, rotation never revokes.

## Environment compatibility

Everything ships inert: `operator_key_registry` defaults empty (the boot
is unchanged without it), registry records without retirement serialise
byte-identically (omit-when-empty), and the rotation receipt rides the
existing authority envelope, verifiable by the standard chain verifier.
