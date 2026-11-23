# Key rotation: operator runbook

The gateway signs every gate and admin-plane receipt with a persistent local
Ed25519 key: the operator plane's signing key. Until X3 slice 3 that key
rotated only through hand-work: generate a successor, move the old file by
hand, re-publish by hand, and hope the receipts minted before the move
still verify afterwards. `raucle operator rotate-keys` is the receipted form
of that rotation, on the rotate-chain discipline: every refusal is named,
the old key is archived and never deleted, the boundary is a signed receipt
in the chain of record, and a fresh boot is verified before the command
reports success.

The command bonds to the same env vars the gateway boot reads:
`RAUCLE_SIGNER_KEY_PATH` (the local key store; by default
`gateway-signing-key.pem` beside the receipt store), and
`RAUCLE_OPERATOR_KEY_REGISTRY` (the operator key registry both the rotation
and the boot guard bind to). When the registry is signed,
`RAUCLE_REGISTRY_OPERATOR_KEY` (or `--registry-key`) names the registry's
own signing key so the rotation's entries are signed like every other
entry. The operator identity comes from `--operator` or `RAUCLE_OPERATOR`.

## When to rotate

- Your key policy says so: the signing key is a long-lived credential, and
  a scheduled rotation cadence is cheaper than an unplanned one.
- Custody of the key material changed hands or host: rotate so the previous
  holder's copy is no longer the serving key. Rotation retires the old key;
  it does not revoke it. If you believe the old key is compromised, revoke
  it as a separate act after the rotation: revocation is the trust cut, and
  it fails closed.
- The boot told you to: the split-brain guard names
  `raucle operator rotate-keys` in its restart-required refusals, and a
  re-run is the recovery path it names.

## Preconditions

The rotation is fail-closed and refuses with named errors rather than
guessing. It needs:

- an operator key registry configured and present
  (`RAUCLE_OPERATOR_KEY_REGISTRY`), with the CURRENT signing key published
  in it (`raucle registry init`, then `raucle registry publish`). If you
  want no registry discipline at all, unset the variable.
- a local signing key to rotate (the gateway boot creates it on first
  start; rotate after the gateway has signed at least once).
- an operator identity (`--operator` or `RAUCLE_OPERATOR`), so the rotation
  receipt attributes the action to a named operator.
- a signed registry accompanied by its operator key
  (`RAUCLE_REGISTRY_OPERATOR_KEY` or `--registry-key`).

## What rotate-keys does

1. Refuses, before any side effect, with a named error when a precondition
   above fails, when the signing key is not registered or is revoked in the
   registry, or when today's retirement archive already exists (a same-day
   retirement must never be overwritten: inspect or move it, or rotate
   after midnight UTC). The refusal is all-or-nothing: no file moves, no
   registry entry and no receipt is minted.
2. Generates the successor keypair.
3. Re-registers the new public key in the registry through the registry's
   own append discipline. The old key RETIRES, a registry state distinct
   from revocation: a retired key still resolves, so every receipt it
   signed keeps verifying, while it stops holding the issuer name so the
   successor publishes under it. The registry holds BOTH keys across the
   transition.
4. Archives the old key file: a rename to
   `gateway-signing-key.pem.retired-<date>` in the same directory, never a
   delete. The digest is printed and recorded in the receipt.
5. Updates the local key store with the new private key (0600 from
   creation).
6. Mints the boundary receipt, signed by the NEW key (the first receipt
   pinned to it): both key ids, the archived key digest, the registry head
   after the update, the operator identity, the reason. Prior links are
   never rewritten.
7. Verifies a fresh boot: the boot's own key load path returns the new
   key, and a canary signed with it verifies against the registry's active
   entry.

## After rotation

- Receipts minted before the rotation verify unchanged. Each stays pinned
  to the key id that signed it, and verification resolves that id through
  the registry, retired or active. Nothing re-signs history; that is the
  point.
- New receipts carry the new key id.
- Revoking the retired key (`raucle registry revoke`) is a separate
  operator decision, and it is the trust cut: after it, receipts the
  retired key signed fail closed. Rotation never revokes; retire then
  revoke composes.
- Restart the gateway. The running process keeps the signer it loaded at
  boot; receipts it mints until the restart still verify (the retired key
  stays resolvable), but the serving signer should be the new key, and the
  boot guard re-checks the key store against the registry at construction.
- The retired key file stays on the box and counts against disk. Keep it
  while verification needs it: it is the offline verification copy for
  every receipt the old key signed. Deleting it is an owner's explicit
  action, and the rotation receipt records its digest, so a deleted
  retirement is always visible as a gap named in the receipt.
- Re-verify the deployment as you would after any restart: container
  health, `/health`, admin surface, then the public URL.

## The crash window and the boot guard

Stated honestly: the registry update lands before the key store moves. A
crash between the two leaves the registry AHEAD of the store. The boot's
split-brain guard refuses that state rather than serving receipts on a key
the registry does not vouch for:

- `RAUCLE_OPERATOR_KEY_REGISTRY` is set but the registry file is missing, or
  the registry fails its own integrity verification;
- the local signing key is not registered in the registry;
- the local signing key is revoked in the registry;
- the local signing key is RETIRED in the registry (the registry moved
  ahead: a rotation's registry update landed without its key-store update,
  or an old key was hand-restored).

Each refusal is a named, restart-required `KeyStoreRegistryMismatch`
naming `raucle operator rotate-keys` and the restart. Recovery is a
re-run: the crashed attempt's public-only key retires visibly in the
registry and a fresh key takes the name; nothing wedges.

The guard applies to the local signer backend only: KMS and TEE signers
keep their own key lifecycle, a named follow-up. An unset
`RAUCLE_OPERATOR_KEY_REGISTRY` leaves the boot exactly as it was.
