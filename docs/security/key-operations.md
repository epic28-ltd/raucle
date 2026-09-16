# Key operations runbook

How raucle keys live, rotate, escrow and recover. Every procedure here maps
to an executable test: `tests/test_key_rotation_e2e.py` is this document's
proof, and changes with it.

## The key inventory

| Key | Held by | Persistence | What breaks if lost |
|---|---|---|---|
| Gateway signing key (Ed25519) | The gateway host | `<data-dir>/gateway-signing-key.pem`, 0600, or `RAUCLE_SIGNER_KEY_PATH` | New receipts cannot chain onto the old identity; old receipts still verify offline (archive the PEM) |
| Agent capability keys | Each agent process | Per-agent; the registry holds the public keys | That agent cannot authenticate until re-registered |
| Admin panel keys | The users file | `<data-dir>/users.jsonl` (hashed) | Individual account; re-issue from an admin session |
| Trust registry operator key | Operations | Where the registry's integrity signer lives | New registry entries cannot be signed |
| PQ keys (ML-DSA-65) | Local files until cloud KMS ships ML-DSA | Beside their classical peers | Hybrid chains for that identity stop verifying |

## Rotation

The registry enforces **one active classical key per issuer name**: two
different keys claiming the same active identity is an impersonation, and the
registry rejects it. Zero-downtime rotation therefore mints the new
generation under a **versioned issuer identity** (`acme.bank/v2`), runs a
dual-trust window, then retires the old key.

```bash
# 1. Mint and publish the new generation (versioned identity)
raucle cap keygen --issuer acme.bank/v2 --out new-key.pem
raucle registry publish new-key-pub.pem --issuer acme.bank/v2

# 2. Dual-trust window: agents holding either generation pass while you
#    roll out the new credentials. Both keys are active in the fold.

# 3. Retire the old generation
raucle registry revoke <old-key-id> --reason "scheduled rotation"

# 4. Post-conditions (the e2e test proves each):
#    - new mints under the old key FAIL CLOSED (no trust)
#    - tokens minted before rotation still verify (during the window)
#    - after revoke, only the new generation authorises
```

Gateway signing-key rotation (the `agent:gate` identity) is a restart
procedure: archive the PEM, remove it, boot. The new boot generates a new
identity; the archived public key verifies every old receipt offline,
forever. Old and new receipts coexist in one chain - verification needs
both public keys, which is what audit packs bundle (`--pubkeys` accepts
several).

**Revocation is not erasure.** Revoking a key removes the *trust* (new
authorisation fails closed) but the *math* stands: signatures made before
revocation still verify against the public key. That is the archival
property a regulator needs, and it is why verification keys are archived
with the audit packs, never deleted.

## Escrow and recovery

- **Gateway signing key:** copy the PEM to offline storage (encrypted, two
  copies, two locations) at generation and at every rotation. The recovery
  drill: restore the PEM, boot, run `raucle provenance verify` against the
  latest segment. Practise it annually.
- **Verification keys (public):** every audit pack carries them. Losing
  them costs nothing - re-export from any pack or from the archived PEMs.
- **Registry:** the registry JSONL is itself an append-only signed chain.
  Recovery = restore the latest copy; integrity is checked with
  `raucle registry verify`. Back it up with the same schedule as the
  receipt segments.

## The split PQ-key posture (honest note)

Cloud KMS does not yet ship ML-DSA-65. Hybrid deployments therefore hold
the classical key in the cloud HSM and the ML-DSA key in a local file.
That split is a real, documentable posture: the classical component has
HSM-grade protection, the PQ component has host-file protection, and both
must verify. When AWS KMS or Azure Key Vault ships ML-DSA, move the key
and delete the file; the `pq` extra's `RAUCLE_SIGNER` plumbing already
abstracts the backend.

## What fails closed

- Corrupt or non-Ed25519 key material at the signing path: the gateway
  refuses to boot (a regenerated key would orphan every prior receipt).
- A revoked issuer at the gate: caller tokens deny on the next request.
- An unwritable receipt: the decision downgrades to deny.
- An unwriteable registry: gate auth (token mode) loses its issuer list and
  fails closed.

Each of those has a test; none of them is a surprise in an incident.