# Hardware-attested signing (EPIC H3, slice 1)

Status: shipped as slice 1 of EPIC H3. The design proposal lives at
`docs/proposals/tee-gate.md`; the receipt-level contract this slice touches
is the capability statement in `docs/spec/provenance/v1.md` (§5.1).

## Why hardware attestation

Every receipt raucle emits is only as trustworthy as the process that signs
it. The provenance verifier proves *what was decided and signed*, and the
KMS signer backends (`raucle/kms.py`) prove the signing key never sat in
readable memory on the gateway host. Neither proves *which code signed the
receipt*: a compromised gate runtime could sign anything with a valid key,
and an offline verifier could not tell the difference. That is the gap
EPIC H3 closes, by binding the receipt-signing key to a Trusted Execution
Environment (TEE) measurement and carrying that binding in signed material.

The new trust assumption is deliberately smaller than the one it replaces:
instead of trusting the gate operator's runtime, a verifier trusts the TEE
vendor's attestation chain (for example the AWS Nitro root of trust, AMD's
KDS, or Intel's Provisioning Certification Service). For cross-organisation
receipt verification, that is the difference between "we believe the bank's
gate is the published gate" and "we can check which binary produced the
receipt, on validated hardware".

## What slice 1 ships (and what it does not)

| Piece | State | Notes |
|---|---|---|
| `raucle.tee.TEESigner` adapter behind the existing `raucle.kms.Signer` protocol | Production-ready contract | Signing is delegated across a named boundary callable (`sign_fn`), exactly like `KMSSigner`. The adapter never holds or returns key material. |
| `SimulatedNitroEnclave` mock boundary | Clearly labelled simulation | Provides the same interface as a real enclave signing service: key material stays inside the simulated enclave closure, the public half and the attestation document are the only exports. Not for production assurance. |
| Attestation binding on the receipt signer identity | Production-ready contract, optional field | `CapabilityStatement.attestation` (optional, backward-compatible: absent from the signed body when not set) carries the attestation statement reference. The statement's Ed25519 signature covers it. |
| Gateway boot: `RAUCLE_SIGNER=tee` | Production-ready wiring, fail-closed | Boots only with `RAUCLE_TEE_SIMULATED=1` (the mock boundary) or with an explicitly wired enclave signer. Refusing to boot on a missing mode never silently substitutes a simulated attestation. |
| Demo key-model view serialisation | Production-ready contract | `build_demo_key_model` reports the attestation binding of the receipt-signing identity, rechecking the key binding, plus an honest export-posture sentence. |
| Real TEE attestation providers | Named follow-up | The `/dev/nsm` device call, vsock or KMRA (AWS Nitro Enclaves), Azure MAA attestation, and generic vTPM/SEV contracts are follow-up slices. The mock boundary exists precisely because no real enclave runtime is available in CI, and the interface is built so a real provider only has to implement `attestation_document(user_data, nonce) -> bytes`. |

The honest headline: every *interface*, *binding* and *fail-closed default*
in this slice is production code and test-pinned. The *attestation
documents themselves* are simulated in this slice. A deployment running the
mock boundary gets genuine Ed25519 signatures, genuine receipt verification,
and a signed statement that names its attestation reference as simulated;
it does not get a hardware guarantee.

## How the binding chains

1. The enclave (or, in this slice, the simulated enclave) generates or holds
   an Ed25519 key. Only the public half and signatures cross the boundary.
2. The attestation provider returns an attestation document that embeds the
   public key (the Nitro pattern binds it through the `user_data` field) and
   the measured image digest. `raucle.tee` records the document's SHA-256
   digest as the attestation statement reference, so the reference is a
   pointer to bytes a verifier can re-hash.
3. The gateway signs its `agent:gate` capability statement with the TEE
   key, and the statement now carries the attestation block: platform,
   measurement digest, attestation statement reference, and a `simulated`
   flag. The statement signature covers the block, so stripping it or
   editing it breaks verification of the identity itself.
4. Receipts cite the statement by `key_id` (spec v1 §5.1), exactly as they
   already do: `receipt -> statement -> attestation reference`. Receipt
   payloads are unchanged, so receipts from a TEE deployment verify with
   the same offline verifier and the same vectors as every other receipt.

## What a TEE does and does not defend

What it defends (once a real provider is wired):

- Key exfiltration from the gateway host: the signing key never leaves the
  measured enclave, unlike the current 0600 PEM path.
- Substituted gate binary: the measurement binds the signing key to a
  published, audited image, so a verifier can detect a gate that is not the
  deployment it claims to be.
- Operator-side tampering after attestation: an operator cannot mint a
  validly-attested receipt without running the measured code.

What it does not defend (same list as the proposal's non-goals):

- Prompt injection and unauthorised tool calls: the gate's decision logic
  is unchanged; attestation is integrity of the gate, not new enforcement.
- Compromise of the TEE vendor's attestation chain or firmware: that
  becomes the new root assumption, a separate and much-studied risk surface.
- The host OS: the host can deny service to the enclave (refuse to boot it,
  replay old attestation), which freshness checks and rotation documents
  partially mitigate and which is a named follow-up.
- Output-side attestation: streamed responses already carry no output
  digest in the base product (threat-model residual M12); a TEE backend
  does not change that.

## Configuration

Code-level (explicitly wired enclave signer):

```python
from raucle.tee import SimulatedNitroEnclave, TEESigner

signer = SimulatedNitroEnclave().signer()  # mock boundary, labelled simulated
# or, with a real enclave signing service behind sign_fn:
signer = TEESigner(
    sign_fn=enclave_dispatch,          # bytes in, 64-byte signature out
    public_key_pem=enclave_public_pem,
    attestation_provider=enclave_provider,  # attestation_document(user_data, nonce)
)
```

Gateway boot with the mock boundary (explicit acknowledgement required):

```sh
RAUCLE_SIGNER=tee
RAUCLE_TEE_SIMULATED=1
```

Boot fails closed when `RAUCLE_SIGNER=tee` is set without either an
explicitly wired signer or `RAUCLE_TEE_SIMULATED=1`: a simulated attestation
is never applied silently. The mock boundary's signing key is ephemeral, so
every restart issues a new gate identity (the reason a real enclave seals
its first-boot key is part of the real-provider follow-up). Old receipts
still verify against their recorded public key, as with any rotation.

The panel does not yet expose the TEE backend (the signer backend picker is
unchanged in this slice): configuration is environment-driven until the
real-provider slice lands.

## Follow-up slices

1. Real attestation providers: AWS Nitro Enclaves NSM/KMRA, Azure
   attestation, generic vTPM or SEV-SNP contract, all behind
   `TEEAttestationProvider`.
2. Remote attestation verification chain: verifier-side checking of the
   attestation document, the vendor certificate chain, and the published
   measurement registry for the gate image.
3. Sealed first-boot key persistence and rotation chaining: the outgoing
   enclave signs the incoming key's introduction, as proposed in
   `docs/proposals/tee-gate.md`.
4. Per-receipt attestation transport (a `teeAttestation` JOSE critical
   extension) once real providers exist, replacing the statement-pointer
   indirection for deployments that need the document in-band.
