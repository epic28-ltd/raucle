# Receipts v1.1: delegated-authority binding (additive extension)

Status: accepted for LASR Area 1 (agent delegation, authorisation and
attribution). 29 October 2026. Backwards compatible with receipts v1: absent
fields produce byte-identical receipts to v1, so every existing verifier and
conformance vector is unaffected.

## What it binds

A gate receipt may now carry `x_gate.authorization_chain`: the ordered list of
capability token ids the presented capability descends from, ending at a
registered root issuer, plus the SHA-256 digest of the chain's canonical form.
The block is OPTIONAL: only calls WITHOUT a presented capability emit
byte-identical v1 receipts. A root capability binds the block with
`attenuated: false` and a null `parent_id`.

## Verification rules

1. If `authorization_chain.chain_digest` is present, the receipt must also
   present `authorization_chain.tokens: [capability token ids]` (>= 1) and
   `root_issuer` (the chain's terminating issuer id).
2. `chain_digest` must equal SHA-256 over the canonical JSON of
   `tokens` + `root_issuer`. A verifier recomputes this and fails closed on
   mismatch.
3. Each listed token id must be either (a) registered in the trust registry, or
   (b) reconstructible from the receipt chain itself (the parent receipt
   carrying the same id). A verifier that cannot resolve a token id fails
   closed.
4. Capability monotonicity: for the present version the verifier reports the
   chain for human/automated audit; enforcement of transitive narrowing stays
   the producer-side duty (`CapabilityIssuer.attenuate` rejects widening) with
   its Lean 4 attenuation theorem unchanged. A future v2 may promote this to a
   verifier-side check against registered tokens.

## Rationale

Coordination layers (YC's QM, Pentagon-style org code) can delegate freely but
cannot produce third-party-verifiable evidence of what authority was used. With
v1.1, a delegation hop becomes: principal mints an attenuated child capability
(parent_id set), the sub-agent presents it at the gate, the receipt binds the
full chain, and any auditor replays the authority path offline.
