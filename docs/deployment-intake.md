# Deployment intake (H1 phase 5)

`POST /api/deployments/accept` — the gate's intake for EXTERNAL
(portal-signed) policy deployments. This document is the trust model.

## What the gate trusts — and only via a pinned root

A deployment push is `{jws, artefact}`: the portal's Ed25519 JWS
deployment receipt (`iss: raucle-portal`, phase-4 envelope shape) plus
the canonical policy artefact it binds. The gate accepts it **only when**

1. a `deployment_trust` section is configured (YAML section / `RAUCLE_DEPLOYMENT_TRUST_FILE` JSON):

   ```yaml
   deployment_trust:
     issuer: raucle-portal        # the ONLY accepted iss
     key_path: /etc/raucle/portal-public.pem   # or inline public_key_pem
     algorithm: EdDSA             # EdDSA (Ed25519) only
     policy_target: /etc/raucle/policies.yaml  # "" = the gate's policy_file
     nonce_cache: /data/deploy-nonces.json     # "" = beside audit_chain
   ```

2. the JWS verifies against THAT pinned public key (the gate holds only
   a public key; portal credentials never flow to the gate);
3. `iss` equals the pinned issuer and the header is `EdDSA` +
   `provenance-receipt/v1` + the `raucle/v1` crit member;
4. `x_policy_deploy.artefact_sha256` equals sha256 of the artefact
   presented in the same request (digest binding);
5. the artefact parses as a gate policy file (version/issuer/policies);
6. the receipt's `nonce` has never been seen (bounded persistent cache).

## What the gate does on accept (under its OWN identity)

- writes the artefact atomically (tmp + `os.replace`, 0600) to
  `policy_target`, then hot-reloads the policy store (a reload failure
  is a 503 and is audited);
- issues a GATE-signed provenance receipt (`iss: raucle-gateway`,
  `x_policy_deploy` extension) into the org's receipt store;
- appends ONE hash-chained audit event to the chain of record
  (`audit_chain`), checkpoint-signed with the gate key, binding
  `{policy_digest, policy_id, version, action, actor, portal_receipt_hash,
  gate_receipt_hash}`.

## What the gate refuses (fail-closed; every refusal is audited)

| Condition                                             | Status | Audit kind         |
|-------------------------------------------------------|--------|--------------------|
| bad signature (key mismatch/tamper)                   | 401    | `bad_signature`    |
| unknown issuer / wrong alg/typ/crit / malformed receipt | 403    | `untrusted_issuer` / `malformed_jws` / `bad_algorithm` / `bad_typ` / `bad_crit` |
| artefact digest mismatch                              | 400    | `digest_mismatch`  |
| replayed nonce                                        | 403    | `replayed_nonce`   |
| malformed artefact                                    | 400    | `malformed_artefact` |
| pinned key unreadable / not Ed25519 (signer absent)   | 503    | `trust_root_unavailable` |
| nonce cache unreadable/unwritable                     | 503    | `nonce_cache_unavailable` |
| reload failure (after apply: artefact written, chain keeps the gate receipt) | 503 | `reload_failed` |

The live policy is never touched on a verification refusal. The nonce is
claimed BEFORE the artefact is applied, so a crash between claim and
apply can only lose a deployment (operator re-pushed as a new receipt),
never double-apply one.

## Default posture unchanged

A deployment that configures no `deployment_trust` has NO intake
endpoint (404). Nothing about `/gate`, the admin panel, policy loading,
or the receipt chain changes.

## How a third party verifies offline (the chain of record)

1. **Portal receipt**: verify the pushed JWS with the PINNED portal
   public key and check `x_policy_deploy` is bounded (policy id, version,
   action, actor, stage, artefact digest — no constraint values).
2. **Gate receipt**: locate `gate_receipt_hash` in the org's receipt
   store and verify it with `ProvenanceVerifier` and the gate's public
   key (same offline path every gate receipt already admits).
3. **Chain**: run `raucle.audit.AuditVerifier(public_key_pem=gate_public_pem).verify_chain(audit.jsonl)`
   and check the `policy_deployed` event binds the portal receipt's
   action to the gate receipt. Re-reading the chain recomputes every
   `prev_hash`/`hash` link, so any edit anywhere breaks verification.

The link between the portal's signature and the gate's chain is
cryptographic at two points: the digest binding (the gate only chains
artefacts the portal signed) and the gate receipt (the gate only issues
it after verification). Nothing asserts the join; both halves verify.