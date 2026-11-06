# Nelson-14 delegation gate (profile implementation)

Status: PROFILE (implementing draft semantics; no standards-claim). 6 November 2026.

`raucle/nelson14.py` implements the normative checks of
[draft-nelson-agent-delegation-receipts-14](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/)
(Nelson, 15 October 2026) — the Agent Delegation Receipt — as an additive,
self-contained verifier module. It implements the semantics of the cited
PROFILE sections of that draft; this document records which, and makes no
compliance claim of any kind. Existing Raucle receipt schemas are untouched.

## What is implemented (each check, its draft section)

| Check | Draft section | Implementation | Test |
|---|---|---|---|
| Closed body field set; `metadata` as the only extension point; unknown top-level body fields rejected | §4.1 | `validate_body` → `UNKNOWN_BODY_FIELD` | `test_vector_unknown_body_field_rejected`, `test_vector_unknown_metadata_fields_are_extension_point` |
| Required/optional field validation | §4.2, §4.3 | `validate_body` | `test_vector_missing_required_field_rejected` |
| `instructionsHash` = SHA-256 over the §4.2 normalisation | §4.2 | `normalise_instructions`, `check_instructions` | `test_vector_instructions_hash_mismatch`, `test_vector_instruction_normalisation_is_lossy_by_design` |
| Signing input is JCS (RFC 8785) canonical body; bytes must BE canonical | §5 | `canonicalise_body`, `verify_jws` → `NON_CANONICAL_PAYLOAD` | `test_vector_non_canonical_payload_rejected` |
| Compact JWS pinned; `typ` = `drp-receipt`; `kid` optional; undefined header parameters rejected | §6.1 | `verify_jws` → `TYP_MISMATCH`, `BAD_HEADER`, `DETACHED_NOT_SUPPORTED` | `test_vector_typ_must_be_drp_receipt`, `test_vector_undefined_header_parameter_rejected` |
| `alg` = ES256 only; `none` PROHIBITED; raw `R||S` 64-byte signature, DER rejected | §6.3, §6.5 | `verify_jws`, `_es256_verify` | `test_vector_alg_none_prohibited`, `test_vector_alg_not_in_profile_rejected`, `test_vector_der_signature_rejected` |
| `receiptId` = SHA-256 hex of the compact serialization's ASCII bytes | §6.6 | `compute_receipt_id` | `test_vector_receipt_id_is_sha256_of_compact` |
| Attenuation: a delegated grant may only NARROW (literal `operation::resource` keys; strict proper subset; parent denials must be carried) | §8.5 | `check_attenuation` → `SCOPE_WIDENED`, `NARROWING_REQUIRED`, `DENIED_ACTION_DROPPED` | `test_vector_scope_widened_rejected`, `test_vector_equal_scope_rejected_delegation_must_narrow`, `test_vector_dropped_denial_rejected_child_may_only_add` |
| Wildcards compare as literal strings, never expanded | §8.5 note | `check_attenuation` | `test_vector_literal_wildcard_is_not_expanded` |
| Text scope is advisory; no machine check without `scopeSchema` on both sides (schema parity) | §8.4, §8.7 | `check_attenuation` → `SCHEMA_PARITY` | `test_vector_schema_parity_required` |
| Chain depth limit (default 3) | §8.6 | `verify(..., max_depth=3)` → `CHAIN_DEPTH_EXCEEDED` | `test_vector_depth_limit_enforced` |
| Sub-receipt checks: parent signature, binding over `orchestrator-delegation:<parentReceiptId>:<receiptId>` verified against the SUB-receipt's `signerPublicKey`, child window inside parent window | §4.4, §8.7 | `verify`, `verify_orchestrator_binding` | `test_vector_orchestrator_key_must_be_the_sub_receipt_signer`, `test_vector_window_containment_enforced`, `test_vector_orchestrator_binding_wrong_pair_rejected` |
| Cascade revocation: walk every ancestor via `parentReceiptId`; any revoked ancestor denies | §9.3 | `verify` + `RevocationRegistry` → `ANCESTOR_REVOKED` | `test_vector_cascade_revocation_denies_descendants` |
| Offline fail-closed: `revocationRequired` with no (or unchecked) registry state denies | §9.4 | `verify` → `REVOCATION_CHECK_REQUIRED`, `ANCESTOR_REVOCATION_CHECK_REQUIRED` | `test_vector_offline_revocation_required_fails_closed`, `test_vector_offline_ancestor_revocation_required_fails_closed`, `test_vector_registry_reached_but_receipt_not_checked_fails_closed` |
| One-time-use: durable shared store required; consumed ⇒ denied; consumption only after every other check passes; consumption key `receiptId[:nonce]` | §9.5 | `verify` + `ConsumptionStore`, `consume_key` | `test_vector_one_time_use_requires_durable_store`, `test_vector_replay_after_consume_denied`, `test_vector_nonce_scopes_the_consumption_key`, `test_vector_denied_receipt_never_burns_a_consumption_slot` |
| COSE_Sign1 profile | §7 | named stub: `COSE_PROFILE_STATUS == "UNIMPLEMENTED-PH"` | `test_corpus_publishes_vectors_for_n10` |

All denials are named (`Nelson14Error.code`) and fail closed; nothing falls
back to allow.

## Composition with existing Raucle machinery

- **Canonicalisation** (§5): JCS key ordering is done THROUGH the shared
  UTF-16 code-unit helpers in `raucle/_canon.py` (`reorder_keys_utf16`) — the
  same ordering the rest of the signed material in raucle uses. Composed, not
  reimplemented.
- **Attenuation** (§8.5): the draft's literal-key narrowing rule is kept
  distinct from raucle's capability-chain narrowing (`raucle.capability`
  chain digests): receipts are narrowed per the draft, capabilities per the
  capability model, and neither silently reimplements the other.
- **One-time consume** (§9.5): the store contract (`was_consumed`/`consume`)
  matches the existing one-time consume patterns in the codebase (canary
  credentials, approvals, activation requests): consume-after-verify, atomic
  in the store, never burned on a denial.
- **Cascade revocation** (§9.3): enforced live at the gate by the ancestor
  walk, in the draft's own words; eager descendant marking by a registry is
  an optimisation the gate does not depend on.

## Additive by construction

No changes to existing receipt schemas, payload shape, canonical JSON
conventions or verifier behaviour. The module has no imports from the
receipt/provenance pipeline beyond `raucle._canon`; dropping it from an
instance changes nothing else.

## Published vectors

- Machine-readable corpus (for N10):
  [v1/test-vectors.json](nelson14-delegation-gate/v1/test-vectors.json) —
  31 vectors across the classes above; bodies plus expected outcomes are
  published, signatures are reproduced live by the tests because ECDSA is
  randomised per issuance.
- Executable form: `tests/nelson14_vectors.py` — one test per vector, plus
  corpus-integrity tests pinning the JSON to the executable classes.

## What is deliberately NOT implemented

- **COSE profile (§7)**: stub only — `COSE_PROFILE_STATUS` is the named,
  machine-greppable status `UNIMPLEMENTED-PH`. Follow-up, per the task
  scoping.
- JCS number serialisation beyond integers (the §4 body carries only
  integers; floats raise `NON_INTEGER_NUMBER` rather than risk a wrong
  shortest-round-trip form).
- Receipt issuance of production deployments: `issue_receipt`/`compact_from_body`
  exist to build the test vectors, not to authorise anything on their own.
