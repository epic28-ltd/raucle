# Dependency failure matrix

- **Status:** Proposed
- **Date:** 2026-11-26
- **Scope:** raucle gateway enforcement dependencies
- **Programme:** [Enterprise Readiness Programme #108](https://github.com/epic28-ltd/raucle-agent-assurance/issues/108), [Raucle issue #344](https://github.com/epic28-ltd/raucle/issues/344) (items 1 and 5)
- **Boundary:** references [ADR 0010](../adr/0010-enforcement-failure-modes-and-policy-watch.md) for the mode doctrine (strict fail-closed default, no `FAIL_SAFE` semantics, three distinct evaluation modes). This matrix does not restate the ADR; it maps each dependency class to its current failure behaviour and the exact test that proves it.

Evidence classification: `PROVEN` means behaviour is asserted by a named, passing test id on main; `GAP` means no test proves the stated behaviour and the honest conclusion is an explicit test gap. Nothing here is a certification: every row cites the test that proves it, or is marked a gap.

## Summary

| # | Dependency class | Current failure behaviour | Evidence | Status |
|---|---|---|---|---|
| 1 | Policy and config load | Deny pre-gate with named status on tampered enforcement bytes; refused reload keeps the active policy; broken seal/signing-key config refuses the boot | test_policy_bytes.py::test_gateway_out_of_band_edit_denies_named; TestRaucleGateway::test_seal_refusal_during_reload_preserves_active_policy; test_required_mode_refuses_unsigned_policy_at_boot | PROVEN |
| 2 | Trust registry | Unknown/untrusted issuer tokens refused pre-gate by name; revoked issuers drop out per call; corrupt/tampered registry never reaches the issuer map; snapshot freshness checks refuse stale registries | TestTrustRootAndTokenFreshness::test_foreign_issuer_token_refused_pre_gate; test_trust_registry.py revoked/snapshot/integrity tests | PROVEN |
| 3 | Signer and KMS | Re-mint failure denies `token expired and re-mint failed`; receipt-emission failure downgrades the allow to deny `receipt emission failed`; corrupt boot key refuses the boot | TestRaucleGateway::test_expired_token_signer_failure_denies_without_stale_token; TestReceiptSignerOutage::test_signer_outage_downgrades_allow_to_deny_and_recovery_is_receipted | PROVEN |
| 4 | Replay store | Missing/None/consumed keys refuse; store faults return a signed fail-closed REJECT ack named `replay store unavailable (fail-closed)`; storage errors roll back and propagate, never classified as replays | test_replay_store_failure_returns_signed_fail_closed_ack; test_replay_store_propagates_non_integrity_sqlite_errors; test_replay_refused_after_restart | PROVEN |
| 5 | Solver (formal proof) | Proof failures deny in gate `strict` mode; without z3 the counterfactual receipt leg honestly labelling `undecided` degrades the receipt metadata, never the decision; EQR stale/unknown evidence denies or narrows | test_proof_leg_reports_undecided_without_z3; test_eqr_gate.py deny tests | PROVEN with named degraded labelling |
| 6 | Telemetry exporter | Exporter failure buffers the event and never changes the enforcement decision | TestSIEMForwarder::test_exporter_failure_does_not_change_gate_decision | PROVEN |
| 7 | Receipt store | Legacy flat-writer write failure propagates (no silent drop); emission failure at decision time denies `receipt emission failed`; index-insert failure degrades queries, never the chain | TestReceiptPersistenceFailures::test_flat_receipt_write_failure_propagates; TestReceiptSignerOutage::test_signer_outage_downgrades_allow_to_deny_and_recovery_is_receipted | PROVEN (legacy writer; segmented crash rollback noted below) |
| 8 | Receipt sidecar | Sidecar failure after a completed decision is a named evidence-persistence degradation: advisory `x_sidecar` receipts, bounded pending list, never an enforcement change | test_receipt_sidecar.py::test_named_refusal_and_receipted_advisory; x3-sidecar-v0.1 spec | PROVEN as deliberate degradation |
| 9 | Downstream boundary | Enforcement decision is authorisation evidence only: receipts bind `x_evidence` = gate observed and never claim execution proof; downstream execution is outside the gateway's control | x_evidence receipt field (receipts v1.2); ADR 0010 downstream clause | PROVEN boundary; execution-attestation linkage is an explicit GAP |

## Per-dependency detail

### 1. Policy and configuration load

- Boot: invalid auth mode, unreadable seal keys or a corrupt signing-key file raise and refuse the boot (`raucle/gateway.py` boot checks; seal keys resolved once at boot, `ConfigurationError`).
- Runtime tamper: divergence of any enforcement file (policy, seal, revocations) from the activation seal denies every served call pre-gate with the named status `policy_tampered: <digest divergences>` (`_policy_tampered_reason`).
- Reload: a policy-seal refusal during reload replaces nothing - the currently active ruleset continues to authorise, the failed candidate is dropped.
- Sealing mode `required` refuses an unsigned policy at boot and refuses the reload of a sealed-file change without a seal.

Proven by:

- `tests/test_gateway.py::TestRaucleGateway::test_seal_refusal_during_reload_preserves_active_policy` (PR #351)
- `tests/test_policy_seal.py::test_required_mode_refuses_unsigned_policy_at_boot`
- `tests/test_policy_seal.py::test_required_mode_missing_seal_refuses_on_reload`
- `tests/test_policy_bytes.py::test_tampered_bytes_against_valid_seal_refuse` and the boot-time refusal variant in the same file
- `tests/test_gateway.py::TestRaucleGateway::test_reload_policies`

### 2. Trust registry

- Unknown issuer: a token signed by a key that is not an ACTIVE registry entry is refused pre-gate by name (`unknown key_id ...`); no receipt, identity-stage failure. Proven by `tests/test_identity_freshness_fail_closed.py::TestTrustRootAndTokenFreshness::test_foreign_issuer_token_refused_pre_gate` (this PR) and `tests/test_trust_registry.py::TestCrossOrgVerification::test_gate_built_from_registry_verifies_foreign_token`.
- Revocation freshness: revoked issuers drop from the issuer map on the next call (`tests/test_trust_registry.py::TestRevocation::test_revoked_issuer_drops_from_issuer_map`); token revocations reload per call (see class 4's revocation registry rows below).
- Registry corruption: a tampered registry never reaches the issuer map (`tests/test_trust_registry.py::TestGatewayIssuerMapConstructionSite::test_tampered_registry_never_reaches_the_issuer_map`); for gate auth a corrupt registry degrades to the gateway's own issuer - a strict subset that refuses third-party tokens (fail closed by narrowing; the fallback is the named narrowing in `_ensure_caller_gate`, and gateway-level denial for foreign tokens is proven above).
- Snapshot freshness: stale snapshot detection against expected head, min index and max age (`test_stale_snapshot_detected_via_expected_head`, `test_stale_snapshot_detected_via_min_index`, `test_stale_snapshot_detected_via_max_age`, `test_future_dated_head_rejected`).
- Append integrity: write/fsync failure rolls the file and the in-memory head back, and an irrecoverable rollback raises `RegistryIntegrityError` requiring operator repair (`test_append_write_failure_rolls_back_file_and_memory`, `test_append_fsync_failure_rolls_back_file_and_memory`, PR #358). Single-writer, local-file semantics; not a multi-writer guarantee.

### 3. Signer and KMS

- Boot: a corrupt persisted local signing key refuses the boot - regenerating would orphan prior receipts (`tests/test_gateway_persistence.py::TestSignerPersistence::test_corrupt_key_fails_closed`); unavailable signer in strict signed-audit mode raises `ConfigurationError` naming the mode (`tests/test_audit_strict.py::test_gateway_boot_refuses_when_the_signer_is_unavailable`).
- Token re-mint: a signer outage while refreshing an expired policy token denies the call as `token expired and re-mint failed` and leaves the stale token in place (Proven: `tests/test_gateway.py::TestRaucleGateway::test_expired_token_signer_failure_denies_without_stale_token`, PR #353).
- Receipt signing: a gate-identity signer outage after a policy match downgrades the allow to a deny named `receipt emission failed` - an unaudited allow is never returned - and restoring the signer resumes receipted decisions (Proven: `tests/test_identity_freshness_fail_closed.py::TestReceiptSignerOutage::test_signer_outage_downgrades_allow_to_deny_and_recovery_is_receipted`, this PR).
- KMS backend selection: `raucle/kms.py` + `tests/test_kms.py`; the split-brain guard binds a local boot key to the operator key registry at construction.
- GAP: KMS outage during cross-org handshake ack signing is not separately exercised (`test_handshake.py` covers replay/transport faults, not signer faults); acknowledgement signing failures surface as an exception at the handshake boundary (fail closed, but without a named operator status).

### 4. Replay store

- Mandatory: `accept_call` refuses a `None` store by name (`test_accept_call_refuses_a_none_replay_store_by_name`); a request without a nonce is refused (`test_missing_nonce_refused_when_replay_protection_is_mandatory`).
- Replay: consumed keys refuse persistently across restart (`test_replayed_request_refused_via_store`, `test_replay_refused_after_restart`, `test_replay_store_consume_is_atomic_under_threads`).
- Store failure: a raising store returns a SIGNED REJECT acknowledgement with stable reason `replay store unavailable (fail-closed)` and stops before trust/capability evaluation (PR #356, `test_replay_store_failure_returns_signed_fail_closed_ack`).
- Storage errors: non-integrity SQLite failures roll back and propagate with a 3.10-compatible duplicate-key classifier, so a storage constraint is never mistaken for a replay (PR #359: `test_replay_collision_classifier_supports_python310_errors`, `test_replay_store_propagates_non_integrity_sqlite_errors`, `test_replay_store_does_not_misclassify_storage_constraint_as_replay`).
- Retention: forgetting nonces is never silent; `purge_expired` without a configured window refuses by name (`test_replay_store_default_keeps_rows_forever`).

### 5. Solver and formal verification

- Gate-time proof enforcement is explicit per mode (`CapabilityGate`): `strict` denies any token whose proof is missing, unverified or hash-mismatched; `off` (default) carries `policy_proof_hash` informationally; `lenient` is a documented development affordance that logs a missing proof at WARNING - it is not a fail-closed mode and is marked as such rather than claimed.
- Counterfactual receipt leg: without z3 the proof leg reports `undecided` and the receipt carries the replay verdict with honest labelling (`tests/test_counterfactual.py::test_proof_leg_reports_undecided_without_z3`); the solver is an analysis dependency - its absence degrades receipt metadata, never the enforcement decision.
- Evidence quality: EQR stale/unknown/below-floor evidence denies outright or narrows to the EQR-declared reduced scope; degraded evidence never widens (`tests/test_eqr_gate.py::test_gateway_unknown_evidence_denies_named`, `tests/test_eqr_gate.py::test_gateway_on_degraded_deny_fails_closed`).

### 6. Telemetry exporter

- An exporter exception after a valid policy match keeps the decision `allow`, keeps the counters correct and buffers the event for later delivery (Proven: `tests/test_gateway.py::TestSIEMForwarder::test_exporter_failure_does_not_change_gate_decision`, PR #350).
- The sink contract: an inner audit sink failure propagates; a SIEM failure does not (`tests/test_siem.py::test_inner_failure_propagates_siem_failure_does_not`).
- Buffer visibility: `buffered_events()` is queryable via the admin SIEM route (`raucle/gateway_app.py` `/api/siem`).

### 7. Receipt store

- Chain of record: the legacy flat JSONL writer's `write()` failure propagates from `_sign_and_store_receipt` and `flush()` is not called after a failed write (Proven: `tests/test_gate_receipts.py::TestReceiptPersistenceFailures::test_flat_receipt_write_failure_propagates`, PR #361). A failed chain write denies at the HTTP layer for that decision; it is never a silent drop.
- Post-decision emission failure: a receipt signer outage on a would-be allow downgrades the decision to deny `receipt emission failed` (above, class 3).
- Index projection: an index-insert failure degrades queryability, never the chain (S5 chaos `delay_index_write` + catch-up drain, `tests/test_gate_chaos.py::test_delay_index_write_defers_and_drain_catches_up`).
- Named faults: `drop_receipt` and `misorder_chain` fire exactly once and are flagged by the offline verifier (`tests/test_gate_chaos.py::test_drop_receipt_fires_once_and_is_flagged_named`, `tests/test_gate_chaos.py::test_misorder_chain_breaks_the_offline_verifier`); each fault emits a signed, named fault receipt that verifies offline (`test_each_fault_receipts_run_flags_offline_verifier`).
- Segmented-store crash rollback and fsync/durability semantics of segments: explicit GAP (separate coverage; not proven by any current test id).

### 8. Receipt sidecar

- The sidecar owns the append and the index after the in-gateway mint: submission failures are NAMED and never exceptions into the gate path (`SidecarError.reason`: `receipt_sink_overflow`, `sidecar_unreachable`, `unauthorized`).
- Overflow is the named refusal `receipt_sink_overflow` (HTTP 503); the gateway receipts the loss as an advisory `x_sidecar` receipt: the enforcement decision completed before submission and stands. This is fail-open for receipt persistence only, never for enforcement, per `docs/spec/x3-sidecar-v0.1.md` and the module contract in `raucle/sidecar.py`.
- Proven by: `tests/test_receipt_sidecar.py::TestOverflowContract::test_named_refusal_and_receipted_advisory`, `tests/test_receipt_sidecar.py::TestHandshakeAndValidation::test_wrong_secret_is_a_named_refusal_and_appends_nothing`, `tests/test_receipt_sidecar.py::TestRestartResume::test_restart_resumes_and_rebuilds_behind_index`.

### 9. Downstream boundary

- Every gate receipt carries `x_evidence` marking the receipt as the AUTHORISATION decision record, not the executor's attestation; a downstream tool run cannot be proven by a gate receipt. Proven by `tests/test_evidence_assurance.py::test_authorisation_row_denies_execution_proof` and `tests/test_evidence_assurance.py::test_gate_row_names_the_authorisation_only_honesty` (the receipts v1.2 evidence-level self-description).
- Downstream execution failures are outside the gateway's direct control (ADR 0010, dependency class list): the gateway receipts what it decided and observed, and no matrix row may describe an execution guarantee the gateway does not have.
- GAP: binding an execution outcome to the gate receipt (execution attestation) is unimplemented; no test id proves any execution-outcome linkage and none is claimed.

## Regression additions in this change (credential, trust-root, revocation freshness)

New file `tests/test_identity_freshness_fail_closed.py`, 12 tests, all failing closed at the gateway boundary:

- `TestCredentialFreshness::test_rotated_apikey_old_key_denies_pre_gate_new_key_receipted` - rotation cut-over denies the predecessor pre-gate and receipts the new key.
- `TestCredentialFreshness::test_revoked_apikey_denies_pre_gate` - revocation denies pre-gate by name.
- `TestTrustRootAndTokenFreshness::test_foreign_issuer_token_refused_pre_gate` - unknown/trust-root miss refuses by name.
- `TestTrustRootAndTokenFreshness::test_expired_capability_token_refused_pre_gate` - genuine TTL expiry refuses pre-gate.
- `TestTrustRootAndTokenFreshness::test_revoked_token_id_refused_pre_gate` - a revocation-registry id stops a still-validly-signed token pre-gate.
- `TestRevocationRegistryFreshness::test_corrupt_revocation_registry_refused_by_name` - a corrupt registry refuses token calls by name instead of raising an unaudited exception (code fix on this branch).
- `TestRevocationRegistryFreshness::test_revocation_registry_vanishing_refuses_until_restored` - a registry that vanishes after being read refuses; restore ends the refusal and the recorded revocation still holds (code fix on this branch).
- `TestRevocationRegistryFreshness::test_registry_absent_before_first_revocation_still_serves` - the lazy pre-first-revocation steady state is preserved.
- `TestReceiptSignerOutage::test_signer_outage_downgrades_allow_to_deny_and_recovery_is_receipted` - receipt-signer outage downgrade and recovery.
- `test_corrupt_registry_variants_all_refuse_by_name[...]` - three corrupt-record variants (invalid JSON, non-object, blank token id) each refuse by name.

## Honest limitations

- Revoked capability denial is currently classified as an unattributable pre-gate refusal (`receipt_id` None). House doctrine makes attributable-but-unauthorised token calls receiptable; a still-validly-signed token that is revoked is arguably attributable evidence. Reclassifying it changes the receipts contract and is deliberately not done in this change; the current classification is pinned by `test_revoked_token_id_refused_pre_gate`.
- Trust-registry gate-auth fallback narrows to the gateway's own issuer on any registry load failure. That is fail closed for third-party issuers; the narrowing is observed in `_ensure_caller_gate`, not asserted by a dedicated gateway-level test (test gap, honestly recorded).
- The vanished-revocation-registry refusal state is per-process memory (`_revocations_ever_seen`); a gateway restart before the file is restored re-enters the absent-before-first-read state. Durable cross-restart tracking is a registered follow-up, not built here.
- Segmented-store crash rollback, sidecar-specific fsync durability and KMS/handshake signer-fault coverage remain the explicit gaps listed above.
