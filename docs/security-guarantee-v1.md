# Raucle security guarantee, v1

This document states exactly what the raucle gate decision layer guarantees at a pinned source revision, and what it does not. Every claim names the pin that fails if the claim regresses. It is one page by rule: anything that cannot be stated inside this page is not a guarantee.

| Field | Value |
|---|---|
| Guarantee version | v1.0.0 |
| Source revision | this commit (tagged v0.23.8) |
| Status | Released with raucle v0.23.8 |
| Maintainer | EPIC28 Ltd |
| Companion documents | [security model](security-model.md), [threat model](threat-model/v1.md), [spec index](spec/README.md) |

## 1. Version and source pin

Guarantee version v1 describes one source revision, the commit named in the table above. Test counts in this document were measured at that revision by test collection, not from memory. A revision that is not pinned is not covered by this document.

## 2. What is protected: the gate decision layer

The guarantee covers the receipted decision layer at the out-of-process gateway (`POST /gate`), where decisions are made, signed and chained. It does not cover execution (section 3).

- **Capability authorisation on gateway-routed actions.** A tool call on a `/gate`-routed path runs only when covered by a valid, unexpired, correctly signed capability whose constraints are satisfied; out-of-scope calls deny before the tool body runs, and the denial is itself a receipted decision. Every authentication failure returns a receipted DENY with the reason, never a bare 401. Scope note: the gate enforces on the argument names declared in the policy and does not yet bind the tool's parameter schema; `allowed_values` whitelists are the recommended posture for security-critical fields. Pins: `tests/test_gateway.py`; deny rows of the Q18 adapter conformance table, `tests/test_adapter_conformance.py` (40 collected rows across five adapters at the source revision).
- **Signed receipt issuance.** Every `/gate` decision, allow, deny or escalate, is emitted as a receipt signed by the persistent gateway identity (`agent:gate`), written as a content-addressed JWS envelope whose identifier is the receipt's own hash and which verifies offline; if a receipt cannot be written, an allowed decision is downgraded to deny. Pins: `tests/test_gate_receipts.py` (`TestGateReceiptEmission`, `TestSegmentedStoreIntegration`).
- **Replay refusal.** A human approval (rules carrying `require_approval_when`) binds to one exact tool, agent and canonical argument hash, is consumed by exactly one action under a lock, and every concurrent or late re-submission is refused by name (`already consumed`); expired requests refuse in the 410 class. Cross-organisation acknowledgements are replay-bound by the same discipline. Pins: `tests/test_approval_consume_atomicity.py` (`TestApprovalConsumeAtomicity`), `tests/test_handshake.py`.
- **Policy-seal integrity.** Policy files, including session-rule files, ride a signature seal over the exact policy bytes: an out-of-band edit fails closed ("policy_tampered"). Seal mode `required` refuses an unsigned policy at boot; the default advisory mode logs a named warning rather than failing silently. Pins: `tests/test_policy_seal.py` (`TestPolicySealMechanism`, `TestSealingMode`, `TestGatewayPolicySeal`).
- **Verifier input bounds.** The offline verifier protects itself by default: fixed resource bounds on bundle bytes, parents per receipt, ancestry depth and node budget refuse oversized or cycling input with a named failure, `ProvenanceVerifierBoundsExceeded`, carrying the limit hit, the observed value and the cap. The bounds are ON by default; the legacy unbounded behaviour is an explicit environment opt-out (`RAUCLE_VERIFY_BOUNDS=off`), never a silent default. Pin: `tests/test_provenance_bounds.py`.
- **pq1 hybrid signatures.** A quantum-safe receipt carries BOTH an Ed25519 and an ML-DSA-65 (FIPS 204) signature and is valid only if both verify. The JOSE profile is pinned: `crit` carries both profile ids so an unaware verifier rejects rather than guesses, `alg` remains `EdDSA`, and the signature slot is a single base64url segment over the raw 64-byte Ed25519 signature concatenated with the 3309-byte ML-DSA-65 signature, no delimiter, conformant Compact JWS framing. Stripping the ML-DSA component is rejected; there is no downgrade path. Verifiers accept the legacy dot-separated two-segment slot form through the deprecation window and log `LEGACY_DOT_FORM_DEPRECATION` on every such acceptance; signature-family routing is header-based, so a v1-headered four-segment JWS cannot verify as pq1. Legacy window: v1-only receipts verify unchanged indefinitely and pq1 is additive; during migration, dual mode links a v1 receipt and a hybrid receipt for the same event across the chain. Pins: `tests/test_pq.py` (incl `TestJoseShapeConformance`), `tests/test_pq_surfaces.py`, vectors at `docs/spec/provenance/v1/pq1-test-vectors.json`; operator assertion `raucle provenance verify --require-pq`.

The Lean 4 mechanisation covers a deliberately narrower model (the constraint kinds `allowed_values`, `forbidden_values`, `max_value`/`min_value`, `required_present`) than the runtime gate; items above describe runtime-and-test-enforced behaviour, and the exact proof boundary is stated in `paper/lean/README.md` and [security-model.md](security-model.md).

## 3. What is not protected

This list is part of the guarantee. Reading item 4 is not optional.

1. **Deployments that bypass the gate.** Receipts are minted by the gate on paths you wire it into. Where tools can be reached without crossing the gate, calls that bypass it have no receipts. The primary no-bypass control is the deployment's own network rule that accepts gate traffic only: the Foundry sidecar acceptance record states that enforcement requires both the APIM route and the inbound network rule, and that without the network rule the boundary is advisory, with direct calls continuing to work wherever the network permits. In-process framework handlers are observability and correctness controls, not a security boundary; a co-resident control cannot resist a compromised host process.
2. **The OpenClaw plugin is detection only.** The plugin scans inbound prompts, outbound messages and tool call arguments and blocks MALICIOUS content. It issues no capability receipts and performs no capability enforcement; its local decision log is a bounded, plugin-local buffer, not a receipt chain. Coverage is limited to what the host dispatches through typed hooks: the Claude CLI backend executes `mcp.servers` tools directly, bypassing gateway hooks, and OpenClaw's hook runner defaults to fail-open, so fail-closed behaviour must be selected deliberately (`failureMode: closed`).
3. **The Foundry M2-class forwarder is proposed, not shipped.** The APIM policy and Bicep template are a PROPOSED integration of M2 class under `docs/proposals/foundry-mcp-gateway.md`. The `serve --mode foundry-sidecar` executable does not exist; `RAUCLE_BACKEND_URL` forwarding with tools/call gating and per-call receipt emission are not shipped; the deployed container runs the shipped detection server. That path therefore has no receipts and no gate today, and no artefact presents it as deployable.
4. **A receipt proves the decision, not the execution.** An authorisation receipt records the decision the gate reached; the gate never sees the tool run. A tool-execution record is the executing application's own self-report. This is the authorisation-does-not-prove-execution caveat: receipt presence is evidence about authorisation, receipt absence is not evidence of action absence, and no receipt kind issues the EXECUTION_CONFIRMED level today.
5. **Credential custody is not part of the OSS package.** The package ships the receipt machinery of custody (`x_lease` grants, redemptions and revocations binding the delegated authority chain, the lease suspension registry) and not the custody itself: the vault that holds real secrets and the proxy that delivers them are the deployment's own infrastructure or the closed-source Enterprise Edition. This guarantee covers the receipts about custody; a tool credential used outside the lease path has no receipt.

## 4. Which integrations are tested at which level

| Integration | Level tested | Pins |
|---|---|---|
| OpenClaw plugin | Detection conformance: typed hook registration (refuses untyped hosts instead of degrading), no matcher restriction on the tool gate, activation refusal when a ready scanner never arrives in closed mode; fail-closed modes: named advisories per failure class, explicit block decisions that never rely on host exceptions, scanner trust (per-boot secret, schema-strict identity probe) | `plugins/openclaw/test/` (`typed-registration`, `failure-mode`, `authority`, `scanner-secret`, `startup-receipts`, `late-arrival-derivation`) run with `node --test`; note: not currently a GitHub Actions gate |
| MCP CLI surface (detection MCP server; AWS MCP broker CLI) | Protocol conformance: handshake, tools listing, call routing through the gate, denied calls as tool errors, unknown methods, required-argument enforcement, egress error non-leakage, auth behaviour | `tests/test_mcp.py`, `tests/test_mcp_server.py`, `tests/test_mcp_auth.py`, `tests/test_demo_mcp_d56.py` (54 collected tests at the source revision) |
| Framework adapters (Q18) | The reviewed conformance table (no token denies, wrong agent denies, wrong tool denies, forbidden argument denies, receipt-store-unavailable denies in durable mode, tool exception keeps the decision, unwrapped tool not blocked by the wrapper) across agent_framework, autogen, crewai, langchain and langgraph, with honest per-extra skips | `tests/test_adapter_conformance.py` (40 collected rows); the unwrapped-invocation row records the deployment-coverage residual rather than claiming prevention |
| Assurance correlation | Alpha: the correlation and coverage engine lives in the separate `raucle-agent-assurance` service, which is alpha and makes no CI claims. The gateway-side coverage contract keeps telemetry loss visible: out-of-gate and pending are disclosed named zeros, never folded into the number; a receipt minted without a trace id stays under its explicit label; an empty plane answers unavailable, never zero | `tests/test_demo_coverage.py`, `tests/test_demo_session_plane.py`; the demo card is labelled "Simulated demo data" |

## 5. Evidence per claim: the verdict ladder

Receipts are the evidence payload. An offline verifier holding only the operator's published material can reach four verdict levels, and no higher:

| Level | What it says | Availability |
|---|---|---|
| `PROVENANCE_SIGNATURE_VALID` | the named key signed the receipt | issued |
| `CAPABILITY_OPERATION_PERMITTED` | the resolved, trust-labelled capability statement permits the broad operation class | issued |
| `GATE_DECISION_VERIFIED` | the specific tool and hashed arguments were gate-authorised | issued: authorisation evidence only; it does not prove execution |
| `EXECUTION_CONFIRMED` | independent downstream evidence that the action ran | designed, not shipped: no receipt kind issues this level |

Two honesty rules ride every level. Trust modes are labelled informationally: a resolved capability statement is reported as `self-asserted` unless marked `authority-issued`, and a self-signature never upgrades to organisational authority. The receipt's own `x_evidence` claim (`gate_observed` on decision receipts, `self_reported` on application-recorded receipts) is advisory: its absence on legacy receipts is tolerated and a receipt claiming a higher level earns no extra verifier trust. The reviewer vocabulary `SELF_REPORTED` / `GATE_OBSERVED` / `EXECUTOR_ATTESTED` / `EXTERNALLY_CONFIRMED` is planned schema evolution; only the first two values exist today, as that informational claim.

## 6. How to reproduce

At the pinned revision, from a checkout:

```bash
# Gate decision layer pins
pytest tests/test_gateway.py tests/test_gate_receipts.py \
       tests/test_policy_seal.py tests/test_provenance_bounds.py \
       tests/test_approval_consume_atomicity.py tests/test_gate_session_id.py

# Adapters (skips honestly where an extra is absent)
pytest tests/test_adapter_conformance.py

# pq1 hybrid signatures
pytest tests/test_pq.py tests/test_pq_surfaces.py
raucle provenance verify receipts.log --pubkey issuer.pub --require-pq

# MCP CLI surface
pytest tests/test_mcp.py tests/test_mcp_server.py tests/test_mcp_auth.py tests/test_demo_mcp_d56.py

# OpenClaw plugin conformance
(cd plugins/openclaw && npm test)

# Spec vectors and conformance data must match publication
pytest tests/test_spec_conformance.py
python scripts/gen_conformance_data.py --check
```

CI jobs at the source revision (`.github/workflows/ci.yml`) gate the same claims: `test`, `test-integration-extras`, `test-integration-extras-p2a` and `cli-test` (suite and integrations), `policy-static-verify` (policy surface), `conformance` (cross-language byte-identity across five reference ports, with an explicit guard that refuses a silently skipped language), `demo-bundle-verify` (digest pinned outside the bundle), `conformance-data` (generated equals committed), `lean-proof` and `threat-model`, plus `lint`, `typecheck`, `dependency-audit`, `changelog-hygiene` and `build`. The claim-honesty discipline itself is pinned by `tests/test_evidence_assurance.py`; when a section of this document changes, update that pin discipline in the same commit.

## 7. Versioning

- This document carries its own semantic version. PATCH: clarifications and pin renames that change no claim. MINOR: a new claim added, or coverage extended to a new surface. MAJOR: a claim narrowed, withdrawn, or the source semantics underlying an existing claim changed in meaning.
- Every version pins exactly one source revision (section 1) and is verified against that revision before it merges.
- Changelog pointer: changes to raucle surfaces are recorded in `CHANGELOG.md`; every change to this document appends a line to the version history kept below, in the same commit as the document's version bump and refreshed pin.
- Supersession: a later version of this document supersedes an earlier version when it lands on main with its own pinned revision and green reproduction run. Superseded versions remain published for audit history. Receipt wire formats themselves follow the specification discipline in [spec/README.md](spec/README.md) (versioned, immutability for clarifications, 14-day comment period on substantive changes), independent of this document's versioning.

### Version history

| Version | Date | Notes |
|---|---|---|
| v1.0.0 | 2026-11-24 | First guarantee version, verified at the v0.23.8 release commit |

## Known residual risks

Named plainly: gate authentication defaults to `off` as an explicit owner decision (residual R14, boot banner warning, switchable via `/api/config`); revocation without a parent resolver relies on short TTLs or per-descendant revocation; the verifier's legacy unbounded mode is reachable by environment opt-out during a migration window; the policy seal is advisory by default with `required` as the opt-in; audit-chain tail truncation is detected only against an external high-water mark, with the externally anchored level still on the roadmap; registry reads cache on file mtime and size, so a same-length in-place rewrite can be served stale (R16); SIEM target validation is syntactic and does not resolve DNS (R15); the admin panel's TOTP secret rests in plaintext beside its digest pending a master-key source (R13); identity-level quarantine and session counters are per-process, so a restart resets counters and replay bounds the gap (a `gradual_extraction` signal can undercount, never fabricate); approvals live in memory and pending requests are re-requested after a restart; session identifiers remain caller-supplied until the server-issued workflow identity work lands; the detection server ships unauthenticated by default and must be keyed before exposure. The register these residuals belong to is [threat-model/v1.md](threat-model/v1.md).
