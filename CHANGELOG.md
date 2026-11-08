# Changelog

## Unreleased

### Added - EPIC S5: gate chaos mode (default-off)

- `RAUCLE_CHAOS=1` (read through `raucle._env.env`) enables three NAMED
  faults against the gate's evidence writes, each firing exactly once per
  run and recorded: `drop_receipt` (a receipt withheld from the store
  while the caller still holds its hash), `delay_index_write` (the index
  projection lags the chain until `drain_pending_index_writes` catches it
  up) and `misorder_chain` (`ChaosAuditSink` lands a chain record after
  its successor, breaking the index sequence the offline verifier
  checks).
- Blast radius is deliberately narrow: chaos requires `RAUCLE_ENV=dev`,
  is off in every other profile, and a gateway REFUSES to enable it when
  `RAUCLE_GATE_AUTH` is not `off` - a fault-injecting evidence writer
  behind real authentication is refused at construction with a named
  error.
- Every injection can be emitted as a NAMED FAULT RECEIPT
  (`raucle/chaos.py::emit_fault_receipt`): a signed compact JWS naming
  the fault, verifiable offline under the gate identity's public key,
  failing closed under any other key or after tampering.
- Tests: `tests/test_gate_chaos.py` (new, 9 cases) pins default-off, both
  refusals, each named fault with its offline flag (offline_flags /
  AuditVerifier), the drain catch-up contract, and the fault-receipt
  verification roundtrip.

=======
>>>>>>> 1733a30 (feat: the receipt-bound bilateral policy diff + threat model as code (EPIC S2, S3))
### Added - EPIC S2: the receipt-bound bilateral policy diff

- The counterfactual replay report (`raucle.counterfactual`) can now be
  signed into a receipt-bound diff document
  (`raucle.policy_diff.sign_policy_diff_document`): a compact JWS
  (`alg=EdDSA` only, canonical payload, integer epochs) binding the chain
  head, the SHA-256 digests of BOTH policy files and the replay's bounded
  summary and actions.
- Verification is offline and fail-closed
  (`verify_policy_diff_document`): given only the public key and the
  referenced material, the counterparty re-checks the signature, the
  document hash, every binding, and RE-RUNS the replay; a tampered
  summary, a wrong key, a swapped chain, an edited policy file or a wiped
  stored input each fail with a NAMED error. A retyped verdict - the
  thing this feature exists to prevent - cannot pass.
- Cross-org demo `examples/cross_org_demo/policy_diff_demo.py`: Org A
  signs, Org B verifies offline with a key resolved from the shared
  trust registry; ends with the failure case demonstrated live.

### Added - EPIC S3: threat model as code, with a CI guard

- `docs/threat-model/threat-model.json` maps every control documented in
  `docs/threat-model/v1.md` (T1-T9) to its module and the tests that pin
  it, or marks it explicitly out-of-scope with a reason (future
  mitigations M1-M12, the private-line portal controls, the U2 residual
  register R13-R16).
- `scripts/threat_model_check.py` fails when a mapped control loses its
  test, when a control is mapped without tests, when an out-of-scope
  control carries no reason, and when a new `## T<n>` section in the
  source document is not declared in the mapping.
- The `threat-model` CI job (`.github/workflows/ci.yml`) runs the checker
  on every push and pull request: a control that loses its test goes
  red, not silently.

### Fixed - Helm chart: demo key could not render, and two knobs were unwired

- `{{- with .Values.config.demoKey }}` rebinds `.` to the *value*, so the
  `include "raucle-gateway.fullname" .` inside it was handed a string and
  `helm template` failed with "can't evaluate field Values in type string".
  Setting `config.demoKey` could never render the chart. `config.healthKey`
  had the same defect. Both now use the root context (`$`).
- The chart did not set `RAUCLE_DEMO_MODE`, so a Helm install with a demo key
  served `/api/demo-key` as 404 after RED-035, and it did not set the
  per-route rate limit introduced by RED-037. `config.demoMode`,
  `config.gateRouteRateLimit` (default `200/minute`, matching the code),
  `config.gateRateLimit` and the optional `config.trustProxy` are now wired.
- `deploy/prod.env.example` documents every production variable the
  remediation touched, each with its contract, and deliberately carries no
  working secret.
- Tests: `tests/test_helm_chart_contract.py` (new, 8 cases) pins the
  with-scope rule, the wiring, and the agreement between the chart default and
  the code default. Helm is not in CI, so the assertions are source-level.

### Tests - RED-038: seam coverage for the classes the suite missed

Every finding in the 8 Nov review was in a seam rather than in a rule the
suite already tested: an evaluator that raised on an unconsidered type, a
persisted flag nobody wrote, a value interpolated in the wrong context, an
index fed on one sink and not the other, a boundary checked against the wrong
field set. Two new suites generalise those.

- `tests/test_policy_properties.py`: the constraint and approval evaluators are
  total over a fixed adversarial corpus (null, booleans, non-finite floats,
  numeric text, empty and 4 KiB strings, tuples, sets, nested dicts). A
  non-number cannot satisfy a numeric bound, a stringified number cannot slip
  a numeric bound, collections are checked element-wise, a forbidden value is
  found inside a collection, and every approval operator is total for every
  value. The monotonicity property is pinned too: a larger amount never needs
  less scrutiny than a smaller one.
- `tests/test_restart_roundtrip.py`: every store that writes to disk is
  created, mutated, reloaded and compared on observable behaviour - users
  (including the MFA flag), agent credentials (including rotation), the
  delegation ledger (including attenuation) and the receipt index (rebuilt
  projection agrees with the original).
- Deliberately no Hypothesis: it is not in the dependency tree, and adding a
  dev dependency is a supply-chain decision rather than a testing one. A fixed
  corpus covers this failure class, which is type confusion rather than deep
  input-space exploration.
- `ReceiptIndex.index_receipt` now returns whether it indexed the record, so a
  rebuild count states what happened rather than how many lines were attempted
  (an undecodable envelope used to be counted as indexed).

### Fixed - RED-037: rate limits that exist, mean the right thing, and are documented

- `docs/gateway-security.md` claimed "200 requests per minute on `/gate`". No
  per-route limit existed: only a 1000/minute default for every route. `/gate`
  now carries the documented limit (`RAUCLE_GATE_ROUTE_LIMIT`, default
  200/minute) as a real decorator, and the other routes keep the default
  (`RAUCLE_GATE_RATE_LIMIT`).
- The limiter keyed on the socket peer address, so behind a TLS-terminating
  proxy every caller shared one bucket. `RAUCLE_TRUST_PROXY=1` now honours the
  left-most `X-Forwarded-For` entry, the same convention `raucle/server.py`
  already used for its token bucket.
- A missing `slowapi` left the gateway with no rate limiting and no signal.
  It now logs a conspicuous boot warning, and the route decorator is
  unconditional through a null limiter so the route definition does not branch
  on the import.
- The gate-auth banner is now a multi-line block naming the consequence ("the
  agent_id it declares is the identity written into the receipt chain"), and
  `gate_auth` is exposed on `GET/PUT /api/config` with validation, so an
  operator can change the posture from the panel the banner points them at
  instead of only from the environment.
- Tests: `tests/test_gate_rate_limit.py` (new, 9 cases), including a test that
  the documented number and the code agree.

### Fixed - RED-036: per-call registry cost, export memory, SIEM target

- Every gate call re-read and re-parsed the revocation list, the trace
  quarantine registry, the lease suspension registry, the trust registry and
  the delegation ledger. Those files are append-only and unbounded, so the
  cost of a call grew with their length. All five now go through one
  read-through cache keyed on `(mtime_ns, size)`: a write invalidates the
  entry, so a revocation still lands on the next call, and a stat failure
  raises into the deny path rather than serving a stale set.
- The receipt export buffered the whole chain in a `StringIO` and sent it as
  one chunk, so a multi-gigabyte chain was held in the gateway process. It is
  now a generator feeding `StreamingResponse` line by line.
- The SIEM target was posted to verbatim. It is now validated both when
  configured and at forward time: `http(s)` only, no loopback, link-local,
  private, reserved or multicast literal addresses, and no `.local` /
  `.internal` names, with `RAUCLE_SIEM_ALLOW_PRIVATE=1` as the deliberate
  opt-in for an internal collector. A hostname that resolves to a private
  address is not detected (that needs DNS at validation time); the residual is
  documented rather than pretended away.
- `PolicyRule.matches` used `fnmatch`, which normalises case on Windows only,
  so the same policy could match differently per host. It now uses
  `fnmatchcase`, so matching is case-sensitive everywhere.
- Tests: `tests/test_gate_cost_and_targets.py` (new, 17 cases).

### Fixed - RED-035: evidence paths are guarded, the demo key is a posture

- `PUT /api/config` accepted any absolute path for `audit_chain`,
  `receipt_store`, `policy_file`, the registries and the signing key, then
  persisted it. An operator key could point the audit chain at any file on the
  host and the gateway would start writing there at the next restart, which
  moves the evidence trail the product exists to produce. Changes to those
  fields now require the `admin` role, must be absolute, and must resolve
  inside the data root (`RAUCLE_DATA_ROOT`, defaulting to the receipt
  directory). A violation is a 400 naming every bad field, and the in-memory
  config is rolled back so nothing half-applies. Only the fields actually being
  changed are checked, so an existing layout cannot block an unrelated edit.
- `/api/demo-key` returned an auditor key, unauthenticated, whenever
  `RAUCLE_DEMO_KEY` was set. That key reads the entire receipt chain, and it
  lived in the same user table as real operators. It is now served only when
  `RAUCLE_DEMO_MODE` is on, and a demo key set without the mode logs a boot
  warning instead of registering a user.
- `ConfigUpdateRequest` now exposes the remaining evidence fields
  (`policy_seal_file`, `policy_ledger_path`, `receipt_store_dir`,
  `receipt_index_path`, `revocations_file`, `delegations_file`,
  `signer_key_path`), so the guard covers what the API can actually set.
- Tests: `tests/test_config_evidence_guard.py` (new, 10 cases) and one boot
  test for the demo-mode rule.

### Fixed - RED-034: the receipt index is fed on every sink

- The SQLite receipt projection was updated only inside the segmented-store
  branch of `_sign_and_store_receipt`. A deployment that set
  `RAUCLE_RECEIPT_INDEX_PATH` without `RAUCLE_RECEIPT_STORE_DIR` (the flat
  file sink) wrote every receipt to the chain and none to the index, so the
  admin panel reported `total 0` against a store holding the whole chain. The
  chain was intact; the audit view was empty, which is the more dangerous
  failure because it looks like a quiet week.
- The insert now runs after whichever sink wrote the line, and a boot with an
  empty index rebuilds from a flat file as well as from segments
  (`ReceiptIndex.rebuild_from_flat_file`, with the line walker shared between
  both rebuild paths).
- Index write failures still degrade queries and never touch the chain; that
  contract is pinned by a test.
- Tests: `tests/test_receipt_index_sinks.py` (new, 7 cases).

### Fixed - RED-033: panel output escaping and security headers

- The receipts table interpolated `tool`, `agent_id`, `decision`, `trace_id`
  and the receipt hash into `innerHTML` unescaped. A gate receipt carries
  caller-influenced text (`x_gate.agent_id` is echoed from the request), so
  one `POST /gate` was enough to plant script that ran in an operator's
  session with the admin key in page scope. Every field is now escaped.
- Four inline handlers interpolated values into a **JavaScript-string**
  context: `onclick="toggleSource('${esc(n)}')"` and friends, for source,
  tool, destination and user id. HTML escaping does not protect a JS string,
  because the browser decodes entities before parsing the attribute. Those
  handlers now carry their value in a `data-` attribute and are served by one
  delegated handler each (`flowItemClick`, `userMfaAction`, `scenarioClick`),
  the pattern the receipt ancestry row already used.
- Both FastAPI apps now return `Content-Security-Policy` (`default-src
  'none'`, no external scripts, `frame-ancestors 'none'`, `base-uri 'none'`),
  `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`. Note the
  honest limit: the single-string panel needs `script-src 'unsafe-inline'`,
  so CSP is containment, not an XSS barrier; the escaping is the control.
- Tests: `tests/test_admin_panel_render.py` (new, 7 cases) pins the escaping
  contract, the data-attribute rule and the headers on both apps, so the
  class cannot come back silently.

### Fixed - RED-032: admin identity durability, hashed keys, MFA honesty

- MFA was silently disabled for every operator on restart: the TOTP secret
  was persisted, the `mfa_enabled` flag never was, and the loader never
  restored it. The flag is now written and restored, and a record written by
  an earlier version (secret present, no flag) is read as enabled rather than
  downgrading the operator to key-only auth.
- `users.jsonl` stored API keys and TOTP secrets in plaintext, keyed by the
  key itself. Keys are now stored as SHA-256 digests, looked up by digest,
  and a legacy file is migrated in place on load (the plaintext leaves disk
  in the same construction). Users are addressed on the admin routes by a
  stable `user_id` handle derived from the digest, so the panel no longer
  needs to hold key material; the full key is still accepted for scripts.
- `POST /api/users` now mints a 256-bit key when none is supplied and
  returns it once. A supplied key must be at least 24 characters.
- The env bootstrap admin was re-added on **every** boot, resurrecting an
  admin removed in the panel and keeping a rotated key valid for ever.
  Bootstrap now runs only when the store holds no admin.
- `RAUCLE_ADMIN_KEY_FILE` is implemented: it was documented in
  `docs/gateway-security.md` and `docs/deployment-security.md` and never read
  by any code, so the documented Docker/Kubernetes secret pattern silently
  produced a gateway with no admin at all. An unreadable file now logs a
  warning and yields no key rather than falling back.
- MFA made the panel unusable: only three of thirty admin routes accepted an
  `X-TOTP` header, and the shared checker was called with FastAPI's `Header`
  default object rather than the value, so every other route raised or
  403'd for an MFA-enabled operator. All admin routes now declare and pass
  the header, and the checker coerces non-string values to "absent".
  `/api/users` also returned a truncated key while the MFA routes took a full
  key, so an admin could not enable MFA for anyone but themselves.
- TOTP replay: a code from a previous window is refused. Reuse inside the
  current window stays allowed because the panel polls several times a
  minute; a real session-token exchange is the honest fix and is scoped with
  the identity work.
- Tests: `tests/test_admin_identity_durability.py` (new, 24 cases covering
  restart durability, hashing and migration, user_id routing, key minting
  and the entropy floor, bootstrap semantics, `RAUCLE_ADMIN_KEY_FILE` and the
  replay guard).

### Fixed - RED-031: approval thresholds evaluate fail-closed

- An approval threshold is a human check, so an argument that cannot be
  shown to sit below it now ESCALATES. Comparisons previously ran on raw
  caller types: `amount="99999"` against `amount_gt: 5000` raised
  `TypeError` out of `check_tool_call`, which surfaced as an HTTP 500 with
  no receipt written, and a type-mismatched `eq` threshold (`"10000"` vs
  `amount_eq: 10000`) compared False and let the call proceed to ALLOW
  without the approval the policy demanded. Operands are now classified
  (number / string / incomparable; bools and non-finite floats are not
  numbers), numeric text compares numerically, and any mixed or
  unclassifiable pair escalates. Unknown operators escalate rather than
  falling through to equality.
- The decision path gained a receipted fault boundary: any exception raised
  while deciding (data-flow evaluation, EQR, approval consumption, SIEM)
  becomes a `gate_fault: internal error during decision (<ExcType>)` DENY
  with a receipt, instead of an unaudited 500. The reason carries the
  exception type only, never its message, which can quote caller-supplied
  values.
- Tests: `tests/test_policy.py` (+8 cases) and `tests/test_gateway.py`
  (`TestApprovalThresholdGatePath`, +3 cases).

### Tests - dark-corners remediation round 2

- SCITT anchoring (`raucle/transparency.py`): the poll/HTTP edge states get
  fake-host tests in `tests/test_transparency.py` — pending-forever (named
  `PENDING` with the resumable operation location), op-failed after poll
  (named `TRANSPARENCY-FAILED` with the service reason), unknown/garbage
  poll status (fails closed, named), malformed poll body, unparseable
  `Date` header (named rejection), HTTP-date `Retry-After` honoured and
  clamped to 30s, garbage `Retry-After` treated as zero, and a
  connection-refused service surfacing immediately instead of hanging.
- EQR (`raucle/eqr.py`): `EvidenceStore` record/snapshot/clear slices are
  covered with real behaviour assertions — a one-(tool, kind)-slice clear,
  a tool-wide clear, the everything clear, clearing an absent slice as a
  no-op, snapshot as an independent copy, dict-form `record`, and
  re-recording after a full refresh (`tests/test_eqr_gate.py`).
- Gateway entry point (`raucle/gateway_server.py`): kept, not deleted —
  it is the `Dockerfile.gateway` `CMD`, referenced by
  `docker-compose.gateway.yml` and the helm chart, so the audit's
  "dead entry point" branch did not apply. Smoke tests
  (`tests/test_gateway_server.py`) pin the wiring (env → config →
  gateway/user bootstrap → two uvicorn servers) and the README now names
  the single-process deployment path.

### Fixed - M026/M027: round-3 bypass remediations (RED-026 / AV-02, RED-027 / AV-10)
- M-026 (RED-026 authority re-mint escape): while a hold is applied, the
  containment manager publishes a receipted control row into the
  delegation ledger (`containment_hold_active`, with the hold's
  receipt id and revocations surface; a receipted `containment_resume`
  row on release). `DelegationLedger.register` now consults active
  holds at mint/registration time: new authority entering a held agent
  scope or a held chain is refused into the live deny set (revocation
  row named `hold_active`), or the registration fails closed (named)
  when the hold's revocations surface is unusable. Resolvers ignore
  control rows entirely.
- M-027 (RED-027 snapshot re-stamp): the resume digest check was
  integrity-only - a state writer who re-stamped
  `original_bytes_b64` + `original_sha256` together committed attacker
  policy bytes silently on resume. Resume now binds the snapshot to the
  RECEIPTED hold: the hold receipt carries the snapshot digest, and a
  state whose snapshot digest or scope does not match the receipt is
  refused (fail-closed, named `snapshot_restamped`), receipted as
  `containment_resume_refused`, and the halt stays applied. A held
  state without its receipt stream is likewise a named refusal.
### Fixed - Round-3 bypass remediations (RED-029, RED-030)
- Containment (RED-029 / AV-12): the receipt stream is no longer
  append-only by convention alone. A SCITT-style head anchor (N2
  machinery pattern) is maintained beside the stream — every receipt
  emit updates a sidecar `.head` file binding (count, stream_head),
  where stream_head is a hash chain folded over the emitted receipt
  hashes. Deleting, truncating or rewriting the stream is detected
  under its own name `receipt_stream_gap`: the next operator /
  containment action refuses with a named `ContainmentError`, and
  `status()` surfaces `receipt_integrity` / `receipt_stream_erased`.
  Honest anchoring limit (documented, not claimed away): detection runs
  at the next containment action or status read, so there is a
  detection lag window; a writer who rewrites BOTH the stream and the
  co-located anchor resets anchoring — equivocation proof against a
  collusive writer requires an external Transparency Service.
- urlgate (RED-030 / AV-14): gating is method-agnostic for content-
  bearing methods (GET, POST, PUT, PATCH, DELETE) — a GET with
  prompt-bearing content in the request target to a gated suffix now
  hits the same gate path as the POST of the same body, receipted
  allow AND deny; a policy deny never contacts the upstream. HEAD and
  OPTIONS remain the only exempt methods, narrowly, with a named
  `X-Raucle-Passthrough: method-exempt-head-options` marker and no
  receipt minted (no receipt inflation).

### Added - N2: SCITT transparency anchoring of receipt-chain heads
- `raucle/transparency.py` registers a receipt-chain head (final event
  index + record hash) with a SCITT Transparency Service per the
  draft-noa-scitt-ai-agent-receipt profile semantics: submit entry,
  poll operation status, fetch signed_statement. Standard-library HTTP
  only, no vendor SDK; strict RFC header handling (unparseable `Date`
  raises; `Retry-After` honoured); bearer tokens arrive as parameters,
  never globals; anchoring never mutates the chain file.
- Offline verifier-side check `verify_transparency_anchor` recomputes
  the chain head and compares it against a cached/fetched signed
  statement (digest match + signature path present). Optional and OFF
  by default; absent transparency root yields the honestly named
  `SELF-SIGNED-ONLY` status with the reason recorded — a named
  fail-open, never a silent pass. Digest divergence is named
  `DIGEST-MISMATCH`. Anchoring proves non-equivocation of the chain
  head — nothing more; no compliance claim is made or implied.
- Loopback HTTP double in `tests/test_transparency.py` (no external
  network calls); canonical-bytes SHA-256 invariant pinned by test.
- Spec: `docs/spec/transparency-v1.md`.

### Added - N3: Nelson-14 delegation-receipt gate (Python profile)
- `raucle/nelson14.py`: first-class verifier module for the normative checks
  of draft-nelson-agent-delegation-receipts-14 (Agent Delegation Receipts,
  15 October 2026): compact-JWS/JCS pinning (ES256 only, `typ`/`kid` header
  rules, DER signatures rejected, `none` prohibited), monotonic
  attenuation on literal `operation::resource` keys (delegated grants may
  only NARROW — equal scope rejected), deterministic cascade revocation by
  parent walk, and fail-closed one-time-use consumption bound to the
  existing consume-after-verify pattern. All denials are named and
  fail-closed; the COSE profile is a named `UNIMPLEMENTED-PH` follow-up
  stub. Additive: no existing receipt schema is touched; §5 JCS ordering
  reuses the shared `raucle._canon` UTF-16 machinery.
- Published test vectors: `tests/nelson14_vectors.py` (45 tests) plus the
  machine-readable corpus
  `docs/spec/nelson14-delegation-gate/v1/test-vectors.json` (31 vectors
  across every implemented check class) for downstream N10 consumption.
- Spec document `docs/spec/nelson14-delegation-gate.md` mapping each check
  to its draft section, implementation and test.

### Added - N1: x_bilateral execution-boundary co-signed receipts
- New `x_bilateral` extension (v1.2, docs/spec/provenance/v1.2/bilateral-
  outcomes.md): the tool/execution side CO-SIGNS the outcome it actually
  produced — `executed` | `failed` | `rejected` (a closed vocabulary) — over
  the receipt's own output_hash, INSIDE the signed payload. The co-signature
  is bound by the same JWS: the agent's signature, the output_hash and the
  executor's claim cannot move independently of one another. Additive:
  receipts without the block verify exactly as before.
- `raucle/bilateral.py`: the dependency-light executor-side surface
  (`sign_bilateral_outcome`, `bilateral_signing_input`, the closed outcome
  vocabulary), imported by harness adapters directly; `raucle.provenance`
  re-exports the helpers.
- `ProvenanceVerifier(executor_keys=...)`: offline fail-closed re-check.
  A receipt carrying x_bilateral whose co-signature is missing, names an
  unregistered executor key, or does not verify over the bilateral binding
  FAILS with a named reason — the outcome is never inferred. A verifier
  that was never told the executor keys fails bilateral receipts closed by
  default, while legacy receipts verify untouched.
- `QmHarnessBridge.bilateral_outcome()` (the QM adapter seam): the executor
  co-signs its outcome; `QmHarnessBridge.executor_keys()` produces the
  verifier-side key map; `wiring()` carries the exec-side block.
- tests/test_x_bilateral.py pins the acceptance: well-formed co-sign
  verifies, missing executor signature fails named, co-signature over a
  re-labelled outcome fails, mixed bilateral+legacy chains verify, the
  outcome vocabulary is closed and the block's object shape is validated.

### Added - O1: data-flow-aware policy rule kinds
- New rule-level policy key `deny_from_chain_taint` (`raucle/PolicyRule`,
  spec `docs/spec/dataflow/v1.md`): deny any call whose destination class is
  D whenever a prior tool output in the SAME task/delegation chain carries a
  listed taint tag - riding the existing provenance taint propagation.
  Deterministic per-call semantics: the rule is evaluated against the
  REPLAYED chain state at each gate decision (no side-channel state).
- Destination-class allow-listing via `allow_destination_classes` (fail-closed:
  any class not listed denies while chain taint applies). The kind only ever
  denies - it composes with the existing constraint machinery without
  changing its per-call semantics and never widens authority; the deny fires
  before escalation so an approval path cannot bypass it.
- Fail-closed with named reasons: unknown (empty) destination class and
  unknown/malformed taint tags in the chain state deny; a rule with the kind
  but no replayable chain state (missing trace_id) denies.
- Gateway surface: `RaucleGateway.record_chain_output()` records tool
  outputs + their taint tags per trace; `check_tool_call` takes
  `destination_class`; the HTTP `/gate` request accepts `destination_class`.
  Corpus vector `standards/test-vectors/dataflow_v1_01_taint_denies_destination.json`
  pins the backlog acceptance: two-call chain, call 1 output taint T, call 2
  target D under 'T denies D' - call 2 denies while each call alone is
  allowed. tests/test_dataflow_rules.py (19 tests).

### Added - I1: counterfactual proofs (the z3 leg)
- `raucle counterfactual policy` attaches a proof to every prevented
  action. PROVEN: the alternative policy's constraints exclude the whole
  recorded argument CLASS. The prover (JSONSchemaProver.prove_exclusion,
  the dual of prove()) checks a JSON schema derived from the recorded
  args' shapes, field names and primitive types only, never values, and
  answers whether any call of that shape can satisfy the alternative
  constraints. REFUTED: the deny was value-specific, not structural, and
  the escaping field is NAMED (its value never leaves the prover).
  UNDECIDED, honestly: constraint kinds the prover does not model
  (allowed_values, starts_with), a recorded shape outside its grammar,
  a denial by absence of grant, or z3 not installed. Never upgraded; the
  replay verdict stands alone either way.
- The report summary gains prevented_proven / prevented_refuted /
  prevented_undecided, and the verdict states the proof when one is
  proven. Bounded disclosure holds in every proof row: status, prover
  identity, the grammar/policy hashes (which bind the material without
  disclosing it) and field NAMES only. No recorded values, no constraint
  values, no counterexample values.
- prove.py: the JSONSchemaProver's encoding is now shared between
  prove() and prove_exclusion() so the two query directions cannot
  drift. prove_exclusion is fail-closed in BOTH directions: unmodelled
  grammar blocks a PROVEN, and a would-be REFUTED witness cannot be
  certified while unassessed constraints might still deny it. A vacuous
  exclusion over an uninhabited grammar is UNDECIDED, never PROVEN.
- The [dev] extra now includes [proof] (z3), so the prover tests run in
  CI instead of silently skipping.

## 0.23.5 (2026-10-30) - records lifecycle, counterfactual replay, authorship receipts, time-source anchoring


### Added - I1: counterfactual replay (the incident-review question, answered deterministically)
- `raucle counterfactual policy --chain ... --inputs ... --policy alt.yaml`:
  re-run every recorded gate decision under an alternative policy and
  answer, per action, whether the stricter policy would have denied it.
  The verdict is replayed from the receipts and the input store, not
  inferred: authority held constant, the question is a policy question.
- Bounded disclosure holds in the report: no denial reasons, no arg
  values; each row cites its receipt hash. Receipts without a stored
  input are unreplayable, never guessed. The replay never writes to the
  incident chain it examines (pinned by test).

### Added - G3: records lifecycle (retention stamps + tamper-evident disposal)
- Gate receipts stamp `retention_until` when `retention_days` is configured
  (a records schedule on every decision; zero when unset).
- `raucle records destroy` writes a signed destruction receipt (x_destruction)
  binding the span, count and digest of what left, an escrow copy of the
  removed records, and the re-anchored surviving chain. `raucle records
  verify` re-checks the signature offline, and re-checks the span digest
  against the escrow when supplied - each escrow record's own hash is
  recomputed first, so a payload edited after the fact fails before the
  digest comparison. Disposal is evidence, like every other lifecycle event.

### Added - I3 + H4: auditor exports over the pack, and SBOM per release
- `raucle compliance export --pack DIR --format csv|json`: auditor-facing
  coverage.csv, extracts.csv and a combined pack-export.json over an
  existing pack bundle. The exports derive from the bundle; they carry
  nothing the bundle does not.
- .github/workflows/sbom.yml: a CycloneDX SBOM for every tagged release,
  validated and uploaded as a workflow artefact. Isolated from the publish
  pipeline so an SBOM failure can never block a release.

### Added - E1b: the compliance evidence pack (dora first, the x_compliance certificate)
- `raucle compliance pack --chain ... --framework dora --pubkey ... 
  --operator-key ... --out DIR` builds the regime bundle: report.md,
  coverage.json (control results with regulation citations), extracts.jsonl
  (bounded decision extracts, no args, no reasons, no constraint values,
  every line citing its receipt id), retention.json (observed span vs the
  regime expectation), and the x_compliance verification certificate.
- The certificate is a signed JWS receipt the auditor verifies offline with
  the public verifier and the operator public key: no account, no trust in
  the vendor. A chain that fails verification gets verifier_result invalid,
  the report says so on its first line, and the CLI exits non-zero. The
  pack never upgrades bad evidence.
- The dora framework joins the registry (RTS 2024/1774 Article 12 controls,
  with the FSB attribution expectation): RTS-12(2)(d) is satisfied only by
  signature verification actually run against the provided key, never by
  assertion.
- Spec: docs/spec/compliance/pack-v1.md.

### Added - EPIC D: harness findings as verifiable evidence (x_finding)
- A QM/Pentagon-class harness running its security tests through the
  raucle gate reports every finding as a signed receipt citing the gate
  receipt that covered the request (RaucleGateway.emit_finding).
- The offline verifier replays the claim: a finding citing a receipt not
  in the chain, or misreporting the gate's decision, fails verification
  with a named error. Emission is the harness's claim; verification is
  the truth check.
- Verdict vocabulary closed: confirmed, refuted, expected_pass. Finding
  ids deterministic per (harness, test_id, cited receipt).
- Spec: docs/spec/provenance/v1.2/harness-findings.md.


- Release note: the first release carrying the H1-era evidence tooling -
  raucle records destroy|verify (tamper-evident disposal), raucle
  counterfactual policy (the incident-review question answered
  deterministically), the Claude Code authorship hooks, the RFC 3161
  three-mode time-source model, the receipt-chain-to-audit-chain
  projection, and the SonarCloud hardening (validated bundle writes,
  temp-dir verifier chains).
## 0.23.4 (2026-10-30) - credential-lease receipts (the x_lease evidence layer)

### Added - C1: credential-lease receipts (the x_lease evidence layer)
- A credential lease - a gate-minted, time-limited grant of a vault
  secret's USE, scoped by the delegated authority that authorised it - is
  now a receipted event: granted, denied, redeemed, revoked, each carrying
  an x_lease extension (capability chain, secret by HASH only, scopes
  narrowed from the capability's constraints, TTL).
- The verifier re-checks redemptions offline without vault access: a
  redemption must cite a grant, fall inside its TTL window, and never
  widen its scope.
- Spec: docs/spec/provenance/v1.2/lease-extension.md. The vault, lease
  manager and injection proxy ship in raucle-cloud (the 16.3 split).
- Found and fixed while landing this: authority receipts (suspend,
  revocation) carried an empty ruleset_hash, which the standard chain
  verifier rejects on truthiness - they now bind the extension block's
  hash and verify through the standard verifier like every other receipt.
- Tests: tests/test_lease_receipts.py.

## 0.23.3 (2026-10-30) - intent binding, cascade revocation, pair permissioning

### Added - B1: agent+user pair permissioning (OSS evidence half)
- The principal becomes the (agent, acting-for user) pair: a capability may
  bind to a user via acting_for (user:-prefixed principal grammar); tokens
  without a pair stay byte-identical to v1.1.
- The gate refuses cross-pair use - a pair-bound token used with a
  different (or undeclared) acting-for user denies, attributable, and the
  receipt records both halves of the pair (x_gate.acting_for).
- A delegated child inherits the pair and may never re-target a different
  user; narrowing an unpaired parent to a pair is allowed (setting a user
  narrows the authority).
- /gate gains an acting_for request field. The per-pair policy resolution
  and minting workflows ship in raucle-cloud (the 16.3 split); the
  two-user demo (same agent, different permission sets, different
  receipts) is exercised there.
- Tests: tests/test_pair_permissioning.py; raucle-cloud
  tests/test_pair_resolution.py.

### Added - A3: cascade revocation with evidence
- Revoking a capability now cascades: the whole subtree is walked from the
  delegation ledger, persisted to a revocations file (RAUCLE_REVOCATIONS_FILE,
  loaded per call so revocations propagate immediately), and receipted. The
  revocation itself is a signed, attributable receipt (x_revocation:
  revoked-by-whom, when, which subtree) that verifies offline like every
  other receipt.
- The gate refuses new actions on the subtree: token ids, their direct
  parents, and every ancestor are checked against the live revocation set.
- The verifier marks revoked-at-H: a receipt minted AFTER a revocation of
  its cited authority is INVALID with a named reason; receipts minted
  before it remain valid evidence - the authority was live when they
  minted. Single-pass temporal order, no trust in the gate's own
  enforcement story.
- Owner-departure operation: POST /api/agents/{id}/revoke-chains revokes
  every delegated chain of an identity in one receipted action (the
  lifecycle audit trail); POST /api/revocations revokes a single subtree.
- Tests: mid-chain cascade, verifier marking, owner departure
  (tests/test_cascade_revocation.py).

### Added - receipts v1.2: task-intent binding (A1)
- A capability token may carry an intent: the approved task statement plus
  structured constraints (resource class via tools, data bound via the
  standard constraint vocabulary). Tokens without an intent stay
  byte-identical to v1.1.
- The gate enforces the intent deterministically on every call (no model
  involvement): the tool must sit inside the approved class and the
  arguments must satisfy the intent constraints. Denials are attributable.
- Receipts carry x_gate.intent (the approved purpose, signed) plus a
  bounded x_gate.intent_check disclosure - only the constrained fields'
  values, nothing else.
- The verifier re-checks ALLOW receipts against their own intent and
  rejects a chain-valid receipt whose action violates the approved
  purpose, with a named reason. DENY receipts are exempt (a denial for an
  out-of-intent attempt IS the enforcement).
- A delegated child inherits its parent's intent and may only narrow it;
  widening is refused (the same monotonicity as every other dimension).
- Spec: docs/spec/provenance/v1.2/intent-binding.md. Fixtures: the
  calendar-vs-archive and recipient-allowlist cases in
  tests/test_intent_binding.py.
- Found and fixed while landing this: the verifier's v1.1 chain-digest
  re-check never fired (it read x_gate off the envelope, which only
  carries {receipt_hash, jws}) and the recompute used the wrong field
  names. Both now live: the verifier decodes the JWS payload and
  recomputes the digest from the block's own fields.

### Changed - B2 attribution audit: unattributed calls deny across all adapters
- The invariant: every ALLOWED execution carries a real acting identity,
  and no minted receipt carries a fabricated placeholder. The same
  fail-closed doctrine as the gateway (v0.23.2), prerequisite for
  agent+user pair permissioning (B1).
- langchain: require_agent_id now defaults True (bearer-mode trust is an
  explicit opt-out); the "<unbound>" placeholder is gone - unattributed
  attempts deny with the reason recorded and receipts carry an honest null.
- crewai: bearer mode (agent_id=None) is closed; unattributed attempts
  deny with "no acting agent identity".
- autogen: an empty agent_id denies. Found and fixed a latent adapter bug
  surfaced by the audit: the gated wrapper's bare **kwargs signature made
  autogen's FunctionTool build a broken args model ("kwargs: Field
  required") - the wrapper now preserves the original signature via
  functools.wraps.
- agent_framework: accepted, documented - the caller id comes from the
  framework context with a documented bearer fallback to the token's own
  agent_id; B1 should surface the acting-for user so the fallback never
  triggers.
- a2a: audited clean (identity required by construction).


## 0.23.2 (2026-10-29) - attributable token denials are receipted, not pre-gate

### Fixed - the evidence gap found by the QM live integration
- A validly-signed token whose call exceeds its delegated authority (wrong
  tool binding, agent mismatch, constraint violation, proof mismatch) was
  rejected during authentication: deny with the reason echoed but no
  receipt, no persisted evidence. Who tried what is exactly what an auditor
  needs, so the denial is now receipted with the delegated-authority chain
  bound (x_gate.authorization). Fail-closed semantics unchanged.
- GateDecision.attributable distinguishes per-call authorization failures
  (identity established, authority refuses) from identity-stage failures
  (unknown key, bad signature, expiry, unverifiable chain), which stay
  pre-gate denials: there is no trustworthy chain to bind.
- _deny_result now threads the authorization block into the receipt, so
  every denial where identity is known carries the chain.
- Found by exercising the constraint-deny path against a real socket
  through the QM deployment-directory gate tool (raucle-cloud Move 3).

## 0.23.1 (2026-10-29) - receipts v1.1: delegated-authority binding, delegation ledger, verifier digest check

### Added - receipts v1.1: delegated-authority binding in gate receipts
- Gate receipts carry an x_gate.authorization block (capability_id,
  issuer, key_id, parent_id, attenuated, chain_digest) binding each
  decision to the delegated-authority chain that authorised it. The
  chain_digest is SHA-256 over the canonical chain; the verifier fails
  closed on any mismatch.
- raucle/capability.py: DelegationLedger, an append-only JSONL of signed
  capability records. register() refuses any record its stated issuer did
  not sign; resolver() satisfies CapabilityGate's parent_resolver.
- GatewayConfig delegations_file: token-auth mode resolves attenuated
  chains through the ledger when set. Fail-closed when unset: an
  attenuated token without a resolvable parent denies.
- Calls without any capability token remain byte-identical v1 receipts.
- docs/spec/provenance/v1/delegation-extension.md specifies the format;
  tests/test_delegated_receipts.py pins the semantics (attenuated child
  allowed through the chain, ledger holds both hops, digest tamper
  fails, no-resolver deny).

### Fixed - admin panel and demo reliability
- Demo entry button dead in production: an over-escaped quote pair in the
  receipt-ancestry link broke the whole script block. Hashes moved to a
  data-hash attribute with one shared click handler. CI now parses every
  shipped script block with node --check, so parse breakage cannot ship
  silently.
- Live topology rendered empty: the layout helper returned a cache
  wrapper instead of the position map, so every node drew at undefined
  coordinates. Scroll now pans (clamped to the graph extents) instead of
  silently zooming; first launch frames the five busiest chains as
  aligned rows.
- Connections page: live tailing off by default, one example connection
  shown, click a row to reveal its path; connection-log entries carry
  receipt_id.
- Public aggregate /api/live-pulse endpoint served by both the
  agent-facing and admin apps; RAUCLE_GATE_RATE_LIMIT knob (default
  1000/minute per source) for load-test headroom.


## 0.23.0 (2026-10-21) - receipt store, chain projections, authority attribution

### Fixed — SonarCloud findings sweep: one real security gap, 49 hygiene items
- REAL BUG (python:S1172 on audit_pack._verify_pack_chain): the pack's
  require_pq declaration was accepted but never enforced. A pack whose
  index declared require_pq=True but whose receipts carried only
  classical signatures verified as valid - the exact field-stripping
  downgrade the strict mode exists to close. ProvenanceVerifier gains
  require_pq strict mode (mirror of AuditVerifier's): every receipt in
  the chain must be a 4-segment pq1 hybrid. Regression test:
  test_declared_require_pq_with_classical_chain_fails. Pack verdicts now
  surface the verifier's specific errors (bounded) instead of only the
  generic chain-invalid reason.
- handshake.accept_call: removed the unused require_unrevoked parameter
  (documented behaviour is fail-closed on revoked keys; nothing passed
  the override).
- Receipt-page and export collection logic extracted to module helpers
  (cognitive complexity: _register_receipt_routes 74, check_tool_call,
  gate_tool_call, _verify_chain_header, _check_issuer_uniqueness,
  _verify_operator_signatures, _verify_signature all now under the 15
  threshold; behaviour unchanged, 1003 tests pass).
- Receipt vocabulary constants (sha256:/provenance-receipt/v1/raucle/v1/
  agent:gate; CLI default store path) extracted (S1192).
- Undocumented HTTPException status codes added to route "responses"
  (health 401 x2, policies 400, ancestry 501) (S8415).
- Redundant exception classes removed (binascii.Error subclasses
  ValueError; FileNotFoundError subclasses OSError) (S5713).
- Duplicate A-Z ranges removed from (?i) regexes in mcp_scanner (S5869);
  fuzz PRNG made an explicit seeded random.Random instance with the
  security rationale documented (S2245); slice-comparisons restructured
  (S6659); dict() constructor -> literal (S7498); consecutive appends ->
  extend (S9409); dead pq1_count removed (S1481); commented-out-code
  false positive rephrased (S125); corrupt-key log now logger.exception
  (S8572); unused gateway param removed from _register_user_routes
  (S1172); single-return restructures (S3516 x2).
- TypeScript reference ports (behaviour-neutral; conformance re-verified
  in CI): async-without-await dropped from import helpers, redundant
  `?? {}` spread removed, unknown-absorbing union simplified.


### Added — authority attribution: approval receipts, policy ledger, envelope, kill switch (PR-E)
- raucle/approvals.py: ApprovalManager. Escalated calls now create a
  receipted human approval request (x_approval); decisions through the
  admin API are receipted with the named approver; the approval binds to
  the exact tool, agent and canonical args hash and is consumed once.
  Re-submitted call with X-Approval-Id allows through the threshold and
  the action receipt cites the approval (full authority chain:
  request → human decision → action).
- Policy change ledger: every admin panel policy write appends a
  hash-chained entry (seq, actor, action, content sha256, prev_hash) to
  RAUCLE_POLICY_LEDGER; GET /api/policy-ledger returns entries and
  recomputed-chain integrity. Receipts already bind ruleset hashes; the
  ledger closes the loop upward: who changed the rules, and when.
- Authority envelope: GET /api/agents/{id}/authority returns a signed
  statement (raucle/authority-envelope/v1) of what the agent could use:
  policies (tools, constraints, TTL) and credential status, verifiable
  offline with the gate identity's public key.
- Kill switch: POST /api/agents/{id}/suspend (admin-only) revokes the
  agent's credential and writes an x_stop receipt (agent, reason, actor,
  revoked). The stop itself is evidence: who stopped the agent, when, why.
- GatewayConfig: approval_ttl_seconds (RAUCLE_APPROVAL_TTL, default 300),
  policy_ledger_path (RAUCLE_POLICY_LEDGER, empty = disabled).
- tests/test_authority_attribution.py: 16 tests across all four features
  (full approval flow, args binding, single consumption, expiry, denial,
  tamper detection, envelope signature, suspend RBAC).


### Added — key operations, deployment topologies, Helm chart (PR-D)
- docs/security/key-operations.md: rotation (versioned-issuer zero-downtime
  procedure; the registry's one-active-key-per-issuer impersonation control
  is the reason), escrow, recovery, split PQ-key posture, fail-closed list.
  Maps 1:1 to the executable test.
- tests/test_key_rotation_e2e.py: the runbook's proof. Old receipts verify
  after rotation (archival property: revoke != erase), new mints use the new
  key, revocation fails new authorisation closed while old signatures still
  verify; gateway signing-key restart rotation with both generations in one
  chain.
- docs/deployment-topologies.md: where raucle sits (not the model path),
  the trust boundary stated plainly (in-process = observability; the
  boundary is out-of-process gate + credential isolation), single node /
  hot standby / namespace sharding, edge patterns (TLS/mTLS/OIDC), the
  Postgres trigger, retention as a file operation.
- docs/getting-started/20-production-hardening.md: the 90-minute evaluator
  path (auth on, segments+index, restart test, offline verify, query,
  checklist, runbooks).
- deploy/helm/raucle-gateway: chart with REQUIRED adminKey (renders fail
  without it), replicaCount pinned to 1 (one writer per chain), PVC,
  probes, ingress; CI job lints + kubeconform-validates templates and
  asserts the no-adminKey render fails.

### Added — receipt query index, ancestry API and bulk egress (PR-C)
- ReceiptIndex: SQLite (WAL) projection over the segmented store; rebuild
  from chain at any time; never a trust decision.
- /api/receipts upgraded to real query: agent/tool/decision/trace/time
  filters with keyset pagination (tie-safe composite cursor).
- /api/receipts/{hash}/ancestors: parents-DAG walk, nodes+edges JSON,
  cycle-safe, depth-capped.
- /api/receipts/export: JSONL streaming egress for the caller's data
  platform.
- Admin panel Receipts tab: filter bar, paginated table, ancestry
  drill-down.

### Added — signed gate receipts and segmented storage (PR-B, production readiness)
- Every /gate decision (allow, deny, escalate) emits a signed provenance
  receipt (guardrail_scan + x_gate extension) written as a minimal envelope;
  receipt_id returned in the response and verifiable offline with the
  standard verifier, CLI, MCP tool and all five reference ports.
- X-Trace-Id threads caller traces through receipts; generated and echoed
  when absent.
- Fail-closed accountability: an unwritable receipt downgrades the
  decision to deny.
- SegmentedReceiptStore: size-based segments with read-only sealing and
  .meta sidecars; sealed segments are pure receipt chains (verify and
  audit-pack directly); bounded-memory newest-first queries. Opt-in via
  RAUCLE_RECEIPT_STORE_DIR; the legacy flat file remains the default.
- RAUCLE_EMIT_RECEIPTS=0 restores pre-PR-B behaviour exactly.

### Added — gateway identity and key persistence (PR-A, production readiness)
- Gate authentication modes (`RAUCLE_GATE_AUTH=off|apikey|token`): per-agent
  API keys (`X-Api-Key`, hashed at rest, constant-time verify, instant
  revocation) and capability-token authentication (`X-Capability-Token`,
  verified against the trust registry with per-call revocation propagation).
  `off` preserves the previous declared-identity behaviour (compat).
  Auth failures return a receipted DENY with the reason, not a bare 401.
- `raucle agents issue-key|revoke-key|list` CLI for credential management.
- Gateway signing key persistence: local signers persist the Ed25519 key
  (0600, default `<data-dir>/gateway-signing-key.pem`); tokens and receipts
  now verify across restarts; corrupt key material fails closed instead of
  silently regenerating.
- Admin user persistence (`RAUCLE_USERS_FILE`): users and MFA secrets
  survive restarts; demo-mode users remain in-memory by design.
- `docs/gateway-security.md`: auth-mode selection table, fail-closed
  semantics, in-process vs out-of-process trust boundary guidance.

### Added — conformance re-verification layer (`raucle.conformance`)

- Field-level Merkle commitments over call arguments (JCS-canonical leaves,
  UTF-16 code-unit ordering, domain-separated SHA-256 throughout; the scheme
  is deliberately zk-proof-system-portable).
- Selective disclosure: the operator opens only the fields a verifier
  requests, with Merkle paths; `verify_disclosure` fails closed on any
  tamper or root mismatch.
- Partial constraint re-check: per-constraint `SATISFIED` / `VIOLATED` /
  `UNKNOWN` verdicts re-derived independently of the operator's runtime.
  `UNKNOWN` is fail-closed and never counts as conformance.
- Design document: `docs/spec/provenance/v1/conformance-reverification.md`
  (Layer 1 of a three-layer roadmap; Layer 2 is a zkVM proof of the gate
  check with zero disclosure).

### Documentation

- NCSC Cyber Assessment Framework (CAF v3.2) and NCSC ML-security-principles
  control mapping: `docs/security/ncsc-caf-mapping.md`.
- Repository URLs updated across docs, package metadata, reference ports,
  and CI after the organisation move to `epic28-ltd/raucle`.
- Paper (§5, §8, author's note): conformance layer, remote-key signing, and
  policy-DSL gateway recorded as post-freeze engineering additions; the
  evaluation's pre-registration scope is unchanged.


## 0.22.0 (2026-06-11) — package renamed: raucle-detect is now raucle

The library outgrew "detect": receipts, provenance, the trust registry,
passports, and compliance evidence are the product; detection is one module.

### Changed

- **PyPI package**: `raucle-detect` -> `raucle` (`pip install raucle`).
  `raucle-detect` on PyPI receives one final transition release depending on
  `raucle` (so pinned installs surface the rename), then no further releases.
- **Import name**: `raucle_detect` -> `raucle`. A deprecation shim keeps
  `import raucle_detect` working (with a `DeprecationWarning`) for one
  transition cycle.
- **CLI**: `raucle` is the command; `raucle-detect` remains as a deprecated
  alias entry point.
- **GitHub repo**: renamed to `epic28-ltd/raucle` immediately after this
  release merged (old URLs redirect).
- **Env vars**: `RAUCLE_*` is the primary prefix; legacy `RAUCLE_DETECT_*`
  names remain supported.
- **Go reference port** (breaking): the module path is now
  `github.com/epic28-ltd/raucle/reference/provenance-go` — Go consumers must
  update import paths (Go modules cannot alias a renamed declared path).

### Unchanged — wire compatibility

- The provenance receipt `iss` identifier remains the frozen wire constant
  `"raucle-detect/provenance"` (spec v1, committed cross-language test
  vectors, and all five reference ports are byte-for-byte unaffected).
- Receipt/audit/registry formats, signatures, and canonical JSON are
  untouched: every existing receipt still verifies.


## 0.21.0 (2026-06-11) — platform trust layer (registry / handshake / passport / compliance)

Four new modules forming the cross-organisation trust layer, hardened through
**nine rounds of iterative adversarial security review** (independent codex
auditor; find → fix → re-verify until clean of HIGH and MEDIUM findings).
Every fix landed with a regression test.

### Added

- **Agent Trust Registry** (`raucle_detect.trust_registry`): append-only,
  hash-chained, operator-signed JSONL directory of issuer keys. Fail-closed
  revocation, canonical-issuer-name uniqueness (NFC + casefold), key_id↔PEM
  invariant enforced on load, and a signed freshness anchor (per-entry `ts`,
  `head()`, `min_index`/`expected_head_hash`/`max_age_seconds`) so a verifier
  can reject a rolled-back signed snapshot that omits a later revocation.
  CLI: `raucle-detect registry init|publish|list|resolve|revoke|verify`.
- **Cross-org handshake** (`raucle_detect.handshake`):
  `build_request`/`accept_call`/`verify_ack` — two organisations' agents
  authenticate via the shared registry with no prior key exchange. Signed ack
  receipts, responder-side replay rejection, and `verify_ack` requires a real
  anti-replay binding (`expected_request` or `expected_nonce`) by default.
- **Agent passport** (`raucle_detect.passport`): issuer-countersigned,
  registry-anchored identity document wrapping a `CapabilityStatement` —
  one portable artifact verifiable offline by any framework integration.
  Fail-closed on malformed input including hostile-but-signed bodies.
  CLI: `raucle-detect passport issue|verify`.
- **Compliance evidence packs** (`raucle_detect.compliance`): maps a signed
  receipt chain to EU AI Act / ISO/IEC 42001 / SOC 2 controls. Honest by
  design: an evidence map, not a conformance attestation — SATISFIED requires
  cryptographic chain verification; otherwise PARTIAL or OUT_OF_SCOPE.
  CLI: `raucle-detect compliance report --framework eu-ai-act|iso-42001|soc2`.
- All four modules exported from the top-level `raucle_detect` package.
- Runnable two-org demo under `examples/cross_org_demo/`.

## 0.20.0 (2026-06-10) — three fail-open fixes + MCP quickstart + LangChain demo

A security release. A post-relicense scan-and-build pass over the repository
surfaced **three fail-open/leak issues**, each found by actually exercising the
shipped integration paths and each now pinned by regression tests.

### Fixed — security

- **LangChain integration was fail-open on DENY.** langchain-core's callback
  manager swallows handler exceptions unless the handler sets ``raise_error``;
  ``RaucleCallbackHandler`` did not, so the ``CapabilityDenied`` raised by
  ``on_tool_start`` was logged as a warning and **the denied tool executed
  anyway** — the gate was advisory. The handler now sets ``raise_error=True``
  and ``run_inline=True`` (load-bearing, commented). End-to-end tests run the
  real ``tool.run(..., callbacks=[handler])`` dispatch path; the ``langchain``
  extra is now part of ``[dev]`` so CI exercises them.
- **MCP server: missing required arguments were a clean verdict.** A
  ``tools/call`` omitting a schema-required argument (e.g. ``detect_injection``
  called with the wrong key) silently scanned the empty string and returned
  CLEAN/ALLOW. The server now enforces each tool's declared
  ``inputSchema.required`` (derived from the published definitions, so
  enforcement cannot drift from ``tools/list``) and returns ``isError``.
- **Gate constraint-evaluation errors leaked internals.** The caller-visible
  DENY reason included the raw exception text; it is now generic, with the full
  traceback logged server-side only.

### Added

- **``Scanner(require_receipts=True)``** — fail-loud mode: failure to issue
  the verdict receipt, audit event, or provenance receipt raises
  ``ReceiptEmissionError`` instead of warn-and-continue (default unchanged).
- **Runnable LangChain demo** (``examples/langchain_demo/``) — no API key:
  legitimate payment ALLOWED, prompt-injected transfer DENIED before
  execution, signed receipt chain verified offline, tampering detected. Exit
  code doubles as a CI self-test.
- **MCP client quickstart** (``docs/getting-started/03-mcp-clients.md``) —
  2-minute setup for Claude Desktop, Claude Code, Cursor, Cline/Continue.
- **Registry publication pipeline** (``.github/workflows/publish-reference.yml``)
  — tag ``ref-v<version>`` publishes ``@raucle/provenance`` (npm, with
  provenance attestation), ``raucle-provenance`` (crates.io),
  ``Raucle.Provenance`` (nuget.org) and tags the Go nested module, gated on
  the 5-port cross-language conformance harness.
- Issuer ↔ standalone ``cap-verifier`` conformance round-trip tests; first
  test coverage for the REST server's auth fail-closed paths and the ML →
  heuristic classifier fallback.

### Fixed — other

- ``provenance-rs`` ``spec_vectors`` test could not load the v0.18.0 vectors
  file (the intentional lone-surrogate vector is unrepresentable in a Rust
  ``String``); the test now neutralises lone-surrogate escapes at load and
  skips ``must_reject`` vectors. This would have blocked ``cargo publish``.
- Rust crate metadata pointed at the wrong repository URL.
- CI language-setup actions pinned to commit SHAs (closing a documented
  policy deviation); duplicate-key JSON rejection consolidated into a shared
  ``_canon`` helper; proposal docs no longer reference phantom release
  versions; retired ``commercial@raucle.com`` contact replaced.

## 0.19.0 (2026-06-08) — relicensed to Apache-2.0

**The core package is now licensed under the Apache License, Version 2.0.**
This replaces the previous AGPL-3.0-or-later + commercial dual-licence model.

### Changed — licensing

- **Core (`raucle_detect/`) relicensed from AGPL-3.0-or-later to Apache-2.0.**
  Apache-2.0 is permissive and includes an explicit patent grant, making the
  engine trivial to embed in any agent runtime, gateway, SDK, or cloud —
  consistent with the goal of becoming the de-facto reference for verifiable
  agent authorization and provenance receipts.
- **Dual-licence apparatus retired.** Removed `COMMERCIAL.md`, `CLA.md`, and the
  `commercial@raucle.com` licensing lever. Contributions are now Apache-2.0
  (inbound = outbound) under the existing [DCO](DCO) sign-off; no separate
  copyright-assignment CLA is required.
- **Trademark posture unchanged.** Apache-2.0 §6 does not grant rights to the
  **"Raucle"** name; the trademark remains held separately
  (see [TRADEMARK.md](TRADEMARK.md)).
- **Unaffected:** the five reference implementations (`reference/`) remain MIT;
  the Provenance Receipt specification remains CC-BY-4.0.

> **Note on earlier releases.** This change is forward-looking. Releases
> **≤ v0.18.0** were published under AGPL-3.0-or-later and remain available under
> those terms; it does not retroactively alter copies already received.

## 0.18.0 (2026-06-02) — cross-language canonicalisation fix (B7) + interop vectors

A correctness release centred on a real **cross-language signing bug** found by
cross-model (Codex) review and hardened out across ~20 find→fix→verify rounds.

### Fixed — cross-language byte-identity (security/correctness)

- **Non-BMP object-key ordering diverged across the five reference encoders.**
  Python/Go/Rust sorted object keys (and `parents`/`taint`) by Unicode **code
  point**; TypeScript/C# by **UTF-16 code unit**. Identical for BMP/ASCII (so
  every shipped vector passed) but divergent for non-BMP (astral) keys — any
  signed object with an emoji/astral key would hash to different bytes across
  languages. All five are now unified on **UTF-16 code-unit ordering**
  (RFC 8785 / JCS §3.2.3), the spec's normative rule (§4.3.1). **Byte-neutral
  for all existing BMP material — no signature/ID churn.**
- All Python signed-material canonicalisers (`provenance`, `capability`,
  `prove`, `audit`, `feed`, `verdicts`) and the OWASP `cap-verifier` share one
  UTF-16 canonicaliser (`raucle_detect/_canon.py`).

### Added

- **New interop test vectors** — `canonicalization_vectors` and
  `invalid_canonicalization_vectors` in the published v1 set, including an
  A2A/APS `action_ref`-shaped vector. Each exposes the JCS preimage,
  `expected_canonical_hex`, and SHA-256; the invalid set covers floats and
  out-of-range integers that MUST be rejected.
- **`reference/canon_conformance.py`** — drives all five encoders and proves
  5-language byte-identity on the published vectors, non-BMP probes, and
  invalid-rejection.

### Hardened — capability gate / cap-verifier parity (fail-closed)

- Verifiers reject unsorted/duplicate `parents`/`taint`; `Capability.from_dict`
  validates all signed string fields, `parent_id` shape, and timestamps (no
  coercion) and rejects non-object input — every failure fails closed with
  `ValueError`.
- The OWASP `cap-verifier` reference brought to single-token parity with the
  gate (numeric/NaN/safe-int, unknown kinds, bool bounds, agent-id regex, NFC
  field names, constraint shapes, attenuation-chain deny, empty-field rejection).

### Docs

- Spec §13 now cites the authoritative GitHub vectors URL (always current;
  pin a tag for a stable snapshot).

## 0.17.0 (2026-06-01) — fail-closed redesign (stricter by default)

A structural pass that flips the prover/gate/verifier from "enumerate-bad" to
**fail-closed**: anything the system does not explicitly model now hits a
conservative verdict (gate → DENY, prover → UNDECIDED, mint/verify → reject)
**by construction**, driven by a single executable **Modelled Language Registry**
(`raucle_detect/registry.py`) with a CI drift guard. Designed across three
cross-model (Codex) design-review passes and hardened across three cross-model
code-review passes (6 fail-open blockers + 2 governance items closed) before
release.

### ⚠️ Breaking / stricter-by-default

- **Provenance chain envelope is now minimal `{receipt_hash, jws}`.** The
  previous format mirrored the whole payload into the envelope (unsigned,
  unvalidated). The verifier now rejects any other top-level field (no wildcard
  extension in v1). **Existing chain files with the old rich envelope will be
  rejected** — re-emit them (the authoritative payload is inside the signed JWS).
- **Canonical integers are bounded to the JS-safe range ±(2^53−1)** in all five
  reference encoders, so values round-trip byte-identically across
  Python/TS/Go/Rust/C#. Integers outside this range are rejected at
  sign/verify. (Real timestamps and bounds are far inside this range.)
- **Some inputs that previously returned `PROVEN` now return `UNDECIDED`:**
  policies carrying keys the prover does not model (`allowed_values`,
  `starts_with`), URL grammars/policies with unmodelled keys, and SQL templates
  using unmodelled constructs (quoted identifiers, `LATERAL`/`UNNEST`/`VALUES`,
  recursive CTEs, table functions). Narrow the grammar or accept UNDECIDED.
- **Some malformed constraint shapes now raise at mint** instead of being
  signed: non-list value sets (sets/tuples), non-JSON-scalar members, `bool`/
  float numeric bounds, non-string `starts_with` prefixes, and field names that
  collide under Unicode NFC.
- **`CapabilityGate.check` denies a token citing a `parent_id` when no
  `parent_resolver` is configured** (the chain cannot be verified → fail closed).
- **`from_jws(strict=True)` now also validates per-receipt structure** (root
  rule, required fields, sorted/unique parents+taint); pass
  `validate_structure=False` for the chain-verifier path that reports per-line.

### Security fixes (fail-open paths closed)

- **Decorative proof inputs (§8.2):** the JSON prover ignored
  `allowed_values`/`starts_with` while the gate enforced them, so a policy could
  be PROVEN with those keys silently dropped. Unmodelled policy keys now force
  UNDECIDED.
- **URL prover fail-open:** unknown URL grammar/policy keys returned PROVEN; now
  UNDECIDED.
- **SQL unmodelled-construct net was conditional** on `allowed_tables`; it now
  runs unconditionally, and unknown SQL grammar/policy keys force UNDECIDED.
- **Reference-verifier canonical parity (§8.10):** the TS/Go/Rust/C# verifiers
  now re-encode and byte-compare header+payload (JCS), matching Python — a
  non-canonical receipt no longer verifies in the ports.
- **JSONL envelope hardening:** duplicate-key rejection on the envelope wrapper
  (not just the inner JWS) and rejection of unknown envelope fields.
- **Unresolved attenuation chain DENY** (§8.7) and **mint value-domain
  rejection** (§8.5), as above.

### Scope & claims (read before citing)

- **SQL:** the SQL component is a **finite SQL-template checker over a modelled
  subset**, not a general "SQL prover". It proves properties over an enumerated
  set of statement templates; anything outside the modelled construct surface
  (quoted identifiers, `LATERAL`/`UNNEST`/`VALUES`, recursive CTEs, table
  functions, …) returns UNDECIDED.
- **`forbidden_values` is a best-effort denylist.** The gate enforces it on the
  argument *names* the policy declares; it cannot see a tool's full parameter
  schema, so a forbidden value supplied under a different parameter name is not
  caught. For security-critical fields prefer the fail-closed positive
  constraints — `allowed_values`, `required_present`, `max_value`/`min_value`.
- **Strict proof mode is opt-in.** `CapabilityGate(proof_enforcement_mode=...)`
  defaults to `"off"` for backward compatibility, so a token's
  `policy_proof_hash` is *informational* unless an operator enables
  `"lenient"`/`"strict"`. **Offline, proof-backed authorisation claims require
  strict proof mode** — without it the gate does not consult or enforce the
  cited proof.

### Internal

- **Modelled Language Registry** (`registry.py`): the executable source of truth
  for constraint kinds, JSON-schema keywords, URL/SQL grammar+policy keys, the
  SQL construct surface, and envelope fields. Runtime allowlists derive from it;
  `tests/test_registry_drift.py` fails CI if any consumer's modelled set diverges
  (exact `.get()`-literal extraction, not a heuristic scan).
- Consolidated strict receipt verification into a single documented
  `_validate_receipt_strict()` contract (§3.3).

## 0.16.4 (2026-06-01) — prover soundness + adapter scope (cross-model review)

Findings from an independent cross-model (Codex) review, on top of the round-3
adversarial audit and SonarQube static analysis. No wire-format change.

- **JSONSchemaProver soundness (was a false PROVEN):** a `forbidden_values`
  policy over a field that the schema permits via `additionalProperties` was
  silently discarded, returning PROVEN even though e.g. `{"x":"ok","role":"admin"}`
  is schema-valid and violates the policy. The prover now models an
  attacker-suppliable additional property as a free variable and REFUTES (with a
  counterexample); a closed schema (`additionalProperties: false`) keeps the
  blacklist correctly vacuous.
- **Agent Framework adapter:** the caller identity passed to the gate is now the
  framework context's caller (deployer-populated `metadata`/`session`), not the
  in-force token's own `agent_id` — so the token's agent scope is actually
  enforced against the caller rather than checked against itself. Falls back to
  the token's `agent_id` only when the framework surfaces no identity.
- **Receipt verifier:** strict verification additionally enforces the JOSE `typ`
  (`provenance-receipt/v1`) and the `raucle/v1: "provenance"` profile marker
  (spec v1 §4.1), after the existing alg/crit/kid/signature checks.

## 0.16.3 (2026-06-01) — static-analysis hardening (SonarQube Cloud)

Findings from a third, independent analysis method (SonarQube Cloud static
analysis), on top of the round-3 adversarial audit. No wire-format change;
five-language byte-identity preserved.

- **feed.py:** pin an explicit TLS 1.2 floor (`ctx.minimum_version`) rather than
  relying on the interpreter default — defence in depth for the (already
  SSRF-pinned) feed fetch. Adds a live DNS-rebind pin integration test.
- **TS reference impl:** strip base64url padding with `String#replaceAll` (no
  ReDoS-shaped regex); make the JCS canonical sort use an explicit UTF-16
  code-unit comparator (documented NOT to be `localeCompare`, which would break
  cross-language byte-identity). Behaviour byte-identical.
- **cli.py:** avoid a float-equality check in the fuzz coverage gate
  (`coverage <= 0.0`).
- Scoped SonarQube Cloud analysis to the shipped package via
  `.sonarcloud.properties`. Security and Reliability ratings: A (0 vulnerabilities,
  0 bugs).

## 0.16.2 (2026-06-01) — security hardening (round 3 + blind cross-check)

Two independent adversarial audits (a multi-agent finder/refutation workflow plus
a blind independent pass) and manual verification of every fix. No receipt wire-format
change; five-language byte-identity preserved. 20 new security regression tests.

- **Provers:** `SQLClauseProver` no longer returns PROVEN for a query reading a
  forbidden table via `EXCEPT`/`INTERSECT`/`MINUS`; default forbidden tokens add
  `INTO`/`MERGE`/`CREATE`; `URLPolicyProver` returns UNDECIDED for `forbid_query_keys`
  over an open query-key grammar (declare `query_keys_closed: true` to prove it).
- **Adapters:** the AutoGen adapter now enforces the token's `agent_id` scope (was
  recorded in the receipt but not checked); the LangChain adapter fails closed when a
  `forbidden_values` blacklist can't be enforced on an opaque string tool input.
- **Provenance verifier:** binds receipt `agent_id` to the capability statement,
  enforces statement `expires_at`, and requires the JOSE `kid` to equal `agent_key_id`
  (matching the TS/Go/Rust/C# verifiers).
- **Audit:** keyless verification of a chain declaring `signed=true` now fails closed
  (was reporting valid); `allow_nan=False` in canonical JSON; a non-hex (tampered) leaf
  hash yields `valid=False` instead of crashing.
- **Server:** request body / batch size caps, rate-bucket eviction (+ opt-in
  `RAUCLE_TRUST_PROXY`), and `/metrics` gated behind auth when an API key is set.
- **Other:** multimodal media/pixel/page caps; fixed a dead SSRF-pinning path in
  `fetch_feed`; CLI keygen writes private keys 0600 atomically; MCP no longer echoes
  raw exception text; conformance harness only claims five-language parity when all
  five run; formal-proof claims in README / Lean docs scoped to what is actually
  mechanised (the runtime gate enforces more than the Lean model proves).

## 0.16.1 (2026-06-01) — CLI developer-experience fix

No behaviour or wire-format changes. Polishes the command-line surface.

- **CLI:** expected user errors (missing file, invalid JSON, missing optional
  extra, malformed input) now print a one-line `error: ...` to stderr with a
  non-zero exit code instead of a raw Python traceback. Genuinely unexpected
  errors still raise a stack trace for debugging.
- **CLI:** `--help` description now reflects the product — verifiable
  authorization & audit (capability tokens, SMT/Lean-proven policies, signed
  provenance receipts), not just prompt-injection detection.

## 0.16.0 (2026-06-01) — security hardening (round 2 + re-audit)

A full security-focused audit + confirmation re-audit. All CRITICAL/HIGH/MEDIUM
findings closed with regression tests; receipt wire format unchanged (five-language
byte-identity preserved). New `docs/security-model.md` documents the trust model.

- **Gate:** reject non-finite numbers (NaN/Inf no longer satisfy numeric bounds);
  agent_id grammar forbids trailing/double dots; revocation denies descendants of a
  revoked ancestor when a resolver is configured.
- **Provenance:** SANITISATION may only clear taint tags the agent's
  `sanitisation_authority` permits (verifier-side); unknown `agent_key_id` is a
  violation when capabilities are supplied; `from_jws` hardened (size caps, duplicate
  keys rejected, strict `alg`/`crit`).
- **Audit chain:** signed chains require a head checkpoint covering the final index;
  `verify_chain(expected_head=...)` external anchor; unsigned/unknown chains are invalid
  when a key is supplied.
- **Provers:** `SQLClauseProver` no longer returns PROVEN for comma-join / subquery
  table references it can't soundly resolve (UNDECIDED instead); `URLPolicyProver`
  `max_path_depth` is UNDECIDED over prefix grammars.
- **Scanner:** ReDoS fixed — per-pattern length cap on ALL patterns, bounded wildcard
  spans, per-scan wall-clock budget (an 82s pathological scan is now ~0.01s).
- **Feed:** `fetch_feed` is https-only, blocks private/loopback/metadata IPs, pins the
  validated IP (no DNS-rebind), rejects redirects, caps body size.
- **Keys/supply chain:** private keys written `0600`; `*.pem`/`*.key` git-ignored; CI
  actions pinned to commit SHAs.

## 0.15.0 (2026-06-01) — security hardening

Pre-launch end-to-end audit. Closes gate-authorisation bypasses, hardens the
proof/verifier guarantees, and makes the reference implementations genuinely
interoperable.

### Security (gate)
- **Agent-id privilege escalation fixed.** Agent matching required a bare
  prefix, so a token for `agent:billing` authorised `agent:billing-evil`.
  Now requires exact match or a dot-delimited descendant (`agent:billing.x`);
  same fix in `attenuate()`.
- **Constraint bypass-by-omission fixed.** Value constraints were skipped when
  the named field was absent, so aliasing/omitting an argument bypassed them.
  Positive/bound constraints (`allowed_values`, `starts_with`, `max_value`,
  `min_value`) now **fail closed** on an absent field. (Documented limitation:
  `forbidden_values` blacklists can still be aliased without the tool schema —
  prefer `allowed_values`.)
- **Fail-open/DoS fixed.** Numeric bounds raised an unhandled `TypeError` on
  non-numeric args; non-numeric/bool now DENY, and the whole constraint check
  is wrapped so any error is a DENY, never a propagated exception.
- **Strict proof mode binds to enforced constraints.** A token can no longer
  cite a PROVEN proof over an unrelated policy; in strict mode `policy_hash`
  must equal the hash of the token's own constraints.

### Security (provenance)
- **Verifier-side capability enforcement.** `ProvenanceVerifier` accepts an
  optional `capabilities=` map and independently rejects receipts whose
  model/tool the issuing agent's `CapabilityStatement` does not permit (the
  cross-check the docstring already claimed). Adds `capability_violations`.

### Reference implementations
- **All five impls are now byte-identical.** The TS/Go/Rust/C# ports had each
  diverged from the Python reference and could not reproduce its receipt IDs.
  Reworked to match byte-for-byte; added `reference/conformance.py` proving
  identical `receipt_hash` across all five for every published test vector.

### Docs / claims
- Every quickstart snippet now runs verbatim (`[compliance]` install, real
  `HashChainSink`/`prove`/`audit verify` APIs, dead links removed).
- Eval claims scoped to the evidence (banking-suite '100%', restated latency,
  per-receipt vs one-time-Lean verification).
- Package metadata: author email + URLs corrected to live targets.

## 0.14.0 (2026-06-01)

### Capability constraints

- **`starts_with` prefix constraint** is now a first-class capability
  constraint, enforced at the gate (`{"starts_with": {"field": "prefix"}}`)
  and supported in attenuation (a child may extend a prefix, never broaden
  it). This was referenced in the docs/examples but previously unsupported;
  the headline quickstart now mints **and enforces** as written.
- **Unknown constraint keys now raise** instead of being silently dropped,
  so a mis-cased key (e.g. `allowedValues` vs `allowed_values`) can no
  longer produce a token that enforces less than intended.

### Capability gate — revocation

- `CapabilityGate` now accepts `revoked_token_ids` and exposes a
  `revoke(token_id)` method. A revoked token, or any child citing it as
  `parent_id`, is DENY'd before expiry — the early-revocation path that
  complements short TTLs.

### Fixes & docs

- `__version__` now tracks the package version (was stale at `0.7.0`).
- Spec: added non-normative appendices — related work (vs Biscuit /
  Macaroons / in-toto / SLSA / C2PA / VCs), canonical-form rationale, and
  the token lifetime/revocation model.
- Legal/governance docs name the registered entity, **Raucle
  as Raucle)**, so the dual-licence relicensing grant is unambiguous.
- CI: bumped `actions/checkout`→v5, `setup-python`→v6 (Node-20 retires
  2026-06-16).

## 0.13.0 (2026-05-28)

### Security — fail-loud cryptographic configuration (HOLD SCOPE FIX 1)

Six places in the codebase used `try / except: pass` patterns that silently
degraded cryptographic guarantees when configuration was wrong. Banking and
healthcare deployers explicitly do NOT want a silent fallback — they want a
loud failure they can act on. The behaviour is now:

- **Explicit config + broken = REFUSE.** Operator misconfigured the
  deployment; raise `ConfigurationError`, exit non-zero.
- **No config + safe default exists = WARN.** Log a prominent WARNING and
  continue in explicitly-marked unsigned mode.
- **Never silent.**

Specifics:

- `raucle_detect/errors.py` — new module exposing two named exception types:
  `ConfigurationError` (broken explicit config) and `PolicyUnproven` (strict
  mint mode refused).
- `raucle_detect.server._init_compliance()` — extracted from import-time
  init. When `RAUCLE_DETECT_VERDICT_KEY_PEM` or
  `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM` is set but unparseable, raises
  `ConfigurationError` (module import fails; uvicorn refuses to start).
  When no key is configured at all, emits a `WARNING` and continues in
  unsigned mode.
- `VerdictSigner.__init__` and `Ed25519Signer.__init__` — replaced
  `except Exception: self._public_pem = b""` with a `logger.error(...)` +
  `raise ConfigurationError(...)`. A signer that cannot expose its public
  key cannot produce verifiable receipts; the swallowed-error path produced
  receipts that looked normal but were silently unverifiable.
- `audit.sink_from_env()` — when `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM` is set
  but invalid, raises `ConfigurationError` instead of warning and returning
  an unsigned sink.
- `HashChainSink.__init__` — when no signer is supplied, emits a prominent
  `WARNING` at construction. **Every newly-created chain now writes a
  `chain_meta` header on line 1** carrying `{signed: bool, version, key_id?,
  signature?, created_at}`. The header is Ed25519-signed when a signer is
  present.
- `AuditVerifier` — reads the header and surfaces
  `report.signed_mode ∈ {"signed", "unsigned", "unknown"}` plus
  `report.chain_key_id`. Rejects signed checkpoints appearing in chains
  whose header declares `signed=false` (forgery indicator). Rejects
  checkpoints whose `key_id` does not match the header's `key_id`
  (cross-chain splice indicator). Legacy chains without a header remain
  verifiable but report `signed_mode == "unknown"`.

### Security — strict proof-enforced mint mode (HOLD SCOPE FIX 2)

Until now, `cap mint --policy-proof-hash` was advisory: a caller could pass
any string. Tokens cited proofs they had no structural relationship to. The
new strict mint mode makes the relationship enforceable:

- `Capability` gains two new optional fields, `grammar_hash` and
  `policy_hash`. Both nullable; backward-compatible default-absent. When
  set, they're covered by `token_id` and the signature.
- `CapabilityIssuer(..., require_proof=False)` is the new default; passing
  `require_proof=True` (or setting `RAUCLE_REQUIRE_PROOF=1`) enables strict
  mode. In strict mode, `mint()` requires a `ProofResult` whose `status` is
  `PROVEN` — anything else (absent, REFUTED, UNDECIDED) raises
  `PolicyUnproven`. The bound `policy_proof_hash`, `grammar_hash`, and
  `policy_hash` are taken from the supplied `ProofResult` so the linkage is
  structural, not advisory.
- Even outside strict mode, `mint(proof_result=...)` refuses to bind a
  non-PROVEN proof and refuses to bind contradictory hashes.
- `CapabilityGate` gains `proof_enforcement_mode ∈ {"off", "lenient",
  "strict"}` and `trusted_proofs: dict[str, ProofResult]`. Defence-in-depth
  at gate time: `"lenient"` warns on missing/invalid proof; `"strict"`
  denies. Default `"off"` preserves existing behaviour. (Registry-fetcher
  ships in a follow-up; current cache is in-memory + caller-supplied.)
- CLI: `raucle-detect cap mint --require-proof --proof-result PATH` for the
  strict path. `--policy-proof-hash` still works for the legacy advisory
  path.
- `raucle-detect prove json|url|sql` already returned exit-code 2 on REFUTED
  and 1 on UNDECIDED — both non-zero, both pipeline-fail by `set -e`. Now
  asserted by tests so CI never silently regresses.

15 new tests across `tests/test_audit.py`, `tests/test_verdicts.py`,
`tests/test_capability.py`, `tests/test_server_init.py`,
`tests/test_cli_exit_codes.py`.

## 0.12.0 (2026-05-27)

### Microsoft Agent Governance Toolkit integration — now first-class

raucle's contribution at [microsoft/agent-governance-toolkit#2610](https://github.com/microsoft/agent-governance-toolkit/pull/2610) — adding `proof_artefact` and `verification_pointers` carry-through on AGT's `BackendDecision` — **merged upstream on 2026-05-27** (commit `25abf72`, accepted by Microsoft maintainer Imran Siddique). raucle's reference integration ships in this release as a first-class module.

- **`raucle_detect.integrations.agt_backend.RauclePolicyBackend`** — implements AGT's `agent_os.policies.backends.ExternalPolicyBackend` Protocol. Plug raucle into any AGT-governed agent through the same seam OPA and Cedar already use. The backend reads the in-force capability token from the asyncio-ContextVar that the Agent Framework middleware also uses, so a single primed token covers both integration paths.
- Every `BackendDecision` raucle returns carries the cited `proof_artefact` (the policy proof hash from the capability token) and a `verification_pointers` dict (issuer pubkey URL, policy registry URL, optional Lean development URL). AGT's `PolicyEvaluator` propagates both into `PolicyDecision.audit_entry`, so any AGT audit-chain consumer immediately gets offline-verifiable evidence attached to every raucle-rendered decision.
- Graceful degradation — the backend detects whether the installed AGT carries the merged fields and silently drops them on older installs. raucle deployments survive pre-merge AGT.
- 7 tests in `tests/test_agt_backend.py`. Skipped automatically when `agent_os` is not installed; passing 7/7 against `microsoft/agent-governance-toolkit@main` post-merge.

This is the second of the three Microsoft-stack integrations. v0.11.0 shipped the Agent Framework `FunctionMiddleware`; v0.12.0 ships the AGT backend; the third (Azure AI Foundry MCP Gateway sidecar) ships when the recorded walkthrough lands.

### Stub-shape integration deprecated

The pre-merge `raucle_detect.integrations.agt` module — containing the `IPolicyProvider` stub we originally proposed (Microsoft instead chose to keep the existing `ExternalPolicyBackend` Protocol they already ship, which we then extended) — remains importable for one minor version and will be removed in v0.13.0. New consumers should use `raucle_detect.integrations.agt_backend.RauclePolicyBackend`.

## Unreleased

### Relicensed: MIT → AGPL-3.0-or-later + commercial

raucle-detect is now dual-licensed. The default open-source licence becomes the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later); a commercial licence is available from Raucle for organisations whose use is incompatible with AGPL terms.

The change protects the project from being absorbed into closed-source commercial forks while preserving full openness for self-hosting enterprises, academic research, security audits, and contributors. Self-hosting inside a single organisation for internal use — the dominant use case in our regulated-fintech ICP — is unaffected.

Versions tagged on or before commit `ac9aed0` remain available under the MIT licence under which they were released. See [LICENSING.md](LICENSING.md) for the rationale. (Note: the project was subsequently relicensed to Apache-2.0 in v0.19.0; the AGPL + commercial dual-licence described in this historical entry applied to releases v0.10.0–v0.18.0.)

## 0.10.0 (2026-05-14)

### Capability-based agent permissions — unforgeable tool handles

Every prompt-injection mitigation in 2026 still asks an LLM, in English, not to misuse its tools. v0.10.0 replaces that polite request with an OS-style capability discipline: a tool refuses to execute unless the caller presents an Ed25519-signed `Capability` token whose constraints are satisfied by the actual call arguments. Prompt injection becomes structurally irrelevant for tool calls — the malicious instruction has nothing to act with.

- **`Capability`** — the token. Binds `(agent_id, tool, constraints, nbf, exp, parent_id, policy_proof_hash, issuer, key_id)` under one Ed25519 signature. Constraint schema mirrors v0.9.0's `JSONSchemaProver` policy keys: `forbidden_values`, `allowed_values`, `max_value`/`min_value`, `required_present`, `forbidden_field_combinations`.
- **`CapabilityIssuer`** — mints fresh tokens; attenuates parents into more-restricted children.
- **`CapabilityIssuer.attenuate()`** — the killer property. A child cannot outlive its parent. A child's bounds can only narrow (min of two `max_value`s; intersection of two `allowed_values`; union of two `forbidden_values`). A child's `agent_id` must be a prefix-extension of the parent's. Broadening is structurally impossible.
- **`CapabilityGate`** — the choke point. `check(token, tool, args)` verifies issuer pinning, signature, `token_id` binding, time bounds, tool match, agent match, and every constraint against the supplied args. Optional `parent_resolver` walks the full attenuation chain. Fails closed by default.
- **`policy_proof_hash`** — a token can cite a v0.9.0 `ProofResult.hash`, claiming "these constraints are formally complete over this tool's schema". The proof, the receipt, the audit chain, and the capability all reference each other by hash. The trust graph closes.
- **CLI** — `raucle-detect cap keygen | mint | verify | check | attenuate`. Exit codes: 0 OK / ALLOW, 2 INVALID / DENY.
- 20 new tests covering signing, expiry, tampering, every attenuation invariant, full chain verification, and serialisation round-trip.

This is Move #2 of the revolutionary roadmap. With v0.9.0 (proofs over the tool grammar) and v0.10.0 (unforgeable handles to invoke that tool), the strongest agent-safety story on the market is now MIT-licensed open source.

## 0.9.0 (2026-05-14)

### Formal verification of bounded guardrails — proofs, not statistics

Every other AI security product on the market ships with the same line: *"tested against 10,000 attacks."* That is statistics over a sample. For bounded sub-languages — tool-call JSON and URL allowlists — we can do dramatically better: produce an actual **proof** that no string in the grammar bypasses a given policy. (SQL is narrower: a finite-template checker over a *modelled subset* that returns `UNDECIDED` for constructs it does not model — not a general SQL proof. See the v0.17.0 "Scope & claims" note for the precise framing.) v0.9.0 is the first release of that machinery.

- **`JSONSchemaProver`** — SMT-backed (Z3). Given a JSON Schema (type=object with primitive properties + enum + min/max) and a policy (`forbidden_values`, `max_value` / `min_value`, `required_present`, `forbidden_field_combinations`), returns `PROVEN` or a **concrete counterexample tool-call**. The right thing to point at every agent's tool-call interface.
- **`URLPolicyProver`** — enumerative. `require_https`, `forbid_query_keys`, `host_allowlist` (with `*.example.com` wildcards), `max_path_depth`. Counterexamples are concrete URLs.
- **`SQLClauseProver`** — bounded read-only-ish policy over a finite set of statement templates. `forbidden_tokens` (DROP, DELETE, TRUNCATE…), `allow_statement_chaining`, `allowed_tables`. Counterexamples include the offending template plus the rule that broke.
- **`ProofResult`** — canonical-JSON-hashed artifact carrying `(status, prover, prover_version, grammar_hash, policy_hash, counterexample, notes, timeout_ms)`. The hash drops straight into the v0.5.0 receipt and v0.4.0 audit chain — proof artifacts become first-class citizens of the trust graph.
- **`UnsupportedGrammar`** — explicit refusal. Recursive schemas, arbitrary string regex constraints, and full SQL grammars raise instead of pretending to prove something they can't. Honest scope beats lying coverage.
- **CLI** — `raucle-detect prove json --schema tool.json --policy policy.json`, `prove url --grammar grammar.json --policy policy.json`, `prove sql --grammar grammar.json --policy policy.json`. Exit codes: 0 PROVEN, 2 REFUTED, 1 UNDECIDED.
- **Optional `[proof]` extra** — `pip install 'raucle-detect[proof]'` pulls Z3. Core stays dependency-free.
- 19 new tests covering positive proofs, refutation paths with concrete counterexample inspection, hash determinism, and the rejection of unsupported grammars.

This is the depth play. The v0.8.0 feed is breadth — fast distribution of known badness. v0.9.0 is depth — cryptographic guarantees about declared interfaces. Together they bracket the field.

Move #3 of the revolutionary roadmap.

## 0.8.0 (2026-05-14)

### Federated signed-IOC feeds — Sigstore-shaped threat intel for AI

Every new deployment that subscribes makes every other deployment safer. Novel jailbreaks discovered by one team propagate to every gateway worldwide, cryptographically signed, no central authority, no API token.

- **`SignedIOC`** — content-addressed Indicator of Compromise. Fields: `kind` (`regex` | `substring` | `unicode_signature`), `pattern`, `severity`, `categories`, `issuer`, `key_id`, `issued_at`, optional `revokes` / `expires_at`. Body is canonical-JSON-hashed; `content_hash` is the identifier; Ed25519 `signature` is mandatory.
- **`Feed`** — a bundle of IOCs from one issuer, plus a Merkle root over sorted content hashes and one manifest signature. Every IOC is *also* individually signed, so partial copies remain verifiable offline.
- **`IOCSigner`** — publisher API. `generate(issuer=...)`, `sign_ioc(...)`, `build_feed(...)`, `save_private_key(...)`. Pure Ed25519 (`cryptography` extra).
- **`FeedStore`** — consumer API. Directory-backed, pinned-pubkey verification on every merge, honours intra-issuer `revokes`, drops expired IOCs. Renders the live set as pattern rules consumable by `Scanner(feed_store=...)`.
- **`Scanner(feed_store=...)`** — one new keyword. Feed-derived rules merge alongside built-ins and custom YAML, with `source: "feed:<issuer>"` carried through to `matched_rules` so downstream audit/receipt can attribute every hit.
- **Trust model** — no global root. Consumers pin one issuer pubkey per feed. Multiple feeds compose. Hostile cross-issuer revocations are silently ignored: an issuer can only revoke its own IOCs.
- **CLI** — `raucle-detect feed keygen`, `feed sign`, `feed verify`, `feed pull`, `feed list`.
- **Composition** — feed-derived rules participate in the ruleset hash bound into every v0.4.0 audit-chain entry and v0.5.0 signed receipt. Subscribing to a feed mutates the verdict surface in a way that is itself attestable.

This is the network-effect layer. Move #6 of the frontier roadmap.

## 0.7.0 (2026-05-14)

### Multimodal scanning — the 2026 attack surface

Attackers are no longer typing `ignore all previous instructions`. They hide it inside images (OCR + invisible-pixel encoding), audio (steganography), ASCII art (the ArtPrompt class), EXIF metadata, PDF streams, and zero-width Unicode wrapped around innocent-looking text. This release adds the detection layer text-only scanners miss.

- **`strip_invisible_unicode(text)`** — dep-free, always available. Strips zero-width spaces (U+200B/C/D), bidi overrides (U+202A–E, U+2066–9), variation selectors (U+FE00–F, U+E0100–1EF), word joiners (U+2060–4), the entire **tag-character block** (U+E0001–7F) used in 2024-era invisible-prompt attacks, the BOM, and the soft hyphen. Returns the cleaned string plus a list of every codepoint that was hidden, so the finding can be surfaced rather than silently sanitised away.
- **`detect_ascii_art(text)`** — dep-free heuristic for the **ArtPrompt** class. Identifies blocks of 5+ consecutive art-shaped rows (high fill-character density, low alphanumerics), then matches each 6-column slice against a library of 13 letter glyphs (A, B, E, G, I, N, O, P, R, S, T, U, V) at a 70% structural-similarity threshold. Catches the canonical "draw the word IGNORE in `#` characters and ask the model to read it" attack without needing OCR.
- **`MultimodalScanner`** — orchestrator that wraps a `Scanner` and pre-processes input through every detector. Returns a typed `MultimodalScanResult` with a `combined_verdict` that auto-escalates to MALICIOUS when any HIGH-severity finding is present — *seeing* invisible-Unicode in prose is itself evidence of bad intent, separate from what the scrubbed text scans as.
- **Image scanning** via Tesseract OCR + EXIF inspection. Extracts text from `.png`/`.jpg`/etc., inspects EXIF for prompt-bearing metadata, concatenates everything, and feeds it back through the standard text scanner. Requires the `[multimodal]` extra (Pillow + pytesseract + tesseract on PATH).
- **PDF scanning** via `pypdf` stream extraction. Same pattern: extract text, scrub, scan.

### New CLI

- **`raucle-detect scan-image <path>`** — full pipeline. `--mode`, `--rules-dir`, `--format table|json`. Exit code 0/1/2 by verdict.
- **`raucle-detect scan-pdf <path>`** — same options.
- **`raucle-detect scrub <text>`** — quick utility. Reports every invisible codepoint in the input and prints the scrubbed text.

### Deliberately not done yet

- Audio steganography — needs librosa/audio deps; deferred to a future release with its own `[audio]` extra.
- Image-pixel-encoded prompts (least-significant-bit steganography) — separate detector, separate PR.
- Multimodal LLM input correlation — Scanner currently treats text and image as separate scans.

### Stats

- 1 new module (`multimodal.py`)
- 3 new CLI commands (`scan-image`, `scan-pdf`, `scrub`)
- 22 new tests (20 dep-free + 2 that gracefully skip without Pillow/pypdf)
- 333 tests passing total
- New optional dependency group: `pip install 'raucle-detect[multimodal]'`

### Compatibility

All new functionality additive. `Scanner` unchanged. Existing chains, receipts, replay flows continue to work. Version 0.6.0 → 0.7.0.

## 0.6.0 (2026-05-14)

### Counterfactual replay — the SOC killer feature

Given any provenance chain produced by v0.5.0, you can now re-run every guardrail decision in it against a *different* policy and see exactly what would have changed. Answers the question every incident response actually needs: *"if we'd had stricter rules on last Tuesday, would we have caught this?"*

- **`InputStore`** — JSONL-backed, append-only, hash-verified mapping of `input_hash → original_text`. Lives alongside (not inside) the provenance chain so receipts stay privacy-by-default. Tampered entries are detected on lookup and reported as missing rather than silently returning the wrong prompt.
- **`Replayer`** — walks every `guardrail_scan` receipt in a chain, looks up the original input in the store, re-runs against a fresh `Scanner` configured with the counterfactual policy, and emits a typed diff.
- **`ReplayResult`** — separates **unchanged**, **newly blocked**, **newly allowed**, **newly alerted**, and **missing-input** receipts. Each `ReplayChange` carries the original receipt hash, the verdict transition, and a one-line explanation pulled from the new scan's matched rules.
- **Scanner integration** — pass `input_store=` to `Scanner()` and every `scan` / `scan_output` / `scan_tool_call` automatically persists the input text to the store. Opt-in, zero-cost when not configured.

### CLI

- **`raucle-detect provenance replay <chain> --input-store <store>`** — table or JSON output. Flags: `--mode` (strict/standard/permissive), `--rules-dir` for custom rule packs, `--show-unchanged` to include receipts whose verdict didn't change. Exit code 0 always (replay always succeeds at the analysis level; the diff is the output).

### How it works end-to-end

```python
from raucle_detect import AgentIdentity, ProvenanceLogger, Scanner
from raucle_detect.replay import InputStore

identity = AgentIdentity.generate(agent_id="agent:gateway")
with (
    ProvenanceLogger(agent=identity, sink_path="audit/chain.jsonl") as log,
    InputStore.open("audit/inputs.jsonl") as inputs,
):
    scanner = Scanner(mode="standard", provenance_logger=log, input_store=inputs)
    scanner.scan(user_prompt)  # writes signed receipt + persists prompt
```

Then, days later, after a near-miss:

```bash
raucle-detect provenance replay audit/chain.jsonl \
    --input-store audit/inputs.jsonl \
    --mode strict
```

→ table of every receipt whose verdict would have changed, with the rule that would have fired.

### What this is uniquely possible because of

Counterfactual replay is the first feature that *requires* the v0.5.0 provenance primitive. Every other guardrail vendor would have to log raw prompts in plaintext to do this; raucle does it from hash-keyed receipts plus a separately-managed input store, so the *signed* audit trail never has to carry the content. That separation is what makes the feature deployable in regulated environments.

### Stats

- 1 new module (`replay.py`)
- 1 new CLI subcommand (`provenance replay`)
- 13 new tests (input store round-trip, idempotency, tamper detection, malformed-line handling, Scanner auto-save, same-policy/strict-policy/missing-input replay, non-guardrail-receipt handling, result-view sanity)
- 311 tests passing total

### Compatibility

- All new parameters optional. Scanner gains an optional `input_store=` kwarg.
- No new mandatory dependencies; replay uses the existing crypto stack from v0.4.0/v0.5.0.
- Version 0.5.0 → 0.6.0.

## 0.5.0 (2026-05-14)

### AI Provenance Graph — cryptographic chain-of-custody for the agentic stack

The first open-source implementation of end-to-end signed provenance for multi-agent / multi-tool LLM workflows. Every step (user input, model call, tool call, retrieval, guardrail scan, agent handoff, sanitisation, merge) emits a signed receipt that composes into a Merkle DAG. Given any output you can reconstruct the entire causal chain back to the original input and prove nothing in the chain has been tampered with. The LLM-equivalent of certificate transparency + SBOM + DNSSEC.

- **`AgentIdentity`** — Ed25519 keypair plus a self-signed capability statement listing the agent's permitted models, tools, and data classifications. Acts as the agent's "TLS certificate".
- **`ProvenanceReceipt`** — compact JWS (EdDSA, `typ=provenance-receipt/v1`) binding `(agent_id, parent_receipts, operation, input_hash, output_hash, taint, timestamp)`. Hashes only — receipts never carry the raw prompt/output, privacy by default.
- **`ProvenanceLogger`** — high-level API: `record_user_input`, `record_model_call`, `record_tool_call`, `record_retrieval`, `record_guardrail_scan`, `record_agent_handoff`, `record_sanitisation`, `record_merge`. Auto-inherits taint from parents so callers can't accidentally drop it. Enforces capability allowlists at write time.
- **`ProvenanceVerifier`** — verifies (a) every signature, (b) every parent link exists, (c) taint monotonicity (descendants ⊇ parents, unless a `sanitisation` step explicitly removes specific tags). `trace()` walks the DAG backwards; `to_dot()` exports Graphviz for visualisation.
- **Auto-emit from `Scanner`** — pass `provenance_logger=` to `Scanner()` and every `scan` / `scan_output` / `scan_tool_call` automatically emits a `guardrail_scan` receipt with the verdict + ruleset hash. `ScanResult.provenance_hash` is the new receipt's hash. Downstream steps cite it as a parent, so the chain proves the guardrail actually ran before each model/tool call.

### CLI

- **`raucle-detect provenance keygen <agent_id>`** — generates Ed25519 keypair + capability statement. `--allowed-models` / `--allowed-tools` / `--ttl-days` shape the statement.
- **`raucle-detect provenance verify <chain> --pubkeys …`** — verifies signatures, DAG integrity, and taint monotonicity. Accepts capability statement JSON files or raw PEM keys.
- **`raucle-detect provenance trace <receipt> --chain …`** — walks the DAG backwards from a leaf to all roots; table or JSON output.
- **`raucle-detect provenance graph <receipt> --chain … --out g.dot`** — exports Graphviz DOT for visualisation.

### Receipt format (v1)

JWS header includes `typ=provenance-receipt/v1`, `crit=["raucle/v1"]`, `kid=<agent_key_id>`. Payload fields: `iss`, `iat`, `agent_id`, `agent_key_id`, `operation`, `parents` (list), `input_hash`, `output_hash`, `model`/`tool`/`corpus` (operation-specific), `ruleset_hash`, `guardrail_verdict`, `taint` (sorted list), optional `tenant`. Receipt's own hash = `sha256(compact_jws)` — content-addressed, deterministic.

### Stats

- 1 new module (`provenance.py` — ~600 lines)
- 1 new CLI subcommand with 4 actions (`keygen`, `verify`, `trace`, `graph`)
- 28 new tests (DAG composition, taint monotonicity, signature verification, tampering detection, capability enforcement, Scanner auto-emit)
- 293 tests passing total

### Compatibility

- All new parameters are optional. `ScanResult` gains an optional `provenance_hash` field.
- Requires `raucle-detect[compliance]` extra (already present in 0.4.0) for the `cryptography` dependency.
- Version 0.4.0 → 0.5.0.

## 0.4.0 (2026-05-13)

### Compliance & Audit (EU AI Act / SOC 2 ready)

- **Tamper-evident hash-chained audit log** (`HashChainSink`) — every detection event is hash-chained to its predecessor; Ed25519-signed Merkle-root checkpoints anchor the chain at configurable intervals. `AuditVerifier` detects any past-record tampering and pinpoints the first invalid index. Resumes existing chains seamlessly. CLI: `raucle-detect audit verify` and `audit keygen`.
- **Signed JWS verdict receipts** (`VerdictSigner` / `VerdictVerifier`) — every scan can emit a compact JWS receipt (Ed25519, `typ=raucle-receipt/v1`) containing input hash, ruleset hash, model version, and timestamp. Downstream SIEMs/gateways can verify decisions without trusting transport logs. The `crit=raucle/v1` header prevents generic JWT libraries from accidentally accepting these as auth tokens. CLI: `raucle-detect verify-receipt`.
- **`ScanResult.receipt`** field — present when a `VerdictSigner` is configured.
- REST endpoints: `POST /verdict/verify`, `GET /audit/status`.

### Outcome Verification

- **`OutcomeVerifier`** — classifies whether a malicious prompt actually *landed*: `LANDED`, `REFUSED`, or `UNCERTAIN`. Combines refusal-pattern detection, canary-leak checks, system-prompt-leak heuristics, secret-leak detection, and sensitive tool-call diffs. The single metric CISOs actually care about — cuts noise from prompts that *attempted* but were refused.
- REST endpoint: `POST /verify/outcome`.

### Model Context Protocol (MCP)

- **MCP server mode** (`raucle-detect mcp serve`) — speaks JSON-RPC 2.0 over stdio per the MCP 2024-11-05 spec. Exposes 8 tools to any MCP-compatible client (Claude Desktop, Cursor, Continue.dev, Cline): `detect_injection`, `scan_output`, `scan_tool_call`, `verify_outcome`, `scan_mcp_manifest`, `list_rules`, `embed_canary`, `check_canary_leak`. Zero external MCP SDK dependency.
- **MCP manifest static scanner** (`raucle-detect mcp scan`) — finds tool-poisoning attacks in other MCP servers: hidden instruction tags (`<IMPORTANT>`, `<SYSTEM>`, `[INST]`), invisible Unicode, direct injection phrases, rug-pull indicators, baked-in credentials, SSRF targets, dangerous tool names. Outputs JSON or **SARIF 2.1.0** for GitHub Advanced Security ingestion.

### Scanner integration

- `Scanner` now accepts optional `audit_sink`, `verdict_signer`, `model_version`, and `tenant` parameters. When wired, every `scan`, `scan_output`, and `scan_tool_call` automatically writes to the audit chain and attaches a signed receipt to the result.
- Server reads `RAUCLE_DETECT_AUDIT_PATH`, `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM`, `RAUCLE_DETECT_VERDICT_KEY_PEM`, `RAUCLE_DETECT_MODEL_VERSION`, `RAUCLE_DETECT_TENANT` from env.

### Dependencies

- New optional extra: `raucle-detect[compliance]` pulls `cryptography>=42.0` for Ed25519 signing/verification. Core install remains zero-dependency.

### Stats

- 5 new modules: `audit.py`, `verdicts.py`, `outcome.py`, `mcp_scanner.py`, `mcp_server.py`
- 5 new CLI commands: `audit verify`, `audit keygen`, `verify-receipt`, `mcp serve`, `mcp scan`
- 3 new REST endpoints: `/verdict/verify`, `/verify/outcome`, `/audit/status`
- SARIF output for GitHub code-scanning integration

## 0.3.0 (2026-05-13)

### New Features

- **Canary watermarking** (`CanaryManager`) — embed invisible tokens in system prompts to detect if the model is manipulated into leaking its instructions. Three concealment strategies: zero-width Unicode encoding, semantic sentence injection, and HTML comment. Supports HMAC-signed tokens for offline verification.
- **Attack export & replay** (`AttackLog`) — collect scan results and export to JSONL, Garak, PyRIT, or PromptBench format so production detections feed back into your test suite automatically.
- **Rule mutation fuzzer** (`raucle-detect rules fuzz`) — auto-generates leet-speak, homoglyph, zero-width, base64, ROT13, reversed, and case-flip variants of seed attack phrases, then measures what percentage each rule catches. Highlights low-coverage rules.
- **API authentication** — set `RAUCLE_DETECT_API_KEY` to require `Authorization: Bearer <key>` on all scan endpoints. Uses `secrets.compare_digest` to prevent timing attacks.
- **Rate limiting** — built-in token-bucket rate limiter per client IP. Configure via `RAUCLE_DETECT_RATE_LIMIT` (req/min) and `RAUCLE_DETECT_BURST_LIMIT`. Returns HTTP 429 with `Retry-After` header.
- **Prometheus metrics** (`GET /metrics`) — plain-text request counters, verdict histograms, per-endpoint latency (avg + p99), rate-limit and auth-failure counters. Scrape directly with Prometheus.
- **Docker Compose** (`docker-compose.yml`) — one-command deployment with all env vars documented.

### Bug Fixes

- **Negation window expanded** (`classifier.py`) — increased from 10 to 40 characters before a keyword, catching phrases like "I am NOT asking you to ignore".
- **Position bonus gameable bypass fixed** (`classifier.py`) — the 1.5× position multiplier no longer fires when benign preamble text appears in the first 100 characters, preventing "please help me: ignore all previous instructions" bypass.
- **Pattern compilation cached** (`patterns.py`) — `_compile_pattern()` is now module-level LRU-cached (2048 entries). `scan_with_rules()` no longer recompiles the same regex on every call; all `Scanner` instances share compiled patterns.
- **YAML rule schema validation** (`rules.py`) — rules are validated for required fields (`id`, `name`, `category`, `patterns`, `score`), score range (0–1), severity values, and valid regex patterns. Invalid rules are skipped with an error log instead of crashing at match time.
- **Session memory leak fixed** (`middleware.py`) — sessions idle longer than `session_ttl` seconds (default 1 hour) are automatically evicted. Added `active_session_count()` for monitoring.
- **Encoding error transparency** (`cli.py`) — file decoding with `errors='replace'` now counts and reports replacement characters to stderr instead of silently swallowing them.

### Stats

- 3 new modules: `canary.py`, `export.py`, `mutator.py`
- REST API: 7 endpoints (added `/metrics`; `/health` now reports `auth_enabled`)
- `HealthResponse` includes `auth_enabled` field

## 0.2.0 (2026-03-27)

### New Features

- **Output scanning** (`scan_output()`) — detect data leakage, system prompt exfiltration, and injection in LLM responses
- **Tool call validation** (`scan_tool_call()`) — block shell injection, path traversal, SQL injection, and SSRF in tool arguments
- **Session scanner** (`SessionScanner`) — multi-turn attack detection with escalation tracking, cumulative risk scoring, and trend analysis
- **Middleware interface** (`RaucleMiddleware`) — framework-agnostic `pre_process()`, `post_process()`, `pre_tool_call()` hooks with alert/block callbacks
- **OpenClaw plugin** (`plugins/openclaw/`) — real-time agent protection via `before_prompt_build` hook
- **RAG poisoning rules** (RAG-001 to RAG-004) — document injection, retrieval manipulation, invisible text, citation poisoning
- **Agent attack rules** (AGT-001 to AGT-005) — goal hijacking, tool abuse, memory manipulation, action coercion, privilege escalation
- **Output-specific rules** (OUT-001 to OUT-003) — system prompt leak, injection in output, exfiltration channels
- **Tool call rules** (TOOL-001 to TOOL-004) — dangerous shell commands, path traversal, SQL injection, SSRF

### Improvements

- **Weighted heuristic classifier** — position-aware scoring, negation detection, density bonuses (replaced flat keyword counting)
- **Broadened PI-004 patterns** — catches "print/show/display your system prompt" and variants
- **ReDoS protection** — risky regex patterns capped at 10K chars
- **Input size limits** — 1MB file cap in CLI, 100K char truncation in scanner
- **Worker count clamping** — batch scan workers clamped to CPU count
- **`ScanResult.notes` field** — reports truncation and other scan metadata

### Stats

- 55 rules, 250+ patterns (was 39 rules, 180+ patterns in 0.1.0)
- 208 tests passing (was 95 in 0.1.0)
- REST API: 5 endpoints (`/scan`, `/scan/batch`, `/scan/output`, `/scan/tool`, `/health`)

## 0.1.0 (2026-03-25)

- Initial release
- 39 detection rules across 6 categories
- Pattern matching + heuristic semantic classifier
- Python library, CLI tool, REST API
- Three sensitivity modes (strict/standard/permissive)
- YAML custom rule framework
- Zero mandatory dependencies
