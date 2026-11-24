# Changelog

## Unreleased

## 0.23.8 (2026-11-24) - adversarial hardening wave

- The published security guarantee, v1 (docs/security-guarantee-v1.md): a one-page statement of exactly what the receipted gate decision layer guarantees at a pinned source revision and what it does not, with every claim naming the test pin that fails if the claim regresses; the source revision row pins the v0.23.8 release commit.
- The checker verdict trail (docs/checker-verdicts/): the per-PR checker verdict records from the hardening wave review rounds (raucle PRs #310 to #328 plus raucle-agent-red #45, including the superseded unsound-pass tombstone for #310), committed as the audit trail of the review cycle.

- Security remediation (RED-039, a second external review of the main branch): the TrustRegistry constructor verifies integrity BY DEFAULT, so every construction path (the gateway boot issuer map, the cross-org registry loader, the CLI registry commands) refuses a parseable-but-tampered history - reordered entries, swapped key material, broken operator signatures - with the same named `RegistryIntegrityError` instead of silently folding attacker-issued keys into the issuer map. The one escape hatch is an explicit `verify=False` for authoring/repair tooling, used nowhere in an authorisation path. Honest limit: for SIGNED registries without the operator key present, the documented integrity-only model applies (chain, key-id binding and issuer uniqueness still enforced; authentication requires the operator key).
- RED-039 continuation: the operator-key-registry boot guard (`KeyStoreRegistryMismatch`) now records the registry head it serves on in a `<registry>.head-pin` file and refuses a registry that moved BACKWARD (truncated or rolled-back tail, which verifies on its own) or SIDEWAYS (same index, different head hash). Forward growth (an operator append between boots) passes and re-records the head; deleting the pin is the documented consumer reset for a legitimately re-initialised registry. The production gap this closes: `gateway._ensure_caller_gate` previously built `TrustRegistry(path=...)` directly and loaded ANY parseable registry unverified.
- RED-039 continuation: handshake replay protection is production-grade. `accept_call` now REQUIRES a persistent, atomic replay store (new `raucle.replay_store`: `ReplayStore` interface + `SqliteReplayStore` on the receipt-index sqlite idiom, WAL, uniqueness enforced by the database primary key, retention opt-in with a retain-forever default). The optional process-local `seen` set is gone; a request without a nonce is refused unconditionally; the consume happens BEFORE any gate decision, so a nonce consumed for a request whose handling crashed cannot be re-executed after a restart. Concurrent duplicate requests accept exactly once.
- The agent passport's `ttl_seconds` refuses 0, negative and non-integer values with a named `ValueError` (previously `ttl_seconds=0` silently meant never-expiring); `None` keeps the documented no-expiry mode (the CLI `--ttl` default). `verify_passport` now refuses a passport whose `issued_at` sits in the future beyond the registry's 300s clock-skew allowance, and runs the vouched statement through the production `CapabilityStatement` parser (unknown fields and wrong shapes fail with a named structural-validation reason, distinct from unknown statements/issuers).
- The cross-org demo and the handshake docs route every responder call through the replay store; the demo's revoked-key scene uses a fresh nonce (its old shape replayed scene 1's nonce, which the mandatory store now refuses as a replay before the registry check).

- Audit multi-process safety (Q11 D): HashChainSink appends run under an inter-process file lock with a head refresh inside the same critical section, so a writer that slept while another process wrote adopts the true chain tail from disk instead of forking the chain; a SIGKILLed writer leaves the torn last line named in the sink's status channel (and again on the next verify), never a silent skip, and the chain continues from the last complete record. A four-process stress test pins one chain, unique strictly increasing indices and verifier green on the merged chain, plus the SIGKILL-mid-append case through real processes.
- Audit advisory single-writer mode (Q11 D): `RAUCLE_AUDIT_SINGLE_WRITER=1` records the operator's promise that the chain file has exactly one writer; boot then holds an exclusive lock for the sink's lifetime and a second writer refuses boot by name (the receipts sidecar's single-writer discipline, applied to the audit chain).
- Signed audit production strict mode (Q11 F): `RAUCLE_REQUIRE_SIGNED_AUDIT=1` refuses boot by name when the signer is unavailable or the audit chain's genesis is unsigned, naming `raucle rotate-chain` as the recovery path; unset keeps the development affordances (an unsigned chain warns and runs). Checkpoint generation failures surface on the sink's named status channel (checkpoint_skipped) instead of a log-only skip, and a writer that adopts a foreign head names the adoption and degrades checkpoint anchoring visibly rather than emitting an unverifiable checkpoint.
- The `/health` readiness payload gains an honest `audit_chain` field (state and the genesis key id) reporting what the chain on disk actually is, set from the chain's `chain_meta` header at boot, never from the config's wish.
- Capability delegation strict ancestry mode (Q11 E): `RAUCLE_REQUIRE_ANCESTRY_RESOLVER=1` refuses a token that cites a parent by name when no parent resolver is configured (root tokens stay servable), and a boot with the strict flag refuses when no delegation ledger backs the resolver, so delegations deeper than one level are never served without resolvable ancestry. With the resolver wired, root, child and grandchild revocation each deny the descendant tree, the denial survives a gateway restart, and the ledger resolver is read-only with appends visible on the next call.
- `HashChainSink.event_count` now counts the records this sink instance appended; the adopted chain head is `HashChainSink.head_index` (and status `head_index`), honest in a multi-writer deployment where one sink's local count and the shared chain head diverge. The verifier's no-key mode reports a hash-intact chain as valid with `signed_mode` `unverifiable`, matching its documented best-effort contract and the checkpoint path's behaviour, while a key-carrying verifier still refuses anything not signed.
- `RAUCLE_DELEGATIONS_FILE` is now loaded by the environment config: it was documented in prod.env.example but was never read, and the strict ancestry mode depends on it. The three enforcement flags are documented in docs/deployment-security.md and listed in deploy/prod.env.example.

- The enforcement control plane closes: a policy file, revocation registry or delegation ledger carrying an operator-signed `.meta` sidecar seal (canonical SHA-256, Ed25519 signature over the raw file bytes, key id, sealed-at) is verified at boot and at reload, and a seal that does not match the current bytes refuses with the named `PolicySealRefused` in every sealing mode  - the RAU-02/M5 filesystem-write-equals-enforcement-control path (residual 5) now needs the signing key, not the filesystem.
- New `raucle policy seal|verify` CLI writes and checks the sidecar seals; verification trusts only the keys configured via `RAUCLE_POLICY_SEAL_PUBLIC_KEY` (key ids follow the house sha256(PEM)[:16] convention; an unreadable configured key file refuses the boot). New `RAUCLE_POLICY_SEALING=required|advisory|off` (default advisory for one release cycle: unsigned policy boots behind a named `POLICY SEAL ADVISORY` banner and nothing denies; `required` refuses unsigned policy at boot; `off` is the explicit opt-out). This mirrors the shipped M2 detection half (unsealed deployments unaffected; divergence still fails closed) rather than bricking existing deployments on upgrade  - `required` is the named flip documented for the next cycle (RED-036's sibling residual 5, M5).
- Gate receipts now bind `x_gate.policy_hash` when the deciding policy file carries a verified seal: an auditor can prove WHICH sealed policy made each decision. The field is optional-when-unsealed, so legacy receipts and legacy verifiers verify byte-identically (RAU-02 receipts leg).
- The revocation-list and delegation-ledger file-cache paths now share the SAME seal mechanism: a registry the operator marks with a `.meta` seal refuses a diverging load into the deny path, in any mode; unmarked registries are unaffected (RAU-02 registries leg).
- `_FileCache` keys registry entries on `(content_sha256, size)` instead of `(mtime_ns, size)`, closing the R16 same-size-edit staleness (a same-size write with a preserved mtime no longer serves a stale revocation set); the stamp is the hash of the bytes the loader parses, so a concurrent write cannot tear an entry across two reads. Parsing stays memoised; read failures still raise into the deny path (RAU-05).
- SIEM target validation resolves DNS and refuses when ANY resolved address lands in loopback/link-local/private/reserved/multicast space (the RED-036/R15 hostname hole), refusing unresolvable targets fail-closed; the forwarder's new pinned transport (`raucle.siem_pinned`) re-resolves and re-judges immediately before each dial and connects to the validated address while SNI, the Host header and certificate verification keep the operator's hostname  - a DNS rebinding race between validation and request now hits a connect-time refusal, never a request (RAU-04).

- OpenClaw plugin hardening (Q14, fourth review): the OpenClaw plugin now registers every hook through the TYPED hook API (`api.on`) - the previous `api.registerHook("before_tool_call", ...)` registration is never invoked by the typed runner (a silent no-op on current hosts), the tool gate registers with no matcher restriction so every registered tool is covered, and `package.json` pins `openclaw.install.minHostVersion: ">=2026.4.22"` (the release that introduced typed hooks). Hosts lacking the typed surface get a named activation refusal instead of a silent degradation.
- Q14: scanner unavailability is no longer equivalent to a clean verdict. A `failureMode` config (`closed` default / `open`) decides the posture: closed mode BLOCKS the protected operation with the hook's native shape (explicit typed block decision for tool calls, cancel for outbound, block instruction injection for inbound) and both modes emit a NAMED advisory with the reason class (timeout, connection-refused, malformed-response, http-500, process-dead, auth-refused). The plugin never relies on exception-based blocking: the host runner defaults to fail-open for before_tool_call, so closed mode returns explicit block decisions whose enforcement does not depend on host policy.
- Q14: local scanner service trust. The plugin generates a per-boot scan secret (`crypto.randomUUID`, or `config.scanSecret` shared with a standalone service via `RAUCLE_PLUGIN_SCAN_SECRET`), requires it in the `X-Raucle-Scan-Token` header on every scan request, and adopts an already-answering service on the port ONLY when it passes the secret-protected `GET /identity` probe with a schema-strict raucle identity body that carries `scan_secret_required: true` (the ARMED flag: only a server that actually enforces the secret answers the probe, so the passing probe plus the flag are the secret round-trip proof) - anything else, including an unarmed raucle server running without `RAUCLE_PLUGIN_SCAN_SECRET` (body `scan_secret_required: false`), is refused by name and replaced by a freshly spawned scanner, with spawn failures on a bounded backoff respawn ladder that gives up with a named advisory after repeated failed rounds instead of re-entering a permanent restart loop on an occupied port. The Python server (`raucle/server.py`) enforces the header (401 without, 403 wrong, constant-time compare) when `RAUCLE_PLUGIN_SCAN_SECRET` is set, serves `/identity`, and keeps `/health` an open liveness probe.
- Q14: startup race closed and bounded hook work. The plugin awaits the bounded scanner readiness wait before treating the gate as active, logs a startup status summary (hooks registered, scanner reachable with the boot-secret fingerprint, active failureMode), and in closed mode REFUSES activation (named) when the scanner never becomes ready - a configured plugin is not proof of active enforcement. Scan calls carry a deadline (default 10s, clamped under the host's 15s hook budget) aligned with `ctx.abortSignal`: on abort or deadline the handler stops its own work, a scan arriving after the seal is DISCARDED and never writes a receipt implying the call proceeded, and decision-log receipts bind to the ACTUAL final outcome (`receipt.issued`/`receipt.bound` of allowed/denied/none).
- Q14: scanner verdicts and authorisation evidence are structurally separate. The plugin's bounded decision log records the scanner verdict, confidence and matched rules under `scanner.*` and the authorisation outcome under host vocabulary fields (`allowed`/`denied`/`unknown` x `enforced`/`unknown` with `plugin_hook_*` reason codes): a CLEAN verdict never appears as an authorisation decision, and any unknown coverage state renders UNAUTHORISED in plugin evidence, never as an allow-equivalent. Each gated call acknowledges an exposed admission-authority callback exactly once (degrading to plugin-side evidence on hosts that keep the receipt path host-internal).
- Q14: the plugin's test suite (node:test, run with `npm test` in `plugins/openclaw`; no external dependencies) covers typed registration, failure modes, the per-boot secret and identity probe, adoption refusals, bounded deadlines with late-scan discarding and the bounded decision log. CI does not run the TypeScript suite today; the Python-side scan-token enforcement is covered by `tests/test_scanner_server_auth.py`.

- The supplied deployment artefacts now require an explicit authentication choice: docker-compose.gateway.yml sets RAUCLE_GATE_AUTH to the :? refusal pattern (Set to apikey or token) so the public HTTPS gate cannot boot unauthenticated by operator inattention, while the library default (off, with its boot banner) stays untouched for local dev; the compose comments point the operator at Step 1 of docs/getting-started/20-production-hardening.md for provisioning apikey/token credentials, and the demo service honestly discloses its unauthenticated-traffic posture (tests/test_compose_deployment_contract.py).
- The compose rate-limit posture is sane and proxy-aware: the 60000/minute default drops to 200/minute (still env-overridable with RAUCLE_GATE_RATE_LIMIT=${...:-200/minute}), the documented 200/minute /gate route limit is pinned explicitly via RAUCLE_GATE_ROUTE_LIMIT, RAUCLE_TRUST_PROXY defaults on for the supplied Caddy topology with the shared-bucket reasoning in comments, and schema binding (RAUCLE_TOOL_SCHEMA_MANIFEST) is documented but deliberately left off so the code default preserves legacy behaviour when unset (tests/test_compose_deployment_contract.py).
- A serving boot without slowapi now refuses with a named error instead of logging a warning and serving unlimited: creating the gateway app is the serving posture, so the boot refuses with a ConfigurationError naming the missing dependency and the escape hatch; RAUCLE_DISABLE_RATE_LIMIT=1 is the deliberate opt-out (the null limiter stands in and the warning is still logged), and local dev/CLI paths never construct the app so they are unaffected; gateway_server exits cleanly with the refusal message (tests/test_gate_rate_limit.py, tests/test_gateway_server.py). slowapi rides in the [server] extra, which the supplied image already installs, so the refusal cannot fire in the compose deployment.
- Packaging honesty for the adapter extras (Finding 85): agent-framework, openai-agents, langchain, autogen, crewai, langgraph, pydantic-ai and google-adk each carry cryptography>=42.0 beside their framework dependency, because every adapter mints signed capability receipts; pip install "raucle[agent-framework]" no longer boots into an ImportError at first receipt (tests/test_compose_deployment_contract.py). The README install section becomes a table of which extra carries what.
- The main README's OpenClaw Plugin section is rewritten to match the plugin's actual behaviour: detection-layer scanner integration with no capability receipts and no capability enforcement, the before_tool_call hook boundary stated plainly (Claude CLI mcp.servers bypass, observational after_tool_call, the gate-at-the-MCP-server remediation endorsed rather than attempted in the plugin), the allowConversationAccess permission grant added to the quick install, the plugin's own server lifecycle (it starts and finds the scanner server, no separate start required), per-agent override precedence, and the detection engine ([server,rules]) versus receipts ([compliance]) split; no claim of protecting all agents remains.

- Receipts now self-describe their evidence level: new `/gate` decision receipts carry `x_evidence` "gate_observed" and new application-recorded `record_tool_call` receipts carry `x_evidence` "self_reported"; additive informational metadata in the x_ extension namespace (no schema version bump, signature and canonicalisation machinery untouched); legacy receipts without the field verify unchanged, and a receipt claiming the higher "executor_attested" level verifies like any other receipt, with no extra verifier trust granted from the label.
- The verify verdict now distinguishes how a resolved capability statement was vouched: `ProvenanceVerifier` accepts optional `capability_trust_modes` ("self_asserted" by default, "authority_issued" for statements resolved through a vouching the caller marks, unknown labels refused as a constructor error) and reports the modes informationally in the verify report (`capability_trust_modes`, omitted when empty so the v1.0 report body stays byte-stable); the agent passport verdict carries `trust_mode` "authority_issued" on success, and a failure verdict resolves no trust at all.
- docs: the security model and the README security-claims section now carry the three-guarantee receipt table (authorisation evidence, application-attested execution evidence, and the registered roadmap upgrades citing the W1 state-verification spec and the AEC evidence-chain composition draft), the four-level verdict vocabulary (PROVENANCE_SIGNATURE_VALID, CAPABILITY_OPERATION_PERMITTED and GATE_DECISION_VERIFIED issued today, EXECUTION_CONFIRMED registered roadmap) and trust-mode labelling; the README no longer carries sentences that could be read as an authorisation receipt proving execution, pinned red-first by tests/test_evidence_assurance.py (docs anchors, claim discipline over the README security section, evidence-field and trust-mode behaviour pins).

- Approvals (RED-039): approval consumption is a compare-and-set under a lock, the activation twin included. One approved request pays exactly once under concurrent re-submission: 100 concurrent consumes on one approved request yield exactly one success and 99 named already-consumed refusals; validation mismatches still refuse without burning the approval; an approved request whose validity window has passed refuses with the 410 class instead of paying out a stale approval. Atomicity is in-process by design; a shared transactional approval store across gateway workers stays a registered follow-up.
- Containment (RED-040): trace quarantine binds to the agent identity as well as the trace id. A refusal for quarantined-trace work records the presenting agent (the authenticated identity with gate auth on, the declared one with auth off, as the off-mode banner already names) into an identity-level quarantine, so a re-rolled X-Trace-Id no longer walks past containment; trace-level state stays keyed by the trace id and shared by whoever presents it, and the identity-level refusal lifts when every binding trace is released. The identity-level state is a per-process layer over the durable trace registry; a durable shared identity store stays a registered follow-up.
- Gate (RED-041): when session behavioural rules are configured, a request that omits the session id refuses by name (session_binding_required) instead of silently skipping the configured control; an omitted session can no longer escape the behavioural window. Deployments with no session rules configured behave exactly as before, and session values stay caller-supplied until the server-issued workflow-identity work.

- Agent Framework middleware durable-receipt mode (Q18 Close 1): `RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1` persists the capability receipt BEFORE the downstream tool call starts and refuses the call by name through the middleware termination refusal when the sink fails, so a receipt is either durably persisted or the call does not run; the default stays advisory (a sink failure is caught and logged loudly) for development continuity. Strict caller-identity mode (Q18 Close 1): `RAUCLE_MW_REQUIRE_AGENT_ID=1` denies by name when the framework context surfaces no independent caller identity instead of degrading to the token's bearer `agent_id`; each documented identity source individually satisfies the mode, and multi-agent production deployments are the recommended audience.
- Agent Framework receipt schema citation (Q18 Close 1b): `_build_receipt` cites the digest of the exact schema-registry entry the gate enforced (the registry a deployment loads from `RAUCLE_TOOL_SCHEMA_MANIFEST`), carrying `schema_evidence: "bound"`; when no schema resolution exists for the called tool the receipt carries `schema_hash=None` plus the explicit `schema_evidence: "unbound"` marker, so no receipt implies schema-bound verification without the hash. Identity extraction now reads the documented sources in priority order - metadata, then session state, then `context.agent.id` (previously ignored, review Finding 80) - and the integration fixtures exercise the documented primary source.
- Wrapper adapter argument normalisation (Q18 Close 2): crewai and langgraph gate on the SIGNATURE-BOUND argument view (`inspect.signature(...).bind(...)`, defaults applied) instead of `dict(kwargs)` / the single-positional `{"input": ...}` heuristic, so positional calls land on real parameter names and the gate evaluation, the receipt digest and the executed arguments carry the same semantic arguments (a forbidden or over-bound positional denied where the old view silently allowed it). When no signature can be resolved the previous heuristic view is kept as the fallback, and the receipt marks the residual (`args_binding: "verbatim"`) with a log line naming the tool.
- The common adapter conformance suite (Q18 Close 3): one parametrised module runs the reviewed conformance table (no token denies, wrong agent denies, wrong tool denies, forbidden argument denies, receipt-store-unavailable denies in durable mode, tool exception keeps the ALLOW decision, the original unwrapped tool is not blocked by the wrapper, concurrent sessions keep tokens isolated) across the agent_framework, autogen, crewai, langchain and langgraph adapters with honest per-extra skips; the unwrapped-invocation row records the deployment-coverage residual openly rather than claiming prevention.

- The provenance verifier now runs under fixed resource bounds with named refusals (`ProvenanceVerifierBoundsExceeded`, naming the limit hit, the observed value and the cap): bundle bytes (256 KiB default), parents per receipt (256), ancestry graph depth (256) and total receipts (1024). Defaults align with the existing receipt-size patterns (the 256 KiB simulate/manifest pasted-input cap family, the 32 KiB payload cap implied fan-out ceiling, the chain-graph query windows and the demo chain-collection cap), documented with a bounds table in the security model's provenance verification section.
- Bounds are default ON (fail-closed posture, stated): each bound is env-overridable for operators with genuinely deep chains (`RAUCLE_VERIFY_MAX_BUNDLE_BYTES`, `RAUCLE_VERIFY_MAX_PARENTS`, `RAUCLE_VERIFY_MAX_DEPTH`, `RAUCLE_VERIFY_MAX_NODES`; malformed or ambiguous values are refused loudly, never defaulted through), and `RAUCLE_VERIFY_BOUNDS=off` restores the legacy unbounded verifier for the documented migration window.
- The verifier's ancestry walk is memoised (visit-set keyed caching, iterative so a deep chain never hits the interpreter recursion limit): shared ancestors resolve once per verify call, the walk counter (one expansion per receipt, one edge examination per adjacency entry) rides the report object as diagnostics only so the v1.0 report body stays byte-stable for pack reproducibility, and cycles are refused by name by a defensive detector that honest content-addressed chains cannot reach.
- Receipts from the existing corpus verify unchanged: per-close parity pins cover the demo-bundle chain and suite-style rich chains field-for-field with bounds on and off, and the memoised pass changes no verdict on honest or tampered chains.

- The receipt store now refuses torn tails at seal and boot with named errors (`ReceiptStoreSealRefused`): sealing a segment containing an unparsable non-blank line refuses (no meta written, segment stays open and writable, operator decides on the resolution), and restarting onto a segment whose tail is torn refuses at open instead of silently chaining past it.
- Existing writable tail segments are resumed on restart rather than orphaned: the first append reopens the recorded writable segment instead of starting a new numbered one and leaving the old file writable, unsealed and never reopened.
- Seal `.meta` sidecars carry a verified signature when a seal identity is configured (the house Ed25519/KMS signer path: `key_id` plus a base64 signature over the canonical meta bytes, checked offline by `verify_seal_meta`), and record `unsigned: true` when none is, so anonymous sealing is never presented as signed.

- The gateway container image is rebuilt from a locked, non-editable runtime install (Q9, external v0.23.7 review): uv resolves the runtime extras `compliance,rules,server` exactly from `uv.lock` (`uv sync --locked --no-dev --no-editable`), so dev tooling (pytest, ruff, mypy) and the language-integration extras no longer ship in production, and the old editable source-tree install is gone from the image. Verified by a real image build: `import ruff`, `import langchain` and `import pytest` all fail inside the new image.
- Base images are digest-pinned: `Dockerfile.gateway` pins `python:3.12-slim` (3.12.16-slim-trixie at pin time) and `docker-compose.gateway.yml` pins `caddy:2-alpine` (v2.11.9-alpine at pin time) to their linux/amd64 registry digests, recorded with pin comments. The builder also pins uv 0.13.9 by digest. The healthcheck now polls the new public `/livez` route on the agent-facing port instead of `/health` on the admin port, so liveness survives a set `RAUCLE_HEALTH_KEY` and does not depend on the admin plane.
- A keyless serving boot now refuses with the new named `AdminKeyMissingError` (the same print-and-exit shape as the boot memory ceiling) instead of warning and running an admin panel that accepts no credentials. Scope is the serving entry point only: library use, the CLI detector server and tests construct gateways without an admin key and keep working (compose and Helm already required the key).
- The admin plane is rate limited in the application (120 requests/minute per client by default, `RAUCLE_ADMIN_RATE_LIMIT`), after per-image verification that the stock `caddy:2` image ships no rate-limit module. The Caddyfile, README and deployment docs now state the in-app limit, recommend an IP allowlist or a separate listener for the admin plane in production, and name the CSP ownership split: the proxy never restates a CSP, the admin app keeps its per-build hash-pinned policy (`_panel_csp()`, the RED-033 fix).
- Type checking lands as a baseline gate: mypy 2.4.1 configured minimally for the `raucle` package, with `tools/mypy-clean-modules.txt` pinning the 97 modules that type-check clean today; a new error in one of those modules fails the new CI `typecheck` job, while the honest package-wide count (120 errors in 30 files) is recorded as known debt. `pip-audit` joins CI as an advisory job (`continue-on-error: true`) over the resolved dev environment.
- Test and packaging ergonomics verified and tightened: the declared dev extra carries fastapi (via the `server` extra) and pytest-asyncio, `pytest --collect-only` collects 3276 tests with zero collection errors on the dev install, and optional-integration suites keep their importorskip guards (a sandbox without those extras skips them cleanly).
- Small correctness and hygiene fixes: `bench/run_bench.py` sizes `/proc` pages by `os.sysconf('SC_PAGESIZE')` with a 4 KiB fallback instead of a hard-coded 4096; `HybridRecordSigner` gains a named `pq_public_key()` accessor and `trust_registry` stops reaching into `_pq_private`; an invalid `RAUCLE_GATE_MAX_PAYLOAD_CHARS` logs a warning and keeps the default instead of a bare except-pass; the lean-action pin carries its `# v1.7.1` inline version comment; and the `raucle_detect` deprecation shim announces its removal version (v0.26.0) in its docstring and warning.

- Q14 checker verdict remedies (PR #322): scanner adoption now requires the identity body to carry `scan_secret_required: true`. The previous boolean-only check accepted `scan_secret_required: false`, so an UNAUTHENTICATED raucle server (one running without `RAUCLE_PLUGIN_SCAN_SECRET`) answering the `/identity` probe with a valid raucle body was adopted on any passing probe; the unarmed server is now refused by name (identity-mismatch naming the unarmed body) and the manager spawns its own secret-carrying scanner. Pinned by plugin tests.
- Q14: on adoption refusal the manager respawned against the same occupied port and the exit-restart loop re-entered every 10 seconds forever (a permanent EADDRINUSE lockout). Respawning now follows a bounded backoff ladder (10 second base delay doubling to a 60 second cap) and gives up after 5 consecutive failed rounds with a named `RESPAWN ABANDONED` advisory naming the remedy; the readiness wait also fails fast when the spawned scanner dies before proving its identity instead of polling a dead port for the full budget.
- Q14: decision-log entries recorded a hard-coded `authorityAcknowledged: true` at every gated site while the actual host acknowledgement return was discarded; every gated site now records the real `acknowledgeAuthority` outcome - true only when the exposed admission-authority callback existed and did not throw. Pinned by plugin tests across the allow, block, scan-failure and late-arrival paths.
- Q14: the late-arrival outcome-derivation pin now drives the SHIPPED index.ts handler path instead of re-declaring the derivation inline (the old pin stayed green against the pre-fix shape); with the real path exercised, the sealed-call reason code moves from the out-of-vocabulary `scanner_unavailable` to the declared `plugin_hook_blocked`, and the malformed-response classification branch (a `_post` JSON-parse rewrap classes as `malformed-response`, never `identity-mismatch`) gains its missing pin. Plugin hook-name comments use the house 'catalogue' spelling.
- Q14: `plugins/openclaw/README.md` and the Q14 changelog entry now state the adoption behaviour the code actually enforces (armed-flag identity body, bounded respawn ladder with a named give-up advisory, truthful authority acknowledgement), and the composite assertion Sonar flagged at `tests/test_scanner_server_auth.py:54` (python:S9073) is split into separate assertions.

- The Q15 checker verdict defects are fixed: tests/test_gate_rate_limit.py splits the pytest.raises guard so it holds exactly one exception-capable invocation (the gateway construction is hoisted out) and pins that the app-factory serving refusal raises independently of gateway construction; tests/test_gateway_server.py drops the @pytest.fixture() empty-parenthesis drift; uv.lock is regenerated for the Q15 lane extras (the adapter extras now carry cryptography), with uv lock --check verified green.
- The receipted-DENY overclaim is truth-up'd: docker-compose.gateway.yml (demo-service comment), docs/deployment-demonstrator.md and docs/getting-started/20-production-hardening.md now state exactly when deny receipts exist - an authenticated caller's gate deny is receipted, while an unauthenticated pre-gate refusal is a transport-layer refusal with receipt_id null and no receipt behind it, because the gateway receipt trail starts at check_tool_call (verified live: a pre-gate refusal writes nothing to the receipt store). scripts/demo_agents.py stays unauthenticated by design and the docs now say what it actually earns (tests/test_compose_deployment_contract.py, tests/test_gate_auth_modes.py, tests/test_deny_receipt_claims.py).

- The pq1 hybrid receipt signature slot becomes JOSE-conformant: emission is a single base64url segment over the raw Ed25519 (64 byte) and ML-DSA-65 (3309 byte) signature concatenation (RFC 7515 Compact conformance; constant lengths frame the split, so any standards-conformant JOSE parser sees a valid three-segment JWS and rejects on the unknown raucle/pq1 crit entry), the parser accepts the previous dot-separated form for verification only during a deprecation window with a named deprecation marker logged on every legacy acceptance, fail-closed framing refusals (wrong length, truncated slot, swapped components, stripped component) hold under both accepted forms, and the pq1 spec plus shared test vectors pin both forms with the legacy reference carried byte-identically and marked verify-only (ports sync from the vectors file; v1 classical receipts are unchanged).

- Foundry sidecar artefact honesty (Q21, external phase-22 review): the `deploy/foundry-mcp-sidecar/` artefacts now state exactly what they implement and deployable-what-actually-ships. README relabelled as the M2-class PROPOSED integration (shipped components listed - `raucle serve` detection REST server, the `POST /gate` capability gateway, `raucle mcp serve` - and the Foundry MCP forwarder, its `--mode foundry-sidecar` executable and `RAUCLE_BACKEND_URL` forwarding, marked unshipped pending the registered proxy integration). The Bicep startup command is fixed to what ships (`raucle serve --host 0.0.0.0 --port 8080 --mode standard`; the probes target the shipped `GET /health` route; the forwarder env/secret wiring is commented PROPOSED), and the antique mutable `ghcr.io/epic28-ltd/raucle:v0.12.0` image default is replaced by the current release tag `v0.23.7` with a pin comment recording the release-tag -> source-commit provenance (`eafba15c3c0d896d284518011bebd3c8c3be5932`, per the PEP 740 PyPI attestation; the digest is captured-then-pinned with `docker buildx imagetools inspect` once the image is published - no image is published by the repo's pipelines at pin time). The APIM policy implements a real direct-route guard (inspects the inbound Host header against the `raucle-mcp-backend-host` named value, a Bicep-provisioned named value derived from `mcpBackendUrl`, and returns a named 403 `raucle_direct_route_denied` before routing; expression constructs per the APIM policy expression reference, with the operator's deploy-time verification annotated in the artefact), the XML now parses as well-formed (attribute quoting fixed), and the network rule becomes a numbered deployment-acceptance step: enforcement requires both the sidecar route and the MCP server's inbound network rules restricted to the sidecar's egress IP, the direct-call attempt must fail, and without the network rule the boundary is advisory. Config-pin tests live in `tests/test_sidecar_artefacts.py` (red-first), and the residual stands: even with the guard, network rules remain the primary no-bypass control.

- Receipt-boundary correction (PR #330 truth-up): unauthenticated pre-gate
  refusals do not mint receipts. A deny earned without a verifiable
  credential carries receipt_id null and writes nothing to the receipt
  store; the receipt trail starts at check_tool_call, and a deny receipt
  exists exactly when the caller presented a verifiable credential and the
  gate verdict itself was deny. This supersedes the 0.23.0 line above
  claiming auth failures return a receipted DENY: identity-stage failures
  (no credential, unknown key, unverifiable chain) stay pre-gate denials
  with no receipt behind them, the attributable distinction 0.23.2 already
  recorded; the receipt claims in scripts/demo_agents.py are scoped in this
  release to the gate-auth off mode where its demo calls are actually
  receipted.

## 0.23.7 (2026-11-23) - receipts v1.2 evidence lanes, X2 cross-org + transparency-log verification, X3 receipted operator key rotation

- The admin panel gains the Data Protection screen (lane D2) on the real advisory redaction engine: /api/demo/dlp-findings reads the signed x_dlp receipts minted after receipted gate decisions, rows carry digests, bounded pattern classes and span counts only (never content) and cite the gate receipt of the scanned call; scripts/demo_agents.py drives the scripted scenario end to end (tests/test_demo_session_plane.py).

- EPIC D lanes D14-D17: the enterprise console reframe of the demo session plane. New raucle/demo_session.py backs the admin panel's Session behaviour tab with read-only endpoints over live machinery (session rules read from the compiled policy configuration, per-session windows derived from the real receipt index, session findings re-verifiable offline against the chain), the scripted runaway-loop scenario runs as real gateway policy, and render-contract tests pin the tab's honest states (tests/test_admin_panel_render.py, tests/test_admin_panel_js.py).

- The 18 Nov incident's class defect closed at the structure (spec
  docs/spec/boot-streaming-v0.1.md, ADR 0007): the gateway binds first and
  streams its stores in bounded windows. The audit chain's resume is a
  bounded reverse tail read (W_replay, RAUCLE_BOOT_SCAN_WINDOW_MB, default
  64 MiB) with an incremental Merkle frontier sidecar replacing the
  whole-file leaf list (roots identical, O(log n) memory, disposable
  state per the strictest-verifier doctrine; the SSE replay tail reads a
  bounded window too, not the whole audit log per dashboard hit).
- Fail-closed where the old resume was silent: a torn or unparsable tail
  line raises the named refusal chain_tail_malformed (file, line number,
  byte offset, naming `raucle rotate-chain`), never the silent skip the
  whole-scan resume carried; the file is never modified. A chain break
  found by the background scan stops it by name (chain_refused with the
  break's coordinates) and the audit sink refuses to append past it.
- The receipt index builds in a background compactor after the bind, in
  the spec's four phases: migration inside the J2 one-transaction
  invariants (recovery inspection stays at open), a TTL-bounded tail
  window that lands session continuity (session-rule calls before it
  lands refuse by name, session_continuity_pending, never a silently
  cold window), a batched historical sweep with cursor-transactional
  resume (interrupted builds resume or restart, never crash-loop), then
  live-tail follow. Mid-build, index-backed query surfaces refuse by
  name with progress (receipt_index_building), never an empty 200 that
  looks complete; after the build, answers are byte-identical to a full
  rebuild_from_store.
- /health keeps its liveness contract and gains the machine-readable
  per-surface readiness block (gate, session continuity, chain scan
  with verified-through offset, receipt index with progress).
- Boot memory is bounded by configuration: the J1 preflight projects the
  window budget (baseline + scan window + index cache, spec 3.1) instead
  of the store's on-disk bytes, so the ceiling lowers as the windows
  shrink while the knob and refusal contracts stay; a runtime watchdog
  samples resident size during the scan and compactor and a breach is the
  shipped BootMemoryCeilingExceeded refusal, never an OOM kill.
- New knobs (honest defaults, pending the X5 bench re-derivation):
  RAUCLE_BOOT_SCAN_WINDOW_MB (64), RAUCLE_INDEX_CACHE_MB (64, SQLite
  page cache cap, mmap off), wired through the helm chart and
  deploy/prod.env.example with the J1 ceiling variable. The
  k1-boot-streaming bench (bench/run_bench.py --k1, scales ci, demo and
  incident) lands its legs in bench/results/k1-2026-11-20.json;
  docs/nfr/boot-streaming-v1.md records this machine's numbers and the
  incident-scale leg ships behind the flag for the X5 session that can
  afford it. The rotation runbook and the receipt-index ops note are
  extended, not contradicted.
- New tests pin the invariants (29 in tests/test_boot_stream.py, plus the
  re-derived preflight suite): bounded-boot flatness (peak allocations
  flat in store size, under the configured ceiling), bind-first against
  the real app factories, readiness honesty, the named torn-tail refusal,
  TTL session-continuity equivalence, the budget projection and the
  pre-binding refusal, the watchdog breach, resume-without-duplicates
  and the projection-equivalence guarantee.

- Admin-plane SSO (X3 slice 2): the OIDC sign-in receipt now binds the
  verified subject and the SHA-256 id-token digest (the digest, never token
  content), and the admin panel gains the SSO path: the login card offers
  provider sign-in when federation is enabled, hands the browser to the
  authorization URL and completes the callback into a receipted session.
- New spec docs/spec/x3-oidc-admin-v1.md: the v1 contract for the
  admin-plane OIDC surface, keeping the T-S3 note (per-request TOTP is not
  session security; raw-key authentication is unchanged) and recording the
  decided scale answer: a single-writer receipt sidecar owns chain append
  for replicas, so this slice ships per-process admin sessions with that
  residual named.
- Key-based admin authentication, per-request TOTP on that path and the
  off-by-default posture are unchanged; existing chains verify
  byte-identically because the new receipt fields are omit-when-empty.

- feat(analytics): `raucle analytics drift` - drift and scope-drift analytics over a receipt chain or segmented store, deterministic reads of receipt fields only, with five named evidence-shaped signals (definition-drift over the W2 tool_definition digests, authority-widening, authority-narrowing, deny-rate-delta over cited windows, revocation-cascade over prior use); every row cites its receipts, a signal that cannot cite them is not emitted, and bounded disclosure holds over the whole report (digests, identifiers and counts, never content)
- docs(nfr): drift-analytics-v1.md records the five signals, the honest states (uncitable receipts, rotations, thin windows, unused revocations emit nothing) and what the report does NOT prove

- `raucle operator rotate-keys` (X3 slice 3): receipted rotation of the operator plane's signing key, on the rotate-chain discipline. The successor publishes through the operator key registry's append discipline and the old key RETIRES (a registry state distinct from revocation: still resolvable, no longer holding the issuer name; the registry holds both keys across the transition), the old key file archives as `<key>.retired-<date>` (never deleted, digest printed), the key store updates, the boundary mints as a signed `x_key_rotation` receipt signed by the new key (the first receipt pinned to it), and a fresh boot is verified signing with it. All-or-nothing: the named refusals (no operator identity, no registry configured, registry file absent, nothing to rotate, same-day retirement already present, signed registry without its operator key, key not registered, key revoked) raise before any side effect.
- The transition semantics: receipts minted before the rotation keep verifying against the retired key, resolved by key id through the registry; new receipts carry the new key id; nothing re-signs history. Revoking the retired key stays a separate operator act and cuts old receipts fail-closed (retire then revoke composes; rotation never revokes).
- The boot split-brain guard: with `RAUCLE_OPERATOR_KEY_REGISTRY` set and the local signer backend, the boot refuses a key the registry does not vouch for (registry missing or failing integrity verification, key unregistered, revoked or retired) with a named restart-required `KeyStoreRegistryMismatch` - the unregistered and retired refusals name `raucle operator rotate-keys`, the missing, unverifiable and revoked refusals name their actual remedy; a re-run recovers the crash window (the registry ahead of the key store) by retiring the crashed attempt's public-only key visibly. KMS and TEE signers keep their own key lifecycle (named follow-up); an unset registry leaves the boot unchanged.
- Registry retirement is additive: `retired` fields are omit-when-empty, existing records serialise byte-identically, and retired keys stay resolvable for verification while the active holder of an issuer name changes.
- docs: operator runbook (docs/ops/key-rotation.md), spec doc and Product-surface row (docs/spec/operator-key-rotation-x3s3.md), the `operator` row in the CLI contract (docs/nfr/cli-contract.md), and docs/security/key-operations.md now names the receipted path for gateway signing-key rotation.

- X3 slice 4: the single-writer receipt sidecar (`raucle sidecar`, a
  stdlib-only service in the same repo) owns the receipt chain append and
  the index projection. Gateway replicas submit their minted envelopes to
  it over local HTTP with a shared-secret handshake
  (RAUCLE_RECEIPT_SIDECAR_URL/SECRET/TIMEOUT/MAX_QUEUE), so several
  gateways can serve traffic while one process writes and the SQLite WAL
  never has two writers. The mint stays in the gateway; the sidecar
  assigns chain order.
- Receipt loss is named, never silent: submit goes through a bounded
  queue, overflow is a named `receipt_sink_overflow` refusal, and the
  gateway receipts the loss as a signed `x_sidecar` advisory (the
  harness-finding pattern, bounded disclosure: refused hash, reason,
  time). The enforcement decision completed before submission and
  stands; this is fail-open for receipt persistence only. A gateway
  configured with a sidecar URL plus a local write projection is a named
  two-writer boot refusal.
- Restart resume is unchanged: the store reopens the last unsealed
  segment, the J2 interrupted-migration recovery still runs in the index
  constructor, and an index left behind by a crash is rebuilt from the
  chain of record. Chains written through the sidecar are byte-identical
  to single-writer ones and verify through the unchanged offline
  verifier.
- The Helm chart gains the sidecar Deployment and Service (replicas
  pinned to 1 with a Recreate strategy, owns the data volume; the
  gateways mount it read-only and their single-replica constraint lifts),
  with the honest notes in the chart README and
  docs/deployment-topologies.md. New spec first:
  docs/spec/x3-sidecar-v0.1.md.

- feat(worm): H3 WORM receipt archive implemented per the 30 October design (`raucle/worm.py`): an append-only, hash-chained archive writer over a store that models S3 Object Lock compliance-mode semantics in software (a key is written once, byte-identical retries are idempotent, retention extends but never shortens, deletion requires both expiry and a cleared legal hold, reads pin content-addressed version IDs); the design's four write moments (chain segment close, evidence-pack publication, disposal, anchoring) land under the design's key families, each write carrying artifact type, chain slug, span, SHA-256, retention category and the ledger position it was cut from; the non-WORM write log is a hash chain in a sidecar store, rebuildable from the bucket alone, and verification recomputes every object digest from the bytes on disk rather than trusting recorded hashes
- feat(worm): disposal and retention binding: `archive_destruction` ingests the signed `x_destruction` receipt, the escrow reference (digest, record count, span digest) and the re-anchored surviving chain, with the destruction receipt floored at the surviving chain's horizon; the chain's archive horizon (the latest `x_gate.retention_until`, G1's value) becomes the WORM retention, floored at the operator's configured minimum, with the 24-hour bucket default locking objects that arrive with no schedule; legal holds are operator-plane events whose decisions are themselves archived; the archive writer exposes no delete surface at all
- docs(designs): the worm-archive design status flipped to implemented, with the local backend named as the in-software model of the compliance-mode semantics and the S3 Object Lock backend as the deployment-side implementation behind the same operations

- Changelog entries convention (L5): builder lanes stop editing CHANGELOG.md directly and write one bullet-only entry file per branch (`docs/changelog-entries/<branch>.md`) instead; `tools/assemble_changelog.py` inserts the entry bullets under `## Unreleased` in file order at merge time, deletes the entry files, and exits non-zero if a bullet would duplicate an existing changelog line. CI enforces the lane rule: a PR that adds changelog entry files must not add lines to CHANGELOG.md (removals stay allowed). The current Unreleased content migrated verbatim to `docs/changelog-entries/migration-journal.md` as the demonstration.

- Lease-use verification (C1 remainder, spec
  docs/spec/provenance/v1.2/lease-extension.md): a lease-use receipt now
  verifies only while the lease is valid and its use is scope-matched. The
  offline verifier rejects a redemption whose lease was revoked at an
  earlier line (`lease_revoked`), on the same temporal doctrine as the A3
  cascade: an `x_lease` `revoked` event and an `x_revocation` block citing
  the lease id are both revocation evidence, and a redemption before the
  revocation line stays valid evidence.
- The lease redemption refusals are named in the verifier errors:
  `pairing_absent` (no grant from an earlier line in the chain),
  `lease_expired` (the redemption's iat past the grant's TTL window),
  `scope_exceeded` (a redemption wider than its grant, the narrowing
  invariant) and `lease_revoked`. Each failure names its class, never a
  generic invalid.
- The shared forbidden-field sweep now covers the `x_lease` block: lease
  receipts carry handles, the grant pairing, scope names and digests only,
  never content; a content-like field anywhere inside the block fails with
  the sweep's named error.
- The verification report body is unchanged: the named errors ride the
  existing `errors` list and no new report keys are added, so the v1.0
  byte shape is preserved and the digest pins and fixture packs stand as
  they were (pinned by test).

- Session continuity without fabrication: the x_gate block carries an optional session_id taken verbatim from the caller's declared session, and the receipt index moves to schema v3 with active_session_ids and session_receipts query paths; only sessions callers themselves declared are represented, so the index never invents continuity (tests/test_gate_session_id.py, red-first).

- Deterministic session behavioural rules join the gate policy family (EPIC Q1): rules evaluate only over calls that declare a session_id, so callers without one are untouched by their deployment's policy file. The shipped rule kind runaway_tool_loop denies at the gate once a tool hits its threshold inside its window, with a signed deny receipt plus a session-monitor finding that cites the exact call it cut off; policies/examples/session-behavioural.yaml ships the worked example as real gateway policy.

- New public specification docs/spec/advisor-classifier-v1.md (EPIC Q1a design slice): the advisory LLM detector designed to run beside the deterministic gate, with the explicit guard confession and promotion-path hook stating that advisory classification informs policy authoring and review while receipted verdicts stay deterministic; docs-only lane, no gate code changes.

- Per-participant policy scoping (EPIC Q3): a participant matcher scopes policy rules to the receipt planes they actually govern, tool_call and tool_response_taint, with the session-behavioural-rules spec extended alongside (tests/test_participant_scoping.py).

- Content-plane DLP receipts as a public v1.2 spec (docs/spec/provenance/v1.2/content-dlp.md) with the schema and gateway mint path implemented: x_dlp carries digests, bounded pattern classes and span counts only, never content, and every finding cites the gate receipt of the scanned call (tests/test_dlp_receipts.py).

- Advisory redaction middleware (EPIC Q7c): raucle/redaction.py and the middleware advisory layer mint receipted findings for scan-and-redact, advisory by design, a fail-open evidence lane beside the deterministic gate and never enforcement, with the v1 spec (docs/spec/advisory-middleware-v1.md) and a getting-started track (tests/test_advisory_middleware.py).

- feat(x2): cross-org receipt verification through the Trust Registry (X2 slice 3): `raucle.cross_org.verify_receipt_cross_org` resolves another org's signing key from the registry artifact alone (operator-signed chain, pinned anchor, freshness pins), verifies the receipt with the same ProvenanceVerifier an auditor runs, holds the registry-published capability statement as the scope leg (unstated by name when none is published), and pairs the transparency log's inclusion proof as the registration leg against a separately pinned log operator key; a third party verifies org A's receipt with no prior key exchange and no trust in either org's operator.
- feat(x2): the shipped offline verifier page (`assets/verifier/x2-verifier.html`) gains a cross-org mode: receipt plus registry artifact plus pinned anchor, optional freshness pins, optional inclusion proof; the four legs (registry, receipt, scope, registration) render with named reasons, the no-network discipline stays test-pinned, and the committed fixture set (`assets/verifier/fixtures/cross-org/`, generator `scripts/x2_cross_org_fixtures.py`) exercises clean and doctored cases in the node harness plus a UI render probe.
- security: Trust Registry `from_jsonl` and `from_url` now parse entries with the duplicate-key rejecter the file path already had, so a crafted registry artifact with duplicate JSON keys cannot smuggle a key_id past integrity checks on the text and network loading paths.


## 0.23.6 (2026-11-12) - demo panels: read-only operator surfaces for the demo visitor

### Added - demo panels: read-only operator surfaces for the demo visitor

- The Users, SIEM and Config tabs now render in demo mode as read-only
  views backed by three new gated endpoints (`/api/demo/users`,
  `/api/demo/siem`, `/api/demo/config`) with the same 404-off-demo
  contract as the rest of the demo plane. The simulated operator roster
  carries names, roles and MFA state only; the SIEM view shows the
  deployment's real forwarding configuration beside a simulated
  forwarder example (endpoint shape, the gate-decision payload shape the
  real forwarder emits, per-hour event counts; nothing is sent
  anywhere); the config view renders the live gateway profile as
  read-only text with secret fields excluded. The authenticated edit
  forms are untouched outside demo mode.
- The MCP Scanner tab is fixed and pre-armed: the `mcpManifests` /
  `mcpSelected` declarations shipped commented out (glued onto a section
  comment), so every panel load threw on the undeclared names and the
  tab landed on its "demo not configured" fallback with nothing
  selected. The declarations now live on their own line, and demo entry
  auto-selects the featured simulated manifest and runs the real scanner
  so findings render on arrival.
- The Raucle Agent Assurance stack gains a Coverage item (after Key
  model): a single read-only demo card backed by `/api/demo/coverage`
  computing the receipted-share metric contract over the deployment's
  OWN gate receipt stream — real demo receipts, which are the correlated
  ground truth of a single-demo-org. The response states the bucket
  contract exactly (`receipted` counted via bound `x_gate.trace_id`;
  `out_of_gate` and `pending` are disclosed zeros — not computed at a
  gate-side vantage and never folded into the number), a receipt minted
  without a trace id never inflates the action number and stays
  disclosed under its explicit label, per-tool/per-agent rollups tie to
  the headline with the partition invariant asserted, and the same plane
  that is empty answers unavailable, never zero. Receipts are minted by
  simulated demo traffic, so the card is labelled "Simulated demo data";
  bounded disclosure applies (aggregate counts and identifiers only —
  no denial reasons, no receipt detail). The companion flags (bypass
  candidates, shadow agents, uninstrumented tools) ship as documented
  semantics with their vantage requirement, not as fabricated counts:
  cross-vantage reconciliation is the assurance service's
  `GET /coverage/{org}` — the OSS coverage engine lives in the
  raucle-agent-assurance correlation service, so this surface presents
  the contract honestly instead of pretending the gateway can serve it.

### Added - H3 slice 1: TEE / hardware-attested signer path

- `raucle/tee.py`: a TEE signer adapter (`TEESigner`) behind the existing
  `raucle.kms.Signer` protocol. Signing is delegated across a named enclave
  boundary callable (`sign_fn`, the same shape as `KMSSigner`), and an
  attestation provider supplies the attestation document binding the
  receipt-signing key to a measured enclave image. A clearly labelled mock
  boundary (`SimulatedNitroEnclave`) stands in for real hardware in CI and
  development; `create_signer(backend="tee")` fails closed unless the mock
  boundary is explicitly acknowledged (`RAUCLE_TEE_SIMULATED=1`) or an
  enclave signer is explicitly wired, so a simulated attestation is never
  applied silently. No new dependencies; real attestation providers
  (AWS Nitro NSM/KMRA, Azure attestation, vTPM/SEV contracts) are named
  follow-up slices.
- Receipt signer identity carries the attestation statement reference:
  the optional `CapabilityStatement.attestation` field (platform,
  measurement, attestation_ref, simulated), covered by the statement's
  Ed25519 signature and omitted from the canonical body when unset so
  existing statements verify byte-for-byte (spec §5.1 amendment, Draft 3).
- Gateway boot honours `RAUCLE_SIGNER=tee` (fail-closed without the
  explicit mock-boundary flag), and the demo key-model view
  (`build_demo_key_model`) serialises the receipt-signing identity's
  attestation binding and an honest export-posture sentence for the
  backend. Docs: `docs/security/hardware-attested-signing.md`.

### Added - X1: OpenAPI as the named secondary schema source

- `ToolSchemaRegistry.register_from_openapi_fragment` (shipped with the
  X1 gate slice) now has its full contract pinned by conformance vectors
  04-07 and tests: undeclared-field rules fail at load against
  OpenAPI-derived schemas (named tool + field), and registering the same
  tool from the MCP primary and the OpenAPI secondary with differing
  schemas is a load-time conflict, never silently last-write-wins.
- A tool with NEITHER an MCP schema nor an OpenAPI fragment keeps the
  documented legacy name-based path — a named, inspectable condition
  (`has_schema == False`; any schema-bind is a named load error), not a
  silent skip (`schema_enforcement_v1_07_neither_source_named_legacy.json`).

### Added - X5: hot-path bench harness + async receipt sink

- `bench/run_bench.py` measures the real production paths —
  gate allow/deny, signed-receipt emit, receipt-store append, index
  append, SIEM forward — and publishes p50/p99 + ceiling throughput.
  Methodology and machine-honest recorded numbers:
  `docs/nfr/x5-performance-bench.md`; results JSON committed per run
  (`bench/results/`).
- `raucle/async_receipt_sink.AsyncReceiptSink`: bounded single-consumer
  queue in front of a receipt writer. Overflow is a NAMED failure event,
  never silent: queue full raises `ReceiptSinkOverflow`, records a
  `receipt_sink_overflow` event (bounded list + ERROR log naming the
  sink, queue bound and lost receipt hash) and counts it. `close()`
  drains and reports written/write_errors/lost — an unbounded queue is
  refused at construction.

### Added - X3 slice 1: optional OIDC/SSO federation for the admin plane

- Optional OpenID Connect identity-provider federation for the ADMIN plane,
  OFF by default. Enabling (`RAUCLE_OIDC_ENABLED` + issuer/client id) starts
  the RFC 6749 authorization-code flow with RFC 7636 PKCE (S256); discovery
  + JWKS are fetched at startup and FAIL CLOSED on an unreachable or
  mismatching issuer. The client secret never enters a config file (env or
  0600 secret file; an inline `client_secret` refuses with a named
  `OIDC_CONFIG_ERROR`). Verified subjects map onto the existing RED-032
  admin user records; an unknown subject is a named `MAPPING_ERROR` — no
  auto-provisioning (SCIM-lite is a named follow-up).
- Receipted admin session tokens (T-S3): `POST /api/session/login` verifies
  the key (and TOTP when MFA is on) once and exchanges it for a short-lived
  `rst_` bearer session held by digest only; OIDC logins get the SAME
  session semantics. Session open and close are signed provenance receipts
  (`x_admin_session`), verifiable by the standard chain verifier. Raw-key
  authentication is unchanged. Follow-ups: SCIM-lite provisioning, provider
  key rotation, receipt sidecar.

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
