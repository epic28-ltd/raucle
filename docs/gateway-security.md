# Raucle Gateway - Production Security Guide

## TLS Termination

The gateway runs on plain HTTP. Production deployments MUST use a reverse
proxy with TLS termination. The included `docker-compose.gateway.yml`
uses Caddy with automatic Let's Encrypt certificates.

```bash
# Set your domain and admin key
export RAUCLE_DOMAIN=raucle.example.com
export RAUCLE_ADMIN_KEY=your-secure-key

# Deploy with TLS
docker compose -f docker-compose.gateway.yml up -d
```

The gateway container is NOT exposed to the host directly. All traffic
goes through Caddy on port 443. The internal Docker network
(`raucle-internal`) isolates the gateway from direct external access.

## WAF (Web Application Firewall)

For additional protection on the admin panel, deploy ModSecurity with
the OWASP Core Rule Set in front of Caddy:

```nginx
# nginx + ModSecurity alternative to Caddy
modsecurity on;
modsecurity_rules_file /etc/modsecurity/owasp-crs.conf;

location / {
    proxy_pass http://raucle-gateway:8081;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## Rate Limiting

## Rate limiting

The gateway includes built-in rate limiting via `slowapi`:

| Limit | Default | Override |
|---|---|---|
| `/gate` (per route) | 200/minute | `RAUCLE_GATE_ROUTE_LIMIT` |
| All other routes | 1000/minute | `RAUCLE_GATE_RATE_LIMIT` |

The limit key is the socket peer address, so behind a TLS-terminating proxy
every caller shares one bucket. Set `RAUCLE_TRUST_PROXY=1` when, and only
when, the gateway sits behind a proxy that sets `X-Forwarded-For`; the
left-most entry is then used as the client identity. This is the same
convention `raucle/server.py` uses for its token bucket.

`slowapi` ships in the `server` extra. If it is not installed the gateway logs
a warning at boot and runs without limiting; it does not pretend to have a
limit it does not have. Caddy provides a separate per-IP limit at the proxy
layer (100 requests/minute in the reference Caddyfile).

## API Key Management

- API keys are required for all admin panel endpoints
- Keys are stored as SHA-256 digests: `users.jsonl` never contains a usable
  key. A file written by an older version (plaintext `api_key`) is migrated
  and rewritten on load
- Keys are looked up by digest, so no plaintext comparison happens at all;
  the digest of a presented key is the dictionary key
- Keys can have expiry timestamps for rotation; expired keys are refused at
  authentication
- `POST /api/users` mints a 256-bit key when none is supplied and returns it
  exactly once. A caller-supplied key must be at least 24 characters
- The bootstrap admin comes from `RAUCLE_ADMIN_KEY_FILE` (the secret-file
  pattern) or `RAUCLE_ADMIN_KEY`, and is created **only when the store holds
  no admin**. Removing an admin in the panel, or rotating the environment
  key, is therefore not undone by the next restart
- Users are addressed by a stable handle (`user_id`, derived from the key
  digest) on the admin routes, so the panel never needs to hold key material.
  The full key remains accepted in the same path for scripted use
- Admin users persist to disk (default `<data-dir>/users.jsonl`, override
  with `RAUCLE_USERS_FILE`). The MFA *enabled* flag is persisted with the
  secret, so MFA survives a restart. TOTP codes may be reused within their
  own window (the panel polls) but a code from an earlier window is refused
  as a replay
- Known residual: `totp_secret` is stored in plaintext beside the digest.
  Protecting the secret needs a master-key source; the per-request TOTP
  residual IS now addressed: the TOTP code is verified once at session open
  (`POST /api/session/login`) and exchanged for a short-lived receipted
  bearer session (below) — see the U2 residual register entry R13
  (`docs/threat-model/v1.md`) for the remaining secret-at-rest half
- Demo-mode synthetic users are in-memory only by design

## Admin session tokens (T-S3)

The per-request bearer model (key + TOTP on every call) is augmented with a
short-lived receipted session exchange:

- `POST /api/session/login` verifies the API key (and the TOTP code for MFA
  users) ONCE and returns a 256-bit bearer session token (``rst_`` prefix).
  Only its SHA-256 digest is stored server-side — the session table is not a
  credential file, same discipline as RED-032 admin keys.
- Sessions expire (default 1h; `RAUCLE_ADMIN_SESSION_TTL`, floored at 60s)
  and expiry is enforced on every resolve. Opening beyond
  `RAUCLE_ADMIN_SESSIONS_MAX` refuses fail-closed rather than silently
  evicting a live session.
- Opening AND closing a session are signed evidence: provenance receipts
  with an `x_admin_session` extension bind the session's hash-derived
  public handle (never the token), the user_id, the auth method (`key` or
  `oidc`) and the expiry. Logout is a receipted lifecycle event, never a
  silent delete.
- Removing a user kills their live sessions immediately (a session dies
  with the identity it authenticated).
- Raw key authentication (with per-request TOTP when MFA is on) still works
  unchanged on every admin route for scripted use.

## OIDC identity-provider federation (X3 slice 1, optional)

The admin plane accepts a second login path against an operator-configured
OpenID Connect provider. **Off by default** — enabling is an operator choice:

- Configure `RAUCLE_OIDC_ENABLED=1` plus `RAUCLE_OIDC_ISSUER`,
  `RAUCLE_OIDC_CLIENT_ID` and `RAUCLE_OIDC_REDIRECT_URI` (or the equivalent
  `oidc:` YAML section). The provider is named in a boot banner when active.
- The client secret NEVER goes in a config file: set
  `RAUCLE_OIDC_CLIENT_SECRET` (env) or `RAUCLE_OIDC_CLIENT_SECRET_FILE`
  (0600 secret-file pattern, same as the bootstrap admin key). A config
  document carrying an inline `client_secret` refuses to load with a named
  `OIDC_CONFIG_ERROR`.
- At startup (only when enabled) the gateway fetches the provider's
  `.well-known/openid-configuration` discovery document and JWKS. The fetch
  is FAIL-CLOSED: an unreachable issuer, a document/issuer mismatch, a
  non-https endpoint or an unusable JWKS refuses the admin app from booting.
- Login is the RFC 6749 authorization-code flow with RFC 7636 PKCE (S256,
  single-use state/nonce/verifier pending logins, 5-minute TTL). The
  returned `id_token` is verified (RS256 against the provider JWKS; strict
  `iss`/`aud`/`exp`/`nbf`/`nonce`) before anything else happens.
- Identity mapping reuses the RED-032 user records: the verified subject
  maps to an existing panel user (bound `oidc_sub`, else first match on
  `preferred_username`/`email`/`name`, with the subject bound and persisted
  on first login). An unknown subject is a NAMED `MAPPING_ERROR` — there is
  no auto-provisioning in this slice (SCIM-lite provisioning is a named
  follow-up).
- A mapped user gets the SAME session as a key login (identical receipts,
  expiry and closure semantics; `auth_method` records which path opened it).
  Key rotation, receipt sidecar and provisioning are named follow-ups.


## Gate authentication (agent callers)

`RAUCLE_GATE_AUTH` controls how the `/gate` endpoint identifies agents.
Pick per deployment posture:

> **Decision record (8 November 2026):** keeping `off` as the shipped
> default is an explicit owner decision, not an oversight. See residual
> R14 in `docs/threat-model/v1.md`. Shipped mitigations: the boot banner
> warning below, and `GET/PUT /api/config` (`gate_auth`), which lets an
> operator switch to `apikey` or `token` without a redeploy.

| Mode | Mechanism | Use when |
|---|---|---|
| `off` (default) | Declared `agent_id` is trusted | Trusted internal networks only. The boot log warns. Kept for backwards compatibility and the demo |
| `apikey` | Per-agent key in `X-Api-Key`, stored hashed, revocable | Quick wins; agents that cannot hold tokens yet |
| `token` | Capability token in `X-Capability-Token`, verified against the trust registry (signature, issuer, TTL, tool/args binding) | The deployment-grade answer; the same construction the Lean soundness theorems cover |

Fail-closed details:

- `apikey`: issue with `raucle agents issue-key --agent-id agent:pay`, revoke
  with `revoke-key`; verification is a constant-time hash lookup; revoked
  keys fail immediately; the plaintext key is shown once and never stored.
- `token`: an authenticated identity that contradicts a declared
  `agent_id` is denied (`agent_id/token mismatch`); expired or tampered
  tokens are denied; the issuer list is the trust registry's active keys,
  rebuilt per call, so a registry revocation propagates to gate auth
  within one request.
- Authentication failures return a DENY decision with the reason
  (receipted), not a bare 401: an unauthenticated decision attempt is
  itself evidence.

In-process framework integrations (LangChain, Agent Framework, CrewAI) are
observability and correctness controls, not a security boundary: a
co-resident control cannot resist a compromised host process. The hard
boundary is the out-of-process gate plus credential isolation: agents hold
tokens, never raw tool secrets; tool execution verifies the gate's
signature before running anything.

### Operator registry caching

The revocation list, trace quarantine and lease suspension registries,
trust registry and delegation ledger are served through a read-through
cache keyed on `(mtime_ns, size)` (`_FileCache`, `raucle/gateway.py`), so
gate calls do not re-read unbounded append-only files. Residual: an edit
that changes a file's contents without changing its size or mtime — an
in-place same-byte-length rewrite — can be served stale. This is recorded
as residual R16 in `docs/threat-model/v1.md` and shares its fix with the
unsigned-policy file residual (R5/M5 there): work them together, not
twice.

## Signed gate receipts

Every `/gate` decision, allow, deny or escalate, is emitted as a signed
provenance receipt (operation `guardrail_scan` with an `x_gate` extension
binding decision, reason, tool, agent, policy and trace id), written as a
minimal `{receipt_hash, jws}` envelope. The response's `receipt_id` is the
receipt's content hash: hand it to `raucle provenance verify` or the MCP
`verify_receipt` tool and it verifies offline like any other raucle receipt.

- Emission is on by default; `RAUCLE_EMIT_RECEIPTS=0` restores pre-PR-B
  behaviour (no receipts, `receipt_id: null`) for compatibility.
- `X-Trace-Id` threads a caller-supplied trace through every receipt
  (`x_gate.trace_id`); absent header generates one and the response echoes
  it so callers can correlate.
- Fail-closed accountability: if a receipt cannot be written, the decision
  is downgraded to deny. An action without its receipt is unauthorised.
- Receipts are signed by the persistent gateway identity (`agent:gate`),
  so decisions verify across restarts.

### Receipt query, ancestry and egress

With the segmented store on, a SQLite index (WAL mode) projects every
receipt for query. The contract is deliberately one-sided: the index is a
query cache, never a trust decision. It can be dropped and rebuilt from
the segments at any time; verification always reads the chain.

- `GET /api/receipts` with filters: `agent_id`, `tool`, `decision`,
  `trace_id`, `since`/`until` (epoch seconds, inclusive), `limit` and
  keyset `cursor` (composite `iat:receipt_hash`, survives burst ties).
- `GET /api/receipts/{hash}/ancestors` walks the parents DAG: nodes and
  edges, cycle-safe, depth-capped (default 50). The incident question -
  everything upstream of this decision - answered from the panel.
- `GET /api/receipts/export?since=&until=` streams JSONL for the caller's
  own data platform; the chain of record stays yours, the copy is theirs.
  The audit pack remains the regulator path.
- Admin panel Receipts tab: filter, paginate, and per-receipt ancestry
  drill-down.

`RAUCLE_RECEIPT_INDEX_PATH` overrides the index location (default:
`<store-dir>/index.sqlite`).

### Segmented receipt storage

Set `RAUCLE_RECEIPT_STORE_DIR` and receipts flow into size-based segments
(`seg-NNNNNN.jsonl`, `RAUCLE_RECEIPT_SEGMENT_MAX_BYTES`, default 64 MiB).
On rollover the segment is sealed read-only with a `.meta` sidecar (receipt
count, last hash, sealed_at) and the next segment begins. A sealed segment
is a pure receipt chain: it verifies with `ProvenanceVerifier` and builds
into an audit pack byte-for-byte, no special casing. Retention becomes a
file operation: archive or delete segments older than your policy, export
any segment as the regulator bundle. Query helpers (`recent`,
`find_by_hash`) read newest-first across segments in bounded memory; they
are conveniences, never a trust decision - verification always reads the
chain.

## Gateway signing key persistence

Local-signer deployments persist the Ed25519 key to
`RAUCLE_SIGNER_KEY_PATH` (default `<data-dir>/gateway-signing-key.pem`,
0600). First boot generates it; later boots load it, so receipts and tokens
verify across restarts. A corrupt key file fails closed with a clear error:
regenerating silently would orphan every receipt signed by the previous
key. If the key is genuinely lost, archive the old receipt chain, remove
the file, and treat the new key as a new identity.

## Health Check Authentication

Set `RAUCLE_HEALTH_KEY` to require authentication on `/health` endpoints.
This prevents unauthenticated health probes from revealing service status.
The Docker healthcheck uses the internal container network, so it works
even with health check auth enabled.

## Docker Security

- Container runs as non-root `raucle` user
- No default admin key in the image (must be injected at runtime)
- Internal Docker network isolates the gateway
- Data volume (`raucle-data`) persists receipts and audit logs
- Policy files mounted read-only

## Secrets Management

For production, use Docker secrets or a secrets manager instead of
environment variables for sensitive values:

```yaml
# docker-compose.secrets.yml
services:
  raucle-gateway:
    secrets:
      - admin_key
      - kms_key
secrets:
  admin_key:
    file: ./secrets/admin_key.txt
  kms_key:
    file: ./secrets/kms_key.txt
```

Then in the gateway:
```bash
RAUCLE_ADMIN_KEY_FILE=/run/secrets/admin_key
```

## SIEM Integration

Gate decisions are forwarded to SIEM in real-time. Supported backends:
- Splunk HEC
- Elasticsearch
- Azure Sentinel (Log Analytics)

Failed SIEM forwards are buffered in memory and retried.

Known residual: SIEM target validation (`siem_target_allowed`,
`raucle/gateway.py`) rejects non-HTTP(S) destinations and literal loopback,
link-local and private addresses, but it does not resolve DNS — a hostname
that resolves to a private address is not detected at validation time.
Protection today is the host's egress posture; `RAUCLE_SIEM_ALLOW_PRIVATE=1`
is the deliberate opt-in for internal collectors.
Recorded in the U2 residual register as R15 (`docs/threat-model/v1.md`).

## Authority attribution endpoints (PR-E)

The admin panel exposes the human leg of the authority chain. Every
endpoint either records a human decision as a signed receipt or serves
verifiable evidence; none of them bypass the receipt chain.

### Human approval workflow

When a policy rule carries `require_approval_when`, the gate escalates
the call and creates an approval request:

1. `POST /gate` returns `escalate` with an `approval_request_id`; a
   receipt with the `x_approval` extension (request_id, tool, agent,
   args hash, expiry) is written to the chain.
2. An operator lists pending requests with `GET /api/approvals` and
   decides with `POST /api/approvals/{request_id}/decision`
   (`{"approved": true}`). The decision is receipted with the named
   approver - the human grant is evidence, not a helpdesk ticket.
3. The agent re-submits the identical call with the `X-Approval-Id`
   header. The approval binds to the exact tool, agent and canonical
   arguments hash; it is consumed by one action and expires
   (`RAUCLE_APPROVAL_TTL`, default 300s). The action receipt cites the
   approval, so the ancestry chain reads request → decision → action.

Approvals live in memory; the receipts are the durable record. A restart
drops the pending list (in-flight escalations are re-requested) but no
evidence is lost.

### Policy change ledger

Set `RAUCLE_POLICY_LEDGER` to a file path. Every policy write through
the admin panel appends a hash-chained entry: sequence, timestamp,
actor, action, content sha256 and the previous entry's hash.
`GET /api/policy-ledger` returns the entries plus an integrity verdict
computed by walking the chain. Gate receipts already bind the ruleset
hash in force at decision time; the ledger answers the question above
them: who changed the rules, and when.

### Authority envelope

`GET /api/agents/{agent_id}/authority` returns a signed statement of
what the agent could use: its policies (tool, constraints, TTL) and
credential status. The JWS (`raucle/authority-envelope/v1`) is signed
by the gate identity and verifies offline - hand it to an auditor or a
partner organisation as a self-contained answer to "what authority did
this agent hold?".

### Kill switch

`POST /api/agents/{agent_id}/suspend` (admin role only) revokes the
agent's gateway credential and writes an `x_stop` receipt recording
who stopped the agent, when, and why. Revocation propagates to
enforcement on the next call; the receipt means the containment
itself is attributable evidence in the incident review.

## Authority attribution endpoints (PR-E)

The admin panel exposes the human leg of the authority chain. Every
endpoint either records a human decision as a signed receipt or serves
verifiable evidence; none of them bypass the receipt chain.

### Human approval workflow

When a policy rule carries `require_approval_when`, the gate escalates
the call and creates an approval request:

1. `POST /gate` returns `escalate` with an `approval_request_id`; a
   receipt with the `x_approval` extension (request_id, tool, agent,
   args hash, expiry) is written to the chain.
2. An operator lists pending requests with `GET /api/approvals` and
   decides with `POST /api/approvals/{request_id}/decision`
   (`{"approved": true}`). The decision is receipted with the named
   approver - the human grant is evidence, not a helpdesk ticket.
3. The agent re-submits the identical call with the `X-Approval-Id`
   header. The approval binds to the exact tool, agent and canonical
   arguments hash; it is consumed by one action and expires
   (`RAUCLE_APPROVAL_TTL`, default 300s). The action receipt cites the
   approval, so the ancestry chain reads request → decision → action.

Approvals live in memory; the receipts are the durable record. A restart
drops the pending list (in-flight escalations are re-requested) but no
evidence is lost.

### Policy change ledger

Set `RAUCLE_POLICY_LEDGER` to a file path. Every policy write through
the admin panel appends a hash-chained entry: sequence, timestamp,
actor, action, content sha256 and the previous entry's hash.
`GET /api/policy-ledger` returns the entries plus an integrity verdict
computed by walking the chain. Gate receipts already bind the ruleset
hash in force at decision time; the ledger answers the question above
them: who changed the rules, and when.

### Authority envelope

`GET /api/agents/{agent_id}/authority` returns a signed statement of
what the agent could use: its policies (tool, constraints, TTL) and
credential status. The JWS (`raucle/authority-envelope/v1`) is signed
by the gate identity and verifies offline - hand it to an auditor or a
partner organisation as a self-contained answer to "what authority did
this agent hold?".

### Kill switch

`POST /api/agents/{agent_id}/suspend` (admin role only) revokes the
agent's gateway credential and writes an `x_stop` receipt recording
who stopped the agent, when, and why. Revocation propagates to
enforcement on the next call; the receipt means the containment
itself is attributable evidence in the incident review.

## Trust boundary: outbound URL fetching

Raucle makes outbound HTTP calls from a small, knowable surface. The
gateway itself does no arbitrary outbound fetching: caller-controlled
URL fetching (`file:`, `ftp:`, arbitrary hosts) is not a gateway
feature, and the outbound call sites that exist are guarded
(`raucle/url_guard.py`, T-S4):

* `raucle.timestamp.submit_timestamp_request` - RFC 3161 timestamp
  authority URLs (operator-configured TSA).
* `raucle.transparency.SCITTAnchorClient` - the SCITT transparency
  service base URL (operator-configured).

The shared guard, `raucle.url_guard.validate_url`, runs immediately
before every `urlopen` at these call sites and enforces:

1. scheme allow-list: only `http://` and `https://`;
2. host deny-list: loopback, link-local (including the cloud metadata
   address), RFC1918 private, reserved, multicast and unspecified
   addresses, plus `localhost` and `.local`/`.internal`/`.localdomain`
   names;
3. an explicit escape hatch: `RAUCLE_ALLOW_PRIVATE_URLS` opts in to
   private targets deliberately (loopback test doubles, on-prem TSA or
   transparency service). There is no silent fallback: a rejected URL
   raises with the opt-in named in the message, so an SSRF attempt and
   a misconfiguration look different in the logs.

Documented limit: the guard classifies the URL syntactically. A public
DNS name that resolves to a private address is not caught here
(resolution-time trust); `raucle/feed.py` pins resolved addresses for
its own fetcher, and new outbound call sites with DNS-resolution
requirements should follow that pattern. The gateway's SIEM forwarder
enforces an equivalent check (`GatewayConfig` SIEM URL validation).

The streamed receipt export (`GET /api/receipts/export`, C4 egress)
records a disconnect fault when a consumer closes the stream early
(`StreamedExportSink.write` counts and the fault lands in the log as
`stream_disconnect`), so partial copies of the chain are attributable
events rather than silent successes.
