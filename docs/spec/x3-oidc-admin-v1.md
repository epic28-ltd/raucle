# X3 v1: OIDC/SSO for the Admin Plane (Spec)

Status: Accepted 2026-11-21 (lane L10, X3 slice 2). Slice 1 (identity
federation + receipted admin sessions) shipped as
[admin-identity-federation-x3s1.md](admin-identity-federation-x3s1.md); this
document is the v1 spec for the complete admin-plane SSO surface and adds the
slice 2 behaviour on top of it.

## Purpose

Single sign-on for the ADMIN plane only: the gateway admin app
(`gateway_app`) and its panel sign-in federate to the operator's OpenID
Connect provider. The agent-facing gate, its credential modes and its
receipts are untouched. When OIDC is not configured the admin plane behaves
exactly as before: the admin API key (with per-request TOTP when MFA is on)
remains the only login path, and the OIDC routes answer 503.

## Base shipped by slice 1 (normative by reference)

Discovery, exchange and verification contracts are the slice 1 ones:

1. Startup fail-closed: `{issuer}/.well-known/openid-configuration` is
   fetched at startup; the document issuer must match exactly (RFC 8414
   3.3); every endpoint must be https; the JWKS must carry a usable RSA
   signing key. Any failure refuses the admin app, and therefore the boot.
2. Authorization-code flow with PKCE S256; single-use state and nonce
   parked for at most 5 minutes; the client secret comes from
   `RAUCLE_OIDC_CLIENT_SECRET` or `RAUCLE_OIDC_CLIENT_SECRET_FILE` (0600
   file) only, never from a config document (named refusal otherwise).
3. Strict id_token verification: RS256 via the JWKS `kid`, exact `iss`,
   `aud` containing the client id, `exp`/`nbf` windows, and the `nonce` of
   the login request. Any doubt is a named `OIDC_EXCHANGE_ERROR` and no
   session opens.
4. Subject mapping onto existing RED-032 user records: a bound `oidc_sub`
   first, then name-claim matches with the binding persisted on first
   match; an unknown subject is a named `MAPPING_ERROR` (no
   auto-provisioning).
5. Sessions: `rst_` bearer tokens stored by SHA-256 digest only, TTL and
   cap enforced fail-closed, and open plus close are signed
   `x_admin_session` receipts verifiable by the standard chain verifier.

## Slice 2 additions (normative)

### 1. The sign-in receipt cites the verified id-token digest

The OIDC session-open receipt is the admin-plane sign-in receipt. Its
`x_admin_session` extension carries, in addition to the slice 1 fields
(action, session_id, user_id, auth_method, expires_at):

| Field | Meaning |
| --- | --- |
| `subject` | the verified `sub` claim: an operator identity string, never token content |
| `id_token_digest` | bare SHA-256 hex digest of the verified id_token bytes |

The receipt binds the mapping evidence a verifier needs: the IdP subject,
the operator id string (`user_id`) it resolved to, and the digest of the
exact id_token whose strict verification produced that identity. The digest
is the only token-derived value that ever enters evidence: id_token,
access-token and refresh-token content never enter receipts, the session
store, the pending-login state or the logs. Key-path receipts omit both
fields, so existing chains verify byte-identically (omit-when-empty).

### 2. Panel sign-in (the SSO path on the login card)

- The login card offers an SSO button only when `GET /api/session/config`
  reports `oidc_enabled: true`; that route discloses no secrets.
- Clicking it fetches `GET /api/oidc/login` and sends the browser to the
  provider authorization URL it returns.
- The provider redirects back to the panel with `code` and `state` in the
  query. The panel POSTs exactly those parameters to
  `POST /api/oidc/callback` and holds the returned `rst_` session token in a
  page-scope variable, the same discipline as the API key today: never
  localStorage, never a cookie, never the DOM. The query string is cleared
  from the address bar after handling.
- A provider-side `error` parameter surfaces as a refusal message; no
  session opens.

### 3. Replay resistance (unchanged, pinned)

`state` and `nonce` are single-use with a 5-minute park TTL; a replayed or
unknown `state` is a named refusal. The nonce is enforced against the
verified id_token, so a token minted for any other login request cannot
complete this one.

## T-S3: the TOTP residual stays named

Per-request TOTP is not session security; a key-plus-code exchange for a
short-lived session token is. OIDC sessions replace per-request TOTP on the
admin plane when federation is configured. This slice does NOT remove the
raw-key path or its per-request TOTP mode: they remain valid on every admin
route. The named config switch is federation itself: unset the
`RAUCLE_OIDC_*` variables and the plane behaves exactly as before. The
remaining residual is `totp_secret` at rest beside the key digest (U2
register, R13), unchanged by this slice.

## Scale posture (the decided answer)

The DECIDED scale answer for the enterprise plane is a single-writer
receipt sidecar that owns the chain so several gateway replicas can append
safely (EPIC X; its own slice). This slice changes no chain-append
semantics and builds no shared session infrastructure. Honest limits, named:

- Admin sessions and pending OIDC logins are per-process state; an OIDC
  login started on one replica completes only on that replica.
- Replica-spanning SSO needs the receipt sidecar plus a shared session
  store, both named follow-ups, not silently assumed here.
- The session cap (`RAUCLE_ADMIN_SESSIONS_MAX`) bounds each process.

## Test contract

Slice 2 pins, red-first:

- The OIDC open receipt cites `id_token_digest` (recomputed from the mock
  provider's token) and `subject`, and token content appears nowhere in the
  receipt store, the session table or the receipts (the no-content sweep).
- Key-path open receipts keep the slice 1 field set exactly, and chains
  verify through the standard chain verifier.
- The panel renders the SSO control wired to the three session routes, and
  the SSO handler never persists token material client-side.
- Discovery failure, strict token validation (issuer, audience, expiry,
  nonce, signature, kid), claim mapping, the off-by-default key fallback and
  the replay-resistant state/nonce stay pinned by the slice 1 suite.

## Non-goals (named, deferred)

SCIM-lite provisioning, provider signing-key rotation, the single-writer
receipt sidecar, replica-shared sessions, and any removal of raw-key
authentication.
