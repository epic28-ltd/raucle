# X3 Slice 1 — Admin-Plane OIDC Identity Federation (Spec)

Status: implemented (optional feature, OFF by default).
Follow-ups named in the PR: SCIM-lite provisioning, provider key rotation,
receipt sidecar. Slice 1 is identity federation only.

## Purpose

Let operators federate admin-panel identities to their enterprise IdP over
OpenID Connect while keeping every other property of the admin plane intact:
same user records (RED-032), same roles, same receipted evidence trail.

## Non-goals (this slice)

- No user auto-provisioning: an OIDC subject that does not map to an existing
  admin user is a named `MAPPING_ERROR`, deliberately.
- No SCIM directory sync; no provider signing-key rotation; no receipt
  sidecar service.

## Configuration contract

| Setting | Where | Notes |
| --- | --- | --- |
| `RAUCLE_OIDC_ENABLED` | env / `oidc_enabled` | `1`/`true` to enable; default OFF |
| `RAUCLE_OIDC_ISSUER` | env / `oidc_issuer` | must be `https://` |
| `RAUCLE_OIDC_CLIENT_ID` | env / `oidc_client_id` | required when enabled |
| `RAUCLE_OIDC_REDIRECT_URI` | env / `oidc_redirect_uri` | the panel's callback URL |
| `RAUCLE_OIDC_SCOPE` | env / `oidc_scope` | default `openid profile email` |
| `RAUCLE_OIDC_CLIENT_SECRET` | env ONLY | never in a config file |
| `RAUCLE_OIDC_CLIENT_SECRET_FILE` | env (path, 0600) | secret-file pattern |
| `RAUCLE_ADMIN_SESSION_TTL` | env / `admin_session_ttl` | seconds, >= 60, default 3600 |
| `RAUCLE_ADMIN_SESSIONS_MAX` | env / `admin_sessions_max` | default 64 |

A config document carrying an inline `client_secret` (YAML `oidc:` section)
refuses to load: `OIDC_CONFIG_ERROR: client_secret must not live in the
config file`.

## Behaviour

1. **Startup, fail-closed (enabled only).** Discovery is fetched from
   `{issuer}/.well-known/openid-configuration`, issuer identity is checked
   exactly (RFC 8414 3.3), all endpoints must be https, JWKS must carry a
   usable RSA signing key. Any failure refuses the admin app (and therefore
   the gateway boot). Success logs the boot banner naming the provider.
2. **Login.** `GET /api/oidc/login` builds the authorization URL:
   `response_type=code`, PKCE S256, single-use `state` + `nonce` held for
   at most 5 minutes. `POST /api/oidc/callback` performs the token exchange
   (client_secret_post) and verifies the `id_token`: RS256 against JWKS by
   `kid`, strict `iss`/`aud`/`exp`/`nbf`/`nonce`. Any violation is a named
   `OIDC_EXCHANGE_ERROR`; no session is ever minted on doubt.
3. **Mapping.** The verified subject resolves to an existing user: bound
   `oidc_sub` first, else first name-claim match (`preferred_username`,
   `email`, `name`), with the subject bound and persisted on that first
   match. Unmapped subject: `MAPPING_ERROR: no admin user maps to OIDC
   subject '<sub>'`.
4. **Sessions (shared with key logins).** `raucle.admin_session` issues a
   256-bit `rst_` bearer token; only its SHA-256 digest is stored. Receipted
   on open and close via the gateway signer (`x_admin_session` extension:
   action, hash-derived session handle, user_id, auth_method, expiry).
   Expiry enforced on resolve; user removal kills live sessions; the cap
   refuses fail-closed rather than evicting.
5. **TOTP (T-S3).** MFA codes are verified once at `POST /api/session/login`
   and exchanged for the bearer session; per-request TOTP re-presentation
   remains valid for raw-key authentication. The honest limit that remains
   is secret-at-rest (`totp_secret` plaintext beside the digest), recorded
   separately.

## Environment compatibility

Everything ships disabled: `GatewayConfig` defaults are inactive, `from_env`
wiring only activates on explicit env, raw-key authentication (with
per-request TOTP when MFA is on) is untouched, and the receipt chain is
byte-compatible — session receipts ride the existing
`GUARDRAIL_SCAN`-shaped authority envelope, verifiable by the standard
chain verifier.
