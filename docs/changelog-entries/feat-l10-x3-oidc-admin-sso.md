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
