"""Receipted admin-panel sessions (X3 slice 1, T-S3).

Historically the admin API was bearer-by-repetition: every request carried
the full API key and, for MFA users, a fresh TOTP code, with an honest
limit noted in ``UserManager._totp_accepts`` that a genuine session-token
exchange (key + code -> short-lived bearer) was the real fix. This module
is that fix, shared by BOTH login paths:

- key-based sessions: POST /api/session/login with the API key (and the
  TOTP code when the user has MFA enabled) opens a short-lived bearer
  session. The code is verified ONCE at login, not on every poll.
- OIDC sessions: a successful OIDC login maps to an admin user record and
  opens the SAME kind of session, carrying ``auth_method="oidc"``.

Session semantics (both paths identical):

- the token is 256 bits of caller-side entropy, prefixed ``rst_``; the
  manager stores only its SHA-256 digest (same discipline as RED-032
  admin keys), so the session store is not a credential file.
- sessions expire (default 1 hour, operator-configurable) and expiry is
  enforced on every resolve.
- opening and closing a session are RECEIPTED: a signed provenance
  receipt with an ``x_admin_session`` extension binds the session id
  (hash-derived public handle, never the token), the user_id, the auth
  method and the expiry. Logout is a signed lifecycle event, never a
  silent delete - the same doctrine as records destroy.

Fail-closed posture: an unknown, expired, malformed or already-closed
token resolves to no user, and the caller treats that exactly like a
missing Authorization header.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections.abc import Callable
from typing import Any

from raucle.gateway import GatewayUser, UserManager

logger = logging.getLogger(__name__)

SESSION_TOKEN_PREFIX = "rst_"
DEFAULT_SESSION_TTL_SECONDS = 3600
DEFAULT_MAX_SESSIONS = 64


class SessionAuthError(Exception):
    """A session-open attempt failed, with the reason for the HTTP layer."""

    def __init__(self, reason: str, status: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _hash_session_token(token: str) -> str:
    """SHA-256 hex digest of a session token (store key, like RED-032 keys)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _derive_session_id(token_hash: str) -> str:
    """Stable public handle for a session, derived from its digest."""
    return "ses-" + token_hash[:12]


class AdminSessionManager:
    """Short-lived receipted admin sessions, shared by key and OIDC logins."""

    def __init__(
        self,
        users: UserManager,
        *,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        receipt_emitter: Callable[[str, dict[str, Any]], str | None] | None = None,
    ) -> None:
        """*receipt_emitter* takes (action, extension) and returns a receipt
        hash or None. Wired by the composition root to the gateway's signed
        admin-session receipt emitter; None = receipts disabled by config."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._users = users
        self._ttl = int(ttl_seconds)
        self._max_sessions = int(max_sessions)
        self._receipt_emitter = receipt_emitter
        self._sessions: dict[str, dict[str, Any]] = {}

    # -- opening ----------------------------------------------------------

    def open_with_key(
        self,
        api_key: str,
        x_totp: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate with an API key (+ TOTP when MFA is enabled) and
        open a session. Raises :class:`SessionAuthError` on any failure;
        the caller maps the reason onto the same 401/403 shapes the
        per-request bearer flow already uses."""
        user = self._users.get_user(api_key or "")
        if user is None:
            raise SessionAuthError("Invalid API key", status=403)
        if user.requires_mfa():
            if not x_totp or not x_totp.strip():
                raise SessionAuthError(
                    "MFA required: provide X-TOTP header with 6-digit code",
                    status=401,
                )
            if not self._users.verify_totp(user, x_totp):
                raise SessionAuthError("Invalid TOTP code", status=403)
        return self._open(user, auth_method="key")

    def open_with_user(self, user: GatewayUser) -> dict[str, Any]:
        """Open a session for an already-authenticated identity (the OIDC
        path after subject mapping). Same receipted semantics as the key
        path; only ``auth_method`` differs."""
        return self._open(user, auth_method="oidc")

    def _open(self, user: GatewayUser, *, auth_method: str) -> dict[str, Any]:
        token = SESSION_TOKEN_PREFIX + secrets.token_hex(32)
        token_hash = _hash_session_token(token)
        now = time.time()
        expires_at = now + self._ttl
        # Bound the session table: opening one more session beyond the cap
        # evicts nothing silently - it refuses, fail-closed, so an operator
        # must close sessions (or restart) rather than silently losing one.
        if len(self._sessions) >= self._max_sessions:
            self._sweep_expired()
        if len(self._sessions) >= self._max_sessions:
            raise SessionAuthError(
                "session limit reached; close a session or wait for expiry",
                status=503,
            )
        self._sessions[token_hash] = {
            "user_id": user.user_id,
            "role": user.role,
            "auth_method": auth_method,
            "opened_at": now,
            "expires_at": expires_at,
        }
        self._emit("open", user, token_hash, auth_method, expires_at)
        logger.info("admin session opened for %s (method=%s)", user.user_id, auth_method)
        return {"token": token, "expires_at": expires_at, "user": user}

    # -- resolve / close --------------------------------------------------

    def resolve(self, token: str) -> GatewayUser | None:
        """Resolve a presented bearer session token to its user, or None
        when unknown, malformed, expired or already closed."""
        record = self._record_for(token)
        if record is None:
            return None
        user = self._users.resolve(record["user_id"])
        if user is None:
            # The user was removed while the session lived: the session
            # dies with the identity it authenticated.
            self._sessions.pop(_hash_session_token(token), None)
            return None
        return user

    def close(self, token: str) -> bool:
        """Close a session. Returns False for unknown/already-closed/expired
        tokens. Closing emits its receipt BEFORE the record is dropped, so
        the ledger never silently loses a live session."""
        record = self._record_for(token)
        if record is None:
            return False
        token_hash = _hash_session_token(token)
        user = self._users.resolve(record["user_id"])
        self._emit("close", user, token_hash, record["auth_method"], record["expires_at"])
        self._sessions.pop(token_hash, None)
        logger.info("admin session closed for %s", record["user_id"])
        return True

    def _record_for(self, token: str) -> dict[str, Any] | None:
        if not isinstance(token, str) or not token.startswith(SESSION_TOKEN_PREFIX):
            return None
        record = self._sessions.get(_hash_session_token(token))
        if record is None:
            return None
        if time.time() > record["expires_at"]:
            self._sessions.pop(_hash_session_token(token), None)
            return None
        return dict(record)

    def _sweep_expired(self) -> None:
        now = time.time()
        for token_hash in [h for h, rec in self._sessions.items() if rec["expires_at"] <= now]:
            self._sessions.pop(token_hash, None)

    def active_count(self) -> int:
        self._sweep_expired()
        return len(self._sessions)

    # -- receipts ---------------------------------------------------------

    def _emit(
        self,
        action: str,
        user: GatewayUser | None,
        token_hash: str,
        auth_method: str,
        expires_at: float,
    ) -> None:
        if self._receipt_emitter is None:
            return
        extension = {
            "action": action,
            "session_id": _derive_session_id(token_hash),
            "user_id": user.user_id if user else "",
            "auth_method": auth_method,
            # Signed/hashed material carries integers only (canonical JSON
            # refuses floats); the session table keeps the precise float.
            "expires_at": int(expires_at),
        }
        try:
            receipt_hash = self._receipt_emitter(action, extension)
        except Exception:  # pragma: no cover - emitter is gateway-internal
            logger.exception("admin-session receipt emission failed")
            receipt_hash = None
        if receipt_hash is None:
            logger.warning(
                "admin-session %s for %s proceeded without a receipt",
                action,
                extension["user_id"] or "<removed>",
            )
