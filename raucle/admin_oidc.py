"""Optional OIDC identity-provider federation for the ADMIN plane (X3 slice 1).

Deliberate scope: identity federation only. The admin panel gains a second
login path - authorization-code flow with PKCE (RFC 6749 + RFC 7636) against
an operator-configured OpenID Connect provider. SCIM-lite user provisioning,
key rotation and the receipt sidecar are named follow-ups.

Configuration posture:

- OFF by default. Enabling is an operator config choice
  (``RAUCLE_OIDC_ENABLED`` + issuer + client id). On enable the boot path
  logs a banner naming the provider, and discovery is fetched at startup:
  an unreachable, malformed or non-HTTPS issuer REFUSES TO START (fail-closed).
- The client secret NEVER lives in a config file. It is read from
  ``RAUCLE_OIDC_CLIENT_SECRET`` (env) or ``RAUCLE_OIDC_CLIENT_SECRET_FILE``
  (a 0600 file, same pattern as RAUCLE_ADMIN_KEY_FILE). A configuration
  document that carries an inline ``client_secret`` key refuses with a NAMED
  error so the mistake cannot pass silently.
- Identity mapping reuses the RED-032 user machinery: an OIDC subject
  resolves to the existing admin-panel user record (matched by the bound
  ``oidc_sub`` or the user's ``name``; on first match the subject is bound
  and persisted). An unknown subject is a NAMED ``MAPPING_ERROR`` - it is
  never auto-provisioned, because provisioning is a follow-up slice.
- Tokens issued after an OIDC login are :mod:`raucle.admin_session`
  sessions with the SAME receipted semantics as key-based sessions.

The identity verdict is fail-closed end to end: discovery failure, a
discovery document missing required endpoints, an unsupported signing
algorithm, a stale or unknown ``kid``, a wrong issuer/audience/expiry or a
failed signature all raise named errors and yield NO session.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import for typing only
    from raucle.gateway import GatewayUser

from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# Named error prefixes - tests and operators grep these exact strings.
CONFIG_ERROR = "OIDC_CONFIG_ERROR"
DISCOVERY_ERROR = "OIDC_DISCOVERY_ERROR"
EXCHANGE_ERROR = "OIDC_EXCHANGE_ERROR"
MAPPING_ERROR = "MAPPING_ERROR"

PKCE_CODE_CHALLENGE_METHOD = "S256"
DEFAULT_SCOPE = "openid profile email"
DEFAULT_TIMEOUT_SECONDS = 5.0
SECRETS_MIN_LENGTH = 8


class OIDCError(Exception):
    """Base for named OIDC federation failures; message carries the prefix."""

    def __init__(self, prefix: str, detail: str) -> None:
        super().__init__(f"{prefix}: {detail}")
        self.prefix = prefix


def _config_error(detail: str) -> OIDCError:
    return OIDCError(CONFIG_ERROR, detail)


def _discovery_error(detail: str) -> OIDCError:
    return OIDCError(DISCOVERY_ERROR, detail)


class OIDCProviderConfig:
    """Operator-facing provider configuration. Holds NO secret."""

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        *,
        redirect_uri: str = "",
        scope: str = DEFAULT_SCOPE,
    ) -> None:
        issuer_url = (issuer_url or "").strip()
        client_id = (client_id or "").strip()
        if not issuer_url:
            raise _config_error("issuer_url is required when OIDC federation is enabled")
        if not issuer_url.startswith("https://"):
            # Fail-closed: identity documents and code exchanges must not
            # travel over plaintext HTTP.
            raise _config_error(f"issuer_url must be an https:// URL, got {issuer_url!r}")
        if not client_id:
            raise _config_error("client_id is required when OIDC federation is enabled")
        self.issuer_url = issuer_url.rstrip("/")
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope or DEFAULT_SCOPE

    @classmethod
    def from_config_dict(cls, cfg: dict[str, Any]) -> OIDCProviderConfig:
        """Build from a mapping (a YAML ``oidc:`` section shape).

        Refuses NAMED when the document carries an inline client secret:
        secrets are env/file only, never a config file that gets edited,
        copied and committed.
        """
        if not isinstance(cfg, dict):
            raise _config_error("oidc config must be a mapping")
        if cfg.get("client_secret"):
            raise _config_error(
                "client_secret must not live in the config file; set "
                "RAUCLE_OIDC_CLIENT_SECRET (env) or RAUCLE_OIDC_CLIENT_SECRET_FILE "
                "(0600 file) instead"
            )
        return cls(
            cfg.get("issuer") or "",
            cfg.get("client_id") or "",
            redirect_uri=cfg.get("redirect_uri") or "",
            scope=cfg.get("scope") or DEFAULT_SCOPE,
        )


def client_secret_from_env(env: dict[str, str] | None = None) -> str:
    """Resolve the client secret from the environment or a secret FILE.

    Same contract as the bootstrap admin key: env value, or the path of a
    0600 file. Never accepts the secret from a config document. Returns ""
    when nothing is configured (login then fails closed at exchange time).
    """
    env = dict(os.environ if env is None else env)
    file_path = env.get("RAUCLE_OIDC_CLIENT_SECRET_FILE", "").strip()
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as fh:
                value = fh.read().strip()
        except OSError as exc:
            raise OIDCError(
                CONFIG_ERROR, f"RAUCLE_OIDC_CLIENT_SECRET_FILE is set but unreadable ({exc})"
            ) from exc
        if not value:
            raise _config_error(f"RAUCLE_OIDC_CLIENT_SECRET_FILE {file_path!r} is empty")
        return value
    return env.get("RAUCLE_OIDC_CLIENT_SECRET", "").strip()


def make_pkce_pair() -> tuple[str, str]:
    """RFC 7636: a high-entropy code_verifier and its S256 challenge."""
    verifier = base64.urlsafe_b64encode(os.urandom(48)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _https_url(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise _discovery_error(f"discovery document is missing {what}")
    if not value.startswith("https://"):
        raise _discovery_error(f"{what} must be https:// in the discovery document")
    return value


class OIDCFederation:
    """The OIDC login machinery: discovery, PKCE, exchange, verification, mapping."""

    def __init__(
        self,
        config: OIDCProviderConfig,
        client_secret: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        http_get: Callable[[str, float], bytes] | None = None,
        http_post_form: Callable[[str, dict[str, str], float], bytes] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._secret = client_secret
        self._timeout = timeout_seconds
        self._http_get = http_get or _default_http_get
        self._http_post_form = http_post_form or _default_http_post_form
        self._clock = clock
        self.authorization_endpoint = ""
        self.token_endpoint = ""
        self.jwks_uri = ""
        self._jwks_keys: dict[str, tuple[Any, str]] = {}  # kid -> (RSA public key, alg)
        self._started = False

    def start(self) -> None:
        """Fetch and validate the discovery document + JWKS at startup.

        Fail-closed: any failure refuses to start the federation (and the
        composition root refuses to start the gateway when OIDC is enabled).
        """
        discovery_url = self.config.issuer_url + "/.well-known/openid-configuration"
        try:
            raw = self._http_get(discovery_url, self._timeout)
        except Exception as exc:
            raise _discovery_error(
                f"discovery fetch failed for issuer {self.config.issuer_url!r}: {exc}"
            ) from exc
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise _discovery_error(f"discovery document is not JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise _discovery_error("discovery document is not a JSON object")
        doc_issuer = doc.get("issuer")
        if doc_issuer != self.config.issuer_url:
            # RFC 8414 3.3: the document's issuer must match. Trailing-slash
            # disagreement is the common real-world drift; refuse and let the
            # operator align the config rather than silently accepting.
            raise _discovery_error(
                f"discovery issuer {doc_issuer!r} does not match configured "
                f"issuer {self.config.issuer_url!r}"
            )
        self.authorization_endpoint = _https_url(
            doc.get("authorization_endpoint"), "authorization_endpoint"
        )
        self.token_endpoint = _https_url(doc.get("token_endpoint"), "token_endpoint")
        self.jwks_uri = _https_url(doc.get("jwks_uri"), "jwks_uri")
        self._load_jwks()
        self._started = True
        logger.info(
            "OIDC federation started: provider issuer %s, authorization %s, PKCE S256 required",
            self.config.issuer_url,
            self.authorization_endpoint,
        )

    def _load_jwks(self) -> None:
        try:
            raw = self._http_get(self.jwks_uri or "", self._timeout)
        except Exception as exc:
            raise _discovery_error(f"JWKS fetch failed ({self.jwks_uri!r}): {exc}") from exc
        try:
            jwks = json.loads(raw)
        except ValueError as exc:
            raise _discovery_error(f"JWKS document is not JSON: {exc}") from exc
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list) or not keys:
            raise _discovery_error("JWKS document carries no keys")
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        except ImportError as exc:  # pragma: no cover - compliance extra absent
            raise _discovery_error(
                "cryptography is required to verify provider signatures "
                "(install raucle[compliance]); refusing to start"
            ) from exc
        loaded: dict[str, tuple[Any, str]] = {}
        for jwk in keys:
            if (
                not isinstance(jwk, dict)
                or jwk.get("kty") != "RSA"
                or jwk.get("use")
                not in (
                    None,
                    "sig",
                )
            ):
                continue
            kid = jwk.get("kid") or ""
            try:
                numbers = RSAPublicNumbers(
                    e=int.from_bytes(_b64url_decode(jwk["e"]), "big"),
                    n=int.from_bytes(_b64url_decode(jwk["n"]), "big"),
                )
                key = numbers.public_key()
            except (KeyError, ValueError, TypeError):
                continue
            loaded[kid] = (key, jwk.get("alg") or "RS256")
        if not loaded:
            raise _discovery_error("JWKS carries no usable RSA signing keys")
        self._jwks_keys = loaded

    # -- authorization-code flow with PKCE ---------------------------------

    def authorization_url(
        self,
        redirect_uri: str,
        *,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        self._require_started()
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.config.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": PKCE_CODE_CHALLENGE_METHOD,
        }
        sep = "&" if "?" in self.authorization_endpoint else "?"
        return self.authorization_endpoint + sep + urlencode(params)

    def exchange_code(
        self,
        code: str,
        code_verifier: str,
        *,
        redirect_uri: str,
        expected_nonce: str = "",
    ) -> dict[str, Any]:
        """Exchange the authorization code for tokens and return the VERIFIED
        id_token claims. Any verification failure raises a named error and
        yields no session."""
        self._require_started()
        if not code or not isinstance(code, str):
            raise OIDCError(EXCHANGE_ERROR, "authorization code is missing")
        if not code_verifier:
            raise OIDCError(EXCHANGE_ERROR, "PKCE code_verifier is required")
        if not self._secret:
            raise _config_error(
                "client secret is not configured; set RAUCLE_OIDC_CLIENT_SECRET "
                "or RAUCLE_OIDC_CLIENT_SECRET_FILE"
            )
        if len(self._secret) < SECRETS_MIN_LENGTH:
            raise _config_error("configured client secret is implausibly short")
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self._secret,
            "code_verifier": code_verifier,
        }
        try:
            raw = self._http_post_form(self.token_endpoint, form, self._timeout)
        except Exception as exc:
            raise OIDCError(EXCHANGE_ERROR, f"token exchange failed: {exc}") from exc
        try:
            tokens = json.loads(raw)
        except ValueError as exc:
            raise OIDCError(EXCHANGE_ERROR, f"token response is not JSON: {exc}") from exc
        id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
        if not id_token or not isinstance(id_token, str):
            raise OIDCError(EXCHANGE_ERROR, "token response carries no id_token")
        return self.verify_id_token(id_token, expected_nonce=expected_nonce)

    # -- id_token verification ---------------------------------------------

    def verify_id_token(self, id_token: str, *, expected_nonce: str = "") -> dict[str, Any]:
        self._require_started()
        parts = id_token.split(".")
        if len(parts) != 3:
            raise OIDCError(EXCHANGE_ERROR, "id_token is not a compact JWS")
        try:
            header = json.loads(_b64url_decode(parts[0]))
            claims = json.loads(_b64url_decode(parts[1]))
        except ValueError as exc:
            raise OIDCError(EXCHANGE_ERROR, f"id_token segments are undecodable: {exc}") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise OIDCError(EXCHANGE_ERROR, "id_token header or claims are not objects")
        if header.get("alg") != "RS256":
            raise OIDCError(
                EXCHANGE_ERROR,
                f"unsupported id_token alg {header.get('alg')!r}; only RS256 is accepted",
            )
        kid = header.get("kid") or ""
        entry = self._jwks_keys.get(kid)
        if entry is None:
            raise OIDCError(EXCHANGE_ERROR, f"id_token kid {kid!r} is not in the current JWKS")
        key, _alg = entry
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError:  # pragma: no cover
            raise OIDCError(
                EXCHANGE_ERROR, "cryptography unavailable; cannot verify id_token"
            ) from None
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        try:
            key.verify(
                _b64url_decode(parts[2]),
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise OIDCError(EXCHANGE_ERROR, "id_token signature verification failed") from exc
        now = self._clock()
        issuer = self.config.issuer_url
        if claims.get("iss") != issuer:
            raise OIDCError(
                EXCHANGE_ERROR,
                f"id_token issuer {claims.get('iss')!r} does not match {issuer!r}",
            )
        aud = claims.get("aud")
        aud_list = aud if isinstance(aud, list) else [aud]
        if self.config.client_id not in [a for a in aud_list if isinstance(a, str)]:
            raise OIDCError(EXCHANGE_ERROR, "id_token audience does not include this client_id")
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or now >= exp:
            raise OIDCError(EXCHANGE_ERROR, "id_token is expired or carries no usable exp")
        nbf = claims.get("nbf")
        if isinstance(nbf, (int, float)) and now < nbf:
            raise OIDCError(EXCHANGE_ERROR, "id_token is not yet valid (nbf in the future)")
        if expected_nonce and claims.get("nonce") != expected_nonce:
            raise OIDCError(EXCHANGE_ERROR, "id_token nonce does not match the login request")
        if not claims.get("sub"):
            raise OIDCError(EXCHANGE_ERROR, "id_token carries no sub claim")
        return claims

    # -- identity mapping ---------------------------------------------------

    def map_user(self, users: Any, claims: dict[str, Any]) -> GatewayUser | None:
        """Map verified subject+claims onto an EXISTING admin user record.

        Match order: a user whose persisted ``oidc_sub`` equals the token
        subject, else a user whose ``name`` equals the ``preferred_username``
        or ``email`` claim - and on that first match the subject is bound and
        persisted. An unknown subject is a NAMED MAPPING_ERROR: no user is
        auto-provisioned in this slice.
        """
        from raucle.gateway import OIDC_MAP_USERNAME_CLAIMS

        sub = claims.get("sub") or ""
        for user in users.list_users():
            if getattr(user, "oidc_sub", "") and user.oidc_sub == sub:
                return user
        for claim_name in OIDC_MAP_USERNAME_CLAIMS:
            candidate = claims.get(claim_name)
            if isinstance(candidate, str) and candidate:
                for user in users.list_users():
                    if not getattr(user, "oidc_sub", "") and user.name == candidate:
                        user.oidc_sub = sub
                        users.persist()
                        logger.info("bound OIDC subject %s to admin user %s", sub, user.user_id)
                        return user
        raise OIDCError(
            MAPPING_ERROR,
            f"no admin user maps to OIDC subject {sub!r}; bind the subject or "
            "create a user whose name matches the token claims",
        )

    def _require_started(self) -> None:
        if not self._started:
            raise _discovery_error("federation has not started; discovery must succeed first")
        if not self.authorization_endpoint or not self.token_endpoint:
            raise _discovery_error("discovery left required endpoints unset")


def _default_http_get(url: str, timeout: float) -> bytes:
    from urllib.request import urlopen

    with urlopen(url, timeout=timeout) as resp:  # noqa: S310 - https-enforced above
        return resp.read()


def _default_http_post_form(url: str, form: dict[str, str], timeout: float) -> bytes:
    from urllib.parse import urlencode as _enc
    from urllib.request import Request, urlopen

    data = _enc(form).encode("ascii")
    req = Request(url, data=data, method="POST")  # noqa: S310 - https-enforced above
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()
