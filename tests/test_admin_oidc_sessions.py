"""X3 slice 1 tests: admin-plane OIDC federation + receipted admin sessions.

Covers the named deliverables: discovery fetch fail-closed, the
authorization-code flow with PKCE against a mock provider, the named
MAPPING_ERROR on an unknown subject, receipts on session open AND close,
off-by-default, and the named refusal of inline client secrets.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any
from urllib.parse import parse_qs

import pytest

from raucle import admin_oidc
from raucle.admin_session import AdminSessionManager, SessionAuthError
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = "https://idp.test.example"  # https by contract; the mock is loopback
CLIENT_ID = "raucle-admin-test"
CLIENT_SECRET = "client-secret-test-value"
REDIRECT_URI = "https://admin.example.test/oidc/callback"


# ---------------------------------------------------------------------------
# Mock OIDC provider (localhost HTTP; in-process RSA keypair)
# ---------------------------------------------------------------------------

_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KID = "test-kid"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _mock_jwk() -> dict:
    numbers = _RSA.public_key().public_numbers()

    def num(value: int) -> str:
        return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": _KID,
        "n": num(numbers.n),
        "e": num(numbers.e),
    }


def _sign_id_token(header: dict, claims: dict) -> str:
    signing = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(claims).encode())
    sig = _RSA.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing + "." + _b64url(sig)


class MockIdPState:
    """What the mock provider remembers, for assertion on round-trips."""

    def __init__(self) -> None:
        self.codes: dict[str, dict[str, Any]] = {}
        self.discovery_up = True
        self.jwks_up = True


def _token_response(record: dict[str, Any]) -> bytes:
    now = int(time.time())
    claims = {
        "iss": record.get("token_issuer", ISSUER),
        "aud": CLIENT_ID,
        "sub": record.get("sub", "subject-1"),
        "preferred_username": record.get("username", "ops.user"),
        "email": "ops.user@example.test",
        "iat": record.get("iat", now),
        "exp": record.get("exp", now + 600),
        "nonce": record.get("token_nonce", record.get("nonce", "")),
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": _KID}
    body = {
        "access_token": "at",
        "token_type": "Bearer",
        "id_token": _sign_id_token(header, claims),
    }
    return json.dumps(body).encode()


class MockIdPHandler(BaseHTTPRequestHandler):
    server_state: MockIdPState

    def log_message(self, *args):  # noqa: ANN401
        pass

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/.well-known/openid-configuration":
            if not self.server_state.discovery_up:
                self._send(500, b"{}")
                return
            doc = {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/jwks.json",
            }
            self._send(200, json.dumps(doc).encode())
            return
        if path == "/jwks.json":
            if not self.server_state.jwks_up:
                self._send(500, b"{}")
                return
            self._send(200, json.dumps({"keys": [_mock_jwk()]}).encode())
            return
        self._send(404, b"{}")

    def do_POST(self) -> None:  # noqa: N802
        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        state = self.server_state
        code = form.get("code", [""])[0]
        record = state.codes.get(code)
        if record is None:
            self._send(400, json.dumps({"error": "invalid_grant"}).encode())
            return
        if form.get("client_id", [""])[0] != CLIENT_ID:
            self._send(401, json.dumps({"error": "invalid_client"}).encode())
            return
        if form.get("client_secret", [""])[0] != CLIENT_SECRET:
            self._send(401, json.dumps({"error": "invalid_client"}).encode())
            return
        verifier = form.get("code_verifier", [""])[0]
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        if not record.get("skip_pkce_check") and challenge != record["challenge"]:
            self._send(400, json.dumps({"error": "invalid_grant"}).encode())
            return
        if form.get("redirect_uri", [""])[0] != record.get("redirect_uri", REDIRECT_URI):
            self._send(400, json.dumps({"error": "invalid_grant"}).encode())
            return
        if record.get("drop_id_token"):
            state.codes.pop(code, None)
            self._send(200, json.dumps({"access_token": "at"}).encode())
            return
        state.codes.pop(code, None)
        self._send(200, _token_response(record))


@pytest.fixture
def idp():
    """A live mock provider on a random loopback port."""
    state = MockIdPState()
    MockIdPHandler.server_state = state  # type: ignore[attr-defined]
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockIdPHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    yield server, state
    server.shutdown()


@pytest.fixture
def users(tmp_path):
    mgr = UserManager(persist_path=tmp_path / "users.jsonl")
    mgr.add_user("a" * 40, "admin", "ops.user")
    mgr.add_user("b" * 40, "auditor", "nobody")
    return mgr


# ---------------------------------------------------------------------------
# Config-layer tests (off-by-default, secret placement, PKCE shape)
# ---------------------------------------------------------------------------


class TestConfig:
    def test_off_by_default(self):
        assert GatewayConfig().oidc_enabled is False

    def test_off_by_default_from_env(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_OIDC_ENABLED", raising=False)
        assert GatewayConfig.from_env().oidc_enabled is False
        monkeypatch.setenv("RAUCLE_OIDC_ENABLED", "1")
        monkeypatch.setenv("RAUCLE_OIDC_ISSUER", "https://sso.example.test")
        monkeypatch.setenv("RAUCLE_OIDC_CLIENT_ID", "raucle")
        cfg = GatewayConfig.from_env()
        assert cfg.oidc_enabled is True
        assert cfg.oidc_issuer == "https://sso.example.test"
        assert cfg.oidc_client_id == "raucle"

    def test_inline_secret_refused_named(self):
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_CONFIG_ERROR") as excinfo:
            admin_oidc.OIDCProviderConfig.from_config_dict(
                {"issuer": ISSUER, "client_id": "raucle", "client_secret": "leak"}
            )
        assert "RAUCLE_OIDC_CLIENT_SECRET" in str(excinfo.value)

    def test_yaml_config_with_inline_secret_refuses_named(self, tmp_path):
        import yaml

        path = tmp_path / "gateway-config.yaml"
        path.write_text(
            yaml.safe_dump(
                {"oidc": {"issuer": ISSUER, "client_id": "raucle", "client_secret": "leak-in-yaml"}}
            )
        )
        with pytest.raises(ValueError, match="OIDC_CONFIG_ERROR"):
            GatewayConfig.from_yaml(path)

    def test_http_issuer_refused(self):
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_CONFIG_ERROR"):
            admin_oidc.OIDCProviderConfig("http://idp.example", "raucle")

    def test_missing_issuer_or_client_id_named(self):
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_CONFIG_ERROR"):
            admin_oidc.OIDCProviderConfig("", "raucle")
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_CONFIG_ERROR"):
            admin_oidc.OIDCProviderConfig(ISSUER, "")

    def test_secret_from_env(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_OIDC_CLIENT_SECRET_FILE", raising=False)
        monkeypatch.setenv("RAUCLE_OIDC_CLIENT_SECRET", CLIENT_SECRET)
        assert admin_oidc.client_secret_from_env() == CLIENT_SECRET
        monkeypatch.delenv("RAUCLE_OIDC_CLIENT_SECRET")
        assert admin_oidc.client_secret_from_env() == ""

    def test_secret_file(self, tmp_path, monkeypatch):
        secret_file = tmp_path / "oidc-secret"
        secret_file.write_text(CLIENT_SECRET + "\n")
        secret_file.chmod(0o600)
        monkeypatch.delenv("RAUCLE_OIDC_CLIENT_SECRET", raising=False)
        monkeypatch.setenv("RAUCLE_OIDC_CLIENT_SECRET_FILE", str(secret_file))
        assert admin_oidc.client_secret_from_env() == CLIENT_SECRET

    def test_unreadable_secret_file_named(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RAUCLE_OIDC_CLIENT_SECRET", raising=False)
        monkeypatch.setenv("RAUCLE_OIDC_CLIENT_SECRET_FILE", str(tmp_path / "nope"))
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_CONFIG_ERROR"):
            admin_oidc.client_secret_from_env()

    def test_pkce_pair_matches_s256(self):
        verifier, challenge = admin_oidc.make_pkce_pair()
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        derived = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        assert challenge == derived
        assert len(verifier) >= 32


# ---------------------------------------------------------------------------
# Discovery: fail-closed at every step
# ---------------------------------------------------------------------------


def _loopback(server) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def _local_fetch(server):
    """Produuction transports rerouted https://idp.test.example -> loopback."""
    base = _loopback(server)

    def get(url: str, timeout: float) -> bytes:
        return admin_oidc._default_http_get(url.replace(ISSUER, base), timeout)

    def post(url: str, form: dict[str, str], timeout: float) -> bytes:
        return admin_oidc._default_http_post_form(url.replace(ISSUER, base), form, timeout)

    return get, post


def _federation_for(server, *, secret: str = CLIENT_SECRET) -> admin_oidc.OIDCFederation:
    # The configured issuer STAYS the https one; only the transport reroutes,
    # so every validation (issuer, https-only endpoints at config) runs against
    # the production strings.
    cfg = admin_oidc.OIDCProviderConfig(ISSUER, CLIENT_ID, redirect_uri=REDIRECT_URI)
    assert cfg.issuer_url == ISSUER
    assert not cfg.issuer_url.startswith("http://")
    get, post = _local_fetch(server)
    return admin_oidc.OIDCFederation(cfg, secret, http_get=get, http_post_form=post)


class TestDiscovery:
    def test_happy_start_names_provider(self, idp):
        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        assert fed.authorization_endpoint == ISSUER + "/authorize"
        assert fed.token_endpoint == ISSUER + "/token"
        assert _KID in fed._jwks_keys

    def test_unreachable_issuer_fail_closed_named(self):
        fed = admin_oidc.OIDCFederation(
            admin_oidc.OIDCProviderConfig(
                "https://idp-refuses.example", CLIENT_ID, redirect_uri=REDIRECT_URI
            ),
            CLIENT_SECRET,
            timeout_seconds=0.5,
        )
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_DISCOVERY_ERROR"):
            fed.start()

    def test_discovery_down_fail_closed_then_recovers(self, idp):
        server, state = idp
        fed = _federation_for(server)
        state.discovery_up = False
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_DISCOVERY_ERROR"):
            fed.start()
        state.discovery_up = True
        fed.start()  # a named failure, never a swallowed one

    def test_jwks_down_fail_closed(self, idp):
        server, state = idp
        fed = _federation_for(server)
        state.jwks_up = False
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_DISCOVERY_ERROR"):
            fed.start()

    def test_document_issuer_mismatch_fail_closed(self):
        doc = {
            "issuer": "https://attacker-claims.example",
            "authorization_endpoint": ISSUER + "/authorize",
            "token_endpoint": ISSUER + "/token",
            "jwks_uri": ISSUER + "/jwks.json",
        }
        fed = admin_oidc.OIDCFederation(
            admin_oidc.OIDCProviderConfig(ISSUER, CLIENT_ID, redirect_uri=REDIRECT_URI),
            CLIENT_SECRET,
            http_get=lambda url, timeout: json.dumps(doc).encode(),
        )
        with pytest.raises(admin_oidc.OIDCError, match="does not match"):
            fed.start()

    def test_non_https_endpoint_in_document_fail_closed(self):
        doc = {
            "issuer": ISSUER,
            "authorization_endpoint": "http://idp.test.example/authorize",
            "token_endpoint": ISSUER + "/token",
            "jwks_uri": ISSUER + "/jwks.json",
        }
        fed = admin_oidc.OIDCFederation(
            admin_oidc.OIDCProviderConfig(ISSUER, CLIENT_ID, redirect_uri=REDIRECT_URI),
            CLIENT_SECRET,
            http_get=lambda url, timeout: json.dumps(doc).encode(),
        )
        with pytest.raises(admin_oidc.OIDCError, match="https://"):
            fed.start()

    def test_unstarted_federation_fails_closed(self):
        fed = admin_oidc.OIDCFederation(
            admin_oidc.OIDCProviderConfig(ISSUER, CLIENT_ID),
            CLIENT_SECRET,
        )
        verifier, challenge = admin_oidc.make_pkce_pair()
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_DISCOVERY_ERROR"):
            fed.authorization_url(REDIRECT_URI, state="s", nonce="n", code_challenge=challenge)


# ---------------------------------------------------------------------------
# Authorization-code + PKCE through the mock provider
# ---------------------------------------------------------------------------


def _register_code(state: MockIdPState, **overrides) -> str:
    code = "code-" + str(len(state.codes) + 1)
    record: dict[str, Any] = {"challenge": "", "nonce": "n-1", "redirect_uri": REDIRECT_URI}
    record.update(overrides)
    state.codes[code] = record
    return code


class TestCodeFlow:
    def test_happy_path_pkce_exchange(self, idp):
        server, state = idp
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge)
        url = fed.authorization_url(REDIRECT_URI, state="s1", nonce="n-1", code_challenge=challenge)
        assert "response_type=code" in url
        assert "client_id=" + CLIENT_ID in url
        assert "code_challenge_method=S256" in url
        assert "code_challenge=" + challenge in url
        claims = fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI, expected_nonce="n-1")
        assert claims["sub"] == "subject-1"

    def test_replayed_code_refused_named(self, idp):
        server, state = idp
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge)
        fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI)
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_EXCHANGE_ERROR"):
            fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI)

    def test_wrong_pkce_verifier_refused_named(self, idp):
        server, state = idp
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge)
        other_verifier, _ = admin_oidc.make_pkce_pair()
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_EXCHANGE_ERROR"):
            fed.exchange_code(code, other_verifier, redirect_uri=REDIRECT_URI)

    def test_nonce_mismatch_named(self, idp):
        server, state = idp
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge, token_nonce="n-evil")
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_EXCHANGE_ERROR"):
            fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI, expected_nonce="n-1")

    def test_issuer_mismatch_named(self, idp):
        server, state = idp
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge, token_issuer="https://evil.example")
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_EXCHANGE_ERROR"):
            fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI, expected_nonce="n-1")

    def test_expired_id_token_named(self, idp):
        server, state = idp
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        now = int(time.time())
        code = _register_code(state, challenge=challenge, iat=now - 3600, exp=now - 1800)
        with pytest.raises(admin_oidc.OIDCError, match="expired"):
            fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI, expected_nonce="n-1")

    def test_missing_id_token_named(self, idp):
        server, state = idp
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge, drop_id_token=True)
        with pytest.raises(admin_oidc.OIDCError, match="no id_token"):
            fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI)

    def test_missing_client_secret_named(self, idp):
        server, state = idp
        fed = _federation_for(server, secret="")
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge)
        with pytest.raises(admin_oidc.OIDCError, match="OIDC_CONFIG_ERROR"):
            fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI)

    def test_unverified_signature_named(self, idp):
        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "x",
            "iat": now,
            "exp": now + 600,
            "nonce": "n-1",
        }
        header = {"alg": "RS256", "typ": "JWT", "kid": _KID}
        signing = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(claims).encode())
        sig = rogue.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        forged = signing + "." + _b64url(sig)
        with pytest.raises(admin_oidc.OIDCError, match="signature"):
            fed.verify_id_token(forged, expected_nonce="n-1")

    def test_unknown_kid_named_before_signature_check(self, idp):
        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "x", "iat": now, "exp": now + 600}
        header = {"alg": "RS256", "typ": "JWT", "kid": "rogue-kid"}
        token = _sign_id_token(header, claims)  # real key, unknown kid label
        with pytest.raises(admin_oidc.OIDCError, match="not in the current JWKS"):
            fed.verify_id_token(token)

    def test_unsupported_alg_named(self, idp):
        import cryptography  # noqa: F401

        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        # A 'none' alg token is structurally valid enough to reach the alg gate.
        token = _b64url(json.dumps({"alg": "none"}).encode()) + "." + _b64url(b"{}") + "."
        with pytest.raises(admin_oidc.OIDCError, match="unsupported id_token alg"):
            fed.verify_id_token(token)


# ---------------------------------------------------------------------------
# Identity mapping
# ---------------------------------------------------------------------------


class TestMapping:
    def test_map_by_name_binds_subject(self, idp, users):
        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        user = fed.map_user(users, {"sub": "subject-1", "preferred_username": "ops.user"})
        assert user.name == "ops.user"
        assert user.oidc_sub == "subject-1"
        assert any(u.oidc_sub == "subject-1" for u in users.list_users())

    def test_map_by_bound_subject(self, idp, users):
        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        target = users.resolve("a" * 40)
        target.oidc_sub = "already-bound"
        users.persist()
        user = fed.map_user(users, {"sub": "already-bound"})
        assert user.user_id == target.user_id

    def test_unknown_subject_named_mapping_error(self, idp, users):
        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        with pytest.raises(admin_oidc.OIDCError, match="MAPPING_ERROR") as excinfo:
            fed.map_user(users, {"sub": "nobody-9"})
        assert "nobody-9" in str(excinfo.value)

    def test_bound_subject_never_remaps_to_a_second_user(self, idp, users):
        server, _ = idp
        fed = _federation_for(server)
        fed.start()
        user = fed.map_user(users, {"sub": "subject-2", "preferred_username": "ops.user"})
        assert user.oidc_sub == "subject-2"
        # the same subject arriving under a different display claim STILL goes
        # to the bound user, and an unbound stranger subject maps to nobody
        again = fed.map_user(users, {"sub": "subject-2", "preferred_username": "zzz"})
        assert again.user_id == user.user_id
        with pytest.raises(admin_oidc.OIDCError, match="MAPPING_ERROR"):
            fed.map_user(users, {"sub": "subject-3", "preferred_username": "zzz"})


# ---------------------------------------------------------------------------
# Sessions + receipts
# ---------------------------------------------------------------------------


def _decode_receipts(path) -> list[dict]:
    payloads = []
    with open(path) as fh:
        for line in fh.read().strip().splitlines():
            env = json.loads(line)
            mid = env["jws"].split(".")[1]
            payloads.append(json.loads(base64.urlsafe_b64decode(mid + "=" * (-len(mid) % 4))))
    return payloads


class TestReceiptedSessions:
    def test_open_and_close_receipts_key_path(self, users, tmp_path):
        cfg = GatewayConfig(receipt_store=str(tmp_path / "receipts.jsonl"))
        gw = RaucleGateway(cfg)
        sessions = AdminSessionManager(users, receipt_emitter=gw._emit_admin_session_receipt)
        opened = sessions.open_with_key("a" * 40)
        assert opened["token"].startswith("rst_")
        assert sessions.resolve(opened["token"]).user_id.startswith("usr-")
        assert sessions.close(opened["token"]) is True
        assert sessions.resolve(opened["token"]) is None
        assert sessions.close(opened["token"]) is False  # replay refused
        payloads = _decode_receipts(cfg.receipt_store)
        opens = [
            p
            for p in payloads
            if "x_admin_session" in p and p["x_admin_session"]["action"] == "open"
        ]
        closes = [
            p
            for p in payloads
            if "x_admin_session" in p and p["x_admin_session"]["action"] == "close"
        ]
        assert len(opens) == 1
        assert len(closes) == 1
        assert opens[0]["x_admin_session"]["auth_method"] == "key"
        assert opens[0]["x_admin_session"]["session_id"] != opened["token"]
        blob = json.dumps(payloads)  # the bearer token never enters evidence
        assert opened["token"] not in blob

    def test_oidc_session_same_receipt_semantics_as_key(self, idp, users, tmp_path):
        server, state = idp
        cfg = GatewayConfig(receipt_store=str(tmp_path / "receipts.jsonl"))
        gw = RaucleGateway(cfg)
        sessions = AdminSessionManager(users, receipt_emitter=gw._emit_admin_session_receipt)
        fed = _federation_for(server)
        fed.start()
        verifier, challenge = admin_oidc.make_pkce_pair()
        code = _register_code(state, challenge=challenge)
        claims = fed.exchange_code(code, verifier, redirect_uri=REDIRECT_URI)
        user = fed.map_user(users, claims)
        oidc_session = sessions.open_with_user(user)
        key_session = sessions.open_with_key("a" * 40)
        payloads = _decode_receipts(cfg.receipt_store)
        exts = [p["x_admin_session"] for p in payloads if "x_admin_session" in p]
        assert {e["auth_method"] for e in exts} == {"key", "oidc"}
        # identical evidence shape and closure rules on both paths
        assert all(sorted(e) == sorted(exts[0]) for e in exts)
        assert all(int(e["expires_at"]) == e["expires_at"] for e in exts)
        assert sessions.close(oidc_session["token"]) is True
        assert sessions.close(key_session["token"]) is True
        payloads = _decode_receipts(cfg.receipt_store)
        closes = [
            p["x_admin_session"]
            for p in payloads
            if "x_admin_session" in p and p["x_admin_session"]["action"] == "close"
        ]
        assert len(closes) == 2
        assert all(c["auth_method"] in ("key", "oidc") for c in closes)

    def test_totp_verified_at_login_not_per_request(self, users):
        pytest.importorskip("pyotp")
        sessions = AdminSessionManager(users)
        users.setup_mfa("a" * 40)
        target = users.resolve("a" * 40)
        target.mfa_enabled = True
        users.persist()
        with pytest.raises(SessionAuthError, match="MFA required"):
            sessions.open_with_key("a" * 40)
        with pytest.raises(SessionAuthError, match="Invalid TOTP"):
            sessions.open_with_key("a" * 40, "000000")
        import pyotp

        opened = sessions.open_with_key("a" * 40, pyotp.TOTP(target.totp_secret).now())
        assert opened["user"].user_id == target.user_id
        # and the session then authorises WITHOUT further codes
        assert sessions.resolve(opened["token"]).requires_mfa()  # user still MFA
        assert sessions.resolve(opened["token"]) is not None

    def test_expiry_enforced(self, users):
        sessions = AdminSessionManager(users, ttl_seconds=1)
        opened = sessions.open_with_key("a" * 40)
        assert sessions.resolve(opened["token"]) is not None
        rec_hash = hashlib.sha256(opened["token"].encode()).hexdigest()
        sessions._sessions[rec_hash]["expires_at"] = time.time() - 1
        assert sessions.resolve(opened["token"]) is None

    def test_malformed_token_shapes_refused(self, users):
        sessions = AdminSessionManager(users)
        assert sessions.resolve("") is None
        assert sessions.resolve("Bearer rst_deadbeef") is None
        assert sessions.resolve("rst_" + "z" * 64) is None
        assert sessions.resolve(None) is None  # type: ignore[arg-type]
        assert sessions.close("rst_" + "z" * 64) is False

    def test_session_limit_refuses_fail_closed(self, users):
        sessions = AdminSessionManager(users, max_sessions=2)
        first = sessions.open_with_key("a" * 40)["token"]
        sessions.open_with_key("a" * 40)
        with pytest.raises(SessionAuthError):
            sessions.open_with_key("a" * 40)
        assert sessions.close(first) is True
        sessions.open_with_key("a" * 40)  # room again after explicit close

    def test_gone_user_kills_their_session(self, users):
        sessions = AdminSessionManager(users)
        opened = sessions.open_with_key("a" * 40)
        assert sessions.resolve(opened["token"]) is not None
        users.remove_user("a" * 40)
        assert sessions.resolve(opened["token"]) is None


# ---------------------------------------------------------------------------
# HTTP layer: off-by-default routes, session end-to-end, boot banner
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_client(users, tmp_path):
    cfg = GatewayConfig(receipt_store=str(tmp_path / "r.jsonl"))
    gw = RaucleGateway(cfg)
    from fastapi.testclient import TestClient

    return TestClient(create_admin_app(gw, users))


class TestAdminApp:
    def test_oidc_off_by_default(self, admin_client):
        cfg = admin_client.get("/api/session/config").json()
        assert cfg["oidc_enabled"] is False
        assert cfg["provider_issuer"] == ""
        assert admin_client.get("/api/oidc/login").status_code == 503
        assert admin_client.post("/api/oidc/callback", json={"state": "nope"}).status_code == 503

    def test_session_login_use_logout(self, admin_client):
        resp = admin_client.post("/api/session/login", json={"api_key": "a" * 40})
        assert resp.status_code == 200
        token = resp.json()["session_token"]
        assert token.startswith("rst_")
        assert resp.json()["user_id"].startswith("usr-")
        me = admin_client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["users"]
        # the raw key still works per-request (backward compatibility)
        direct = admin_client.get("/api/users", headers={"Authorization": f"Bearer {'a' * 40}"})
        assert direct.status_code == 200
        out = admin_client.post("/api/session/logout", headers={"Authorization": f"Bearer {token}"})
        assert out.status_code == 200
        assert (
            admin_client.get("/api/users", headers={"Authorization": f"Bearer {token}"}).status_code
            == 403
        )
        again = admin_client.post(
            "/api/session/logout", headers={"Authorization": f"Bearer {token}"}
        )
        assert again.status_code == 403

    def test_bad_credentials_shapes(self, admin_client):
        bad = admin_client.post("/api/session/login", json={"api_key": "wrong"})
        assert bad.status_code == 403
        missing = admin_client.post("/api/session/login", json={})
        assert missing.status_code in (401, 422)
        ghost = admin_client.get("/api/users", headers={"Authorization": "Bearer rst_" + "0" * 64})
        assert ghost.status_code in (401, 403)

    def test_unknown_session_token_is_an_undisclosed_403(self, admin_client):
        # same shape for expired/unknown/token-of-removed-user: no probing help
        a = admin_client.get("/api/users", headers={"Authorization": "Bearer rst_" + "0" * 64})
        b = admin_client.get("/api/users", headers={"Authorization": "Bearer rst_" + "f" * 64})
        assert a.status_code == b.status_code
        assert a.json()["detail"] == b.json()["detail"]

    def test_oidc_enabled_boot_banner_and_fail_closed_discovery(
        self, users, tmp_path, monkeypatch, caplog
    ):
        cfg = GatewayConfig(
            receipt_store=str(tmp_path / "r.jsonl"),
            oidc_enabled=True,
            oidc_issuer="https://no-such-issuer.invalid",
            oidc_client_id=CLIENT_ID,
            oidc_redirect_uri=REDIRECT_URI,
        )
        gw = RaucleGateway(cfg)
        monkeypatch.delenv("RAUCLE_OIDC_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("RAUCLE_OIDC_CLIENT_SECRET_FILE", raising=False)
        with (
            caplog.at_level("WARNING"),
            pytest.raises(admin_oidc.OIDCError, match="OIDC_DISCOVERY_ERROR"),
        ):
            create_admin_app(gw, users)  # refuses the admin app = fails boot

    def test_oidc_enabled_boot_banner_names_provider(
        self, idp, users, tmp_path, monkeypatch, caplog
    ):
        # Re-route the production transport to the loopback mock (config and
        # validation strings stay https/idp.test.example). Capture the REAL
        # defaults first: patching the module attribute must not recurse.
        real_get = admin_oidc._default_http_get
        real_post = admin_oidc._default_http_post_form
        base = _loopback(idp[0])

        def get(url: str, timeout: float) -> bytes:
            return real_get(url.replace(ISSUER, base), timeout)

        def post(url: str, form: dict[str, str], timeout: float) -> bytes:
            return real_post(url.replace(ISSUER, base), form, timeout)

        monkeypatch.setattr(admin_oidc, "_default_http_get", get)
        monkeypatch.setattr(admin_oidc, "_default_http_post_form", post)
        monkeypatch.setenv("RAUCLE_OIDC_CLIENT_SECRET", CLIENT_SECRET)
        cfg = GatewayConfig(
            receipt_store=str(tmp_path / "r.jsonl"),
            oidc_enabled=True,
            oidc_issuer=ISSUER,
            oidc_client_id=CLIENT_ID,
            oidc_redirect_uri=REDIRECT_URI,
        )
        gw = RaucleGateway(cfg)
        with caplog.at_level("WARNING"):
            create_admin_app(gw, users)
        assert any("OIDC federation ENABLED" in r.message for r in caplog.records)
        assert any(ISSUER in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Receipts verify through the standard chain verifier
# ---------------------------------------------------------------------------


class TestVerifierCompat:
    def test_session_receipts_pass_chain_verifier(self, users, tmp_path):
        cfg = GatewayConfig(receipt_store=str(tmp_path / "r.jsonl"))
        gw = RaucleGateway(cfg)
        sessions = AdminSessionManager(users, receipt_emitter=gw._emit_admin_session_receipt)
        opened = sessions.open_with_key("a" * 40)
        sessions.close(opened["token"])
        from raucle.provenance import ProvenanceVerifier

        verifier = ProvenanceVerifier(
            public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
        )
        report = verifier.verify_chain(cfg.receipt_store)
        assert report.valid, report.errors

    def test_receiver_config_defaults_unchanged(self, monkeypatch):
        # Enabling nothing = zero behaviour drift for existing deployments.
        monkeypatch.delenv("RAUCLE_OIDC_ENABLED", raising=False)
        monkeypatch.delenv("RAUCLE_ADMIN_SESSION_TTL", raising=False)
        cfg = GatewayConfig.from_env()
        assert cfg.oidc_enabled is False
        assert cfg.oidc_issuer == ""
        assert cfg.admin_session_ttl == 3600

    def test_config_via_yaml_round_trip(self, tmp_path, monkeypatch):
        import yaml

        monkeypatch.delenv("RAUCLE_OIDC_ENABLED", raising=False)
        path = tmp_path / "gateway-config.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "oidc_enabled": True,
                    "oidc_issuer": ISSUER,
                    "oidc_client_id": CLIENT_ID,
                    "admin_session_ttl": 1800,
                }
            )
        )
        cfg = GatewayConfig.from_yaml(path)
        assert cfg.oidc_enabled is True
        assert cfg.oidc_issuer == ISSUER
        assert cfg.admin_session_ttl == 1800
        # to_yaml never materialises a secret slot for OIDC
        assert "client_secret" not in cfg.to_yaml()
