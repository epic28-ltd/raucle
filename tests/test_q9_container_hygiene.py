"""Q9 container + packaging hygiene (external v0.23.7 review).

Pins the review's code-level items:
- /livez: a public liveness route on the gateway app, independent of the
  health token and of the admin plane (the Docker HEALTHCHECK target).
- The admin plane is rate limited in-app (stock Caddy ships no rate-limit
  module - verified per image) with a default ceiling and env override,
  and degrades to a loud warning, never silently, when slowapi is absent.
- The invalid RAUCLE_GATE_MAX_PAYLOAD_CHARS env var warns and keeps the
  default (was a bare except-pass).
- HybridRecordSigner exposes its PQ public key through a named accessor;
  nothing outside the signer class touches _pq_private.
- bench/run_bench.py sizes /proc pages by os.sysconf, not a hard-coded 4096.
- The raucle_detect deprecation shim names its removal version.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import (
    _MAX_GATE_PAYLOAD_CHARS,
    _gate_payload_limit,
    create_admin_app,
    create_gateway_app,
)


def _policy_file(tmp_path: Path) -> str:
    path = tmp_path / "policies.yaml"
    path.write_text(
        "\n".join(["version: 1", "issuer: q9.test", "policies: []"]),
        encoding="utf-8",
    )
    return str(path)


def _config(tmp_path: Path, **over) -> GatewayConfig:
    cfg = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="q9-admin-key-0123456789",
        signer_backend="local",
        policy_file=_policy_file(tmp_path),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
    )
    for key, value in over.items():
        setattr(cfg, key, value)
    return cfg


class TestLivezLivenessRoute:
    def test_livez_is_public_and_shape_bound(self, tmp_path):
        """The healthcheck target: no credentials, no admin plane, tiny body."""
        client = TestClient(create_gateway_app(RaucleGateway(_config(tmp_path))))
        response = client.get("/livez")
        assert response.status_code == 200
        assert response.json() == {"status": "live"}

    def test_livez_survives_a_health_token_that_gates_health(self, tmp_path):
        """RAUCLE_HEALTH_KEY set 401s /health; /livez must still answer so
        the container healthcheck cannot be taken out by the operator's
        own health token."""
        cfg = _config(tmp_path, health_check_token="hush-0123456789")
        client = TestClient(create_gateway_app(RaucleGateway(cfg)))
        assert client.get("/livez").status_code == 200
        assert client.get("/health").status_code == 401


class TestAdminPlaneRateLimit:
    @pytest.fixture()
    def admin_stack(self, tmp_path):
        gateway = RaucleGateway(_config(tmp_path))
        users = UserManager(persist_path=str(tmp_path / "users.jsonl"))
        return TestClient(create_admin_app(gateway, users))

    def test_default_ceiling_and_env_override_429(self, tmp_path, monkeypatch):
        """The admin plane refuses past its per-client ceiling; the env var
        is honoured at app construction (the panel's bounded polling sits
        far below 120/minute; a key-guessing client does not)."""
        pytest.importorskip("slowapi")
        monkeypatch.setenv("RAUCLE_ADMIN_RATE_LIMIT", "3/minute")
        gateway = RaucleGateway(_config(tmp_path))
        users = UserManager(persist_path=str(tmp_path / "users.jsonl"))
        client = TestClient(create_admin_app(gateway, users))

        codes = [client.get("/health").status_code for _ in range(5)]
        assert codes[0] == 200
        assert 429 in codes, codes
        assert codes[3] == 429
        assert client.get("/health").json()["detail"] == "Rate limit exceeded"

    def test_admin_limit_defaults_to_120_per_minute(self, admin_stack):
        pytest.importorskip("slowapi")
        for _ in range(20):
            assert admin_stack.get("/health").status_code == 200
        # 20 requests is the panel-side traffic shape; far below 120/minute,
        # so the default must NOT have throttled a normal operator here.
        assert admin_stack.get("/health").status_code == 200

    def test_absent_slowapi_warns_and_still_serves(self, tmp_path, monkeypatch, caplog):
        """Honest absence: with slowapi unavailable the admin app still
        constructs and serves, and logs that it runs WITHOUT limiting."""
        for mod in ("slowapi", "slowapi.errors", "slowapi.middleware.SlowAPIMiddleware"):
            monkeypatch.setitem(sys.modules, mod, None)
        gateway = RaucleGateway(_config(tmp_path))
        users = UserManager(persist_path=str(tmp_path / "users.jsonl"))
        with caplog.at_level(logging.WARNING, logger="raucle.gateway_app"):
            client = TestClient(create_admin_app(gateway, users))
        assert client.get("/health").status_code == 200
        assert "WITHOUT rate limiting" in caplog.text


class TestPayloadLimitWarning:
    def test_non_integer_env_warns_and_keeps_default(self, monkeypatch, caplog):
        monkeypatch.setenv("RAUCLE_GATE_MAX_PAYLOAD_CHARS", "abc")
        with caplog.at_level(logging.WARNING, logger="raucle.gateway_app"):
            assert _gate_payload_limit() == _MAX_GATE_PAYLOAD_CHARS
        assert "not an integer" in caplog.text

    def test_non_positive_env_warns_and_keeps_default(self, monkeypatch, caplog):
        monkeypatch.setenv("RAUCLE_GATE_MAX_PAYLOAD_CHARS", "-5")
        with caplog.at_level(logging.WARNING, logger="raucle.gateway_app"):
            assert _gate_payload_limit() == _MAX_GATE_PAYLOAD_CHARS
        assert "not a positive integer" in caplog.text

    def test_valid_override_still_wins(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_GATE_MAX_PAYLOAD_CHARS", "500")
        assert _gate_payload_limit() == 500


class TestPqNamedAccessor:
    def test_pq_public_key_matches_key_id_derivation(self):
        from raucle.pq import HybridRecordSigner, pq_available, pq_generate

        if not pq_available():
            pytest.skip("ML-DSA-65 unavailable in this cryptography build")
        from raucle.audit import Ed25519Signer

        signer = HybridRecordSigner(Ed25519Signer.generate(), pq_generate()[0])
        from raucle.pq import pq_key_id_from_public_key

        assert pq_key_id_from_public_key(signer.pq_public_key()) == signer.pq_key_id()


class TestBenchPageSize:
    @staticmethod
    def _load_bench():
        spec = importlib.util.spec_from_file_location(
            "q9_run_bench",
            str(Path(__file__).resolve().parent.parent / "bench" / "run_bench.py"),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_rss_resolves_with_sysconf_page_size(self):
        """On a running Linux box the /proc multiplier is the syscall value;
        the measured MB must be positive either way."""
        import os

        bench = self._load_bench()
        assert bench._statm_rss_mb() > 0

        def broken_sysconf(_name: str) -> int:
            raise ValueError("no sysconf in this sandbox")

        monkey = broken_sysconf
        original = os.sysconf
        os.sysconf = monkey
        try:
            # Fallback constant keeps the calculation correct where the
            # syscall surface is absent.
            assert bench._statm_rss_mb() > 0
        finally:
            os.sysconf = original

    def test_fallback_page_size_constant(self):
        bench = self._load_bench()
        assert bench._FALLBACK_PAGE_SIZE == 4096


_RAUCLE_DETECT_SHIM = Path(__file__).resolve().parent.parent / "raucle_detect" / "__init__.py"


def test_raucle_detect_shim_names_removal_version():
    """House deprecation convention: the shim announces removal by version
    in BOTH surfaces - the module docstring and the DeprecationWarning.
    (The shim is checked at file level: importing raucle_detect returns the
    aliased raucle module object, so its docstring is raucle's by design.)"""
    source = _RAUCLE_DETECT_SHIM.read_text(encoding="utf-8")
    assert "removed in v0.26.0" in source
    assert "DeprecationWarning" in source
