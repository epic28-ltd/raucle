"""S4 acceptance: /.well-known/raucle-conformance serves the build-pinned record."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from fastapi.testclient import TestClient  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = REPO_ROOT / "docs" / "spec" / "conformance" / "conformance.json"
SCHEMA_PATH = REPO_ROOT / "docs" / "spec" / "conformance" / "raucle-conformance-v1.schema.json"
README_PATH = REPO_ROOT / "docs" / "spec" / "conformance" / "README.md"


def _client(tmp_path: Path) -> TestClient:
    from raucle.gateway import GatewayConfig, RaucleGateway
    from raucle.gateway_app import create_gateway_app

    config = GatewayConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
    )
    return TestClient(create_gateway_app(RaucleGateway(config)))


def _jsonschema_validate(instance: object) -> None:
    """Validate against the schema; skip the test module if jsonschema is absent."""
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed")
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(instance, schema)


class TestConformanceEndpoint:
    def test_endpoint_serves_committed_record(self, tmp_path: Path):
        client = _client(tmp_path)
        resp = client.get("/.well-known/raucle-conformance")
        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "no-store"
        assert resp.json() == json.loads(DATA_PATH.read_text())

    def test_record_validates_against_schema(self):
        _jsonschema_validate(json.loads(DATA_PATH.read_text()))
        schema_text = SCHEMA_PATH.read_text()
        assert '"raucle-conformance/v1"' in schema_text

    def test_record_claims_are_real_suits_that_pass(self):
        data = json.loads(DATA_PATH.read_text())
        assert data["schema_version"] == "raucle-conformance/v1"
        assert data["all_passed"] is True
        assert data["suites"], data
        for suite in data["suites"]:
            assert suite["passed"] is True
            assert (REPO_ROOT / suite["source"]).is_file(), suite["source"]

    def test_data_digest_pins_the_canonical_record(self):
        import hashlib

        data = json.loads(DATA_PATH.read_text())
        digest = data.pop("data_digest")
        canonical = json.dumps(data, indent=2, sort_keys=True)
        assert digest == "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    def test_generator_check_mode_matches_committed_file(self):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "gen_conformance_data.py"), "--check"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stderr

    def test_spec_docs_exist(self):
        assert README_PATH.is_file()
        assert SCHEMA_PATH.is_file()
        readme = README_PATH.read_text()
        assert "raucle-conformance" in readme
        assert "503" in readme
