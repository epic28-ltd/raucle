"""RED-035: config writes cannot redirect the evidence trail.

An operator key could PUT `/api/config` with `audit_chain` pointing anywhere
on the filesystem, and the gateway would persist that and start writing there
on the next restart. The audit trail is the product, so moving it is an admin
decision and must stay inside the configured data root.

Also covers the demo key: it is an auditor key worth read access to the whole
receipt chain, and it used to be served unauthenticated by design whenever the
env var was set, in the same user table as real operators.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app

ADMIN_KEY = "admin-key-for-tests-0123456789"
OPERATOR_KEY = "operator-key-for-tests-0123456789"


def _client(tmp_path, *, data_root: str = "") -> tuple[TestClient, RaucleGateway]:
    cfg = GatewayConfig(
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key=ADMIN_KEY,
        signer_backend="local",
        data_root=data_root,
    )
    gateway = RaucleGateway(cfg)
    users = UserManager()
    users.add_user(ADMIN_KEY, "admin", "Admin")
    users.add_user(OPERATOR_KEY, "operator", "Op")
    return TestClient(create_admin_app(gateway, users)), gateway


def _hdr(key: str = ADMIN_KEY) -> dict[str, str]:
    return {"Authorization": key}


class TestEvidencePaths:
    def test_operator_may_not_move_the_audit_chain(self, tmp_path):
        client, _gateway = _client(tmp_path)
        resp = client.put(
            "/api/config",
            headers=_hdr(OPERATOR_KEY),
            json={"audit_chain": str(tmp_path / "elsewhere.jsonl")},
        )
        assert resp.status_code == 403
        assert "admin role" in resp.json()["detail"]

    def test_admin_may_move_it_inside_the_data_root(self, tmp_path):
        client, gateway = _client(tmp_path)
        target = str(tmp_path / "audit-moved.jsonl")
        resp = client.put("/api/config", headers=_hdr(), json={"audit_chain": target})
        assert resp.status_code == 200, resp.text
        assert gateway.config.audit_chain == target

    def test_relative_path_is_refused(self, tmp_path):
        client, gateway = _client(tmp_path)
        before = gateway.config.policy_file
        resp = client.put("/api/config", headers=_hdr(), json={"policy_file": "policies.yaml"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "bad_evidence_path"
        assert any("absolute" in e for e in resp.json()["detail"]["errors"])
        assert gateway.config.policy_file == before  # rolled back

    def test_path_outside_the_data_root_is_refused_and_rolled_back(self, tmp_path):
        root = tmp_path / "data"
        root.mkdir()
        client, gateway = _client(tmp_path, data_root=str(root))
        before = gateway.config.audit_chain
        resp = client.put("/api/config", headers=_hdr(), json={"audit_chain": "/tmp/evil.jsonl"})
        assert resp.status_code == 400
        assert any("data root" in e for e in resp.json()["detail"]["errors"])
        assert gateway.config.audit_chain == before

    def test_every_evidence_field_is_guarded(self, tmp_path):
        from raucle.gateway_app import EVIDENCE_PATH_FIELDS

        client, gateway = _client(tmp_path, data_root=str(tmp_path / "data"))
        (tmp_path / "data").mkdir(exist_ok=True)
        for field in EVIDENCE_PATH_FIELDS:
            before = getattr(gateway.config, field)
            resp = client.put("/api/config", headers=_hdr(), json={field: "/etc/passwd"})
            assert resp.status_code == 400, f"{field} was not guarded"
            assert getattr(gateway.config, field) == before

    def test_data_root_defaults_to_the_receipt_dir(self, tmp_path):
        client, gateway = _client(tmp_path)
        # receipt_store lives directly under tmp_path, so its parent is the root
        resp = client.put(
            "/api/config",
            headers=_hdr(),
            json={"audit_chain": str(tmp_path.parent / "outside.jsonl")},
        )
        assert resp.status_code == 400
        assert gateway.config.audit_chain.endswith("audit.jsonl")


class TestDemoKey:
    def test_demo_key_needs_demo_mode(self, tmp_path, monkeypatch):
        client, _gateway = _client(tmp_path)
        monkeypatch.setenv("RAUCLE_DEMO_KEY", "demo-auditor-key")
        monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
        assert client.get("/api/demo-key").status_code == 404

    def test_demo_mode_serves_it(self, tmp_path, monkeypatch):
        client, _gateway = _client(tmp_path)
        monkeypatch.setenv("RAUCLE_DEMO_KEY", "demo-auditor-key")
        monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
        resp = client.get("/api/demo-key")
        assert resp.status_code == 200
        assert resp.json()["demo_key"] == "demo-auditor-key"


class TestDataRootEnv:
    def test_read_from_env(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_DATA_ROOT", "/srv/raucle")
        assert GatewayConfig.from_env().data_root == "/srv/raucle"

    def test_defaults_to_empty(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_DATA_ROOT", raising=False)
        assert GatewayConfig.from_env().data_root == ""
