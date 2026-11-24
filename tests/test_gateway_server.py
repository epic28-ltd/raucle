"""Smoke tests for the single-process gateway entry point.

``raucle/gateway_server.py`` was flagged by the dark-corners audit (1.4):
0% coverage and undocumented — but NOT dead code. It is the container
entrypoint referenced by ``Dockerfile.gateway`` (its ``CMD``),
``docker-compose.gateway.yml`` and ``deploy/helm/raucle-gateway``
(whose image is built from that Dockerfile). So the audit's "delete it"
branch does not apply; per the audit's recommendation the module gets a
smoke test plus a README mention.

These tests pin the process wiring: environment → ``GatewayConfig.from_env``
→ gateway/user bootstrap (default admin from ``RAUCLE_ADMIN_KEY``, the
read-only demo account from ``RAUCLE_DEMO_KEY``) → two uvicorn servers
(gateway API port + admin panel port) driven concurrently in one process.
Real socket serving is deliberately not exercised here — the FastAPI apps
themselves have dedicated suites (``test_gateway_http.py``, admin tests);
a stub uvicorn keeps this smoke fast, port-free and deterministic.
"""

from __future__ import annotations

import asyncio

import pytest

from raucle import gateway_server
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager


class _StubUvicornServer:
    """Stands in for ``uvicorn.Server``: records the config, never binds."""

    built: list = []

    def __init__(self, config) -> None:
        self.config = config
        self.served = False
        type(self).built.append(self)

    async def serve(self) -> None:
        self.served = True


@pytest.fixture()
def stub_uvicorn(monkeypatch) -> type[_StubUvicornServer]:
    monkeypatch.setattr(gateway_server.uvicorn, "Server", _StubUvicornServer)
    _StubUvicornServer.built = []
    return _StubUvicornServer


def _config(tmp_path, **over) -> GatewayConfig:
    cfg = GatewayConfig(
        host="127.0.0.1",
        port=8080,
        admin_port=8081,
        admin_api_key="smoke-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "creds.jsonl"),
    )
    for key, value in over.items():
        setattr(cfg, key, value)
    return cfg


def _gateway(tmp_path) -> tuple[GatewayConfig, RaucleGateway]:
    cfg = _config(tmp_path)
    return cfg, RaucleGateway(cfg)


def test_run_both_servers_wires_gateway_and_admin_uvicorn_servers(stub_uvicorn, tmp_path) -> None:
    cfg, gateway = _gateway(tmp_path)
    users = UserManager(persist_path=str(tmp_path / "users.jsonl"))
    asyncio.run(gateway_server.run_both_servers(cfg, gateway, users))

    assert len(_StubUvicornServer.built) == 2
    gateway_server_cfg, admin_server_cfg = _StubUvicornServer.built
    # Gateway API and admin panel: distinct ports, same host, both "served".
    assert gateway_server_cfg.config.host == "127.0.0.1"
    assert gateway_server_cfg.config.port == cfg.port
    assert admin_server_cfg.config.port == cfg.admin_port
    assert all(s.served for s in _StubUvicornServer.built)


def test_main_bootstrap_from_env_registers_admin_and_demo(
    stub_uvicorn, tmp_path, monkeypatch
) -> None:
    users_file = tmp_path / "users.jsonl"
    monkeypatch.setenv("RAUCLE_GATEWAY_PORT", "8180")
    monkeypatch.setenv("RAUCLE_ADMIN_PORT", "8181")
    monkeypatch.setenv("RAUCLE_ADMIN_KEY", "k-admin")
    monkeypatch.setenv("RAUCLE_DEMO_KEY", "k-demo")
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
    monkeypatch.setenv("RAUCLE_SIGNER", "local")
    monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
    monkeypatch.setenv("RAUCLE_RECEIPT_STORE", str(tmp_path / "receipts.jsonl"))
    monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("RAUCLE_REGISTRY_PATH", str(tmp_path / "registry.jsonl"))
    monkeypatch.setenv("RAUCLE_AGENT_CREDENTIALS", str(tmp_path / "creds.jsonl"))
    monkeypatch.setenv("RAUCLE_USERS_FILE", str(users_file))

    gateway_server.main()  # stubbed uvicorn: main() returns instead of serving

    # The entry point stood up exactly the two configured servers.
    assert [s.config.port for s in _StubUvicornServer.built] == [8180, 8181]
    assert len(_StubUvicornServer.built) == 2
    # Bootstrap created the durable user store with the default admin
    # (from RAUCLE_ADMIN_KEY) and the read-only demo (from RAUCLE_DEMO_KEY).
    mgr = UserManager(persist_path=str(users_file))
    assert mgr.get_user("k-admin").role == "admin"
    assert mgr.get_user("k-demo").role == "auditor"


def test_demo_key_without_demo_mode_is_not_registered(stub_uvicorn, tmp_path, monkeypatch) -> None:
    """RED-035: a demo key on a production instance must not become a user."""
    users_file = tmp_path / "users.jsonl"
    monkeypatch.setenv("RAUCLE_ADMIN_KEY", "k-admin")
    monkeypatch.setenv("RAUCLE_DEMO_KEY", "k-demo")
    monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
    monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
    monkeypatch.setenv("RAUCLE_RECEIPT_STORE", str(tmp_path / "receipts.jsonl"))
    monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("RAUCLE_REGISTRY_PATH", str(tmp_path / "registry.jsonl"))
    monkeypatch.setenv("RAUCLE_AGENT_CREDENTIALS", str(tmp_path / "creds.jsonl"))
    monkeypatch.setenv("RAUCLE_USERS_FILE", str(users_file))

    gateway_server.main()

    mgr = UserManager(persist_path=str(users_file))
    assert mgr.get_user("k-demo") is None


def test_main_without_admin_key_refuses_to_boot(
    stub_uvicorn, tmp_path, monkeypatch, capsys
) -> None:
    """Q9 review (external v0.23.7): a keyless SERVING boot is refused with
    the named error before any server is built. The pre-Q9 behaviour
    (warn, then boot both servers anyway) shipped a login page that
    accepts no credentials behind the public proxy; compose and Helm
    already required the key, so a bare ``docker run`` without one now
    exits 1 like the boot memory ceiling does."""
    for var in ("RAUCLE_ADMIN_KEY", "RAUCLE_DEMO_KEY"):
        monkeypatch.setenv(var, "")
    monkeypatch.setenv("RAUCLE_GATEWAY_PORT", "8182")
    monkeypatch.setenv("RAUCLE_ADMIN_PORT", "8183")
    monkeypatch.setenv("RAUCLE_SIGNER", "local")
    monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
    monkeypatch.setenv("RAUCLE_RECEIPT_STORE", str(tmp_path / "receipts.jsonl"))
    monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("RAUCLE_REGISTRY_PATH", str(tmp_path / "registry.jsonl"))
    monkeypatch.setenv("RAUCLE_AGENT_CREDENTIALS", str(tmp_path / "creds.jsonl"))
    monkeypatch.setenv("RAUCLE_USERS_FILE", str(tmp_path / "users.jsonl"))

    with pytest.raises(SystemExit) as excinfo:
        gateway_server.main()

    assert excinfo.value.code == 1
    # The refusal happened before any server was built.
    assert _StubUvicornServer.built == []
    err = capsys.readouterr().err
    assert "error:" in err
    assert "RAUCLE_ADMIN_KEY" in err


def test_require_admin_key_raises_and_passes_by_name(tmp_path) -> None:
    """The refusal helper: named error when the key is missing, silent
    pass-through when one is configured (the serving path's contract)."""
    from raucle.errors import AdminKeyMissingError

    with pytest.raises(AdminKeyMissingError, match="admin key"):
        gateway_server._require_admin_key(_config(tmp_path, admin_api_key=""))
    gateway_server._require_admin_key(_config(tmp_path))  # key set: no raise


def test_keyless_dev_paths_still_construct_the_gateway(tmp_path) -> None:
    """Q9 scope discipline: the refusal lives in the SERVING entry point
    only. Library use, the CLI detector server and tests construct a
    gateway with no admin key and keep working unchanged."""
    cfg = _config(tmp_path, admin_api_key="")
    gw = RaucleGateway(cfg)
    assert gw.config.admin_api_key == ""


def test_boot_memory_preflight_refusal_exits_cleanly_without_serving(
    stub_uvicorn, tmp_path, monkeypatch, capsys
) -> None:
    """J1: when the boot RSS projection exceeds the memory ceiling the entry
    point refuses with a named error naming ``raucle rotate-chain`` and never
    builds the servers (the pre-fix failure mode was an OOM kill loop under
    restart:always)."""
    import json as _json

    (tmp_path / "audit.jsonl").write_text(
        _json.dumps({"index": 0, "pad": "x" * 2_000_000}) + "\n", encoding="utf-8"
    )
    monkeypatch.setenv("RAUCLE_SIGNER", "local")
    monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
    monkeypatch.setenv("RAUCLE_RECEIPT_STORE", str(tmp_path / "receipts.jsonl"))
    monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("RAUCLE_AUDIT_PERSIST", "true")
    monkeypatch.setenv("RAUCLE_AUDIT_LOG", str(tmp_path / "gateway-audit.jsonl"))
    monkeypatch.setenv("RAUCLE_REGISTRY_PATH", str(tmp_path / "registry.jsonl"))
    monkeypatch.setenv("RAUCLE_USERS_FILE", str(tmp_path / "users.jsonl"))
    monkeypatch.setenv("RAUCLE_BOOT_MEM_CEILING_MB", "1")
    # Q9: the admin-key refusal runs BEFORE the memory preflight; give the
    # boot a key so this test reaches the ceiling refusal it is about.
    monkeypatch.setenv("RAUCLE_ADMIN_KEY", "k-admin")

    with pytest.raises(SystemExit) as excinfo:
        gateway_server.main()

    assert excinfo.value.code == 1
    # No servers were built: the refusal happened before any serve.
    assert _StubUvicornServer.built == []
    assert "raucle rotate-chain" in capsys.readouterr().err
