"""Gateway entry point: starts both the gateway API and admin panel
in a single process using asyncio.

Usage:
    python -m raucle.gateway_server

Environment variables (see GatewayConfig for full list):
    RAUCLE_ADMIN_KEY       Admin panel API key (required)
    RAUCLE_SIGNER          Signer backend: local, aws, azure, vault
    RAUCLE_POLICY_FILE     Path to policy YAML file
    RAUCLE_Siem_ENABLED    Enable SIEM forwarding (true/false)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import uvicorn

from raucle.errors import AdminKeyMissingError, BootMemoryCeilingExceeded
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app, create_gateway_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def run_both_servers(
    config: GatewayConfig,
    gateway: RaucleGateway,
    users: UserManager,
) -> None:
    """Run the gateway API and admin panel concurrently in one process."""
    gateway_app = create_gateway_app(gateway)
    admin_app = create_admin_app(gateway, users)

    # X4: the boot self-test drives the gate with hostile types and
    # receipts its results before the servers accept traffic.
    gateway.run_boot_selftest_at_startup()

    gateway_config = uvicorn.Config(
        gateway_app,
        host=config.host,
        port=config.port,
        log_level="info",
    )
    admin_config = uvicorn.Config(
        admin_app,
        host=config.host,
        port=config.admin_port,
        log_level="info",
    )

    gateway_server = uvicorn.Server(gateway_config)
    admin_server = uvicorn.Server(admin_config)

    await asyncio.gather(
        gateway_server.serve(),
        admin_server.serve(),
    )


def _require_admin_key(config: GatewayConfig) -> None:
    """Refuse a keyless SERVING boot with the named error (Q9 review).

    The compose file (``${RAUCLE_ADMIN_KEY:?...}``) and the Helm chart
    (``required "config.adminKey is REQUIRED"``) already demand an admin
    key; this closes the bare ``docker run`` hole where the image boots
    anyway and serves a login page that accepts no credentials behind the
    public proxy. Dev/CLI paths never enter this module and are untouched.
    """
    if config.admin_api_key:
        return
    raise AdminKeyMissingError(
        "gateway serving mode requires an admin key: set RAUCLE_ADMIN_KEY "
        "(or RAUCLE_ADMIN_KEY_FILE pointing at a 0600 file holding the key) "
        "and restart. Without it the admin panel serves a login page that "
        "accepts no credentials, so the serving boot refuses instead of "
        "shipping a dead admin plane."
    )


def main() -> None:
    config = GatewayConfig.from_env()

    # Q9 (external v0.23.7 review): a keyless serving boot is a refusal,
    # not a warning. Same print-and-exit shape as the boot memory ceiling.
    try:
        _require_admin_key(config)
    except AdminKeyMissingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Initialise gateway
    logger.info("Initialising Raucle Gateway...")
    try:
        gateway = RaucleGateway(config)
    except BootMemoryCeilingExceeded as exc:
        # J1: refuse the boot with the named error rather than balloon into
        # an OOM kill loop under restart:always. The message names the
        # projected size, the ceiling and the rotate command.
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Initialise user management (A3: persisted to disk beside the data)
    users_file = os.environ.get(
        "RAUCLE_USERS_FILE", str(Path(config.receipt_store).parent / "users.jsonl")
    )
    users = UserManager(persist_path=users_file)
    # Bootstrap only when the store holds no admin. Re-adding the env key on
    # every boot resurrected an admin removed in the panel and kept a rotated
    # key valid for ever (RED-032).
    if config.admin_api_key and not any(u.role == "admin" for u in users.list_users()):
        users.add_user(config.admin_api_key, "admin", "Default Admin")
        logger.info("Bootstrap admin created from the configured admin key")
    elif config.admin_api_key:
        logger.info("Admin user store already holds an admin; configured key not re-applied")

    # Read-only demo account (auditor role): powers the admin panel's
    # View Demo button. Dashboard, connections and receipts only; every
    # privileged route 403s for this role.
    import os as _os

    demo_key = _os.environ.get("RAUCLE_DEMO_KEY", "")
    demo_mode = _os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")
    if demo_key and demo_mode:
        users.add_user(demo_key, "auditor", "Demo (read-only)")
        logger.info("Read-only demo user created from RAUCLE_DEMO_KEY")
    elif demo_key:
        logger.warning(
            "RAUCLE_DEMO_KEY is set without RAUCLE_DEMO_MODE: the key is not "
            "registered and /api/demo-key stays closed. Set RAUCLE_DEMO_MODE=1 "
            "for a public demo instance."
        )

    logger.info("Starting gateway API on %s:%d", config.host, config.port)
    logger.info("Starting admin panel on %s:%d", config.host, config.admin_port)

    try:
        asyncio.run(run_both_servers(config, gateway, users))
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
