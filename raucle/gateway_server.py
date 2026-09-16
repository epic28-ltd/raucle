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


def main() -> None:
    config = GatewayConfig.from_env()

    if not config.admin_api_key:
        logger.warning(
            "RAUCLE_ADMIN_KEY is not set. Admin panel will be open with no auth. "
            "Set RAUCLE_ADMIN_KEY to secure it."
        )

    # Initialise gateway
    logger.info("Initialising Raucle Gateway...")
    gateway = RaucleGateway(config)

    # Initialise user management (A3: persisted to disk beside the data)
    users_file = os.environ.get(
        "RAUCLE_USERS_FILE", str(Path(config.receipt_store).parent / "users.jsonl")
    )
    users = UserManager(persist_path=users_file)
    if config.admin_api_key:
        users.add_user(config.admin_api_key, "admin", "Default Admin")
        logger.info("Default admin user created from RAUCLE_ADMIN_KEY")

    # Read-only demo account (auditor role): powers the admin panel's
    # View Demo button. Dashboard, connections and receipts only; every
    # privileged route 403s for this role.
    import os as _os

    demo_key = _os.environ.get("RAUCLE_DEMO_KEY", "")
    if demo_key:
        users.add_user(demo_key, "auditor", "Demo (read-only)")
        logger.info("Read-only demo user created from RAUCLE_DEMO_KEY")

    logger.info("Starting gateway API on %s:%d", config.host, config.port)
    logger.info("Starting admin panel on %s:%d", config.host, config.admin_port)

    try:
        asyncio.run(run_both_servers(config, gateway, users))
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
