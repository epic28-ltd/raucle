"""Admin panel + gateway API FastAPI application.

This module provides:
  - Gateway API on port 8080: POST /gate (agent tool calls)
  - Admin panel on port 8081: policy management, stats, receipts, config
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from raucle.gateway import (
    GatewayUser,
    RaucleGateway,
    UserManager,
)

_BEARER_PREFIX = "Bearer "

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class GateRequest(BaseModel):
    """A tool call from an AI agent to be gated."""

    tool: str = Field(..., description="Tool name to call")
    args: dict[str, Any] = Field(default_factory=dict, description="Tool call arguments")
    agent_id: str = Field(default="", description="Agent identity (optional, defaults to policy)")
    source: str = Field(default="", description="Inbound source (agent name, IP, or service ID)")
    destination: str = Field(
        default="", description="Outbound destination (API endpoint, service, or tool target)"
    )


class PolicyUpdateRequest(BaseModel):
    """A policy file update from the admin panel."""

    content: str = Field(..., description="YAML policy content")


class UserCreateRequest(BaseModel):
    """Create a new admin panel user."""

    api_key: str
    role: str = Field(..., description="admin, operator, or auditor")
    name: str = Field(default="")


class ConfigUpdateRequest(BaseModel):
    """Update gateway configuration fields."""

    host: str | None = None
    port: int | None = None
    admin_port: int | None = None
    signer_backend: str | None = None
    kms_key_id: str | None = None
    kms_region: str | None = None
    policy_file: str | None = None
    policy_dir: str | None = None
    receipt_store: str | None = None
    audit_chain: str | None = None
    audit_persist: bool | None = None
    audit_log_file: str | None = None
    siem_enabled: bool | None = None
    siem_backend: str | None = None
    siem_url: str | None = None
    siem_token: str | None = None
    compliance_framework: str | None = None
    registry_path: str | None = None
    health_check_token: str | None = None


class SIEMConfigRequest(BaseModel):
    """Update SIEM forwarding configuration."""

    enabled: bool = False
    backend: str = Field(default="", description="splunk, elastic, sentinel")
    url: str = ""
    token: str = ""


# ---------------------------------------------------------------------------
# Gateway API (port 8080)
# ---------------------------------------------------------------------------


def create_gateway_app(gateway: RaucleGateway) -> FastAPI:
    """Create the gateway API app (agent-facing)."""
    app = FastAPI(
        title="Raucle Gateway",
        description="AI agent governance gateway",
        version="0.1.0",
    )
    _limiter = None
    try:
        from slowapi import Limiter
        from slowapi.errors import RateLimitExceeded
        from slowapi.middleware import SlowAPIMiddleware
        from slowapi.util import get_remote_address

        _limiter = Limiter(key_func=get_remote_address, default_limits=["1000/minute"])
        app.state.limiter = _limiter
        app.add_exception_handler(
            RateLimitExceeded,
            lambda req, exc: JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded", "retry_after": "60"},
            ),
        )
        app.add_middleware(SlowAPIMiddleware)
    except ImportError:
        pass  # slowapi not installed, no rate limiting

    @app.post("/gate")
    def gate_tool_call(
        request: Request,
        req: GateRequest,
        x_api_key: str | None = Header(None, alias="X-Api-Key"),
        x_capability_token: str | None = Header(None, alias="X-Capability-Token"),
    ) -> dict[str, Any]:
        """Gate a tool call. Returns allow/deny/escalate decision.

        Authentication (RAUCLE_GATE_AUTH): "off" trusts the declared
        agent_id (internal networks only); "apikey" requires X-Api-Key;
        "token" requires X-Capability-Token (verified against the trust
        registry). On auth failure the decision is DENY with the reason
        - a 401 would hide the denial from the receipt trail, and an
        unauthenticated decision must still be receipted as denied.
        """
        import json as _json

        token_dict = None
        if x_capability_token:
            try:
                token_dict = _json.loads(x_capability_token)
            except _json.JSONDecodeError:
                return {
                    "decision": "deny",
                    "reason": "X-Capability-Token is not valid JSON",
                    "tool": req.tool,
                    "agent_id": req.agent_id,
                    "source": req.source,
                    "destination": req.destination,
                    "policy": None,
                    "args_hash": "",
                    "receipt_id": None,
                    "latency_us": 0,
                    "timestamp": "",
                }
        agent_id, auth_reason = gateway.authenticate_caller(
            api_key=x_api_key,
            capability_token=token_dict,
            tool=req.tool,
            args=req.args,
            declared_agent_id=req.agent_id,
        )
        if agent_id is None:
            return {
                "decision": "deny",
                "reason": f"unauthenticated: {auth_reason}",
                "tool": req.tool,
                "agent_id": req.agent_id,
                "source": req.source,
                "destination": req.destination,
                "policy": None,
                "args_hash": "",
                "receipt_id": None,
                "latency_us": 0,
                "timestamp": "",
            }
        return gateway.check_tool_call(req.tool, req.args, agent_id, req.source, req.destination)

    @app.get("/health")
    def health(authorization: str | None = Header(None)) -> dict[str, str]:
        if gateway.config.health_check_token:
            key = authorization or ""
            if key.startswith(_BEARER_PREFIX):
                key = key[len(_BEARER_PREFIX) :]
            import hmac as _hmac

            if not _hmac.compare_digest(key, gateway.config.health_check_token):
                raise HTTPException(status_code=401, detail="Health check unauthorized")
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# Admin Panel API (port 8081)
# ---------------------------------------------------------------------------


def _validate_policy_content(content: str) -> dict[str, Any]:
    """Parse and validate policy YAML content.

    Returns ``{"valid": True}`` when the content is a well-formed policy
    document, ``{"valid": False, "error": ...}`` otherwise. Used as the
    sanitiser for user-supplied policy content before it is written to
    disk (taint-flow break for S2083).
    """
    try:
        import yaml

        from raucle.policy import PolicyFile

        data = yaml.safe_load(content)
        PolicyFile.from_dict(data)
        return {"valid": True}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def _check_auth(
    users: UserManager,
    authorization: str | None,
    x_totp: str | None,
) -> GatewayUser:
    """Extract and validate the API key and optional TOTP code."""
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    key = authorization
    if key.startswith(_BEARER_PREFIX):
        key = key[len(_BEARER_PREFIX) :]
    user = users.get_user(key)
    if user is None:
        raise HTTPException(status_code=403, detail="Invalid API key")
    if user.requires_mfa():
        if not x_totp:
            raise HTTPException(
                status_code=401,
                detail="MFA required: provide X-TOTP header with 6-digit code",
            )
        if not users.verify_totp(user, x_totp):
            raise HTTPException(status_code=403, detail="Invalid TOTP code")
    return user


def _check_access(users: UserManager, user: GatewayUser, resource: str) -> None:
    """Raise 403 unless the user's role may access *resource*."""
    if not users.can_access(user.api_key, resource):
        raise HTTPException(
            status_code=403, detail=f"Role '{user.role}' cannot access '{resource}'"
        )


def create_admin_app(gateway: RaucleGateway, users: UserManager) -> FastAPI:
    """Create the admin panel app (operator-facing).

    Thin composition root: auth closures over *users*, then endpoint
    groups are registered by dedicated module-level functions.
    """

    def check_auth(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> GatewayUser:
        return _check_auth(users, authorization, x_totp)

    def check_access(user: GatewayUser, resource: str) -> None:
        _check_access(users, user, resource)

    app = FastAPI(
        title="Raucle Gateway Admin",
        description="Enterprise admin panel for policy, stats, and config",
        version="0.1.0",
    )

    _register_health_routes(app, gateway)
    _register_stats_routes(app, gateway, check_auth, check_access)
    _register_learn_routes(app, gateway, check_auth, check_access)
    _register_policy_routes(app, gateway, check_auth, check_access)
    _register_receipt_routes(app, gateway, check_auth, check_access)
    _register_siem_routes(app, gateway, check_auth, check_access)
    _register_user_routes(app, gateway, users, check_auth, check_access)
    _register_config_routes(app, gateway, check_auth, check_access)
    _register_ui_routes(app)

    return app


def _register_health_routes(app: FastAPI, gateway: RaucleGateway) -> None:
    """Health endpoint (optional auth via health_check_token)."""

    @app.get("/health")
    def admin_health(authorization: str | None = Header(None)) -> dict[str, str]:
        if gateway.config.health_check_token:
            key = authorization or ""
            if key.startswith(_BEARER_PREFIX):
                key = key[len(_BEARER_PREFIX) :]
            import hmac as _hmac

            if not _hmac.compare_digest(key, gateway.config.health_check_token):
                raise HTTPException(status_code=401, detail="Health check unauthorized")
        return {"status": "ok"}

    @app.get(
        "/api/demo-key",
        responses={
            "200": {"description": "Public read-only demo key"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_key() -> dict[str, str]:
        """Public endpoint exposing the read-only demo key (RAUCLE_DEMO_KEY).

        The key this returns holds the auditor role only: dashboard, connections
        and receipts, all read-only. It exists so the admin panel's View Demo
        button can enter demo mode without the visitor needing credentials.
        Never returns an admin or operator key.
        """
        import os

        dk = os.environ.get("RAUCLE_DEMO_KEY", "")
        if not dk:
            raise HTTPException(404, "demo mode not configured")
        return {"demo_key": dk}


def _register_stats_routes(
    app: FastAPI, gateway: RaucleGateway, check_auth: Any, check_access: Any
) -> None:
    """Dashboard stats and the live connection log."""

    @app.get(
        "/api/stats",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def get_stats(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "stats")
        return gateway.get_stats()

    @app.get(
        "/api/connections",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def get_connections(
        limit: int = 100,
        tool: str = "",
        decision: str = "",
        source: str = "",
        destination: str = "",
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        """Return recent connections, optionally filtered."""
        user = check_auth(authorization)
        check_access(user, "stats")
        connections = gateway.get_connections(limit=500)
        # Apply filters
        if tool:
            connections = [c for c in connections if tool.lower() in c.get("tool", "").lower()]
        if decision:
            connections = [
                c for c in connections if decision.lower() in c.get("decision", "").lower()
            ]
        if source:
            connections = [c for c in connections if source.lower() in c.get("source", "").lower()]
        if destination:
            connections = [
                c for c in connections if destination.lower() in c.get("destination", "").lower()
            ]
        return {"connections": connections[:limit], "count": len(connections)}


def _register_learn_routes(
    app: FastAPI, gateway: RaucleGateway, check_auth: Any, check_access: Any
) -> None:
    """Learn mode: observe unmatched traffic, draft policies from it.

    Fail-closed by design: learn mode never authorises traffic. The gate
    records unmatched calls only when RAUCLE_LEARN_MODE is enabled, and
    the endpoints below expose counts and a draft policy for human review.
    The draft is never deployed automatically: the operator copies it
    into the policy editor, edits, saves, and reloads.
    """

    @app.get(
        "/api/learn/summary",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Insufficient role"},
        },
    )
    def learn_summary(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        return gateway.learn_summary()

    @app.get(
        "/api/learn/draft",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Insufficient role"},
            "200": {"description": "Draft policy YAML (empty string if nothing learned)"},
        },
    )
    def learn_draft(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        return {"yaml": gateway.draft_policy()}

    @app.post(
        "/api/learn/clear",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Insufficient role"},
        },
    )
    def learn_clear(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        gateway._learn_clear()
        return {"status": "cleared"}


def _policy_dir_response(
    policy_dir: str,
    validate_path: Any,
    file: str,
) -> dict[str, Any]:
    """Build the directory-mode response for GET /api/policies.

    SECURITY: never touches a user-supplied path. The requested file is
    matched by basename against the files enumerated from the policy
    directory via glob (server-controlled list), making path traversal
    structurally impossible.
    """
    pdir = validate_path(policy_dir, must_exist=False)
    if not pdir.is_dir():
        return {"content": "", "files": [], "mode": "dir", "path": str(pdir)}
    files = sorted(pdir.glob("*.yaml"))
    file_list = [{"name": f.name, "path": str(f), "size": f.stat().st_size} for f in files]
    if file:
        target = next((f for f in files if f.name == Path(file).name), None)
        if target is None:
            raise HTTPException(404, "File not found in policy directory")
        content = target.read_text(encoding="utf-8")
    elif files:
        content = files[0].read_text(encoding="utf-8")
    else:
        content = ""
    return {"content": content, "files": file_list, "mode": "dir", "path": str(pdir)}


def _register_policy_routes(
    app: FastAPI, gateway: RaucleGateway, check_auth: Any, check_access: Any
) -> None:
    """Policy file management (view, edit, validate, reload)."""

    @app.get(
        "/api/policies",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "File not found"},
        },
    )
    def get_policies(
        file: str = "",
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        """Get policy file content. If policy_dir is set, list all files."""
        from raucle._paths import validate_path

        user = check_auth(authorization)
        check_access(user, "policies")
        if gateway.config.policy_dir:
            return _policy_dir_response(gateway.config.policy_dir, validate_path, file)
        policy_path = validate_path(gateway.config.policy_file, must_exist=False)
        content = policy_path.read_text() if policy_path.exists() else ""
        return {
            "content": content,
            "files": [{"name": policy_path.name, "path": str(policy_path)}],
            "mode": "single",
            "path": str(policy_path),
        }

    @app.put(
        "/api/policies",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def update_policies(
        req: PolicyUpdateRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        # SECURITY: validate user-supplied YAML before writing to disk,
        # then write the CANONICALLY RE-SERIALISED document (not the raw
        # request string). This breaks the request-to-disk taint flow:
        # what lands on disk is parser output, not raw user input.
        import yaml as _yaml

        from raucle._paths import validate_path
        from raucle.policy import PolicyFile as _PolicyFile

        try:
            parsed = _yaml.safe_load(req.content)
            _PolicyFile.from_dict(parsed)
        except Exception as exc:
            raise HTTPException(400, f"Invalid policy content: {exc}") from exc
        safe_content = _yaml.dump(parsed, default_flow_style=False, sort_keys=False)

        policy_path = validate_path(gateway.config.policy_file, must_exist=False)
        policy_path.write_text(safe_content, encoding="utf-8")
        result = gateway.reload_policies()
        return result

    @app.post(
        "/api/policies/reload",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def reload_policies(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        return gateway.reload_policies()

    @app.post(
        "/api/policies/validate",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def validate_policy(
        req: PolicyUpdateRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        return _validate_policy_content(req.content)


def _register_receipt_routes(
    app: FastAPI, gateway: RaucleGateway, check_auth: Any, check_access: Any
) -> None:
    """Provenance receipt browsing."""

    @app.get(
        "/api/receipts",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def get_receipts(limit: int = 50, authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "receipts")
        from raucle._paths import validate_path

        path = validate_path(gateway.config.receipt_store, must_exist=False)
        if not path.exists():
            return {"receipts": [], "count": 0}
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        recent = lines[-limit:] if len(lines) > limit else lines
        receipts = []
        import contextlib

        for line in recent:
            with contextlib.suppress(json.JSONDecodeError):
                receipts.append(json.loads(line))
        return {"receipts": receipts, "count": len(receipts), "total": len(lines)}


def _register_siem_routes(
    app: FastAPI, gateway: RaucleGateway, check_auth: Any, check_access: Any
) -> None:
    """SIEM forwarding configuration."""

    @app.get(
        "/api/siem",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def get_siem_config(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "config")
        return {
            "enabled": gateway.siem.enabled,
            "backend": gateway.siem.backend,
            "url": gateway.siem.url,
            "token_configured": bool(gateway.siem.token),
            "buffered_events": len(gateway.siem.buffered_events()),
        }

    @app.put(
        "/api/siem",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def update_siem_config(
        req: SIEMConfigRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "config")
        gateway.config.siem_enabled = req.enabled
        gateway.config.siem_backend = req.backend
        gateway.config.siem_url = req.url
        gateway.config.siem_token = req.token
        gateway.siem.enabled = req.enabled
        gateway.siem.backend = req.backend
        gateway.siem.url = req.url
        gateway.siem.token = req.token
        return {"status": "ok"}


def _register_user_routes(
    app: FastAPI, gateway: RaucleGateway, users: UserManager, check_auth: Any, check_access: Any
) -> None:
    """User management and TOTP MFA administration."""

    @app.get(
        "/api/users",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
        },
    )
    def list_users(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "users")
        return {
            "users": [
                {"api_key": u.api_key[:8] + "...", "role": u.role, "name": u.name}
                for u in users.list_users()
            ]
        }

    @app.post(
        "/api/users",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "400": {"description": "Invalid role"},
        },
    )
    def create_user(
        req: UserCreateRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "users")
        if req.role not in ("admin", "operator", "auditor"):
            raise HTTPException(400, "role must be admin, operator, or auditor")
        new_user = users.add_user(req.api_key, req.role, req.name)
        return {"status": "ok", "api_key": new_user.api_key[:8] + "...", "role": new_user.role}

    @app.delete(
        "/api/users/{api_key}",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "User not found"},
        },
    )
    def delete_user(api_key: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "users")
        if users.remove_user(api_key):
            return {"status": "ok"}
        raise HTTPException(404, "user not found")

    @app.post(
        "/api/users/{api_key}/mfa/setup",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "User not found"},
        },
    )
    def setup_mfa(api_key: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        """Generate a TOTP secret and provisioning URI for a user.

        Returns the secret and otpauth:// URI. The user must scan the
        QR code with their authenticator app and then call /mfa/verify
        with the first 6-digit code to confirm MFA setup.
        """
        user = check_auth(authorization)
        check_access(user, "users")
        result = users.setup_mfa(api_key)
        if result is None:
            raise HTTPException(404, "user not found or pyotp not installed")
        return {
            "status": "ok",
            "secret": result["secret"],
            "uri": result["uri"],
            "qr_instructions": "Scan this URI with Google Authenticator, Authy, or 1Password. Then call /mfa/verify with the 6-digit code.",
        }

    @app.post(
        "/api/users/{api_key}/mfa/verify",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "400": {"description": "Invalid or missing code"},
            "404": {"description": "User not found"},
        },
    )
    def verify_mfa_setup(
        api_key: str,
        code: str = "",
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        """Verify the first TOTP code and enable MFA for the user."""
        user = check_auth(authorization)
        check_access(user, "users")
        if not code:
            raise HTTPException(400, "code parameter is required")
        if users.verify_mfa(api_key, code):
            return {"status": "ok", "mfa_enabled": True}
        raise HTTPException(400, "Invalid TOTP code")

    @app.post(
        "/api/users/{api_key}/mfa/disable",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "User not found"},
        },
    )
    def disable_mfa(api_key: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        """Disable MFA for a user. Requires admin role."""
        user = check_auth(authorization)
        check_access(user, "users")
        if users.disable_mfa(api_key):
            return {"status": "ok", "mfa_enabled": False}
        raise HTTPException(404, "user not found")


def _no_change_response() -> dict[str, Any]:
    """Response body for a config update with no effective changes."""
    return {
        "status": "ok",
        "changed": [],
        "restart_needed": False,
        "message": "No changes detected",
    }


def _apply_secret_updates(gateway: RaucleGateway, req: ConfigUpdateRequest) -> list[str]:
    """Apply secret fields excluded from update_from_dict. Returns changed names."""
    applied: list[str] = []
    if req.siem_token is not None:
        gateway.config.siem_token = req.siem_token
        gateway.siem.token = req.siem_token
        applied.append("siem_token")
    if req.health_check_token is not None:
        gateway.config.health_check_token = req.health_check_token
        applied.append("health_check_token")
    return applied


def _apply_runtime_siem(gateway: RaucleGateway, changed: list[str]) -> None:
    """Push SIEM fields that can take effect without a restart."""
    siem_fields = {
        "siem_enabled": "enabled",
        "siem_backend": "backend",
        "siem_url": "url",
    }
    for cfg_field, siem_field in siem_fields.items():
        if cfg_field in changed:
            setattr(gateway.siem, siem_field, getattr(gateway.config, cfg_field))


def _register_config_routes(
    app: FastAPI, gateway: RaucleGateway, check_auth: Any, check_access: Any
) -> None:
    """Gateway configuration view and update."""

    @app.get("/api/config")
    def get_config(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "config")
        c = gateway.config
        return {
            "host": c.host,
            "port": c.port,
            "admin_port": c.admin_port,
            "signer_backend": c.signer_backend,
            "kms_key_id": c.kms_key_id,
            "kms_region": c.kms_region,
            "policy_file": c.policy_file,
            "policy_dir": c.policy_dir,
            "receipt_store": c.receipt_store,
            "audit_chain": c.audit_chain,
            "audit_persist": c.audit_persist,
            "audit_log_file": c.audit_log_file,
            "siem_enabled": c.siem_enabled,
            "siem_backend": c.siem_backend,
            "siem_url": c.siem_url,
            "siem_token_configured": bool(c.siem_token),
            "compliance_framework": c.compliance_framework,
            "registry_path": c.registry_path,
            "health_check_token_set": bool(c.health_check_token),
            "config_file": c.config_file,
        }

    @app.put("/api/config")
    def update_config(
        req: ConfigUpdateRequest,
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        """Update gateway configuration. Writes to YAML config file.

        Accepts a JSON body with any GatewayConfig fields (except admin_api_key).
        Changes are applied to the running gateway and persisted to disk.
        Some changes (ports, host, signer) require a restart to take effect.
        """
        user = check_auth(authorization)
        check_access(user, "config")

        updates = {k: v for k, v in req.model_dump().items() if v is not None}
        if not updates:
            return _no_change_response()

        changed = gateway.config.update_from_dict(updates)
        changed += _apply_secret_updates(gateway, req)

        try:
            gateway.config.save_to_yaml()
        except Exception as exc:
            return {
                "status": "partial",
                "changed": changed,
                "restart_needed": False,
                "warning": f"Config updated in memory but failed to persist: {exc}",
            }

        _apply_runtime_siem(gateway, changed)

        restart_needed = any(
            f in changed for f in ("host", "port", "admin_port", "signer_backend", "kms_key_id")
        )
        return {
            "status": "ok",
            "changed": changed,
            "restart_needed": restart_needed,
            "message": f"Config saved to {gateway.config.config_file}"
            if changed
            else "No changes detected",
        }


def _register_ui_routes(app: FastAPI) -> None:
    """Admin panel and topology HTML pages."""

    @app.get("/", response_class=HTMLResponse)
    def admin_panel() -> str:
        return ADMIN_PANEL_HTML

    @app.get("/topology", response_class=HTMLResponse)
    def topology_view() -> str:
        return TOPOLOGY_HTML

    return app


# ---------------------------------------------------------------------------
# Admin Panel HTML (inline, no build step required)
# ---------------------------------------------------------------------------


ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Raucle Gateway</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: #fff; color: #171717; }
  .header { display: flex; align-items: center; justify-content: space-between;
    padding: 10px 24px; border-bottom: 1px solid #f0f0f0; position: sticky; top: 0; background: #fff; z-index: 40; }
  .header-left { display: flex; align-items: center; gap: 16px; }
  .logo { font-size: 18px; font-weight: 600; letter-spacing: -0.025em; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: #f5f5f5; color: #737373; font-weight: 500; }
  .tabs { display: flex; gap: 2px; padding: 0 24px; border-bottom: 1px solid #f0f0f0; }
  .tab { padding: 10px 16px; cursor: pointer; color: #a3a3a3; font-size: 14px; border-bottom: 2px solid transparent; transition: all 0.15s; }
  .tab:hover { color: #525252; }
  .tab.active { color: #171717; border-bottom-color: #171717; }
  .content { max-width: 1400px; margin: 0 auto; padding: 24px; }
  .card { background: #fff; border: 1px solid #f0f0f0; border-radius: 12px; padding: 24px; margin-bottom: 16px; }
  .card-title { font-size: 13px; font-weight: 600; color: #737373; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 16px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; }
  .stat { text-align: center; padding: 16px 0; }
  .stat-value { font-size: 36px; font-weight: 700; letter-spacing: -0.03em; }
  .stat-label { font-size: 12px; color: #a3a3a3; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; font-size: 12px; font-weight: 600; color: #a3a3a3; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #f0f0f0; }
  td { padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #f7f7f7; }
  tr:hover td { background: #fafafa; }
  .badge-allow { background: #171717; color: #fff; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 500; }
  .badge-deny { background: #f5f5f5; color: #525252; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 500; }
  .badge-escalate { background: #f5f5f5; color: #737373; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 500; border: 1px solid #e5e5e5; }
  .btn { background: #171717; color: #fff; border: none; padding: 8px 20px; border-radius: 999px; cursor: pointer; font-size: 14px; font-weight: 500; }
  .btn:hover { background: #000; }
  .btn-secondary { background: #f5f5f5; color: #171717; }
  .btn-secondary:hover { background: #ebebeb; }
  .input { padding: 8px 14px; background: #fff; border: 1px solid #e5e5e5; border-radius: 999px; font-size: 14px; font-family: inherit; color: #171717; outline: none; }
  .input:focus { border-color: #171717; }
  textarea.input { border-radius: 12px; }
  .editor { width: 100%; height: 400px; background: #fafafa; color: #171717; border: 1px solid #e5e5e5; border-radius: 12px; padding: 16px; font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; resize: vertical; }
  .editor:focus { outline: none; border-color: #171717; }
  .actions { display: flex; gap: 8px; margin-top: 16px; }
  .login { max-width: 360px; margin: 80px auto; }
  .login .input { width: 100%; margin-bottom: 12px; }
  .hidden { display: none; }
  pre { background: #fafafa; padding: 16px; border-radius: 12px; border: 1px solid #f0f0f0; overflow-x: auto; font-size: 13px; font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  .toggle { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 14px; color: #525252; }
  .toggle input { width: 16px; height: 16px; accent-color: #171717; }
  .live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  .file-list { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
  .file-chip { padding: 4px 12px; border-radius: 999px; background: #f5f5f5; font-size: 12px; color: #525252; cursor: pointer; }
  .file-chip:hover { background: #ebebeb; }
  .file-chip.active { background: #171717; color: #fff; }
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
  .dir-toggle { display: inline-flex; background: #f5f5f5; border-radius: 8px; padding: 2px; gap: 2px; }
  .dir-toggle button { border: none; background: transparent; padding: 6px 14px; font-size: 13px; border-radius: 6px; cursor: pointer; color: #737373; font-family: inherit; }
  .dir-toggle button.active { background: #fff; color: #171717; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }

  /* === TRAFFIC FLOW GRAPH (Netbird-style) === */
  .flow-graph { position: relative; min-height: 500px; overflow: hidden; }
  .flow-svg { position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 1; }
  .flow-cols { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0; position: relative; z-index: 2; }
  .flow-col { display: flex; flex-direction: column; }
  .flow-col-mid { border-left: 1px solid #f0f0f0; border-right: 1px solid #f0f0f0; background: #fafafa; }
  .flow-col-header { padding: 10px 16px; font-size: 12px; font-weight: 600; color: #737373; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #f0f0f0; display: flex; align-items: center; justify-content: space-between; }
  .flow-col-header .count { font-size: 11px; color: #a3a3a3; font-weight: 400; }
  .flow-col-filter { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }
  .flow-col-filter input { width: 100%; font-size: 12px; padding: 6px 10px; border: 1px solid #e5e5e5; border-radius: 8px; }
  .flow-col-body { flex: 1; overflow-y: auto; max-height: 400px; }
  .flow-item { padding: 10px 16px; border-bottom: 1px solid #f7f7f7; cursor: pointer; transition: all 0.15s; position: relative; }
  .flow-item:hover { background: #f5f5f5; }
  .flow-item.active { background: #f0f0f0; border-left: 3px solid #171717; }
  .flow-item.highlighted { background: #f0fdf4; }
  .flow-item-name { font-size: 13px; font-weight: 500; color: #171717; }
  .flow-item-meta { font-size: 11px; color: #a3a3a3; margin-top: 2px; }
  .flow-item-bar { height: 3px; border-radius: 2px; margin-top: 6px; background: #f0f0f0; overflow: hidden; }
  .flow-item-bar-fill { height: 100%; border-radius: 2px; transition: width 0.3s; }
  .flow-item-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; vertical-align: middle; }
  .dot-allow { background: #22c55e; }
  .dot-deny { background: #ef4444; }
  .dot-escalate { background: #f59e0b; }
  .flow-empty { text-align: center; padding: 40px 16px; color: #a3a3a3; font-size: 13px; }
  .protocol-tag { font-size: 10px; padding: 1px 6px; border-radius: 4px; background: #f0f0f0; color: #737373; margin-left: 4px; font-family: ui-monospace, monospace; }

  /* Connection log */
  .conn-table { max-height: 400px; overflow-y: auto; }
  .conn-row { cursor: pointer; }
  .conn-row.selected td { background: #f5f5f5; }

/* ===== Embedded live topology (hero-styled, light) ===== */
.topo-canvas{
  position:relative;width:100%;height:420px;border-radius:10px;overflow:hidden;
  background-color:#f8f9fb;
  background-image:radial-gradient(rgba(17,18,24,0.10) 1px,transparent 1px);
  background-size:24px 24px;
  cursor:grab;user-select:none;
}
.topo-canvas.panning{cursor:grabbing}
.topo-svg{position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:1}
.topo-content{position:absolute;top:0;left:0;width:100%;height:100%;z-index:2;transform-origin:0 0}
.topo-node{
  position:absolute;width:190px;padding:10px 12px;border-radius:10px;
  background:#ffffff;border:1px solid #e5e7ec;
  box-shadow:0 2px 10px rgba(17,18,24,0.06);
  cursor:pointer;transition:opacity .25s,box-shadow .2s,border-color .2s,transform .2s;
}
.topo-node:hover{border-color:#111218;transform:translateY(-1px);box-shadow:0 6px 18px rgba(17,18,24,0.10)}
.topo-node.selected{border-color:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,0.18),0 4px 14px rgba(17,18,24,0.10)}
.topo-node.dimmed{opacity:0.18}
.topo-node-src{border-left:3px solid #111218}
.topo-node-dst{border-left:3px solid #22c55e}
.topo-node-hdr{display:flex;align-items:center;gap:7px;margin-bottom:2px}
.topo-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;animation:topo-pulse 2s infinite}
.topo-dot.allow{background:#22c55e;box-shadow:0 0 6px rgba(34,197,94,0.7)}
.topo-dot.deny{background:#dd6b78;box-shadow:0 0 6px rgba(221,107,120,0.7)}
.topo-dot.escalate{background:#e5b85c;box-shadow:0 0 6px rgba(229,184,92,0.7)}
@keyframes topo-pulse{0%,100%{opacity:1}50%{opacity:0.45}}
.topo-name{font-size:12px;font-weight:600;color:#111218;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topo-sub{font-size:10px;color:#8b919e;margin-top:1px;font-family:ui-monospace,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topo-badge{display:inline-block;font-size:9px;padding:1px 7px;border-radius:4px;background:#f1f2f4;color:#3a3f4b;margin-top:3px}
/* Hero-style glow loops: drawn around hovered/selected nodes and deny-view nodes */
.topo-loop{pointer-events:none}
/* Topology controls (zoom/fit/fullscreen) */
.topo-controls{position:absolute;top:10px;right:10px;z-index:10;display:flex;gap:2px;background:#fff;border:1px solid #e5e7ec;border-radius:10px;padding:4px;box-shadow:0 2px 10px rgba(17,18,24,0.10)}
.topo-ctrl{width:30px;height:30px;border:none;background:transparent;border-radius:7px;cursor:pointer;font-size:15px;line-height:1;color:#3a3f4b;display:flex;align-items:center;justify-content:center}
.topo-ctrl:hover{background:#f1f2f4}
.topo-ctrl svg{width:15px;height:15px;stroke:#3a3f4b;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
#topoCanvas:fullscreen{height:100vh;border-radius:0;background-color:#f8f9fb}
/* Scenario picker buttons */
.scenario-btn{padding:6px 14px;border-radius:999px;border:1px solid #e5e7ec;background:#fff;font-size:0.78rem;font-weight:600;color:#3a3f4b;cursor:pointer}
.scenario-btn.active{background:#111218;color:#fff;border-color:#111218}
/* Demo mode: hide privileged tabs + disable every edit affordance */
body.demo [data-tab-id="policies"], body.demo [data-tab-id="siem"], body.demo [data-tab-id="users"], body.demo [data-tab-id="config"], body.demo [data-tab-id="topo-link"]{display:none}
body.demo .btn-primary{display:none}

/* Guided tour */
#tourHost{position:fixed;inset:0;pointer-events:none;z-index:9000}
.tour-card{position:fixed;width:320px;background:#fff;border:1px solid #171717;border-radius:12px;padding:16px 18px 12px;box-shadow:0 12px 40px rgba(0,0,0,0.18);pointer-events:auto;animation:tourIn .25s ease}
@keyframes tourIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.tour-step{font-size:0.68rem;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#8b919e;margin-bottom:8px}
.tour-body{font-size:0.85rem;line-height:1.5;color:#171717;margin-bottom:14px}
.tour-actions{display:flex;justify-content:space-between;align-items:center}
.tour-skip{background:none;border:none;color:#8b919e;font-size:0.75rem;cursor:pointer;padding:6px 4px;font-family:inherit}
.tour-skip:hover{color:#171717}
.tour-next{background:#171717;color:#fff;border:none;border-radius:8px;padding:8px 18px;font-size:0.8rem;font-weight:600;cursor:pointer;font-family:inherit}
.tour-next:hover{background:#3a3a3a}
.tour-dots{display:flex;gap:5px;justify-content:center;margin-top:10px}
.tour-dots span{width:6px;height:6px;border-radius:50%;background:#e0e0e0;display:inline-block}
.tour-dots span.on{background:#171717}
.tour-replay{background:none;border:1px solid var(--border);color:#8b919e;font-size:0.72rem;padding:4px 12px;border-radius:999px;cursor:pointer;font-family:inherit;margin-left:auto}
.tour-replay:hover{border-color:#171717;color:#171717}

</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <div class="logo">Raucle</div>
    <span class="badge">Gateway</span>
  </div>
</div>

<div id="login" class="content login">
  <div class="card">
    <div class="card-title">Sign In</div>
    <input class="input" id="apiKey" type="password" placeholder="API Key" onkeydown="if(event.key==='Enter')login()">
    <div id="totpRow" class="hidden" style="margin-top:12px">
      <input class="input" id="totpInput" placeholder="6-digit TOTP code" maxlength="6" style="width:100%" onkeydown="if(event.key==='Enter')loginWithTotp()">
      <button class="btn" style="width:100%;margin-top:8px" onclick="loginWithTotp()">Verify & Sign In</button>
    </div>
    <button class="btn" style="width:100%;margin-top:12px" onclick="login()">Sign In</button>
    <div style="text-align:center;margin:16px 0 8px;color:var(--text-muted,#8b919e);font-size:0.8rem">or</div>
    <button class="btn" style="width:100%;background:#111218;color:#fff" onclick="enterDemo()">View Demo</button>
    <div style="margin-top:10px;font-size:0.75rem;color:var(--text-muted,#8b919e);text-align:center">
      Read-only demonstration across banking, government and health scenarios.
    </div>
  </div>
</div>

<div id="main" class="hidden">
  <div id="tourHost"></div>
  <div id="demoBanner" class="hidden" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 16px;margin-bottom:14px;background:#f8f9fb;border:1px solid #e5e7ec;border-radius:12px">
    <span style="display:inline-flex;align-items:center;gap:6px;font-size:0.78rem;font-weight:600;color:#fff;background:#22c55e;padding:3px 10px;border-radius:999px">
      <span style="width:6px;height:6px;border-radius:50%;background:#fff;display:inline-block"></span>
      DEMO MODE
    </span>
    <span style="font-size:0.82rem;color:#3a3f4b">Read-only view of a live deployment with simulated agent traffic.</span>
    <button class="tour-replay" onclick="tourRestart()">Replay tour</button>
    <span style="flex:1"></span>
    <div id="scenarioPicker" style="display:flex;gap:8px"></div>
    <button class="btn" style="padding:6px 14px;font-size:0.8rem" onclick="location.reload()">Exit Demo</button>
  </div>
  <div class="tabs">
    <div class="tab active" onclick="showTab('dashboard',this)">Dashboard</div>
    <div class="tab" onclick="showTab('connections',this)">Connections</div>
    <div class="tab" onclick="showTab('policies',this)" data-tab-id="policies">Policies</div>
    <div class="tab" onclick="showTab('learn',this)" data-tab-id="learn">Learn</div>
    <div class="tab" onclick="showTab('receipts',this)">Receipts</div>
    <div class="tab" onclick="showTab('siem',this)" data-tab-id="siem">SIEM</div>
    <div class="tab" onclick="showTab('users',this)" data-tab-id="users">Users</div>
    <div class="tab" onclick="showTab('config',this)" data-tab-id="config">Config</div>
    <div class="tab" onclick="window.location.href='/topology'" style="color:var(--active-green)" data-tab-id="topo-link">Topology</div>
  </div>
  <div class="content">

    <div id="tab-dashboard">
      <div class="card"><div class="card-title">Gate Decisions</div>
        <div class="stats-grid" id="statsGrid"></div>
      </div>
      <div class="card"><div class="card-title">By Tool</div>
        <table><thead><tr><th>Tool</th><th>Allowed</th><th>Denied</th><th>Escalated</th></tr></thead>
        <tbody id="toolTableBody"></tbody></table>
      </div>
    </div>

    <!-- CONNECTIONS - Netbird-style flow graph -->
    <div id="tab-connections" class="hidden">
      <div class="card">
        <div class="card-title"><span class="live-dot"></span>Live Topology</div>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
          <select class="input" id="topoDecisionFilter" style="width:auto" onchange="topoRender()">
            <option value="">All Decisions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="escalate">Escalate</option>
          </select>
          <label class="toggle"><input type="checkbox" id="topoMotion" checked onchange="topoRender()"> Animated traffic</label>
          <span style="flex:1"></span>
          <span style="font-size:0.75rem;color:#8b919e">Zoomed to the busiest nodes at first. Drag to pan, scroll to zoom, click a node to filter the table below.</span>
        </div>
        <div id="topoCanvas" class="topo-canvas">
          <svg class="topo-svg" id="topoSvg"></svg>
          <div class="topo-content" id="topoContent"></div>
          <div class="topo-controls">
            <button class="topo-ctrl" title="Zoom in" onclick="topoZoomIn()">
              <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><line x1="16.5" y1="16.5" x2="21" y2="21"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
            </button>
            <button class="topo-ctrl" title="Zoom out" onclick="topoZoomOut()">
              <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><line x1="16.5" y1="16.5" x2="21" y2="21"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
            </button>
            <button class="topo-ctrl" title="Fit to view" onclick="topoFit()">
              <svg viewBox="0 0 24 24"><path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M16 3h3a2 2 0 0 1 2 2v3"/><path d="M8 21H5a2 2 0 0 1-2-2v-3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/></svg>
            </button>
            <button class="topo-ctrl" title="Fullscreen" onclick="topoFullscreen()">
              <svg viewBox="0 0 24 24" id="topoFsIcon"><path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M16 3h3a2 2 0 0 1 2 2v3"/><path d="M8 21H5a2 2 0 0 1-2-2v-3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/><line x1="3" y1="3" x2="21" y2="21"/></svg>
            </button>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title"><span class="live-dot"></span>Traffic Flow</div>
        <div class="filter-bar">
          <div class="dir-toggle">
            <button class="active" onclick="setDirFilter('all',this)">All</button>
            <button onclick="setDirFilter('inbound',this)">Inbound</button>
            <button onclick="setDirFilter('outbound',this)">Outbound</button>
          </div>
          <select class="input" id="filterDecision" onchange="loadConnections()">
            <option value="">All Decisions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="escalate">Escalate</option>
          </select>
          <label class="toggle"><input type="checkbox" id="liveMode" checked onchange="loadConnections()"> Live</label>
        </div>
        <div class="flow-graph" id="flowGraph">
          <svg class="flow-svg" id="flowSvg"></svg>
          <div class="flow-cols">
            <div class="flow-col">
              <div class="flow-col-header">Inbound Sources <span class="count" id="srcCount">0</span></div>
              <div class="flow-col-filter"><input id="srcFilter" placeholder="Filter sources..." oninput="renderFlow()"></div>
              <div class="flow-col-body" id="srcList"></div>
            </div>
            <div class="flow-col flow-col-mid">
              <div class="flow-col-header">Gate Processing <span class="count" id="midCount">0</span></div>
              <div class="flow-col-filter"><input id="midFilter" placeholder="Filter by tool..." oninput="renderFlow()"></div>
              <div class="flow-col-body" id="midList"></div>
            </div>
            <div class="flow-col">
              <div class="flow-col-header">Outbound Destinations <span class="count" id="dstCount">0</span></div>
              <div class="flow-col-filter"><input id="dstFilter" placeholder="Filter destinations..." oninput="renderFlow()"></div>
              <div class="flow-col-body" id="dstList"></div>
            </div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Connection Log</div>
        <div class="conn-table">
          <table><thead><tr><th>Time</th><th>Source</th><th>Tool</th><th>Policy</th><th>Decision</th><th>Destination</th><th>Reason</th><th>Latency</th></tr></thead>
          <tbody id="connBody"></tbody></table>
        </div>
      </div>
    </div>

    <div id="tab-policies" class="hidden">
      <div class="card"><div class="card-title">Policy Files</div>
        <div class="file-list" id="fileList"></div>
        <textarea class="editor" id="policyEditor"></textarea>
        <div class="actions"><button class="btn" onclick="validatePolicy()">Validate</button><button class="btn" onclick="savePolicy()">Save & Deploy</button><button class="btn btn-secondary" onclick="reloadPolicy()">Reload</button></div>
      </div>
    </div>
    <div id="tab-learn" class="hidden">
      <div class="card">
        <div class="card-title">Learn Mode — draft policies from observed traffic</div>
        <p style="font-size:0.85rem;color:#8b919e;margin-bottom:14px">
          With learn mode enabled, the gate records every call it <strong>denied</strong> for
          having no matching policy. From those observations it drafts candidate rules:
          allow lists for low-cardinality string fields, bounds for numerics, and required
          fields seen in every call. The gate stays fail-closed the whole time — learning
          never authorises traffic. Review the draft, copy it into the policy editor,
          adjust, then Save & Deploy.
        </p>
        <div class="actions" style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn" onclick="loadLearn()">Refresh</button>
          <button class="btn" onclick="copyDraftToEditor()">Copy into Policy Editor</button>
          <button class="btn" onclick="clearLearn()">Clear Observations</button>
        </div>
        <div id="learnSummary" style="margin-top:14px;font-size:0.85rem"></div>
        <pre id="learnDraft" style="margin-top:10px;max-height:420px;overflow:auto;background:#f8f9fb;border:1px solid #e5e7ec;border-radius:10px;padding:14px;font-size:0.78rem">No observations yet.</pre>
      </div>
    </div>
    <div id="tab-receipts" class="hidden"><div class="card"><div class="card-title">Recent Receipts</div><pre id="receiptsView">Loading...</pre></div></div>
    <div id="tab-siem" class="hidden"><div class="card"><div class="card-title">SIEM Forwarding</div>
      <label class="toggle" style="margin-bottom:16px"><input type="checkbox" id="siemEnabled"> Enabled</label>
      <div style="display:flex;flex-direction:column;gap:8px;max-width:400px">
        <input class="input" id="siemBackend" placeholder="splunk / elastic / sentinel"><input class="input" id="siemUrl" placeholder="SIEM endpoint URL"><input class="input" id="siemToken" type="password" placeholder="SIEM token">
      </div><div class="actions"><button class="btn" onclick="saveSIEM()">Save</button></div></div>
    </div>
    <div id="tab-users" class="hidden">
      <div class="card"><div class="card-title">Add User</div>
        <div style="display:flex;flex-direction:column;gap:8px;max-width:400px">
          <input class="input" id="newKey" placeholder="API Key"><input class="input" id="newRole" placeholder="admin / operator / auditor"><input class="input" id="newName" placeholder="Name">
        </div><div class="actions"><button class="btn" onclick="addUser()">Add</button></div></div>
      <div class="card"><div class="card-title">Users</div>
        <table><thead><tr><th>Key</th><th>Role</th><th>Name</th><th>MFA</th><th>Actions</th></tr></thead>
        <tbody id="userTableBody"></tbody></table>
      </div>
      <div class="card hidden" id="mfaSetupCard">
        <div class="card-title">MFA Setup</div>
        <p style="font-size:13px;color:#525252;margin-bottom:12px">Scan the QR code or enter the secret manually in your authenticator app (Google Authenticator, Authy, 1Password). Then enter the 6-digit code below to confirm.</p>
        <div id="mfaQrCode" style="margin-bottom:12px"></div>
        <div style="font-family:ui-monospace,monospace;font-size:13px;padding:12px;background:#fafafa;border-radius:8px;border:1px solid #e5e5e5;margin-bottom:12px;word-break:break-all" id="mfaSecret"></div>
        <div style="font-size:12px;color:#737373;margin-bottom:8px" id="mfaUri"></div>
        <div style="display:flex;gap:8px;align-items:center">
          <input class="input" id="mfaCodeInput" placeholder="6-digit code" style="width:140px" maxlength="6" onkeydown="if(event.key==='Enter')confirmMfa()">
          <button class="btn" onclick="confirmMfa()">Confirm</button>
        </div>
      </div>
    </div>
    <div id="tab-config" class="hidden">
      <div class="card"><div class="card-title">Gateway Configuration</div>
        <div id="configForm" style="display:grid;grid-template-columns:1fr 1fr;gap:12px 24px;max-width:700px">
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Host</label><input class="input" id="cfg-host" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Gateway Port</label><input class="input" id="cfg-port" type="number" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Admin Port</label><input class="input" id="cfg-admin_port" type="number" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Signer Backend</label>
            <select class="input" id="cfg-signer_backend" style="width:100%">
              <option value="local">local</option><option value="aws">aws</option><option value="azure">azure</option><option value="vault">vault</option>
            </select></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">KMS Key ID</label><input class="input" id="cfg-kms_key_id" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">KMS Region</label><input class="input" id="cfg-kms_region" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Policy File</label><input class="input" id="cfg-policy_file" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Policy Directory</label><input class="input" id="cfg-policy_dir" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Receipt Store</label><input class="input" id="cfg-receipt_store" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Audit Chain</label><input class="input" id="cfg-audit_chain" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Audit Log File</label><input class="input" id="cfg-audit_log_file" style="width:100%"></div>
          <div style="display:flex;align-items:end;gap:8px">
            <label class="toggle"><input type="checkbox" id="cfg-audit_persist"> Audit Persist</label>
          </div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Compliance Framework</label>
            <select class="input" id="cfg-compliance_framework" style="width:100%">
              <option value="eu-ai-act">eu-ai-act</option><option value="iso-42001">iso-42001</option><option value="soc2">soc2</option>
            </select></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Registry Path</label><input class="input" id="cfg-registry_path" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">SIEM Backend</label>
            <select class="input" id="cfg-siem_backend" style="width:100%">
              <option value="">(disabled)</option><option value="splunk">splunk</option><option value="elastic">elastic</option><option value="sentinel">sentinel</option>
            </select></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">SIEM URL</label><input class="input" id="cfg-siem_url" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">SIEM Token</label><input class="input" id="cfg-siem_token" type="password" placeholder="(unchanged)" style="width:100%"></div>
          <div><label style="font-size:12px;color:#737373;display:block;margin-bottom:4px">Health Check Token</label><input class="input" id="cfg-health_check_token" type="password" placeholder="(unchanged)" style="width:100%"></div>
        </div>
        <div class="actions">
          <button class="btn" onclick="saveConfig()">Save Config</button>
          <button class="btn btn-secondary" onclick="loadConfig()">Reset</button>
        </div>
        <div id="configStatus" style="margin-top:12px;font-size:13px"></div>
        <div style="margin-top:16px"><pre id="configView" style="display:none"></pre></div>
      </div>
    </div>

  </div>
</div>

<script>
let key='', totpCode='', connPollId=null, allConns=[], dirFilter='all', selectedSource=null, selectedDest=null;

function login() {
  key = document.getElementById('apiKey').value;
  // Try without TOTP first
  fetch('/api/stats', {headers: {'Authorization': key}})
    .then(r => {
      if (r.ok) { showMain(); }
      else if (r.status === 401 && r.headers.get('content-type','').includes('json')) {
        r.json().then(d => {
          if (d.detail && d.detail.includes('MFA required')) {
            // Show TOTP input
            document.getElementById('totpRow').classList.remove('hidden');
            document.getElementById('totpInput').focus();
            alert('This account has MFA enabled. Enter the 6-digit code from your authenticator app.');
          } else { alert('Invalid API key'); }
        });
      } else { alert('Invalid API key'); }
    });
}
function loginWithTotp() {
  totpCode = document.getElementById('totpInput').value;
  if (!totpCode || totpCode.length !== 6) { alert('Enter the 6-digit TOTP code'); return; }
  fetch('/api/stats', {headers: {'Authorization': key, 'X-TOTP': totpCode}})
    .then(r => { if (r.ok) { showMain(); } else { alert('Invalid TOTP code'); } });
}
function showMain() {
  document.getElementById('login').classList.add('hidden');
  document.getElementById('main').classList.remove('hidden');
  loadAll();
}
function showTab(t,el) {
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('[id^=tab-]').forEach(x=>x.classList.add('hidden'));
  el.classList.add('active'); document.getElementById('tab-'+t).classList.remove('hidden');
  if(t==='dashboard')loadStats(); if(t==='connections'){loadConnections();startConnPolling();} else stopConnPolling();
  if(t==='policies')loadPolicy(); if(t==='learn')loadLearn(); if(t==='receipts')loadReceipts(); if(t==='siem')loadSIEM(); if(t==='users')loadUsers(); if(t==='config')loadConfig();
}
function api(p,o){const h={'Authorization':key,...((o||{}).headers||{})};if(totpCode)h['X-TOTP']=totpCode;return fetch(p,{...(o||{}),headers:h});}
function loadAll(){loadStats();}
function loadStats(){api('/api/stats').then(r=>r.json()).then(d=>{
  document.getElementById('statsGrid').innerHTML=`<div class="stat"><div class="stat-value">${d.total_requests||0}</div><div class="stat-label">Total</div></div><div class="stat"><div class="stat-value">${d.allowed||0}</div><div class="stat-label">Allowed</div></div><div class="stat"><div class="stat-value">${d.denied||0}</div><div class="stat-label">Denied</div></div><div class="stat"><div class="stat-value">${d.escalated||0}</div><div class="stat-label">Escalated</div></div><div class="stat"><div class="stat-value">${d.avg_latency_us||0}</div><div class="stat-label">Avg us</div></div>`;
  let tb=document.getElementById('toolTableBody');tb.innerHTML='';Object.entries(d.tools||{}).forEach(([t,s])=>tb.innerHTML+=`<tr><td>${esc(t)}</td><td>${s.allow||0}</td><td>${s.deny||0}</td><td>${s.escalate||0}</td></tr>`);
});}
function esc(s){return s?s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])):'--';}
function setDirFilter(d,el){dirFilter=d;document.querySelectorAll('.dir-toggle button').forEach(b=>b.classList.remove('active'));el.classList.add('active');loadConnections();}

// === Netbird-style flow graph ===
function loadConnections() {
  let p=new URLSearchParams({limit:500});
  let fd=document.getElementById('filterDecision').value;
  if(fd)p.set('decision',fd);
  api('/api/connections?'+p.toString()).then(r=>r.json()).then(d=>{
    allConns=d.connections||[];
    if(demoMode&&demoScenarioFilter!=='all'){
      const sc=demoScenarioFilter;
      const tools={banking:['lookup_balance','transfer_internal','transfer_external','block_card','increase_card_limit','check_loan_status','create_loan_application','file_sar','check_sanctions','unblock_card','lookup_transaction_history'],government:['check_benefit_entitlement','lookup_payment_history','schedule_benefit_payment','flag_fraud_suspected','lookup_tax_account','calculate_tax_estimate','submit_self_assessment','retrieve_planning_application','update_case_notes','recommend_decision','check_immigration_status','request_dbs_check','search_foi_register','draft_foi_response'],health:['read_patient_record','write_patient_note','prescribe_medication','prescribe_controlled','order_imaging','view_imaging_result','order_lab_test','review_lab_results','triage_assessment','export_patient_summary','book_appointment','cancel_appointment']};
      allConns=allConns.filter(c=>(tools[sc]||[]).includes(c.tool)||(c.policy||'').toLowerCase().includes({banking:'banking',government:'government',health:'healthcare'}[sc]));
    }
    renderFlow();renderConnTable();
  }).catch(()=>{});
}

function getFiltered() {
  let fd=document.getElementById('filterDecision').value;
  let conns=allConns;
  if(fd)conns=conns.filter(c=>c.decision===fd);
  if(selectedSource)conns=conns.filter(c=>c.source===selectedSource);
  if(selectedDest)conns=conns.filter(c=>c.destination===selectedDest);
  const mid=document.getElementById('midFilter');
  if(mid&&mid.value){const mv=mid.value.toLowerCase();conns=conns.filter(c=>(c.tool||'').toLowerCase().includes(mv));}
  return conns;
}

function renderFlow() {
  let conns=getFiltered();
  let sf=(document.getElementById('srcFilter')?.value||'').toLowerCase();
  let mf=(document.getElementById('midFilter')?.value||'').toLowerCase();
  let df=(document.getElementById('dstFilter')?.value||'').toLowerCase();

  // Group by source
  let bySrc={}; conns.forEach(c=>{let s=c.source||'unknown';if(sf&&!s.toLowerCase().includes(sf))return;if(!bySrc[s])bySrc[s]={t:0,a:0,d:0,e:0};bySrc[s].t++;bySrc[s][c.decision[0]]=(bySrc[s][c.decision[0]]||0)+1;});
  // Group by tool
  let byTool={}; conns.forEach(c=>{let t=c.tool||'unknown';let p=c.policy||'';if(mf&&!t.toLowerCase().includes(mf)&&!p.toLowerCase().includes(mf))return;if(!byTool[t])byTool[t]={t:0,a:0,d:0,e:0,p:p};byTool[t].t++;byTool[t][c.decision[0]]=(byTool[t][c.decision[0]]||0)+1;});
  // Group by dest
  let byDst={}; conns.forEach(c=>{let d=c.destination||'unknown';if(df&&!d.toLowerCase().includes(df))return;if(!byDst[d])byDst[d]={t:0,a:0,d:0,e:0};byDst[d].t++;byDst[d][c.decision[0]]=(byDst[d][c.decision[0]]||0)+1;});

  // Render source column
  let srcEntries=Object.entries(bySrc).sort((a,b)=>b[1].t-a[1].t);
  document.getElementById('srcCount').textContent=srcEntries.length;
  document.getElementById('srcList').innerHTML=srcEntries.length?srcEntries.map(([n,d])=>{
    let pct=Math.round(d.a/d.t*100);
    let dot=d.a>d.d?'dot-allow':d.d>d.a?'dot-deny':'dot-escalate';
    return `<div class="flow-item${selectedSource===n?' active':''}" id="src-${esc(n)}" onclick="toggleSource('${esc(n)}')">
      <div class="flow-item-name"><span class="flow-item-dot ${dot}"></span>${esc(n)}</div>
      <div class="flow-item-meta">${d.t} calls: ${d.a||0}A / ${d.d||0}D / ${d.e||0}E</div>
      <div class="flow-item-bar"><div class="flow-item-bar-fill" style="width:${pct}%;background:#171717"></div></div>
    </div>`;
  }).join(''):'<div class="flow-empty">No sources</div>';

  // Render center column
  let midEntries=Object.entries(byTool).sort((a,b)=>b[1].t-a[1].t);
  document.getElementById('midCount').textContent=midEntries.length;
  document.getElementById('midList').innerHTML=midEntries.length?midEntries.map(([n,d])=>{
    let pct=Math.round(d.a/d.t*100);
    let dot=d.a>d.d?'dot-allow':d.d>d.a?'dot-deny':'dot-escalate';
    let pol=d.p?d.p.split('/').pop():'';
    return `<div class="flow-item" id="mid-${esc(n)}" onclick="filterByTool('${esc(n)}')">
      <div class="flow-item-name"><span class="flow-item-dot ${dot}"></span>${esc(n)}</div>
      <div class="flow-item-meta">${d.t} calls: ${d.a||0}A / ${d.d||0}D / ${d.e||0}E ${pol?'<span class="protocol-tag">'+esc(pol)+'</span>':''}</div>
      <div class="flow-item-bar"><div class="flow-item-bar-fill" style="width:${pct}%;background:#171717"></div></div>
    </div>`;
  }).join(''):'<div class="flow-empty">No gate activity</div>';

  // Render destination column
  let dstEntries=Object.entries(byDst).sort((a,b)=>b[1].t-a[1].t);
  document.getElementById('dstCount').textContent=dstEntries.length;
  document.getElementById('dstList').innerHTML=dstEntries.length?dstEntries.map(([n,d])=>{
    let pct=Math.round(d.a/d.t*100);
    let dot=d.a>d.d?'dot-allow':d.d>d.a?'dot-deny':'dot-escalate';
    return `<div class="flow-item${selectedDest===n?' active':''}" id="dst-${esc(n)}" onclick="toggleDest('${esc(n)}')">
      <div class="flow-item-name"><span class="flow-item-dot ${dot}"></span>${esc(n)}</div>
      <div class="flow-item-meta">${d.t} calls: ${d.a||0}A / ${d.d||0}D / ${d.e||0}E</div>
      <div class="flow-item-bar"><div class="flow-item-bar-fill" style="width:${pct}%;background:#171717"></div></div>
    </div>`;
  }).join(''):'<div class="flow-empty">No destinations</div>';

  // Draw SVG connection lines between columns
  drawFlowLines(conns);
}

function drawFlowLines(conns) {
  let svg=document.getElementById('flowSvg');
  let graph=document.getElementById('flowGraph');
  let rect=graph.getBoundingClientRect();
  svg.setAttribute('width',rect.width);
  svg.setAttribute('height',rect.height);
  svg.innerHTML='';

  // Build source->tool and tool->dest edge maps
  let srcToTool={}; conns.forEach(c=>{let s=c.source||'unknown',t=c.tool||'unknown';let k=s+'||'+t;if(!srcToTool[k])srcToTool[k]={count:0,dec:c.decision};srcToTool[k].count++;});
  let toolToDst={}; conns.forEach(c=>{let t=c.tool||'unknown',d=c.destination||'unknown';let k=t+'||'+d;if(!toolToDst[k])toolToDst[k]={count:0,dec:c.decision};toolToDst[k].count++;});

  function getRightEdge(id){let el=document.getElementById(id);if(!el)return null;let r=el.getBoundingClientRect();return{x:r.right-rect.left,y:r.top+r.height/2-rect.top};}
  function getLeftEdge(id){let el=document.getElementById(id);if(!el)return null;let r=el.getBoundingClientRect();return{x:r.left-rect.left,y:r.top+r.height/2-rect.top};}
  function getMidRight(id){let el=document.getElementById('mid-'+id);if(!el)return null;let r=el.getBoundingClientRect();return{x:r.right-rect.left,y:r.top+r.height/2-rect.top};}
  function getMidLeft(id){let el=document.getElementById('mid-'+id);if(!el)return null;let r=el.getBoundingClientRect();return{x:r.left-rect.left,y:r.top+r.height/2-rect.top};}

  let lineColor={'allow':'#22c55e','deny':'#ef4444','escalate':'#f59e0b'};
  let ns='http://www.w3.org/2000/svg';

  // Draw source -> tool lines
  Object.entries(srcToTool).forEach(([k,info])=>{
    let [s,t]=k.split('||');
    let src=getRightEdge('src-'+s);
    let mid=getMidLeft(t);
    if(src&&mid){
      let path=document.createElementNS(ns,'path');
      let cx=(src.x+mid.x)/2;
      path.setAttribute('d',`M${src.x},${src.y} C${cx},${src.y} ${cx},${mid.y} ${mid.x},${mid.y}`);
      path.setAttribute('stroke',lineColor[info.dec]||'#d4d4d4');
      path.setAttribute('stroke-width',Math.min(1+info.count*0.5,4));
      path.setAttribute('fill','none');
      path.setAttribute('opacity','0.4');
      svg.appendChild(path);
    }
  });

  // Draw tool -> dest lines
  Object.entries(toolToDst).forEach(([k,info])=>{
    let [t,d]=k.split('||');
    let mid=getMidRight(t);
    let dst=getLeftEdge('dst-'+d);
    if(mid&&dst){
      let path=document.createElementNS(ns,'path');
      let cx=(mid.x+dst.x)/2;
      path.setAttribute('d',`M${mid.x},${mid.y} C${cx},${mid.y} ${cx},${dst.y} ${dst.x},${dst.y}`);
      path.setAttribute('stroke',lineColor[info.dec]||'#d4d4d4');
      path.setAttribute('stroke-width',Math.min(1+info.count*0.5,4));
      path.setAttribute('fill','none');
      path.setAttribute('opacity','0.4');
      svg.appendChild(path);
    }
  });
}

function toggleSource(n){selectedSource=selectedSource===n?null:n;renderFlow();renderConnTable();}
function toggleDest(n){selectedDest=selectedDest===n?null:n;renderFlow();renderConnTable();}
function filterByTool(t){document.getElementById('midFilter').value=t;renderFlow();renderConnTable();}

function renderConnTable() {
  let conns=getFiltered();
  let tb=document.getElementById('connBody');tb.innerHTML='';
  conns.forEach((c,i)=>{
    let badge=c.decision==='allow'?'badge-allow':c.decision==='deny'?'badge-deny':'badge-escalate';
    let time=c.timestamp?c.timestamp.substring(11,19):'--:--:--';
    let policy=c.policy?c.policy.split('/').pop():'--';
    tb.innerHTML+=`<tr class="conn-row" onclick="selectConn(${i})" data-idx="${i}"><td>${esc(time)}</td><td>${esc(c.source)}</td><td>${esc(c.tool)}</td><td>${esc(policy)}</td><td><span class="${badge}">${esc(c.decision)}</span></td><td>${esc(c.destination)}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(c.reason)}</td><td>${c.latency_us||0}us</td></tr>`;
  });
}
function selectConn(i){document.querySelectorAll('.conn-row').forEach(r=>r.classList.remove('selected'));let row=document.querySelector(`.conn-row[data-idx="${i}"]`);if(row)row.classList.add('selected');}

function startConnPolling(){stopConnPolling();connPollId=setInterval(()=>{if(document.getElementById('liveMode')?.checked&&!document.getElementById('tab-connections').classList.contains('hidden'))loadConnections();},3000);}
function stopConnPolling(){if(connPollId){clearInterval(connPollId);connPollId=null;}}

let currentFile='';
function loadPolicy(){api('/api/policies').then(r=>r.json()).then(d=>{let fl=document.getElementById('fileList');fl.innerHTML='';(d.files||[]).forEach(f=>{let chip=document.createElement('div');chip.className='file-chip'+(f.name===currentFile||(!currentFile&&f===d.files[0])?' active':'');chip.textContent=f.name;chip.onclick=()=>{currentFile=f.name;loadPolicyFile(f.path);document.querySelectorAll('.file-chip').forEach(c=>c.classList.remove('active'));chip.classList.add('active');};fl.appendChild(chip);});if(d.content!==undefined)document.getElementById('policyEditor').value=d.content;});}
function loadPolicyFile(path){api('/api/policies?file='+encodeURIComponent(path)).then(r=>r.json()).then(d=>{document.getElementById('policyEditor').value=d.content||'';});}
function validatePolicy(){api('/api/policies/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:document.getElementById('policyEditor').value})}).then(r=>r.json()).then(d=>alert(d.valid?'Valid':'Invalid: '+d.error));}
function savePolicy(){api('/api/policies',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:document.getElementById('policyEditor').value})}).then(r=>r.json()).then(d=>alert('Saved: '+JSON.stringify(d)));}
function reloadPolicy(){api('/api/policies/reload',{method:'POST'}).then(r=>r.json()).then(d=>alert('Reloaded: '+JSON.stringify(d)));}
function loadReceipts(){api('/api/receipts?limit=20').then(r=>r.json()).then(d=>{document.getElementById('receiptsView').textContent=JSON.stringify(d.receipts,null,2);});}
function loadSIEM(){api('/api/siem').then(r=>r.json()).then(d=>{document.getElementById('siemEnabled').checked=d.enabled;document.getElementById('siemBackend').value=d.backend||'';document.getElementById('siemUrl').value=d.url||'';});}
function saveSIEM(){api('/api/siem',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:document.getElementById('siemEnabled').checked,backend:document.getElementById('siemBackend').value,url:document.getElementById('siemUrl').value,token:document.getElementById('siemToken').value})}).then(r=>r.json()).then(d=>alert('Saved'));}
function loadUsers(){api('/api/users').then(r=>r.json()).then(d=>{let tb=document.getElementById('userTableBody');tb.innerHTML='';d.users.forEach(u=>{tb.innerHTML+=`<tr><td>${esc(u.api_key)}</td><td>${esc(u.role)}</td><td>${esc(u.name||'')}</td><td>${u.mfa_enabled?'<span style="color:#22c55e;font-size:12px">Enabled</span>':'<span style="color:#a3a3a3;font-size:12px">Off</span>'}</td><td><button class="btn btn-secondary" style="padding:4px 10px;font-size:11px" onclick="setupMfa('${esc(u.api_key)}')">Setup MFA</button>${u.mfa_enabled?` <button class="btn btn-secondary" style="padding:4px 10px;font-size:11px" onclick="disableMfa('${esc(u.api_key)}')">Disable</button>`:''}</td></tr>`;});});}
function addUser(){api('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_key:document.getElementById('newKey').value,role:document.getElementById('newRole').value,name:document.getElementById('newName').value})}).then(r=>r.json()).then(d=>{alert('Added');loadUsers();});}
let mfaSetupKey='';
function setupMfa(key){
  mfaSetupKey=key;
  api(`/api/users/${encodeURIComponent(key)}/mfa/setup`,{method:'POST'}).then(r=>r.json()).then(d=>{
    if(d.status==='ok'){
      document.getElementById('mfaSetupCard').classList.remove('hidden');
      document.getElementById('mfaSecret').textContent=d.secret;
      document.getElementById('mfaUri').textContent=d.uri;
      // Generate QR code using Google Charts API fallback to text display
      const qrUrl=`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(d.uri)}`;
      document.getElementById('mfaQrCode').innerHTML=`<img src="${qrUrl}" width="200" height="200" style="border-radius:8px;border:1px solid #e5e5e5" alt="QR Code for TOTP setup" />`;
      document.getElementById('mfaCodeInput').value='';
      document.getElementById('mfaCodeInput').focus();
    } else { alert('MFA setup failed: '+(d.detail||'unknown')); }
  });
}
function confirmMfa(){
  const code=document.getElementById('mfaCodeInput').value;
  if(!code||code.length!==6){alert('Enter the 6-digit code from your authenticator app');return;}
  api(`/api/users/${encodeURIComponent(mfaSetupKey)}/mfa/verify?code=${code}`,{method:'POST'}).then(r=>{if(!r.ok){return r.json().then(d=>{throw new Error(d.detail||'Invalid code');});}return r.json();}).then(d=>{
    alert('MFA enabled successfully! You will need a TOTP code for future logins.');
    document.getElementById('mfaSetupCard').classList.add('hidden');
    loadUsers();
  }).catch(e=>alert('MFA verification failed: '+e.message));
}
function disableMfa(key){
  if(!confirm('Disable MFA for this user?'))return;
  api(`/api/users/${encodeURIComponent(key)}/mfa/disable`,{method:'POST'}).then(r=>r.json()).then(d=>{alert('MFA disabled');loadUsers();});
}
function loadConfig(){api('/api/config').then(r=>r.json()).then(d=>{
  // Populate form fields
  const fields=['host','port','admin_port','signer_backend','kms_key_id','kms_region','policy_file','policy_dir','receipt_store','audit_chain','audit_log_file','siem_backend','siem_url','compliance_framework','registry_path'];
  fields.forEach(f=>{const el=document.getElementById('cfg-'+f);if(el&&d[f]!==undefined)el.value=d[f];});
  const checks=['audit_persist'];
  checks.forEach(f=>{const el=document.getElementById('cfg-'+f);if(el&&d[f]!==undefined)el.checked=d[f];});
  // Clear password fields (don't show existing secrets)
  document.getElementById('cfg-siem_token').value='';
  document.getElementById('cfg-health_check_token').value='';
  document.getElementById('configStatus').textContent='';
  // Also show raw YAML for reference
  document.getElementById('configView').textContent=JSON.stringify(d,null,2);
  document.getElementById('configView').style.display='block';
});}
function saveConfig(){
  const body={};
  const fields=['host','port','admin_port','signer_backend','kms_key_id','kms_region','policy_file','policy_dir','receipt_store','audit_chain','audit_log_file','siem_backend','siem_url','compliance_framework','registry_path'];
  fields.forEach(f=>{const el=document.getElementById('cfg-'+f);if(el&&el.value!=='')body[f]=el.value;});
  body['audit_persist']=document.getElementById('cfg-audit_persist').checked;
  const st=document.getElementById('cfg-siem_token').value;
  if(st)body['siem_token']=st;
  const ht=document.getElementById('cfg-health_check_token').value;
  if(ht)body['health_check_token']=ht;
  api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).then(d=>{
    const status=document.getElementById('configStatus');
    if(d.status==='ok'){
      status.style.color='#22c55e';
      status.textContent=`Saved: ${d.changed.length} fields changed. File: ${d.message}`;
      if(d.restart_needed){
        status.textContent+=' - Restart needed for host/port/signer changes.';
        status.style.color='#e5b85c';
      }
    } else if(d.status==='partial'){
      status.style.color='#e5b85c';
      status.textContent=`Partial: ${d.warning}`;
    } else {
      status.style.color='#ef4444';
      status.textContent='Error: '+JSON.stringify(d);
    }
  });
}

setInterval(()=>{if(!document.getElementById('main').classList.contains('hidden')&&!document.getElementById('tab-dashboard').classList.contains('hidden'))loadStats();},5000);
window.addEventListener('resize',()=>{if(!document.getElementById('tab-connections').classList.contains('hidden'))drawFlowLines(getFiltered());});

// ================= DEMO MODE =================
const DEMO_SCENARIOS = ['banking', 'government', 'health'];
let demoMode = false;
let topoNodes = [], topoEdges = [], topoSelected = null, topoConns = [];
let topoHoverLoop = null, topoDenyLoops = [];

async function fetchDemoKey() {
  // The server exposes the read-only demo key (no other secrets)
  try {
    const r = await fetch('/api/demo-key');
    if (r.ok) { const d = await r.json(); return d.demo_key || ''; }
  } catch (e) {}
  return '';
}

async function enterDemo() {
  const dk = await fetchDemoKey();
  if (!dk) { alert('Demo is not configured on this deployment. Set RAUCLE_DEMO_KEY.'); return; }
  key = dk;
  totpCode = '';
  demoMode = true;
  document.body.classList.add('demo');
  document.getElementById('login').classList.add('hidden');
  document.getElementById('main').classList.remove('hidden');
  document.getElementById('demoBanner').classList.remove('hidden');
  buildScenarioPicker();
  showMainDemo();
  tourMaybeStart();
}
// ?demo=1 (or #demo) auto-enters demo mode after the page settles
window.addEventListener('load', () => {
  const q = new URLSearchParams(window.location.search);
  const h = window.location.hash || '';
  if (q.get('demo') === '1' || h.startsWith('#demo')) {
    const btn = document.querySelector('[onclick*="enterDemo"]');
    if (btn) btn.click();
  }
});

function buildScenarioPicker() {
  const bar = document.getElementById('scenarioPicker');
  if (!bar) return;
  const mk = (label, val) => `<button class="scenario-btn${(demoScenarioFilter===val)?' active':''}" onclick="setDemoScenario('${val}')">${label}</button>`;
  let html = mk('All', 'all');
  DEMO_SCENARIOS.forEach(s => html += mk(s[0].toUpperCase()+s.slice(1), s));
  bar.innerHTML = html;
}

let demoScenarioFilter = 'all';
function setDemoScenario(v) { demoScenarioFilter = v; buildScenarioPicker(); loadConnections(); topoRefresh(); }

function showMainDemo() {
  // Default to the connections tab where the live topology lives
  const connTab = document.querySelector('.tab[data-tab-id], .tab');
  document.querySelectorAll('.tab').forEach(x => {
    if (x.getAttribute('onclick') && x.getAttribute('onclick').includes("'connections'")) x.click();
  });
  loadAll();
}

// ================= GUIDED TOUR =================
const TOUR_SEEN_KEY = 'raucle_demo_tour_done_v1';
let tourStep = 0, tourBox = null, tourTimer = null;
const TOUR_STEPS = [
  {tab:'connections', target:'#liveMode', title:'This is live traffic',
   body:'Real agent tool calls, gated in real time. Green lines are allowed calls; red ones were denied by policy. Use the scenario buttons to focus on banking, government or health.'},
  {tab:'connections', target:'#topoDecisionFilter', title:'Filter what you watch',
   body:'Narrow the flow to allows, denies or escalations. Click any node in the topology to filter the whole view to that agent or tool.'},
  {tab:'dashboard', target:'#statsGrid', title:'Decisions at a glance',
   body:'Counts of every gate decision by tool, with latency. Denied calls are as important as allowed ones: they are the policy working.'},
  {tab:'receipts', target:'#receiptsView', title:'Every decision leaves a receipt',
   body:'Each receipt is signed and content-addressed. Take them offline: an auditor can verify the chain without contacting us, or any vendor.'},
  {tab:'learn', target:'#tab-learn', title:'Want the depth?',
   body:'A short guided walkthrough of capability tokens, policies and what the proofs guarantee. When you are done, close the bubbles and explore freely.'},
];
function tourShow(){
  const s=TOUR_STEPS[tourStep];
  if(!s){tourEnd(true);return;}
  document.querySelectorAll('.tab').forEach(x=>{const oc=x.getAttribute('onclick')||'';if(oc.includes("'"+s.tab+"'"))x.click();});
  setTimeout(()=>{
    const el=document.querySelector(s.target)||document.getElementById('tab-'+s.tab);
    if(!el){tourStep++;tourShow();return;}
    const r=el.getBoundingClientRect();
    let bx=Math.min(Math.max(r.left+r.width/2-160,12),window.innerWidth-332);
    let by=Math.max(r.bottom+12,12);
    if(by+170>window.innerHeight-12) by=Math.max(12,r.top-186);
    const host=document.getElementById('tourHost');
    host.innerHTML=`<div class="tour-card" style="left:${bx}px;top:${by}px">
      <div class="tour-step">Step ${tourStep+1} of ${TOUR_STEPS.length} · ${s.title}</div>
      <div class="tour-body">${s.body}</div>
      <div class="tour-actions">
        <button class="tour-skip" onclick="tourEnd(false)">Skip tour</button>
        <button class="tour-next" onclick="tourNext()">${tourStep+1<TOUR_STEPS.length?'Next':'Start exploring'}</button>
      </div>
      <div class="tour-dots">${TOUR_STEPS.map((_,i)=>`<span class="${i===tourStep?'on':''}"></span>`).join('')}</div>
    </div>`;
  },220);
}
function tourNext(){tourStep++;tourShow();}
function tourEnd(seen){
  clearTimeout(tourTimer);tourStep=0;
  const host=document.getElementById('tourHost');if(host)host.innerHTML='';
  try{localStorage.setItem(TOUR_SEEN_KEY,seen?'1':'1');}catch(e){}
}
function tourMaybeStart(){
  let done=false;
  try{done=localStorage.getItem(TOUR_SEEN_KEY)==='1';}catch(e){}
  if(done)return;
  tourStep=0;tourShow();
}
function tourRestart(){try{localStorage.removeItem(TOUR_SEEN_KEY);}catch(e){}tourStep=0;tourShow();}

// ================= EMBEDDED LIVE TOPOLOGY =================
// Hero palette: ink #111218, green #22c55e, deny red #dd6b78, warn #e5b85c,
// neutral #8b919e. Glow loops (hero-style) appear on node hover and around
// deny sources when deny filtering is active.
const TOPO_COL_X = { source: 40, policy: 400, destination: 760 };
const TOPO_NODE_H = 60, TOPO_NODE_GAP = 22, TOPO_W = 190;

function topoEdgeColor(decision) {
  if (decision === 'allow') return '#22c55e';
  if (decision === 'deny') return '#dd6b78';
  if (decision === 'escalate') return '#e5b85c';
  return '#111218';
}

function topoFilterConns(conns) {
  let out = conns;
  const df = document.getElementById('topoDecisionFilter')?.value || '';
  if (df) out = out.filter(c => c.decision === df);
  if (demoScenarioFilter !== 'all') {
    const sc = demoScenarioFilter;
    out = out.filter(c => {
      // Scenario inference: policy file name or tool name carries the scenario signature
      const pol = (c.policy || '').toLowerCase();
      const tools = { banking: ['lookup_balance','transfer_internal','transfer_external','block_card','increase_card_limit','check_loan_status','create_loan_application','file_sar','check_sanctions','unblock_card','lookup_transaction_history'],
                      government: ['check_benefit_entitlement','lookup_payment_history','schedule_benefit_payment','flag_fraud_suspected','lookup_tax_account','calculate_tax_estimate','submit_self_assessment','retrieve_planning_application','update_case_notes','recommend_decision','check_immigration_status','request_dbs_check','search_foi_register','draft_foi_response'],
                      health: ['read_patient_record','write_patient_note','prescribe_medication','prescribe_controlled','order_imaging','view_imaging_result','order_lab_test','review_lab_results','triage_assessment','export_patient_summary','book_appointment','cancel_appointment'] };
      return (tools[sc] || []).includes(c.tool) || pol.includes(sc) || pol.includes({banking:'banking',government:'government',health:'healthcare'}[sc]);
    });
  }
  return out;
}

function topoBuild() {
  const conns = topoFilterConns(topoConns);
  if (!conns.length) { topoNodes = []; topoEdges = []; return; }
  const bySrc = {}, byTool = {}, byDst = {};
  conns.forEach(c => {
    const s = c.source || 'unknown', t = c.tool || 'unknown', d = c.destination || 'unknown';
    (bySrc[s] = bySrc[s] || {n:0, allow:0, deny:0, escalate:0}).n++; bySrc[s][c.decision] = (bySrc[s][c.decision]||0)+1;
    (byTool[t] = byTool[t] || {n:0, allow:0, deny:0, escalate:0, policy:c.policy||''}).n++; byTool[t][c.decision] = (byTool[t][c.decision]||0)+1;
    (byDst[d] = byDst[d] || {n:0, allow:0, deny:0, escalate:0}).n++; byDst[d][c.decision] = (byDst[d][c.decision]||0)+1;
  });
  const status = d => d.deny > d.allow ? 'deny' : d.escalate > 0 ? 'escalate' : 'allow';
  topoNodes = []; topoEdges = [];
  Object.entries(bySrc).forEach(([n, d]) => topoNodes.push({id:'src-'+n, type:'source', label:n, sub:d.n+' calls', status:status(d), meta:d}));
  Object.entries(byTool).forEach(([n, d]) => topoNodes.push({id:'tool-'+n, type:'policy', label:n, sub:(d.policy||'').split('/').pop(), badge:d.n+' calls', status:status(d), meta:d}));
  Object.entries(byDst).forEach(([n, d]) => topoNodes.push({id:'dst-'+n, type:'destination', label:n, sub:d.n+' calls', status:status(d), meta:d}));
  const seen = {};
  conns.forEach((c, i) => {
    const s = 'src-'+(c.source||'unknown'), t = 'tool-'+(c.tool||'unknown'), d = 'dst-'+(c.destination||'unknown');
    const col = topoEdgeColor(c.decision);
    const seg = (a, b, lbl) => {
      const k = a+'|'+b+'|'+lbl;
      if (seen[k]) return; seen[k] = 1;
      topoEdges.push({id:'e'+i+'-'+a+'-'+b, source:a, target:b, label:lbl, colour:col, decision:c.decision});
    };
    seg(s, t, ''); seg(t, d, (c.policy||'').split('/').pop());
  });
}

function topoEdgePath(sp, dp) {
  const x1 = sp.x + TOPO_W, y1 = sp.y + TOPO_NODE_H/2, x2 = dp.x, y2 = dp.y + TOPO_NODE_H/2;
  const mx = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
}

function topoLayout() {
  const cols = {source:[], policy:[], destination:[]};
  topoNodes.forEach(n => (cols[n.type] || []).push(n));
  const pos = {};
  ['source','policy','destination'].forEach(t => {
    const list = cols[t];
    list.sort((a,b) => a.label.localeCompare(b.label));
    const totalH = list.length * (TOPO_NODE_H + TOPO_NODE_GAP) - TOPO_NODE_GAP;
    let y = Math.max(24, (600 - totalH) / 2);
    list.forEach(n => { pos[n.id] = {x: TOPO_COL_X[t], y}; y += TOPO_NODE_H + TOPO_NODE_GAP; });
  });
  return pos;
}

function topoGlowLoop(svg, x, y, w, h, colour) {
  // Hero-style glowing rounded-rect loop around a node
  const g = document.createElementNS('http://www.w3.org/2000/svg','rect');
  g.setAttribute('x', x - 4); g.setAttribute('y', y - 4);
  g.setAttribute('width', w + 8); g.setAttribute('height', h + 8);
  g.setAttribute('rx', 13); g.setAttribute('fill', 'none');
  g.setAttribute('stroke', colour); g.setAttribute('stroke-width', '2');
  g.setAttribute('opacity', '0.85');
  g.style.filter = `drop-shadow(0 0 6px ${colour})`;
  const anim = document.createElementNS('http://www.w3.org/2000/svg','animate');
  anim.setAttribute('attributeName', 'opacity');
  anim.setAttribute('values', '0.35;0.95;0.35');
  anim.setAttribute('dur', '1.6s');
  anim.setAttribute('repeatCount', 'indefinite');
  g.appendChild(anim);
  svg.appendChild(g);
  return g;
}

function topoRender() {
  const svg = document.getElementById('topoSvg'), content = document.getElementById('topoContent');
  if (!svg || !content) return;
  const motion = document.getElementById('topoMotion')?.checked !== false;
  svg.innerHTML = ''; content.innerHTML = '';
  topoHoverLoop = null; topoDenyLoops = [];
  if (!topoNodes.length) {
    content.innerHTML = '<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:#8b919e;font-size:0.85rem">No connections yet' + (demoScenarioFilter!=='all' ? ' in this scenario' : '') + '</div>';
    return;
  }
  const pos = topoLayout();

  // connected set for dimming
  const conn = new Set();
  if (topoSelected) {
    conn.add(topoSelected);
    topoEdges.forEach(e => { if (e.source===topoSelected) conn.add(e.target); if (e.target===topoSelected) conn.add(e.source); });
  }

  // edges + particles
  topoEdges.forEach(e => {
    const sp = pos[e.source], dp = pos[e.target];
    if (!sp || !dp) return;
    const dimmed = topoSelected && !conn.has(e.source) && !conn.has(e.target);
    const d = topoEdgePath(sp, dp);
    const base = document.createElementNS('http://www.w3.org/2000/svg','path');
    base.setAttribute('d', d); base.setAttribute('stroke', e.colour);
    base.setAttribute('stroke-width','1.4'); base.setAttribute('fill','none');
    base.setAttribute('opacity', dimmed ? '0.08' : '0.35');
    svg.appendChild(base);
    if (motion && !dimmed) {
      const p = document.createElementNS('http://www.w3.org/2000/svg','circle');
      p.setAttribute('r','3'); p.setAttribute('fill', e.colour); p.setAttribute('opacity','0.9');
      p.style.filter = `drop-shadow(0 0 4px ${e.colour})`;
      const a = document.createElementNS('http://www.w3.org/2000/svg','animateMotion');
      a.setAttribute('dur', e.decision==='deny' ? '3.4s' : '2.4s');
      a.setAttribute('repeatCount','indefinite');
      a.setAttribute('path', d);
      p.appendChild(a); svg.appendChild(p);
    }
    if (e.label) {
      const l = document.createElement('div');
      l.textContent = e.label;
      l.style.cssText = 'position:absolute;font-size:10px;padding:2px 8px;border-radius:4px;background:#fff;border:1px solid #e5e7ec;color:#8b919e;font-family:ui-monospace,monospace;pointer-events:none;transform:translate(-50%,-50%);white-space:nowrap';
      l.style.left = ((pos[e.source].x+TOPO_W+pos[e.target].x)/2)+'px';
      l.style.top = ((pos[e.source].y+pos[e.target].y)/2+TOPO_NODE_H/2)+'px';
      content.appendChild(l);
    }
  });

  // nodes
  const denyFilterOn = (document.getElementById('topoDecisionFilter')?.value === 'deny');
  topoNodes.forEach(n => {
    const p = pos[n.id]; if (!p) return;
    const el = document.createElement('div');
    el.className = 'topo-node topo-node-' + (n.type==='source' ? 'src' : n.type==='destination' ? 'dst' : 'pol') +
      (topoSelected === n.id ? ' selected' : '') + (topoSelected && !conn.has(n.id) ? ' dimmed' : '');
    el.style.left = p.x + 'px'; el.style.top = p.y + 'px';
    el.innerHTML = `<div class="topo-node-hdr"><span class="topo-dot ${n.status}"></span>` +
      `<span class="topo-name">${esc(n.label)}</span></div>` +
      `<div class="topo-sub">${esc(n.sub || '')}</div>` +
      (n.badge ? `<span class="topo-badge">${esc(n.badge)}</span>` : '');
    el.addEventListener('click', () => {
      const wasSame = topoSelected === n.id;
      topoSelected = wasSame ? null : n.id;
      // Filter the traffic flow table below to this node's flow
      if (!wasSame) {
        if (n.id.startsWith('src-')) { selectedSource = n.label; selectedDest = null; }
        else if (n.id.startsWith('dst-')) { selectedDest = n.label; selectedSource = null; }
        else { selectedSource = null; selectedDest = null;
               const mid = document.getElementById('midFilter'); if (mid) mid.value = n.label; }
      } else {
        selectedSource = null; selectedDest = null;
        const mid = document.getElementById('midFilter'); if (mid) mid.value = '';
      }
      topoRender();
      renderFlow(); renderConnTable();
    });
    el.addEventListener('mouseenter', () => {
      topoHoverLoop = topoGlowLoop(svg, p.x, p.y, TOPO_W, TOPO_NODE_H, '#111218');
    });
    el.addEventListener('mouseleave', () => {
      if (topoHoverLoop) { topoHoverLoop.remove(); topoHoverLoop = null; }
    });
    content.appendChild(el);
    // Deny view: glowing red loops around deny nodes (hero-styled)
    if (denyFilterOn && n.status === 'deny') {
      topoDenyLoops.push(topoGlowLoop(svg, p.x, p.y, TOPO_W, TOPO_NODE_H, '#dd6b78'));
    }
  });

  // Apply the current view (scale + pan); fit computed lazily on first render
  applyTopoView();
}

// ===== topology view model: zoom + pan =====
let topoScale = 1, topoPanX = 0, topoPanY = 0, topoFitPending = false, topoInitPending = true;

function applyTopoView() {
  const svg = document.getElementById('topoSvg');
  const content = document.getElementById('topoContent');
  const canvas = document.getElementById('topoCanvas');
  if (!svg || !content || !canvas) return;
  if (topoInitPending) {
    topoInitPending = false;
    frameTopActive(6);
  } else if (topoFitPending) {
    const cw = canvas.clientWidth || 1000, ch = canvas.clientHeight || 420;
    const contentW = TOPO_COL_X.destination + TOPO_W + 60;
    let maxY = 0;
    const pos2 = topoLayout();
    Object.values(pos2).forEach(p => { maxY = Math.max(maxY, p.y + TOPO_NODE_H); });
    const contentH = Math.max(maxY + 40, 100);
    const scale = Math.min((cw - 40) / contentW, (ch - 40) / contentH, 1.4);
    topoScale = Math.max(0.15, scale);
    topoPanX = (cw - contentW * topoScale) / 2;
    topoPanY = Math.max(20, (ch - contentH * topoScale) / 2);
    topoFitPending = false;
  }
  const t = `translate(${topoPanX}px,${topoPanY}px) scale(${topoScale})`;
  content.style.transform = t;
  svg.style.transform = t;
  svg.style.transformOrigin = '0 0';
  content.style.transformOrigin = '0 0';
}

// Initial view: zoom in on the k most active nodes (by observed calls).
// The rest of the graph stays reachable by panning or zooming out; this
// only runs once, on the first render that has nodes.
function frameTopActive(k) {
  const canvas = document.getElementById('topoCanvas');
  if (!canvas || !topoNodes.length) { topoFitPending = true; return; }
  const cw = canvas.clientWidth || 1000, ch = canvas.clientHeight || 420;
  const pos = topoLayout();
  const ranked = topoNodes.slice().sort(
    (a, b) => (((b.meta || {}).n) || 0) - (((a.meta || {}).n) || 0)
  );
  const focus = ranked.slice(0, k);
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  focus.forEach(n => {
    const p = pos[n.id];
    if (!p) return;
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x + TOPO_W);
    maxY = Math.max(maxY, p.y + TOPO_NODE_H);
  });
  if (!isFinite(minX)) { topoFitPending = true; return; }
  const pad = 30;
  const bw = (maxX - minX) + pad * 2, bh = (maxY - minY) + pad * 2;
  let scale = Math.min((cw - 20) / bw, (ch - 20) / bh, 1.5);
  topoScale = Math.max(0.3, scale);
  topoPanX = (cw - (minX + maxX) * topoScale) / 2;
  topoPanY = (ch - (minY + maxY) * topoScale) / 2;
}

function topoZoomIn() { topoZoomBy(1.25); }
function topoZoomOut() { topoZoomBy(0.8); }
function topoZoomBy(f) {
  const canvas = document.getElementById('topoCanvas');
  const cw = canvas.clientWidth || 1000, ch = canvas.clientHeight || 420;
  const cx = cw / 2, cy = ch / 2;
  topoPanX = cx - (cx - topoPanX) * f;
  topoPanY = cy - (cy - topoPanY) * f;
  topoScale = Math.min(3, Math.max(0.15, topoScale * f));
  topoFitPending = false;
  applyTopoView();
}
function topoFit() { topoFitPending = true; applyTopoView(); }

function topoFullscreen() {
  const canvas = document.getElementById('topoCanvas');
  if (!document.fullscreenElement) {
    canvas.requestFullscreen().catch(()=>{});
  } else {
    document.exitFullscreen();
  }
}
document.addEventListener('fullscreenchange', () => {
  const icon = document.getElementById('topoFsIcon');
  if (icon) {
    icon.innerHTML = document.fullscreenElement
      ? '<path d="M8 3v3a2 2 0 0 1-2 2H3"/><path d="M21 8h-3a2 2 0 0 1-2-2V3"/><path d="M3 16h3a2 2 0 0 1 2 2v3"/><path d="M16 21v-3a2 2 0 0 1 2-2h3"/><line x1="8" y1="16" x2="16" y2="8"/><line x1="16" y1="16" x2="8" y2="8"/>'
      : '<path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M16 3h3a2 2 0 0 1 2 2v3"/><path d="M8 21H5a2 2 0 0 1-2-2v-3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/><line x1="3" y1="3" x2="21" y2="21"/>';
  }
  topoFitPending = true;
  setTimeout(applyTopoView, 120);
});

// Pan: drag anywhere on the canvas background (not on nodes or controls)
function initTopoPan() {
  const canvas = document.getElementById('topoCanvas');
  if (!canvas || canvas.dataset.panBound) return;
  canvas.dataset.panBound = '1';
  let panning = false, lastX = 0, lastY = 0;
  canvas.addEventListener('mousedown', (ev) => {
    if (ev.target.closest('.topo-node') || ev.target.closest('.topo-controls')) return;
    panning = true;
    lastX = ev.clientX; lastY = ev.clientY;
    canvas.classList.add('panning');
  });
  window.addEventListener('mousemove', (ev) => {
    if (!panning) return;
    topoPanX += ev.clientX - lastX;
    topoPanY += ev.clientY - lastY;
    lastX = ev.clientX; lastY = ev.clientY;
    topoFitPending = false;
    applyTopoView();
  });
  window.addEventListener('mouseup', () => {
    panning = false;
    canvas.classList.remove('panning');
  });
  canvas.addEventListener('wheel', (ev) => {
    ev.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const cx = ev.clientX - rect.left, cy = ev.clientY - rect.top;
    const f = ev.deltaY < 0 ? 1.1 : 0.9;
    topoPanX = cx - (cx - topoPanX) * f;
    topoPanY = cy - (cy - topoPanY) * f;
    topoScale = Math.min(3, Math.max(0.15, topoScale * f));
    topoFitPending = false;
    applyTopoView();
  }, { passive: false });
}

let topoPollId = null;
function topoRefresh() {
  initTopoPan();
  const p = new URLSearchParams({limit: 500});
  api('/api/connections?' + p.toString()).then(r => r.json()).then(d => {
    topoConns = d.connections || [];
    topoBuild(); topoRender();
  }).catch(() => {});
}

// Start topology polling when the connections tab is shown; stop when hidden.
const origShowTab = showTab;
showTab = function(t, el) {
  origShowTab(t, el);
  if (t === 'connections') {
    topoRefresh();
    if (!topoPollId) topoPollId = setInterval(() => {
      if (!document.hidden && !document.getElementById('tab-connections').classList.contains('hidden')) topoRefresh();
    }, 5000);
  } else if (topoPollId) {
    clearInterval(topoPollId); topoPollId = null;
  }
};


// ================= LEARN MODE =================
function loadLearn(){
  api('/api/learn/summary').then(r=>r.json()).then(s=>{
    let el=document.getElementById('learnSummary');
    if(!s.learn_mode){
      el.innerHTML='<span style="color:#e5b85c">Learn mode is off.</span> Set <code>RAUCLE_LEARN_MODE=true</code> and restart the gateway to start observing unmatched traffic.';
    } else if(!Object.keys(s.tools||{}).length){
      el.innerHTML='Learn mode is on. No unmatched calls recorded yet.';
    } else {
      let rows=Object.entries(s.tools).map(([t,d])=>`<tr><td>${esc(t)}</td><td>${d.calls}</td><td>${esc((d.agents||[]).join(', ')||'-')}</td></tr>`).join('');
      el.innerHTML='<table><tr><th>Observed tool</th><th>Denied calls</th><th>Agents</th></tr>'+rows+'</table>';
    }
  }).catch(()=>{});
  api('/api/learn/draft').then(r=>r.json()).then(d=>{
    document.getElementById('learnDraft').textContent=d.yaml||'Nothing learned yet.';
  }).catch(()=>{});
}
function copyDraftToEditor(){
  const draft=document.getElementById('learnDraft').textContent;
  if(!draft||draft.startsWith('Nothing')||draft.startsWith('No obs')){alert('Nothing to copy yet.');return;}
  showTab('policies',document.querySelector('.tab[data-tab-id="policies"]'));
  document.getElementById('policyEditor').value=draft;
  alert('Draft copied into the editor. Review, adjust constraints, then Save & Deploy.');
}
function clearLearn(){
  if(!confirm('Discard all learned observations?'))return;
  api('/api/learn/clear',{method:'POST'}).then(()=>loadLearn());
}

</script>
</body>
</html>"""


TOPOLOGY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Raucle Gateway - Traffic Topology</title>
<style>
:root {
  --bg: #101114;
  --surface: rgba(30,33,39,0.92);
  --surface-hover: rgba(43,47,55,0.98);
  --border: rgba(255,255,255,0.12);
  --text-primary: #f2f4f7;
  --text-secondary: #8e969f;
  --active-green: #39d49a;
  --active-cyan: #45cbd8;
  --warning: #e5b85c;
  --blocked: #dd6b78;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text-primary);overflow:hidden}
.topology-canvas{
  position:relative;width:100%;height:calc(100vh - 48px);
  background-color:var(--bg);
  background-image:radial-gradient(rgba(255,255,255,0.10) 1px,transparent 1px);
  background-size:24px 24px;
  overflow:hidden;cursor:grab;
}
.topology-canvas:active{cursor:grabbing}
.topology-svg{position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:1}
.topology-content{position:absolute;top:0;left:0;width:100%;height:100%;z-index:2;transform-origin:0 0}
.node-card{
  position:absolute;width:180px;padding:12px 14px;border-radius:10px;
  background:var(--surface);border:1px solid var(--border);
  box-shadow:0 4px 12px rgba(0,0,0,0.3);cursor:pointer;
  transition:opacity 0.3s,background 0.2s,transform 0.2s,border-color 0.2s;
  backdrop-filter:blur(8px);user-select:none;
}
.node-card:hover{background:var(--surface-hover);border-color:rgba(255,255,255,0.2);transform:translateY(-1px)}
.node-card.selected{border-color:var(--active-green);box-shadow:0 0 0 2px rgba(57,212,154,0.3),0 4px 12px rgba(0,0,0,0.4)}
.node-card.dimmed{opacity:0.2}
.node-card.inactive{opacity:0.4}
.node-header{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.node-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;animation:pulse-dot 2s infinite}
.node-dot.active{background:var(--active-green);box-shadow:0 0 8px var(--active-green)}
.node-dot.warning{background:var(--warning);box-shadow:0 0 8px var(--warning)}
.node-dot.inactive{background:var(--text-secondary);animation:none;box-shadow:none}
.node-dot.blocked{background:var(--blocked);box-shadow:0 0 8px var(--blocked)}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:0.5}}
.node-label{font-size:13px;font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.node-subtitle{font-size:11px;color:var(--text-secondary);margin-top:2px;font-family:ui-monospace,monospace}
.node-badge{display:inline-block;font-size:9px;padding:1px 6px;border-radius:4px;background:rgba(255,255,255,0.1);color:var(--text-secondary);margin-top:4px}
.node-type-source .node-dot{background:var(--active-cyan);box-shadow:0 0 8px var(--active-cyan)}
.node-type-destination .node-dot{background:var(--active-green);box-shadow:0 0 8px var(--active-green)}

.edge-label{
  position:absolute;font-size:10px;padding:2px 8px;border-radius:4px;
  background:var(--surface);border:1px solid var(--border);color:var(--text-secondary);
  font-family:ui-monospace,monospace;pointer-events:none;transform:translate(-50%,-50%);
  white-space:nowrap;transition:opacity 0.3s;z-index:3;
}
.edge-label.dimmed{opacity:0.15}

.topology-header{display:flex;align-items:center;justify-content:space-between;padding:10px 24px;border-bottom:1px solid var(--border);background:var(--bg);position:relative;z-index:10}
.topology-title{display:flex;align-items:center;gap:12px}
.topology-title h1{font-size:16px;font-weight:600;letter-spacing:-0.025em}
.topology-controls{display:flex;gap:8px;align-items:center}
.topo-btn{background:var(--surface);border:1px solid var(--border);color:var(--text-primary);padding:6px 14px;border-radius:8px;cursor:pointer;font-size:13px;font-family:inherit;transition:background 0.2s}
.topo-btn:hover{background:var(--surface-hover)}
.topo-btn.active{border-color:var(--active-green);color:var(--active-green)}
.filter-select{background:var(--surface);border:1px solid var(--border);color:var(--text-primary);padding:6px 12px;border-radius:8px;font-size:13px;font-family:inherit;outline:none}

.details-panel{position:absolute;top:48px;right:0;width:340px;height:calc(100vh - 48px);background:var(--surface);border-left:1px solid var(--border);padding:20px;overflow-y:auto;transform:translateX(100%);transition:transform 0.3s;z-index:20;backdrop-filter:blur(12px)}
.details-panel.open{transform:translateX(0)}
.details-panel h2{font-size:15px;font-weight:600;margin-bottom:12px;color:var(--text-primary)}
.details-panel .detail-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)}
.detail-label{color:var(--text-secondary);font-size:12px}
.detail-value{color:var(--text-primary);font-size:12px;font-family:ui-monospace,monospace}
.detail-status{display:inline-flex;align-items:center;gap:6px}
.close-btn{position:absolute;top:16px;right:16px;background:none;border:none;color:var(--text-secondary);font-size:20px;cursor:pointer}
.live-indicator{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--active-green);margin-right:6px;animation:pulse-dot 2s infinite}
</style>
</head>
<body>
<div class="topology-header">
  <div class="topology-title">
    <h1>Raucle Gateway</h1>
    <span style="font-size:11px;padding:2px 8px;border-radius:999px;background:rgba(255,255,255,0.08);color:var(--text-secondary)">Topology</span>
  </div>
  <div class="topology-controls">
    <span><span class="live-indicator"></span>Live</span>
    <select class="filter-select" id="decisionFilter" onchange="updateData()">
      <option value="">All Decisions</option>
      <option value="allow">Allow</option>
      <option value="deny">Deny</option>
      <option value="escalate">Escalate</option>
    </select>
    <button class="topo-btn" onclick="fitView()">Fit View</button>
    <button class="topo-btn" id="motionBtn" onclick="toggleMotion()">Motion: On</button>
  </div>
</div>
<div class="topology-canvas" id="canvas">
  <svg class="topology-svg" id="svg"></svg>
  <div class="topology-content" id="content"></div>
</div>
<div class="details-panel" id="detailsPanel">
  <button class="close-btn" onclick="closeDetails()">&times;</button>
  <h2 id="detailTitle"></h2>
  <div id="detailBody"></div>
</div>

<script>
// === DATA MODEL ===
let topologyNodes = [];
let topologyEdges = [];
let selectedNode = null;
let selectedEdge = null;
let motionEnabled = true;
let allConns = [];
let apiKey = '';
let pollId = null;

// === LAYOUT (deterministic three-column) ===
const COL_X = { source: 80, policy: 420, destination: 760 };
const NODE_H = 64;
const NODE_GAP = 24;

function layoutNodes(nodes) {
  const cols = { source: [], policy: [], destination: [] };
  nodes.forEach(n => cols[n.type]?.push(n));
  const positions = {};
  ['source','policy','destination'].forEach(type => {
    const colNodes = cols[type];
    const totalH = colNodes.length * (NODE_H + NODE_GAP) - NODE_GAP;
    let y = Math.max(40, (window.innerHeight - 48 - totalH) / 2);
    colNodes.forEach(n => {
      positions[n.id] = { x: COL_X[type], y };
      y += NODE_H + NODE_GAP;
    });
  });
  return positions;
}

// === SVG EDGE PATHS ===
function edgePath(src, dst) {
  const sx = src.x + 180, sy = src.y + NODE_H / 2;
  const dx = dst.x, dy = dst.y + NODE_H / 2;
  const cx = (sx + dx) / 2;
  return `M${sx},${sy} C${cx},${sy} ${cx},${dy} ${dx},${dy}`;
}

function getEdgeColor(decision) {
  if (decision === 'allow') return '#39d49a';
  if (decision === 'deny') return '#dd6b78';
  if (decision === 'escalate') return '#e5b85c';
  return '#45cbd8';
}

// === RENDER ===
function render() {
  const positions = layoutNodes(topologyNodes);
  const svg = document.getElementById('svg');
  const content = document.getElementById('content');
  svg.innerHTML = '';
  content.innerHTML = '';

  // Determine connected nodes for selection dimming
  let connectedIds = new Set();
  if (selectedNode) {
    connectedIds.add(selectedNode);
    topologyEdges.forEach(e => {
      if (e.source === selectedNode) connectedIds.add(e.target);
      if (e.target === selectedNode) connectedIds.add(e.source);
    });
  }

  // Draw edges
  topologyEdges.forEach(edge => {
    const src = topologyNodes.find(n => n.id === edge.source);
    const dst = topologyNodes.find(n => n.id === edge.target);
    if (!src || !dst) return;
    const sp = positions[src.id], dp = positions[dst.id];
    if (!sp || !dp) return;

    const color = edge.colour || getEdgeColor(edge.status);
    const isDimmed = selectedNode && !connectedIds.has(edge.source) && !connectedIds.has(edge.target);
    const opacity = isDimmed ? '0.1' : '0.5';

    // Base path (faint)
    const pathId = `path-${edge.id}`;
    const d = edgePath(sp, dp);
    const baseLine = document.createElementNS('http://www.w3.org/2000/svg','path');
    baseLine.setAttribute('d', d);
    baseLine.setAttribute('stroke', color);
    baseLine.setAttribute('stroke-width', '1.5');
    baseLine.setAttribute('fill', 'none');
    baseLine.setAttribute('opacity', opacity);
    svg.appendChild(baseLine);

    // Visible path (for hit testing and motion reference)
    const visPath = document.createElementNS('http://www.w3.org/2000/svg','path');
    visPath.setAttribute('d', d);
    visPath.setAttribute('id', pathId);
    visPath.setAttribute('stroke', 'transparent');
    visPath.setAttribute('stroke-width', '20');
    visPath.setAttribute('fill', 'none');
    visPath.setAttribute('style', 'pointer-events:stroke;cursor:pointer');
    visPath.addEventListener('click', () => selectEdge(edge));
    svg.appendChild(visPath);

    // Animated particles
    if (motionEnabled && !isDimmed) {
      const count = edge.particleCount || 2;
      const speed = edge.animationSpeed || 1;
      for (let i = 0; i < count; i++) {
        const particle = document.createElementNS('http://www.w3.org/2000/svg','circle');
        particle.setAttribute('r', '3');
        particle.setAttribute('fill', color);
        particle.setAttribute('opacity', '0.9');
        particle.style.filter = `drop-shadow(0 0 4px ${color})`;

        const anim = document.createElementNS('http://www.w3.org/2000/svg','animateMotion');
        anim.setAttribute('dur', `${3 / speed}s`);
        anim.setAttribute('repeatCount', 'indefinite');
        anim.setAttribute('begin', `${(i / count) * (3 / speed)}s`);
        anim.setAttribute('path', d);
        particle.appendChild(anim);
        svg.appendChild(particle);
      }
    }

    // Edge label (protocol/ports)
    if (edge.label) {
      const mx = (sp.x + 180 + dp.x) / 2;
      const my = (sp.y + NODE_H/2 + dp.y + NODE_H/2) / 2;
      const labelEl = document.createElement('div');
      labelEl.className = 'edge-label' + (isDimmed ? ' dimmed' : '');
      labelEl.style.left = mx + 'px';
      labelEl.style.top = my + 'px';
      labelEl.textContent = edge.label;
      labelEl.dataset.edgeId = edge.id;
      labelEl.addEventListener('click', () => selectEdge(edge));
      labelEl.style.pointerEvents = 'auto';
      labelEl.style.cursor = 'pointer';
      content.appendChild(labelEl);
    }
  });

  // Draw nodes
  topologyNodes.forEach(node => {
    const pos = positions[node.id];
    if (!pos) return;
    const isDimmed = selectedNode && !connectedIds.has(node.id);
    const isSelected = selectedNode === node.id;

    const card = document.createElement('div');
    card.className = `node-card node-type-${node.type}` + (isSelected ? ' selected' : '') + (isDimmed ? ' dimmed' : '') + (node.status === 'inactive' ? ' inactive' : '');
    card.style.left = pos.x + 'px';
    card.style.top = pos.y + 'px';
    card.tabIndex = 0;
    card.setAttribute('role', 'button');
    card.setAttribute('aria-label', `${node.type}: ${node.label}`);

    const statusClass = node.status === 'active' ? 'active' : node.status === 'warning' ? 'warning' : node.status === 'blocked' ? 'blocked' : 'inactive';
    card.innerHTML = `
      <div class="node-header">
        <div class="node-dot ${statusClass}"></div>
        <div class="node-label">${esc(node.label)}</div>
      </div>
      ${node.subtitle ? `<div class="node-subtitle">${esc(node.subtitle)}</div>` : ''}
      ${node.badge ? `<div class="node-badge">${esc(node.badge)}</div>` : ''}
    `;
    card.addEventListener('click', () => selectNode(node));
    card.addEventListener('keydown', (e) => { if (e.key === 'Enter') selectNode(node); });
    content.appendChild(card);
  });
}

function esc(s) { return s ? s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) : ''; }

// === SELECTION ===
function selectNode(node) {
  if (selectedNode === node.id) {
    selectedNode = null;
    closeDetails();
  } else {
    selectedNode = node.id;
    showNodeDetails(node);
  }
  render();
}

function selectEdge(edge) {
  selectedEdge = edge;
  showEdgeDetails(edge);
}

function showNodeDetails(node) {
  const panel = document.getElementById('detailsPanel');
  document.getElementById('detailTitle').textContent = node.label;
  let html = '';
  if (node.subtitle) html += `<div class="detail-row"><span class="detail-label">Address</span><span class="detail-value">${esc(node.subtitle)}</span></div>`;
  html += `<div class="detail-row"><span class="detail-label">Type</span><span class="detail-value">${node.type}</span></div>`;
  html += `<div class="detail-row"><span class="detail-label">Status</span><span class="detail-status"><span class="node-dot ${node.status||'inactive'}"></span>${node.status || 'unknown'}</span></div>`;
  if (node.metadata) {
    Object.entries(node.metadata).forEach(([k,v]) => {
      html += `<div class="detail-row"><span class="detail-label">${esc(k)}</span><span class="detail-value">${esc(String(v))}</span></div>`;
    });
  }
  // Show connected edges
  const conns = topologyEdges.filter(e => e.source === node.id || e.target === node.id);
  if (conns.length) {
    html += `<div style="margin-top:16px;font-size:13px;font-weight:600;color:var(--text-primary)">Connections (${conns.length})</div>`;
    conns.forEach(e => {
      const other = e.source === node.id ? e.target : e.source;
      const otherNode = topologyNodes.find(n => n.id === other);
      html += `<div class="detail-row"><span class="detail-label">${esc(otherNode?.label || other)}</span><span class="detail-value" style="color:${e.colour||getEdgeColor(e.status)}">${e.label || e.status}</span></div>`;
    });
  }
  document.getElementById('detailBody').innerHTML = html;
  panel.classList.add('open');
}

function showEdgeDetails(edge) {
  const panel = document.getElementById('detailsPanel');
  document.getElementById('detailTitle').textContent = edge.label || 'Connection';
  const srcNode = topologyNodes.find(n => n.id === edge.source);
  const dstNode = topologyNodes.find(n => n.id === edge.target);
  let html = '';
  html += `<div class="detail-row"><span class="detail-label">From</span><span class="detail-value">${esc(srcNode?.label || edge.source)}</span></div>`;
  html += `<div class="detail-row"><span class="detail-label">To</span><span class="detail-value">${esc(dstNode?.label || edge.target)}</span></div>`;
  if (edge.protocol) html += `<div class="detail-row"><span class="detail-label">Protocol</span><span class="detail-value">${edge.protocol.toUpperCase()}</span></div>`;
  if (edge.ports) html += `<div class="detail-row"><span class="detail-label">Ports</span><span class="detail-value">${edge.ports}</span></div>`;
  html += `<div class="detail-row"><span class="detail-label">Status</span><span class="detail-status"><span class="node-dot ${edge.status==='active'?'active':'blocked'}"></span>${edge.status || 'unknown'}</span></div>`;
  if (edge.trafficRate !== undefined) html += `<div class="detail-row"><span class="detail-label">Traffic Rate</span><span class="detail-value">${edge.trafficRate}/s</span></div>`;
  if (edge.metadata) {
    Object.entries(edge.metadata).forEach(([k,v]) => {
      html += `<div class="detail-row"><span class="detail-label">${esc(k)}</span><span class="detail-value">${esc(String(v))}</span></div>`;
    });
  }
  document.getElementById('detailBody').innerHTML = html;
  panel.classList.add('open');
}

function closeDetails() {
  document.getElementById('detailsPanel').classList.remove('open');
  selectedNode = null;
  selectedEdge = null;
  render();
}

// === PAN & ZOOM ===
let scale = 1, panX = 0, panY = 0, isDragging = false, dragStartX = 0, dragStartY = 0;
const canvas = document.getElementById('canvas');
const content = document.getElementById('content');
const svg = document.getElementById('svg');

function applyTransform() {
  content.style.transform = `translate(${panX}px,${panY}px) scale(${scale})`;
  svg.style.transform = `translate(${panX}px,${panY}px) scale(${scale})`;
}

canvas.addEventListener('mousedown', e => {
  if (e.target.classList.contains('node-card') || e.target.classList.contains('edge-label')) return;
  isDragging = true;
  dragStartX = e.clientX - panX;
  dragStartY = e.clientY - panY;
});
canvas.addEventListener('mousemove', e => {
  if (!isDragging) return;
  panX = e.clientX - dragStartX;
  panY = e.clientY - dragStartY;
  applyTransform();
});
canvas.addEventListener('mouseup', () => isDragging = false);
canvas.addEventListener('mouseleave', () => isDragging = false);

canvas.addEventListener('wheel', e => {
  e.preventDefault();
  const delta = e.deltaY > 0 ? 0.9 : 1.1;
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  panX = mx - (mx - panX) * delta;
  panY = my - (my - panY) * delta;
  scale = Math.max(0.3, Math.min(3, scale * delta));
  applyTransform();
}, { passive: false });

function fitView() {
  if (!topologyNodes.length) return;
  const positions = layoutNodes(topologyNodes);
  const maxX = Math.max(...Object.values(positions).map(p => p.x + 180));
  const maxY = Math.max(...Object.values(positions).map(p => p.y + NODE_H));
  const w = canvas.clientWidth, h = canvas.clientHeight;
  scale = Math.min(w / (maxX + 40), h / (maxY + 40), 1.2);
  panX = (w - maxX * scale) / 2;
  panY = 20;
  applyTransform();
}

// === MOTION ===
function toggleMotion() {
  motionEnabled = !motionEnabled;
  document.getElementById('motionBtn').textContent = `Motion: ${motionEnabled ? 'On' : 'Off'}`;
  render();
}

// Check prefers-reduced-motion
if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
  motionEnabled = false;
}

// === DATA: Load from gateway API ===
function updateData() {
  // Try to fetch from gateway API
  fetch('/api/connections?limit=500', {
    headers: { Authorization: apiKey || 'test-key' }
  }).then(r => r.json()).then(d => {
    allConns = d.connections || [];
    buildTopology(allConns);
  }).catch(() => {
    // Fallback to sample data
    buildTopology([]);
  });
}

function buildTopology(conns) {
  if (!conns.length) {
    // Sample topology from the spec
    topologyNodes = [
      { id: 'client', type: 'source', label: 'Workstation', subtitle: '100.64.17.61', status: 'active' },
      { id: 'policy-infra', type: 'policy', label: 'workstation-to-infra', subtitle: 'TCP:22,443,8006', status: 'active' },
      { id: 'policy-dns', type: 'policy', label: 'workstation-to-dns', subtitle: 'UDP:53', status: 'active' },
      { id: 'infra', type: 'destination', label: 'Infrastructure', subtitle: '5 resources', status: 'active' },
      { id: 'dns', type: 'destination', label: 'DNS Server', subtitle: '1 resource', status: 'active' },
    ];
    topologyEdges = [
      { id: 'e1', source: 'client', target: 'policy-infra', status: 'active', colour: '#35d6a0', animationSpeed: 1, particleCount: 2 },
      { id: 'e2', source: 'policy-infra', target: 'infra', label: 'TCP:22,443,8006', protocol: 'tcp', ports: '22,443,8006', status: 'active', colour: '#35d6a0', animationSpeed: 1.2, particleCount: 2 },
      { id: 'e3', source: 'client', target: 'policy-dns', status: 'active', colour: '#48c8d8', animationSpeed: 0.8, particleCount: 1 },
      { id: 'e4', source: 'policy-dns', target: 'dns', label: 'UDP:53', protocol: 'udp', ports: '53', status: 'active', colour: '#48c8d8', animationSpeed: 0.8, particleCount: 1 },
    ];
    render();
    fitView();
    return;
  }

  // Build topology from real connections
  const filter = document.getElementById('decisionFilter')?.value;
  let filtered = conns;
  if (filter) filtered = filtered.filter(c => c.decision === filter);

  const bySrc = {}, byTool = {}, byDst = {};
  filtered.forEach(c => {
    const s = c.source || 'unknown';
    const t = c.tool || 'unknown';
    const d = c.destination || 'unknown';
    if (!bySrc[s]) bySrc[s] = { count: 0, allow: 0, deny: 0, escalate: 0 };
    bySrc[s].count++; bySrc[s][c.decision] = (bySrc[s][c.decision] || 0) + 1;
    if (!byTool[t]) byTool[t] = { count: 0, allow: 0, deny: 0, escalate: 0, policy: c.policy || '' };
    byTool[t].count++; byTool[t][c.decision] = (byTool[t][c.decision] || 0) + 1;
    if (!byDst[d]) byDst[d] = { count: 0, allow: 0, deny: 0, escalate: 0 };
    byDst[d].count++; byDst[d][c.decision] = (byDst[d][c.decision] || 0) + 1;
  });

  const nodes = [];
  const edges = [];

  Object.entries(bySrc).forEach(([name, d]) => {
    const status = d.deny > d.allow ? 'blocked' : d.escalate > 0 ? 'warning' : 'active';
    nodes.push({ id: `src-${name}`, type: 'source', label: name, subtitle: `${d.count} calls`, status, metadata: { allow: d.allow, deny: d.deny, escalate: d.escalate } });
  });
  Object.entries(byTool).forEach(([name, d]) => {
    const status = d.deny > d.allow ? 'blocked' : d.escalate > 0 ? 'warning' : 'active';
    const policy = d.policy ? d.policy.split('/').pop() : '';
    nodes.push({ id: `tool-${name}`, type: 'policy', label: name, subtitle: policy, badge: `${d.count} calls`, status, metadata: { allow: d.allow, deny: d.deny, escalate: d.escalate, policy } });
  });
  Object.entries(byDst).forEach(([name, d]) => {
    const status = d.deny > d.allow ? 'blocked' : d.escalate > 0 ? 'warning' : 'active';
    nodes.push({ id: `dst-${name}`, type: 'destination', label: name, subtitle: `${d.count} calls`, status, metadata: { allow: d.allow, deny: d.deny, escalate: d.escalate } });
  });

  // Build edges: source -> tool -> destination
  filtered.forEach((c, i) => {
    const sId = `src-${c.source || 'unknown'}`;
    const tId = `tool-${c.tool || 'unknown'}`;
    const dId = `dst-${c.destination || 'unknown'}`;
    const colour = getEdgeColor(c.decision);
    edges.push({ id: `e-s2t-${i}`, source: sId, target: tId, status: c.decision, colour, animationSpeed: c.decision === 'deny' ? 0.5 : 1, particleCount: 1 });
    edges.push({ id: `e-t2d-${i}`, source: tId, target: dId, label: c.policy ? c.policy.split('/').pop() : '', status: c.decision, colour, animationSpeed: c.decision === 'deny' ? 0.5 : 1.2, particleCount: 1, metadata: { decision: c.decision, reason: c.reason, latency_us: c.latency_us } });
  });

  // Deduplicate edges by (source,target) pair keeping the most recent
  const edgeMap = {};
  edges.forEach(e => {
    const key = `${e.source}|${e.target}`;
    if (!edgeMap[key]) edgeMap[key] = e;
  });
  topologyNodes = nodes;
  topologyEdges = Object.values(edgeMap);
  render();
  fitView();
}

// === POLLING ===
function startPolling() {
  if (pollId) clearInterval(pollId);
  pollId = setInterval(() => {
    if (!document.hidden) updateData();
  }, 5000);
}

// === INIT ===
updateData();
startPolling();
window.addEventListener('resize', () => { render(); fitView(); });
</script>
</body>
</html>"""


__all__ = ["create_gateway_app", "create_admin_app"]
