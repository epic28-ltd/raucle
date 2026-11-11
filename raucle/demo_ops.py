"""Demo-mode operational surfaces: operator roster, SIEM forwarding, config.

Three admin-panel tabs (Users, SIEM, Config) are operator-only identity and
configuration surfaces. In demo mode they render read-only views backed by
the endpoints registered here, so a visitor sees a plausible running
deployment without being offered a single control. Live operator behaviour
is untouched: the edit forms still ship for authenticated sessions.

Gating follows the established demo contract: the routes answer only when
``RAUCLE_DEMO_MODE`` is on, through the same authenticated, read-only
resource gate as the rest of the ``/api/demo/*`` plane, and answer 404
otherwise, exactly like ``/api/demo-key`` does when demo mode is off.

Only GET is registered: nothing here mutates state, no SIEM delivery is
ever attempted from demo mode, and no secret (API key, SIEM token or
health-check token) enters any response.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Header, HTTPException

__all__ = [
    "CONFIG_LABEL",
    "DEMO_OPERATORS",
    "SIMULATED_LABEL",
    "build_demo_config",
    "build_demo_operators",
    "build_demo_siem",
    "register_demo_ops_routes",
]

SIMULATED_LABEL = "Simulated demo data"

#: The config view carries the deployment's REAL settings, so its label is
#: deliberately not the simulated label: only the roster and the SIEM
#: forwarder example are simulated demonstration data.
CONFIG_LABEL = "Live deployment configuration"

# ---------------------------------------------------------------------------
# Simulated operator roster
# ---------------------------------------------------------------------------
# Fixed demonstration records: names, roles and MFA enrolment state only.
# The demo key cannot list the real operator store, and no key material or
# TOTP state of any kind is represented here.
DEMO_OPERATORS: tuple[dict[str, Any], ...] = (
    {
        "user_id": "demo-ops-01",
        "name": "Dana Whitcombe",
        "role": "admin",
        "mfa_enabled": True,
    },
    {
        "user_id": "demo-ops-02",
        "name": "Priya Raman",
        "role": "operator",
        "mfa_enabled": True,
    },
    {
        "user_id": "demo-ops-03",
        "name": "Marcus Oduya",
        "role": "operator",
        "mfa_enabled": False,
    },
    {
        "user_id": "demo-ops-04",
        "name": "Sam Ellison",
        "role": "auditor",
        "mfa_enabled": True,
    },
)

_ROSTER_NOTE = (
    "Simulated demo data: the roster illustrates the panel's operator and MFA "
    "view. No real operator records, keys or sessions are exposed."
)


def build_demo_operators() -> dict[str, Any]:
    """Return the simulated operator roster for the demo Users view."""
    return {
        "users": [dict(op) for op in DEMO_OPERATORS],
        "simulated": True,
        "note": _ROSTER_NOTE,
    }


# ---------------------------------------------------------------------------
# Simulated SIEM forwarding example
# ---------------------------------------------------------------------------
# The example mirrors the exact payload the real SIEMForwarder emits (the
# four gate-decision fields plus the timestamp, see gateway.SIEMForwarder)
# and carries per-hour event counts over the demo window. Nothing here is
# ever sent anywhere: demo mode registers no delivery route.
_SIEM_EVENT_SAMPLE: dict[str, Any] = {
    "event": "gate_decision",
    "tool": "lookup_balance",
    "decision": "deny",
    "reason": "no capability grant covers tool lookup_balance for this agent",
    "timestamp": "2026-11-11T09:24:03+00:00",
}

#: (events in the hour, delivery status) per bucket, oldest first.
_SIEM_ACTIVITY: tuple[tuple[int, str], ...] = (
    (118, "delivered"),
    (126, "delivered"),
    (94, "delivered"),
    (152, "delivered"),
    (140, "delivered"),
    (131, "retried once, then delivered"),
    (97, "delivered"),
    (102, "delivered"),
    (94, "delivered"),
    (86, "delivered"),
    (121, "delivered"),
    (133, "delivered"),
)

_SIEM_WINDOW_HOURS = 12


def _siem_forwarder_example() -> dict[str, Any]:
    """Build the simulated forwarder example served beside the real config."""
    buckets: list[dict[str, Any]] = []
    oldest = _SIEM_WINDOW_HOURS - 1
    for index, (events, status) in enumerate(_SIEM_ACTIVITY):
        offset = oldest - index
        buckets.append(
            {
                "label": f"-{offset}h" if offset else "now",
                "events": events,
                "batches": (events + 49) // 50,
                "status": status,
            }
        )
    return {
        "label": SIMULATED_LABEL,
        "note": (
            "Simulated demo data: the forwarding example illustrates what this "
            "deployment would emit to a SIEM collector and how often over the "
            "demo window. No events leave the gateway in demo mode."
        ),
        "endpoint_shape": {
            "transport": "HTTP POST with a JSON body over TLS",
            "url_example": "https://logs.demo-siem.test:9200/raucle-gate/_doc",
            "content_type": "application/json",
            "authentication": "credential on file, never displayed",
        },
        "event_sample": dict(_SIEM_EVENT_SAMPLE),
        "event_note": (
            "Field shape identical to the real forwarder's gate-decision "
            "payload; the values are simulated."
        ),
        "activity": buckets,
        "window_note": (
            "Event counts per hour over the prior "
            f"{_SIEM_WINDOW_HOURS} hours of the demo window, oldest first."
        ),
        "events_forwarded_total": sum(events for events, _ in _SIEM_ACTIVITY),
    }


def build_demo_siem(gateway: Any) -> dict[str, Any]:
    """Combine the real forwarding config with the simulated forwarder view."""
    siem = gateway.siem
    return {
        "configured": {
            "enabled": bool(siem.enabled),
            "backend": siem.backend or "",
            "url": siem.url or "",
            "token_configured": bool(siem.token),
            "buffered_events": len(siem.buffered_events()),
        },
        "config_note": (
            "The forwarding settings above are this deployment's real, "
            "read-only configuration. Credential fields are never shown."
        ),
        "simulated": _siem_forwarder_example(),
    }


# ---------------------------------------------------------------------------
# Real configuration, rendered read-only
# ---------------------------------------------------------------------------


def _config_row(label: str, value: Any) -> dict[str, Any]:
    """One profile row: the label is display copy, the value is the real one."""
    return {"label": label, "value": "" if value is None else value}


def build_demo_config(gateway: Any) -> dict[str, Any]:
    """Render the live gateway configuration as a read-only profile.

    Secret fields (admin key, SIEM token, health-check token) are excluded;
    the row set mirrors the fields the authenticated config view exposes,
    minus everything a demo visitor must not read.
    """
    c = gateway.config
    siem_summary = "disabled"
    if c.siem_enabled:
        siem_summary = "enabled"
        if c.siem_backend:
            siem_summary = f"enabled via {c.siem_backend}"
    return {
        "read_only": True,
        "label": CONFIG_LABEL,
        "note": (
            "Read-only demo view of the running gateway's real configuration: "
            "binding addresses, ports, signer backend, policy source and "
            "evidence store paths. Secret fields are never shown and editing "
            "stays with the authenticated operator view."
        ),
        "profile": [
            _config_row("Host", c.host),
            _config_row("Gateway port", c.port),
            _config_row("Admin panel port", c.admin_port),
            _config_row("Signer backend", c.signer_backend),
            _config_row("Gate auth mode", c.gate_auth),
            _config_row("Policy file", c.policy_file),
            _config_row("Policy directory", c.policy_dir),
            _config_row("Receipt store", c.receipt_store),
            _config_row("Audit chain", c.audit_chain),
            _config_row("Audit log file", c.audit_log_file),
            _config_row("Receipt registry path", c.registry_path),
            _config_row("Compliance framework", c.compliance_framework),
            _config_row("Audit persistence", "enabled" if c.audit_persist else "disabled"),
            _config_row("SIEM forwarding", siem_summary),
            _config_row("Configuration file", c.config_file),
        ],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _demo_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


def register_demo_ops_routes(app: Any, gateway: Any, check_auth: Any, check_access: Any) -> None:
    """Register the demo Users / SIEM / Config endpoints on *app*.

    ``gateway`` carries the live configuration and SIEM forwarder state the
    SIEM and config views render. Read-only and gated: without demo mode on,
    every route here answers 404 exactly like the other demo-plane
    endpoints, so the tabs a live operator uses keep their authenticated
    behaviour everywhere else.
    """

    def _gate(authorization: Any, x_totp: Any) -> Any:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return user

    @app.get(
        "/api/demo/users",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_users(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """Simulated operator roster: names, roles and MFA state only."""
        _gate(authorization, x_totp)
        return build_demo_operators()

    @app.get(
        "/api/demo/siem",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_siem(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """Real forwarding config plus the simulated forwarder example."""
        _gate(authorization, x_totp)
        return build_demo_siem(gateway)

    @app.get(
        "/api/demo/config",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_config(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """The running gateway's real configuration, read-only, secrets out."""
        _gate(authorization, x_totp)
        return build_demo_config(gateway)
