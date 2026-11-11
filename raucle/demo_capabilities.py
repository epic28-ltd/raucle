"""Demo-mode capability-token inspection (EPIC E, item E1).

Backs the admin panel's Capability tokens tab with the REAL capability
machinery in :mod:`raucle.capability`:

- every token on screen is minted and attenuated live by the gateway's
  own :class:`~raucle.capability.CapabilityIssuer` (there is no canned
  token material in this module beyond the simulated call scenarios),
- every verify result is the real :meth:`CapabilityGate.check` decision -
  allow and deny alike come from the gate's actual checks, and a
  tampered token fails closed with the gate's real reason,

Gating follows the demo key/session model used by the other demo planes:
routes answer only when ``RAUCLE_DEMO_MODE`` is on, everything returned
is simulated demonstration data clearly labelled as such, and the routes
are read-only - minting happens in memory and writes nothing.
"""

from __future__ import annotations

import copy
import os
from typing import Any

from fastapi import Header, HTTPException

from raucle.capability import Capability, CapabilityGate, GateDecision

SIMULATED_NOTE = (
    "Simulated capability chains. The tokens shown are minted live by the "
    "gateway's own issuer over simulated calls: every field, including the "
    "attenuation chain and the expiry, comes from the real capability "
    "machinery, and the verify action runs the real capability gate. "
    "Read-only demonstration data; nothing is delegated or enforced beyond "
    "this screen."
)

VERIFY_NOTE = (
    "The verdict above is the real CapabilityGate decision for the selected "
    "simulated call, verified in-memory. Simulated demo data: an allow here "
    "would not authorise anything outside the demo."
)

# Bounded in-memory inspection surface (mirrors the receipts page caps).
_MAX_TTL_SECONDS = 3600


# ---------------------------------------------------------------------------
# Simulated call scenarios. Constraint keys are the real schema documented on
# Capability: allowed_values, max_value / min_value bounds, required_present.
# `attenuations` drive real CapabilityIssuer.attenuate calls, parent to child.
# ---------------------------------------------------------------------------

DEMO_CAPABILITY_CALLS: tuple[dict[str, Any], ...] = (
    {
        "id": "cap-refund-banking",
        "scenario": "banking",
        "agent_id": "agent:bank-support",
        "tool": "issue_refund",
        "args": {
            "amount": 85,
            "currency": "GBP",
            "account": "GB29 NWBK 6016 1331 9268 19",
            "reason": "service credit for a failed card payment",
        },
        "constraints": {
            "allowed_values": {"currency": ["GBP", "EUR"]},
            "max_value": {"amount": 150},
            "min_value": {"amount": 1},
            "required_present": ["account", "amount", "reason"],
            "forbidden_values": {"reason": ["gift card", "crypto"]},
        },
        "attenuations": [
            {
                "narrower_agent_id": "agent:bank-support.queue-2",
                "extra_constraints": {"max_value": {"amount": 100}},
                "narrower_ttl_seconds": 900,
            }
        ],
        "expectation": "the attenuated child allows this call",
    },
    {
        "id": "cap-overstep-refund",
        "scenario": "banking",
        "agent_id": "agent:bank-audit",
        "tool": "issue_refund",
        "args": {
            "amount": 120,
            "currency": "GBP",
            "account": "GB33 NWBK 0000 0000 0000 01",
            "reason": "scheduled clinic export inside the demo bounds",
        },
        "constraints": {
            "allowed_values": {"currency": ["GBP"]},
            "max_value": {"amount": 90},
            "required_present": ["account", "amount", "reason"],
        },
        # No attenuation: a root token whose bound the call oversteps, so
        # the real gate's deny verdict is on show rather than the allow.
        "attenuations": [],
        "expectation": ("the real gate denies the overstep: the amount is above the bound"),
    },
)


def _demo_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Real-machinery chain builder + views
# ---------------------------------------------------------------------------


def build_demo_chain(issuer: Any, call: dict[str, Any]) -> list[Capability]:
    """Mint the scenario's real token chain with the gateway's own issuer.

    Parent-first: ``CapabilityIssuer.mint`` then each attenuation step via
    ``CapabilityIssuer.attenuate``. In-memory only; nothing is persisted.
    """
    tokens = [
        issuer.mint(
            agent_id=str(call["agent_id"]),
            tool=str(call["tool"]),
            constraints=call["constraints"],
            ttl_seconds=_MAX_TTL_SECONDS,
        )
    ]
    for step in call["attenuations"]:
        kwargs: dict[str, Any] = {}
        if step.get("extra_constraints"):
            kwargs["extra_constraints"] = step["extra_constraints"]
        if step.get("narrower_agent_id"):
            kwargs["narrower_agent_id"] = step["narrower_agent_id"]
        if step.get("narrower_ttl_seconds"):
            kwargs["narrower_ttl_seconds"] = step["narrower_ttl_seconds"]
        if step.get("acting_for"):
            kwargs["acting_for"] = step["acting_for"]
        tokens.append(issuer.attenuate(tokens[-1], **kwargs))
    return tokens


def _compact(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 90 else text[:87] + "..."


def _narrowing_lines(child: Capability, parent: Capability) -> list[str]:
    """What the attenuation actually narrowed, read from the signed bodies."""
    lines: list[str] = []
    if child.agent_id != parent.agent_id:
        lines.append(f"agent binding narrowed: {parent.agent_id} -> {child.agent_id}")
    if child.expires_at != parent.expires_at:
        lines.append(f"expiry moved earlier: {parent.expires_at} -> {child.expires_at}")
    if parent.acting_for and child.acting_for != parent.acting_for:
        lines.append(f"acting-for narrowed: {parent.acting_for} -> {child.acting_for}")
    for key in sorted(set(parent.constraints) | set(child.constraints)):
        if parent.constraints.get(key) != child.constraints.get(key):
            before, after = (
                _compact(parent.constraints.get(key)),
                _compact(child.constraints.get(key)),
            )
            lines.append(f"constraints narrowed [{key}]: {before} -> {after}")
    if not lines:
        lines.append("no dimension widened (same signed scope as the parent)")
    return lines


def token_view(token: Capability, role: str, parent: Capability | None = None) -> dict[str, Any]:
    """Render one real token's envelope for the inspector."""
    view: dict[str, Any] = {
        "role": role,
        "token_id": token.token_id,
        "issuer": token.issuer,
        "issuer_key_id": token.key_id,
        "agent_id": token.agent_id,
        "tool": token.tool,
        "issued_at": token.issued_at,
        "not_before": token.not_before,
        "expires_at": token.expires_at,
        "parent_id": token.parent_id,
        "signature_present": bool(token.signature),
        "signature_prefix": token.signature[:16] + ("..." if len(token.signature) > 16 else ""),
        "pq_key_id": token.pq_key_id,
        "pq_signature_present": bool(token.pq_signature),
        "constraints": copy.deepcopy(token.constraints),
        "acting_for": token.acting_for,
    }
    if parent is not None:
        view["narrowed"] = _narrowing_lines(token, parent)
    return view


def chain_view(tokens: list[Capability]) -> list[dict[str, Any]]:
    out = [token_view(tokens[0], "root")]
    for i, token in enumerate(tokens[1:], start=1):
        out.append(token_view(token, f"attenuated-{i}", parent=tokens[i - 1]))
    return out


# ---------------------------------------------------------------------------
# Real verification path (CapabilityGate.check)
# ---------------------------------------------------------------------------


def verify_demo_call(issuer: Any, call: dict[str, Any]) -> dict[str, Any]:
    """Run the REAL gate over the simulated call's freshly minted chain."""
    tokens = build_demo_chain(issuer, call)
    by_id = {t.token_id: t for t in tokens}
    gate = CapabilityGate(
        trusted_issuers={issuer.key_id: issuer.public_key_pem},
        parent_resolver=lambda token_id: by_id.get(token_id),
    )
    final = tokens[-1]
    decision = gate.check(
        final,
        tool=str(call["tool"]),
        agent_id=str(final.agent_id),
        args=dict(call["args"]),
    )
    # Fail-closed probe: the same token with one constraint value altered in
    # memory. Constraints are signed material, so the real signature check
    # must refuse it - labelled as a simulated tamper.
    tampered = Capability.from_dict(_mutate_constraints(copy.deepcopy(tokens[0].to_dict())))
    tamper_decision = gate.check(
        tampered,
        tool=str(call["tool"]),
        agent_id=str(tampered.agent_id),
        args=dict(call["args"]),
    )
    return {
        "call_id": call["id"],
        "expectation": call["expectation"],
        "chain": [t.token_id for t in tokens],
        "decision": _decision_view(decision),
        "tamper_probe": {**_decision_view(tamper_decision), "simulated_tamper": True},
        "simulated": True,
        "note": VERIFY_NOTE,
    }


def _mutate_constraints(token_dict: dict[str, Any]) -> dict[str, Any]:
    constraints = dict(token_dict.get("constraints") or {})
    bounds = dict(constraints.get("max_value") or {})
    if bounds:
        first_field = min(bounds)
        bounds[first_field] = int(bounds[first_field]) + 10
        constraints["max_value"] = bounds
    else:
        constraints["required_present"] = ["extra_field_simulated_tamper"]
    token_dict["constraints"] = constraints
    return token_dict


def _decision_view(decision: GateDecision) -> dict[str, Any]:
    return {
        "verdict": "allow" if decision.allowed else "deny",
        "reason": decision.reason,
        "token_id": decision.token_id,
        "chain": list(decision.chain or []),
        "attributable": decision.attributable,
    }


# ---------------------------------------------------------------------------
# Routes: same gating shape as the demo MCP / stop / policy-sim lanes
# ---------------------------------------------------------------------------


def register_demo_capability_routes(
    app: Any,
    check_auth: Any,
    check_access: Any,
    gateway_provider: Any,
) -> None:
    """Register the demo capability-token inspector endpoints on *app*.

    Read-only, in-memory minting only. The gate is the demo mode environment
    flag: on any other deployment the routes answer 404 exactly like the
    other demo-plane routes do. ``gateway_provider`` returns the gateway the
    issuer key material is drawn from.
    """

    def _issuer() -> Any:
        gateway = gateway_provider()
        issuer = getattr(gateway, "_issuer", None)
        if issuer is None:
            raise HTTPException(503, "capability issuer not initialised")
        return issuer

    @app.get(
        "/api/demo/capabilities",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_capabilities(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        issuer = _issuer()
        calls = []
        for call in DEMO_CAPABILITY_CALLS:
            calls.append(
                {
                    "id": call["id"],
                    "scenario": call["scenario"],
                    "expectation": call["expectation"],
                    "agent_id": call["agent_id"],
                    "tool": call["tool"],
                    "args": call["args"],
                    "chain": chain_view(build_demo_chain(issuer, call)),
                }
            )
        return {"note": SIMULATED_NOTE, "simulated": True, "calls": calls}

    @app.post(
        "/api/demo/capabilities/{call_id}/verify",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Unknown demo call or demo mode not configured"},
        },
    )
    def demo_capability_verify(
        call_id: str,
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        for call in DEMO_CAPABILITY_CALLS:
            if call["id"] == call_id:
                return verify_demo_call(_issuer(), call)
        raise HTTPException(404, "unknown demo capability call")
