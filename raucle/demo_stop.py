"""D9: the read-only emergency authority stop demo surface.

The demo screen tells the OPERATOR story of :mod:`raucle.containment`
(the B1-B3 work): a default-off control that is itself receipted, a
global stop that is M-of-N by quorum, and every transition signed. A
demo visitor watches the story read-only; nothing here can arm or
apply anything - the panel renders receipts produced in a THROWAWAY
sandbox by the real machinery, labelled simulated.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from raucle.containment import (
    SCOPES,
    VERDICT_BUTTON_ARM,
    VERDICT_BUTTON_DISARM,
    VERDICT_HOLD,
    VERDICT_HOLD_APPROVAL,
    VERDICT_HOLD_PENDING,
    VERDICT_RESUME,
    ContainmentConfig,
    ContainmentManager,
)

_NOTE_SIMULATED = (
    "Simulated demonstration: the receipts below were produced in a "
    "disposable sandbox by the real containment machinery. This screen "
    "is a display only - it cannot arm, hold or resume anything."
)

_DESCRIPTION = (
    "Emergency authority stop: what an operator holds. The control ships "
    "default per deployment, arming it is a signed receipted transition, "
    "and a global stop needs the M-of-N quorum of distinct approver "
    "receipts before the policy swap happens."
)


def _decode_receipts(receipts_path: Path) -> list[dict[str, Any]]:
    if not receipts_path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in receipts_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            payload = json.loads(
                base64.urlsafe_b64decode(
                    record["jws"].split(".")[1] + "=" * (-len(record["jws"].split(".")[1]) % 4)
                )
            )
        except (KeyError, ValueError):  # JSONDecodeError is a ValueError
            continue  # never render a partially parsed stream as a receipt
        extra = payload.get("extra", {})
        out.append(
            {
                "verdict": payload.get("verdict", ""),
                "receipt_id": record.get("receipt_hash", record.get("receipt_id", "")),
                "scope": extra.get("scope", ""),
                "actor": extra.get("actor", ""),
                "operator": extra.get("operator", ""),
                "approvers": extra.get("approvers", []),
                "min_approvers": extra.get("min_approvers"),
                "reason": extra.get("reason", ""),
            }
        )
    return out


def build_demo_stop() -> dict[str, Any]:
    """Run the receipted operator story once in a disposable sandbox.

    Flow mirrors the shipped operator screen semantics: default-off
    button, receipted arm, receipted disarm, then a global-scope hold
    under the default M-of-N quorum (pending -> two distinct approval
    receipts -> applied hold) and the receipted resume.
    """
    story: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="raucle-demo-stop-") as td:
        root = Path(td)
        policy = root / "policies.yaml"
        policy.write_text(
            "version: 1\n"
            "issuer: demo.sim\n"
            "policies:\n"
            "  - tool: lookup_balance\n"
            "    agent_id: agent:svc\n"
            "    ttl_seconds: 60\n"
            "    constraints:\n"
            "      allow:\n"
            '        account: ["ACC-001"]\n',
            encoding="utf-8",
        )
        receipts_path = root / "containment-receipts.jsonl"
        manager = ContainmentManager(
            ContainmentConfig(
                policy_file=str(policy),
                receipts_path=str(receipts_path),
                state_dir=str(root / "containment"),
                actor="demo-operator",
            )
        )
        story.append(
            {
                "step": "Button default",
                "detail": "The control ships OFF. Arm and resume live only with operators.",
                "outcome": manager.button_state(),
            }
        )
        story.append(
            {
                "step": "Arm",
                "detail": "A named operator arms the control: a signed receipted transition.",
                "outcome": manager.arm_button(operator="demo-operator", reason="drill"),
            }
        )
        story.append(
            {
                "step": "Disarm",
                "detail": "Disarming is the symmetric receipted half; never a silent clear.",
                "outcome": manager.disarm_button(operator="demo-operator", reason="drill over"),
            }
        )
        story.append(
            {
                "step": "Hold raised (global scope)",
                "detail": (
                    "A global stop is quorum-gated: with M=2 it enters a receipted "
                    "PENDING state and the enforcement bytes stay untouched."
                ),
                "outcome": dict(manager.hold(scope="global", reason="incident")),
            }
        )
        story.append(
            {
                "step": "First approval",
                "detail": "One distinct approver is not the quorum; the stop stays pending.",
                "outcome": manager.approve_hold(approver="demo-approver-1"),
            }
        )
        story.append(
            {
                "step": "Quorum met",
                "detail": "Second distinct approver: the quorum is met and the hold applies.",
                "outcome": manager.approve_hold(approver="demo-approver-2"),
            }
        )
        story.append(
            {
                "step": "Resume",
                "detail": "The paired resume restores the exact pre-hold policy bytes.",
                "outcome": manager.resume(reason="incident closed"),
            }
        )
        receipts = _decode_receipts(receipts_path)

    # The sandbox layout is an implementation detail: strip filesystem
    # targets from the story outcomes before anything is served.
    SANDBOX_KEYS = ("target_file", "policy_file", "state_dir", "file")
    for step in story:
        outcome = step.get("outcome")
        if isinstance(outcome, dict):
            for k in SANDBOX_KEYS:
                outcome.pop(k, None)

    verdict_counts: dict[str, int] = {}
    for r in receipts:
        verdict_counts[r["verdict"]] = verdict_counts.get(r["verdict"], 0) + 1
    return {
        "note": _NOTE_SIMULATED,
        "simulated": True,
        "description": _DESCRIPTION,
        "scopes": list(SCOPES),
        "quorum": {
            "global": 2,
            "agent": 1,
            "chain": 1,
            "note": (
                "Global defaults to M-of-N with N=2; agent and chain scopes are single-approver."
            ),
        },
        "button_default": {
            "armed": False,
            "note": "Default-off per deployment: arming is itself a receipted operator transition.",
        },
        "verdict_names": {
            "arm": VERDICT_BUTTON_ARM,
            "disarm": VERDICT_BUTTON_DISARM,
            "pending": VERDICT_HOLD_PENDING,
            "approval": VERDICT_HOLD_APPROVAL,
            "hold": VERDICT_HOLD,
            "resume": VERDICT_RESUME,
        },
        "story": story,
        "receipts": receipts,
        "receipt_count": len(receipts),
        "verdict_counts": verdict_counts,
    }


def demo_stop_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


def register_demo_stop_routes(app: Any, check_auth: Any, check_access: Any) -> None:
    """Read-only demo stop screen endpoint.

    Read-only by construction: the endpoint builds its own sandbox per
    call. The gate is the demo mode environment flag; on any other
    deployment the route answers 404 like the other demo planes.
    """
    from fastapi import Header, HTTPException

    @app.get(
        "/api/demo/stop",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_stop(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not demo_stop_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return build_demo_stop()
