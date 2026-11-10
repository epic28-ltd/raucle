"""D10: the policy-simulate demo showpiece.

A guided moment inside the Policies tab: "test a change before you
deploy". The demo visitor picks one of a few preset policy tweaks and
the panel calls ``POST /api/policy/simulate`` machinery (the shipped X6
surface) under the hood via :func:`raucle.policy_simulate.simulate_policy`
over a SIMULATED served traffic window. The outcome shown is the real
deterministic engine's output, and the receipt is the real signed
machine output (EdDSA, deterministic, verifiable offline). No apply
path is exposed to the demo visitor: in a live deployment the flip
lands through the real editor's Save & Deploy, which re-verifies the
signed receipt before any policy change.
"""

from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from fastapi import Request

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.policy_simulate import simulate_policy
from raucle.provenance import _canonical_json
from raucle.replay import InputStore

_NOTE_SIMULATED = (
    "Simulated demonstration: the historical window replayed here is a "
    "simulated served-traffic record; the simulate engine, the "
    "deterministic outcome and the signed receipt are the gateway's real "
    "machinery. Nothing is applied - deploying a validated change in a "
    "live deployment happens through the editor's Save & Deploy path, "
    "which re-verifies the signed receipt before any policy lands."
)

_BASE_POLICY = """\
version: 1
issuer: demo.sim
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-999"]
"""

#: Preset candidate tweaks over the demo base policy. Each is a real,
#: schema-valid candidate policy the real simulate path signs.
_PRESETS = (
    {
        "name": "narrow-export",
        "label": "Remove ACC-999 from the export allow list",
        "description": (
            "Tightens the export_records allow list to a single account. "
            "Calls for the removed account flip from allow to deny."
        ),
        "candidate_policy_yaml": """\
version: 1
issuer: demo.sim
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
""",
    },
    {
        "name": "block-export",
        "label": "Remove the export_records rule entirely",
        "description": (
            "The fail-closed story: with no matching policy the gate denies "
            "every recorded call that used to be allowed."
        ),
        "candidate_policy_yaml": """\
version: 1
issuer: demo.sim
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
""",
    },
    {
        "name": "no-change",
        "label": "Re-sign the same policy (no change)",
        "description": (
            "A candidate identical to the live policy. The engine still "
            "signs a receipt: the honest outcome is that nothing changes."
        ),
        "candidate_policy_yaml": _BASE_POLICY,
    },
)

_lock = threading.Lock()
_cache: dict[str, Any] | None = None


def demo_presets() -> list[dict[str, str]]:
    """Preset metadata for the picker (candidate bytes stay server-side)."""
    return [{k: p[k] for k in ("name", "label", "description")} for p in _PRESETS]


def _sim_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


def _build_demo_window() -> dict[str, Any]:
    """Serve the simulated traffic window once per process, in a
    throwaway environment: two allowed exports through the REAL gate
    machinery, recorded in the REAL receipt chain + input store shapes
    the counterfactual engine replays.
    """
    root = Path(tempfile.mkdtemp(prefix="raucle-demo-sim-"))
    policy = root / "policies.yaml"
    policy.write_text(_BASE_POLICY, encoding="utf-8")
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="demo-sim-local-only",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(root / "receipts.jsonl"),
        audit_chain=str(root / "audit.jsonl"),
        registry_path=str(root / "registry.jsonl"),
        agent_credentials_file=str(root / "creds.jsonl"),
        gate_auth="apikey",
    )
    served = RaucleGateway(config)
    served.check_tool_call(
        "export_records",
        {"account": "ACC-001"},
        agent_id="agent:svc",
        trace_id="demo-sim-1",
    )
    served.check_tool_call(
        "export_records",
        {"account": "ACC-999"},
        agent_id="agent:svc",
        trace_id="demo-sim-2",
    )
    store_path = root / "inputs.jsonl"
    with InputStore(store_path) as store:
        store.add(_canonical_json({"account": "ACC-001"}).decode("utf-8"))
        store.add(_canonical_json({"account": "ACC-999"}).decode("utf-8"))
    # The simulate caller keeps its OWN receipt store: a simulation must
    # never append into the window it is replaying (X6 slice 1 rule).
    import dataclasses as _dc

    sim_config = _dc.replace(config, receipt_store=str(root / "sim-receipts.jsonl"))
    sim_gateway = RaucleGateway(sim_config)
    return {
        "candidate": _BASE_POLICY,
        "window_receipts": str(root / "receipts.jsonl"),
        "input_store": str(store_path),
        "sim_gateway": sim_gateway,
    }


def _demo_env() -> dict[str, Any]:
    global _cache
    with _lock:
        if _cache is None:
            _cache = _build_demo_window()
        return _cache


def run_demo_policy_sim(preset_name: str) -> dict[str, Any]:
    """Run the real simulate path over the cached demo window.

    Returns the deterministic outcome plus the signed simulation
    receipt exactly as the operator endpoint serves them. Refusals of
    an unknown preset are named, never guessed.
    """
    env = None
    for p in _PRESETS:
        if p["name"] == preset_name:
            env = p
            break
    if env is None:
        raise ValueError(f"unknown demo preset: {preset_name}")
    d = _demo_env()
    outcome = simulate_policy(
        d["sim_gateway"],
        candidate_policy_yaml=env["candidate_policy_yaml"],
        window_ref=d["window_receipts"],
        input_store_ref=d["input_store"],
        ref_roots=(d["window_receipts"].rsplit("/", 1)[0],),
    )
    gate = outcome["result"]["gate"]
    return {
        "simulated_input": True,
        "note": _NOTE_SIMULATED,
        "preset": preset_name,
        "label": env["label"],
        "deterministic": True,
        "outcome": {
            "actions_replayed": gate["actions_replayed"],
            "actions_unreplayable": gate["actions_unreplayable"],
            "current": gate["current"],
            "candidate": gate["candidate"],
            "changed_decisions": gate["changed_decisions"],
            "verdict": gate["verdict"],
            "chain_depth": gate["chain_depth"],
            "candidate_policy_hash": outcome["result"]["candidate_policy_hash"],
            "window_hash": outcome["result"]["window_hash"],
        },
        "receipt_hash": outcome["receipt_hash"],
        "jws": outcome["jws"],
    }


def register_demo_policy_sim_routes(app: Any, check_auth: Any, check_access: Any) -> None:
    """Demo endpoints for the guided policy-simulate moment.

    Read-only in effect: presets are listed, the real simulate path is
    re-run over the simulated window, receipts come back signed. There
    is deliberately NO apply route on the demo plane.
    """
    from fastapi import Header, HTTPException

    @app.get(
        "/api/demo/policy-simulate/presets",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_sim_presets(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not _sim_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return {"presets": demo_presets(), "simulated_input": True}

    @app.post(
        "/api/demo/policy-simulate",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
            "400": {"description": "Unknown demo preset"},
        },
    )
    async def demo_policy_sim(
        request: Request,
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not _sim_mode_on():
            raise HTTPException(404, "demo mode not configured")
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(422, "body must be a JSON object") from None
        preset = payload.get("preset")
        if not preset:
            raise HTTPException(422, "body must name a 'preset'")
        try:
            return run_demo_policy_sim(preset)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
