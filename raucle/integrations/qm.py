"""QM harness adapter: task hand-off to gate wiring for QM-class harnesses.

A QM-class coordination layer delegates a task to an agent; this adapter is
the wiring between that hand-off and the raucle gate:

- mint_for_task(): the principal mints an attenuated capability scoped to the
  task (tool + agent + narrowing), registers it in the delegation ledger and
  returns the signed token dict to the harness.
- gate_call(): the harness runs the agent; every tool call crosses the raucle
  gate with the token; the receipt binds the full delegated-authority chain.
- wiring(): the "one wiring file" QM README promises: a static integration
  bundle (endpoint, header name, token injection point, receipt store path).
"""

from __future__ import annotations

from typing import Any

from raucle.capability import Capability, CapabilityIssuer, DelegationLedger
from raucle.provenance import authorization_block


class QmHarnessBridge:
    """Owns the issuer (the delegation principal), the ledger, and the gate
    settings one QM wiring file points at."""

    def __init__(
        self,
        issuer: CapabilityIssuer,
        ledger: DelegationLedger,
        gateway_url: str = "http://raucle-gateway:8080",
    ) -> None:
        self.issuer = issuer
        self.ledger = ledger
        self.gateway_url = gateway_url

    def mint_for_task(
        self,
        *,
        tool: str,
        agent_id: str,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int = 900,
        parent: Capability | None = None,
    ) -> dict[str, Any]:
        """Mint (root or attenuated) + register + return the signed token dict.

        parent=None mints a root capability (a harness-level principal act).
        A parent produces a narrow child; the ledger keeps the whole chain.
        """
        if parent is None:
            cap = self.issuer.mint(
                agent_id=agent_id,
                tool=tool,
                constraints=constraints or {},
                ttl_seconds=ttl_seconds,
            )
        else:
            cap = self.issuer.attenuate(parent, extra_constraints=constraints or {})
            if ttl_seconds:
                import datetime as _dt

                cap.expires_at = min(
                    cap.expires_at,
                    int(_dt.datetime.now(tz=_dt.UTC).timestamp()) + ttl_seconds,
                )
        self.ledger.register(cap, agent_id, verifying_key=self.issuer)
        return cap.to_dict()

    @staticmethod
    def gate_headers(token_dict: dict[str, Any]) -> dict[str, str]:
        """Headers a QM tool runner adds to every agent tool call."""
        import json as _json

        return {"X-Capability-Token": _json.dumps(token_dict)}

    @staticmethod
    def authorization_from(token_dict: dict[str, Any]) -> Any:
        """The receipt-side chain block, for local verification/tests:
        recompute the digest the gate will bind."""
        return authorization_block(token_dict)


def gate_call(
    bridge: QmHarnessBridge,
    token_dict: dict[str, Any],
    tool: str,
    args: dict[str, Any],
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Synchronous gate POST for the QM tool runner (urllib, no extra deps)."""
    import json as _json
    import urllib.error as _err
    import urllib.request as _req

    body = _json.dumps(
        {
            "tool": tool,
            "args": args,
            "agent_id": token_dict["agent_id"],
            "source": token_dict["agent_id"],
            "destination": "qm-runtime",
        }
    ).encode()
    req = _req.Request(
        bridge.gateway_url.rstrip("/") + "/gate",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **bridge.gate_headers(token_dict)},
    )
    try:
        with _req.urlopen(req, timeout=timeout) as resp:
            return _json.load(resp)
    except _err.HTTPError as exc:
        return {
            "decision": "deny",
            "status": exc.code,
            "detail": exc.read()[:200].decode(errors="replace"),
        }


def wiring(bridge: QmHarnessBridge, *, ledger_path: str, receipt_store: str) -> str:
    """The one-wiring-file bundle: JSON the QM harness config references."""
    import json as _json

    return _json.dumps(
        {
            "integration": "raucle-gateway",
            "runtime": "qm",
            "gateway_url": bridge.gateway_url,
            "capability_header": "X-Capability-Token",
            "credential_header": "X-Api-Key",
            "token_injection": "per-tool-call",
            "delegation_ledger": {
                "path": ledger_path,
                "write_on": "task_handoff",
                "resolver": "raucle_cloud.harness_qm.QmHarnessBridge.mint_for_task",
            },
            "receipts": {
                "store": receipt_store,
                "version": "v1.1",
                "verify": "raucle-cli verify-chain",
            },
            "fail_closed_on": [
                "unresolved_parent",
                "broadened_child",
                "tampered_chain",
            ],
        },
        indent=1,
    )
