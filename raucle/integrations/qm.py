"""QM harness adapter: task hand-off to gate wiring for QM-class harnesses.

A QM-class coordination layer delegates a task to an agent; this adapter is
the wiring between that hand-off and the raucle gate:

- mint_for_task(): the principal mints an attenuated capability scoped to the
  task (tool + agent + narrowing), registers it in the delegation ledger and
  returns the signed token dict to the harness.
- gate_call(): the harness runs the agent; every tool call crosses the raucle
  gate with the token; the receipt binds the full delegated-authority chain.
- bilateral_outcome(): the tool/execution side co-signs the outcome it
  produced (executed | failed | rejected) over the receipt's output_hash,
  inside the signed payload — verification is fail-closed when the
  co-signature is missing or does not verify (spec v1.2 bilateral-outcomes).
- wiring(): the "one wiring file" QM README promises: a static integration
  bundle (endpoint, header name, token injection point, receipt store path).
"""

from __future__ import annotations

from typing import Any

from raucle.bilateral import sign_bilateral_outcome
from raucle.capability import Capability, CapabilityIssuer, DelegationLedger
from raucle.integrations.retry_guidance import (
    RETRY_GUIDANCE_SCHEMA as _RETRY_GUIDANCE_SCHEMA,
)
from raucle.integrations.retry_guidance import (
    SCHEMA_NAME as _RETRY_GUIDANCE_SCHEMA_NAME,
)
from raucle.integrations.retry_guidance import (
    attach_retry_guidance as _attach_retry_guidance,
)
from raucle.integrations.retry_guidance import (
    retry_guidance as _retry_guidance,
)
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

    @staticmethod
    def deny_feedback(token_dict: dict[str, Any]) -> dict[str, Any] | None:
        """The O2 retry-guidance shape for a denied call's authority.

        Deterministic, from the same token dict the harness injected:
        the whitelist/required/bounds constraints the gate enforced
        become the machine-readable description of what a retry within
        this authority could look like. ``None`` (honest absence) when
        nothing deterministic can be derived - denylists, rate limits
        and expiry windows say nothing about what WOULD be allowed.
        Never consults the verdict: a deny never fails, softens or
        becomes an allow because of this field.
        """
        return _retry_guidance(token_dict)

    @staticmethod
    def retry_guidance_schema() -> dict[str, Any]:
        """The documented schema of the ``retry_guidance`` shape."""
        return _RETRY_GUIDANCE_SCHEMA

    @staticmethod
    def executor_keys(executors: list[Any]) -> dict[str, bytes]:
        """The verifier-side executor key map, from the executor identities.

        Each executor is an :class:`raucle.provenance.AgentIdentity` (the
        tool/execution side has its own keypair, distinct from the agent's).
        Register the returned ``{key_id: public_key_pem}`` mapping on
        :class:`ProvenanceVerifier(executor_keys=...)`; an x_bilateral block
        naming any other key id fails verification (fail-closed)."""
        return {e.key_id: e.public_key_pem() for e in executors}

    def bilateral_outcome(
        self,
        executor: Any,
        *,
        outcome: str,
        output_hash: str,
    ) -> dict[str, Any]:
        """The executor-side co-signature block (x_bilateral) for one outcome.

        The tool/execution side signs the outcome it actually produced —
        executed, failed or rejected (closed vocabulary, enforced) — over
        the receipt's output_hash. The returned dict rides INSIDE the
        receipt's signed payload (attach before the agent signs), so the
        co-signature is bound by the same JWS: neither the agent's
        signature nor the payload's output_hash can move independently of
        the executor's claim. Verification is fail-closed: a missing or
        non-verifying co-signature fails the chain with a named reason."""
        return sign_bilateral_outcome(
            executor,
            executor_key_id=executor.key_id,
            outcome=outcome,
            output_hash=output_hash,
        )


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
            response = _json.load(resp)
    except _err.HTTPError as exc:
        response = {
            "decision": "deny",
            "status": exc.code,
            "detail": exc.read()[:200].decode(errors="replace"),
        }
    # O2: additive, deterministic retry guidance on deny, from the same
    # token dict the harness injected. The verdict fields pass through
    # byte-identical; a deny with nothing derivable gains no key at all.
    return _attach_retry_guidance(response, token_dict)


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
            "exec_side": {
                "co_signs": "x_bilateral",
                "binds": ["outcome", "output_hash"],
                "outcomes": ["executed", "failed", "rejected"],
                "when": "attach the executor co-signature before the agent signs",
                "verify": "raucle-cli verify-chain (executor_keys)",
            },
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
            "retry_guidance": {
                "schema": _RETRY_GUIDANCE_SCHEMA_NAME,
                "schema_module": "raucle.integrations.retry_guidance.RETRY_GUIDANCE_SCHEMA",
                "on": "deny",
                "derivation": "deterministic, from the injected capability token's constraints",
                "absence": (
                    "absent (key omitted) when no deterministic alternative "
                    "can be derived; never null"
                ),
                "doc": "docs/spec/retry-guidance-v1.md",
            },
            "fail_closed_on": [
                "unresolved_parent",
                "broadened_child",
                "tampered_chain",
            ],
        },
        indent=1,
    )
