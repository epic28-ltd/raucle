"""raucle as an AGT ``ExternalPolicyBackend``.

This module implements Microsoft Agent Governance Toolkit's existing
``agent_os.policies.backends.ExternalPolicyBackend`` Protocol — the same
seam ``OPABackend`` and ``CedarBackend`` already plug into.

It is the **post-merge** integration path for raucle, intended to
become the recommended way to use raucle inside AGT once upstream PR
`microsoft/agent-governance-toolkit#2610`_ lands. Until that PR merges,
the two optional ``BackendDecision`` fields this backend populates
(``proof_artefact`` and ``verification_pointers``) will be ignored by
the AGT evaluator — the backend still produces correct allow/deny
verdicts, just without offline-verifiable evidence attached to the
audit chain.

.. _microsoft/agent-governance-toolkit#2610:
   https://github.com/microsoft/agent-governance-toolkit/pull/2610

Quick start
-----------

.. code-block:: python

    from agent_os.policies.evaluator import PolicyEvaluator
    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.integrations.agent_framework import set_in_force_token
    from raucle.integrations.agt_backend import RauclePolicyBackend

    issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc-platform")
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

    backend = RauclePolicyBackend(gate=gate, verification_base_url="https://acme.bank")

    evaluator = PolicyEvaluator()
    evaluator.add_backend(backend)

    token = issuer.mint(
        agent_id="agent:kyc-prod", tool="lookup_customer",
        constraints={}, ttl_seconds=60,
    )
    set_in_force_token(token)

    decision = evaluator.evaluate({
        "tool_name": "lookup_customer",
        "agent_id":  "agent:kyc-prod",
        "arguments": {"customer_id": "C-1042"},
    })

    assert decision.allowed
    # post-#2610 AGT propagates these into decision.audit_entry:
    #   audit_entry["proof_artefact"]         == "sha256:..."
    #   audit_entry["verification_pointers"]  == {"issuer_pubkey": "...", ...}

Compatibility
-------------

* `agent_os` is imported lazily inside ``__init__`` so this module is
  importable without AGT installed. Tests skip when AGT is absent.
* If AGT's installed copy predates PR #2610, ``BackendDecision`` will
  not accept the two new keyword arguments. ``RauclePolicyBackend``
  detects this at construction and falls back to populating only the
  fields the installed version supports — verdicts remain correct,
  evidence is dropped.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from raucle.capability import CapabilityGate
from raucle.integrations.agent_framework import get_in_force_token

# Module-level version; bumped when the backend's wire contract shifts.
RAUCLE_BACKEND_VERSION = "0.1.0"


class RauclePolicyBackend:
    """raucle's :class:`ExternalPolicyBackend` implementation.

    Conforms to AGT's runtime-checkable
    ``agent_os.policies.backends.ExternalPolicyBackend`` Protocol:
    exposes a ``name`` property and an ``evaluate(context)`` method
    returning a ``BackendDecision``.

    Parameters
    ----------
    gate
        The :class:`~raucle.capability.CapabilityGate` to consult.
    verification_base_url
        Base URL where the deploying organisation publishes its issuer
        public key, policy registry, and (optionally) Lean development.
    issuer_pubkey_path, policy_registry_path, lean_development_path
        Relative paths under ``verification_base_url``; the Lean URL is
        omitted when not supplied.
    """

    def __init__(
        self,
        *,
        gate: CapabilityGate,
        verification_base_url: str,
        issuer_pubkey_path: str = "/.well-known/raucle-issuer.pub",
        policy_registry_path: str = "/.well-known/raucle-policies/",
        lean_development_path: str | None = None,
    ) -> None:
        # Lazy import — raucle stays importable without AGT installed.
        from agent_os.policies.backends import BackendDecision  # noqa: F401

        self._backend_decision = BackendDecision
        self._gate = gate
        self._base = verification_base_url.rstrip("/")
        self._issuer_pubkey_path = issuer_pubkey_path
        self._policy_registry_path = policy_registry_path
        self._lean_development_path = lean_development_path

        # Detect whether the installed AGT carries the PR #2610 fields.
        # If not (i.e. pre-merge), we degrade gracefully.
        self._supports_assurance_fields = (
            "proof_artefact" in BackendDecision.__dataclass_fields__
            and "verification_pointers" in BackendDecision.__dataclass_fields__
        )

    # ── Protocol surface ────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Backend identifier; appears as ``audit_entry["backend"]``."""
        return f"raucle.vcd@{RAUCLE_BACKEND_VERSION}"

    def evaluate(self, context: dict[str, Any]):
        """Render a decision for the given execution context.

        Reads the in-force capability token from the asyncio-ContextVar
        the raucle Agent Framework middleware also uses, so a single
        token primed at the request boundary is shared across both
        integration paths.
        """
        t0 = time.perf_counter()
        tool = context.get("tool_name") or context.get("tool", "")
        agent_id = context.get("agent_id", "")
        arguments: Mapping[str, Any] = context.get("arguments", {}) or {}

        token = get_in_force_token()

        if token is None:
            return self._decision(
                allowed=False,
                action="deny",
                reason="no capability token in force",
                evaluation_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if token.tool != tool or not _agent_id_matches(token.agent_id, agent_id):
            return self._decision(
                allowed=False,
                action="deny",
                reason="capability token does not cover this (tool, agent_id)",
                evaluation_ms=(time.perf_counter() - t0) * 1000.0,
            )

        gate_decision = self._gate.check(
            token,
            tool=tool,
            agent_id=agent_id,
            args=dict(arguments),
        )

        return self._decision(
            allowed=gate_decision.allowed,
            action="allow" if gate_decision.allowed else "deny",
            reason=gate_decision.reason,
            evaluation_ms=(time.perf_counter() - t0) * 1000.0,
            proof_artefact=token.policy_proof_hash,
            verification_pointers=self._pointers(),
        )

    # ── Helpers ─────────────────────────────────────────────────────

    def _decision(
        self,
        *,
        allowed: bool,
        action: str,
        reason: str,
        evaluation_ms: float,
        proof_artefact: str | None = None,
        verification_pointers: dict[str, str] | None = None,
    ):
        kwargs: dict[str, Any] = {
            "allowed": allowed,
            "action": action,
            "reason": reason,
            "backend": self.name,
            "evaluation_ms": evaluation_ms,
        }
        if self._supports_assurance_fields:
            kwargs["proof_artefact"] = proof_artefact
            kwargs["verification_pointers"] = verification_pointers or {}
        return self._backend_decision(**kwargs)

    def _pointers(self) -> dict[str, str]:
        pointers = {
            "issuer_pubkey": self._base + self._issuer_pubkey_path,
            "policy_registry": self._base + self._policy_registry_path,
        }
        if self._lean_development_path:
            pointers["lean_development"] = self._base + self._lean_development_path
        return pointers


def _agent_id_matches(token_agent_id: str, requested_agent_id: str) -> bool:
    """Allow exact match or hierarchical extension (e.g. ``agent:x.region-1``).

    The requested id must be a *well-formed* agent_id before the prefix check —
    otherwise 'agent:x..evil' and 'agent:x.' (both ``startswith('agent:x.')``)
    would be accepted as descendants despite being malformed.
    """
    from raucle.capability import _AGENT_ID_RE

    if not _AGENT_ID_RE.match(requested_agent_id):
        return False
    if token_agent_id == requested_agent_id:
        return True
    return requested_agent_id.startswith(token_agent_id + ".")


__all__ = ["RAUCLE_BACKEND_VERSION", "RauclePolicyBackend"]
