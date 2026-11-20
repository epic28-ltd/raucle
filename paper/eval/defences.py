"""Defence wrappers — each takes a base agent and returns a defended one.

Three of these are stubs that delegate to upstream reference implementations
(Spotlighting, StruQ, the commercial prompt-shields vendor). The three VCD
configurations wire the actual raucle runtime.
"""

from __future__ import annotations

from typing import Any

from raucle import Scanner
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.prove import JSONSchemaProver

# ---------------------------------------------------------------------------
# Stubs — fill in with the upstream reference implementations
# ---------------------------------------------------------------------------


def no_defence(agent: Any) -> Any:
    """Baseline. Returns the agent unchanged."""
    return agent


def spotlighting(agent: Any) -> Any:
    """Spotlighting [HMC+24]. Wrap untrusted regions with marker tokens.

    TODO: vendor the Spotlighting reference implementation from Microsoft's
    repository and adapt to whatever the agent harness expects.
    """
    raise NotImplementedError("vendor the Spotlighting reference impl")


def struq(agent: Any) -> Any:
    """StruQ [CDC+24]. Structured-query fine-tune; we use the released checkpoint.

    TODO: load the released checkpoint and route the agent's LLM calls through it.
    """
    raise NotImplementedError("load StruQ checkpoint")


def prompt_shields(agent: Any) -> Any:
    """Commercial vendor's prompt-shield filter.

    TODO: integrate the vendor's API. Anonymise the vendor name in the paper.
    """
    raise NotImplementedError("integrate prompt-shields vendor API")


# ---------------------------------------------------------------------------
# VCD configurations
# ---------------------------------------------------------------------------


def vcd_text_only(agent: Any) -> Any:
    """Scanner only. No proof, no capability gate. The fair-comparison baseline
    for the text-defence family."""
    scanner = Scanner(mode="strict")
    return _wrap_with_input_scan(agent, scanner)


def vcd_capability_only(agent: Any) -> Any:
    """Capability gate with runtime constraint checking, but no SMT proof.
    Used for the ablation row in §6."""
    issuer = CapabilityIssuer.generate(issuer="eval.example")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    return _wrap_with_gate(agent, issuer, gate, _policy_for_eval())


def vcd_proof_only(agent: Any) -> Any:
    """SMT proof gates the policy author, but constraints are checked at the
    tool boundary without a capability token. Ablation row."""
    return _wrap_with_runtime_policy(agent, _policy_for_eval(), proof_required=True)


def vcd_full_stack(agent: Any) -> Any:
    """Headline configuration: scanner + proof + capability gate."""
    scanner = Scanner(mode="standard")
    issuer = CapabilityIssuer.generate(issuer="eval.example")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    # Pre-register the proven policy for every tool.
    for tool, (schema, policy) in _tool_registry().items():
        proof = JSONSchemaProver().prove(schema, policy)
        if proof.status != "PROVEN":
            raise SystemExit(
                f"Tool {tool} is not provable: {proof.status}. "
                f"Counterexample: {proof.counterexample}"
            )
    return _wrap_full_stack(agent, scanner, issuer, gate)


# ---------------------------------------------------------------------------
# Wrappers (the actual integration with the agent runtime)
# ---------------------------------------------------------------------------


def _wrap_with_input_scan(agent: Any, scanner: Scanner) -> Any:
    """Pre-scan every untrusted input and block on MALICIOUS verdict.

    TODO: bind to the agent harness's hook for "incoming message" / "tool output
    received" / "RAG document fetched". The shape of this hook differs across
    AgentDojo and InjecAgent; expose it via the adapter."""
    raise NotImplementedError("bind to agent harness input hooks")


def _wrap_with_gate(
    agent: Any, issuer: CapabilityIssuer, gate: CapabilityGate, policy: dict
) -> Any:
    """Wrap every tool call site with `gate.check`. Mint a fresh token per session."""
    raise NotImplementedError("bind to agent harness tool-call hooks")


def _wrap_with_runtime_policy(agent: Any, policy: dict, proof_required: bool) -> Any:
    """Runtime constraint checking without the capability token. Ablation."""
    raise NotImplementedError("bind to agent harness tool-call hooks")


def _wrap_full_stack(
    agent: Any, scanner: Scanner, issuer: CapabilityIssuer, gate: CapabilityGate
) -> Any:
    """Compose scan + gate. Per-session token; per-call gate check."""
    raise NotImplementedError("bind to agent harness")


# ---------------------------------------------------------------------------
# Pre-registered policies (commit before measurement to prevent post-hoc tuning)
# ---------------------------------------------------------------------------


def _tool_registry() -> dict[str, tuple[dict, dict]]:
    """Returns {tool_name: (json_schema, policy)} for every tool in the
    AgentDojo + InjecAgent deployments we evaluate.

    The schemas come from the upstream benchmarks. The policies are authored
    once and committed to `paper/eval/policies.json` before any measurement run.
    See README §"Pre-registration".
    """
    import json
    from pathlib import Path

    path = Path(__file__).parent / "policies.json"
    if not path.exists():
        raise SystemExit(
            "Pre-register tool policies first: see paper/eval/README.md. "
            "Expected file: " + str(path)
        )
    return {k: (v["schema"], v["policy"]) for k, v in json.loads(path.read_text()).items()}


def _policy_for_eval() -> dict:
    """Aggregated policy for the ablation variants that don't carry per-tool tokens."""
    raise NotImplementedError("aggregate the per-tool policies into a flat constraint set")
