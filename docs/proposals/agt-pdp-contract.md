# A Policy Decision Point plug-in contract for the Microsoft Agent Governance Toolkit

**Status:** Draft proposal, 2026-05-27 (updated 2026-11-07: the M2
reference implementation has landed at
`raucle.integrations.agt.RauclePolicyProvider`).
**Authors:** Raucle.
**Target:** upstream PR to [`microsoft/agent-governance-toolkit`](https://github.com/microsoft/agent-governance-toolkit); the raucle side has shipped (PDP adapter in current releases).
**Companion proposal:** [`agent-framework-middleware.md`](./agent-framework-middleware.md).

## Summary

The Microsoft Agent Governance Toolkit (AGT), released MIT on 2 April 2026,
ships an in-process policy engine (`Agent OS`) supporting YAML, OPA/Rego,
and Cedar policy languages. The published architecture does not document
a third-party Policy Decision Point (PDP) plug-in contract. This
proposal specifies one: an `IPolicyProvider`-style abstract interface
that AGT's Agent OS can call out to for policy decisions delegated to
external PDPs, and proposes raucle as the reference implementation.

Status today is a design proposal. The intent is to submit this as an
ADR / PR upstream to the AGT repository; raucle provides the
reference adapter alongside.

## Why now

Three reasons, ordered by load-bearing-ness:

1. **The slot is open and time-sensitive.** AGT's published docs name
   `PolicyEngine.add_constraint(...)` and reference Cedar/OPA tutorials,
   but do not specify an abstract contract for "AGT delegates this
   particular decision to an external PDP that knows things AGT does
   not." That slot will close when Microsoft writes their own; capturing
   it with an upstream proposal now establishes both the contract shape
   and a working reference implementation as prior art.
2. **High-assurance verticals need formal verification AGT cannot
   supply.** Banks, healthcare providers, and government departments
   evaluating AGT will reach a point where AGT's runtime-interpreted
   YAML / OPA / Cedar policies do not satisfy their auditors —
   specifically, the auditor wants a *proof* that the policy holds over
   every string the tool's schema admits, not a runtime check that a
   given call happens to pass. AGT cannot supply this; raucle's
   SMT-verified `policy_proof_hash` artefact does. A PDP plug-in is
   the architectural seam through which raucle can serve those
   customers without forking AGT.
3. **The non-displacement framing is the credible commercial posture.**
   AGT has Microsoft's distribution, Foundry's enterprise relationships,
   and the strategic blessing of the Azure AI org. Raucle's defensible
   position is not "instead of AGT" — it is "alongside AGT for the
   decisions AGT cannot verify formally." A documented plug-in contract
   makes that posture operational rather than aspirational.

## What changes

### A single new abstract base class (or gRPC contract) in AGT

The proposal is that AGT's `Agent OS` gains an `IPolicyProvider`-style
abstraction:

```python
# Proposed addition to agent_governance_toolkit/agent_os/policy_provider.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping, Any


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of an external PDP consultation."""

    allowed: bool
    reason: str
    # Optional artefact id (e.g. SMT proof hash, content-address)
    # that the audit chain can record alongside the decision.
    proof_artefact: str | None = None
    # Optional verifier-side material (e.g. published policy registry
    # URL, theorem id) for offline re-verification of this decision.
    verification_pointers: Mapping[str, str] | None = None


class IPolicyProvider(ABC):
    """Abstract Policy Decision Point.

    AGT's Agent OS may delegate any tool-call authorisation decision to
    a registered IPolicyProvider. The provider returns a structured
    decision; AGT records the decision and the provider's verification
    pointers in its Merkle-chained audit log.
    """

    @abstractmethod
    def name(self) -> str:
        """Stable identifier for this provider (used in audit records)."""

    @abstractmethod
    def supports(self, tool: str, agent_id: str) -> bool:
        """Return True if this provider handles decisions for this (tool,
        agent_id) combination. AGT's Agent OS calls each registered
        provider's ``supports`` method to decide which provider to
        delegate to; first-match-wins.
        """

    @abstractmethod
    def decide(
        self,
        *,
        tool: str,
        agent_id: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        """Render a decision for this specific tool call. Synchronous —
        AGT will call this on the hot path; implementations must be
        sub-millisecond or use AGT's async variant ``decide_async``.
        """
```

Equivalent gRPC contract for out-of-process providers (so non-Python
PDPs can participate):

```protobuf
syntax = "proto3";
package agt.policy_provider.v1;

service PolicyProvider {
  rpc Supports(SupportsRequest) returns (SupportsResponse);
  rpc Decide(DecideRequest) returns (DecideResponse);
}

message DecideRequest {
  string tool = 1;
  string agent_id = 2;
  bytes  arguments_canonical_json = 3;
  map<string, string> context = 4;
}

message DecideResponse {
  bool   allowed = 1;
  string reason = 2;
  string proof_artefact = 3;
  map<string, string> verification_pointers = 4;
}
```

### AGT Agent OS registration

```python
# In a deployer's AGT setup code:
from agent_governance_toolkit.agent_os import PolicyEngine

engine = PolicyEngine.from_config("./agt-policies.yaml")
engine.register_provider(RauclePolicyProvider(gate=..., issuer=...))
# AGT's existing in-process policy engine handles everything Raucle
# doesn't explicitly support(); Raucle handles the decisions it does.
```

### Audit-chain fields carry the provider's pointers

AGT's existing Merkle-chained audit emits one record per gate decision.
With the PDP contract, those records gain three optional fields:

```jsonc
{
  // ... existing AGT audit-record fields ...
  // `policy_provider` is the provider's audit-record name string
  // (PDP.name() return) — an identifier, not an import path. The
  // importable reference implementation is
  // `raucle.integrations.agt.RauclePolicyProvider`; the `raucle.vcd`
  // prefix honours the VCD formal model in `paper/lean/VCD/`.
  "policy_provider":        "raucle.vcd@0.1.0",
  "policy_proof_artefact":  "sha256:4b78e687...",  // PolicyDecision.proof_artefact
  "verification_pointers": {
    "issuer_pubkey":     "https://acme.bank/.well-known/raucle-issuer.pub",
    "policy_registry":   "https://acme.bank/.well-known/raucle-policies/",
    "lean_development":  "https://github.com/acme/policy-proofs"
  }
}
```

These three fields are *optional* — providers that don't have proof
artefacts simply omit them and AGT's audit chain is unchanged. For
providers like raucle that *do* produce verifiable artefacts, the
audit chain becomes externally verifiable: a third-party verifier
fetches the pointers, re-checks the cited proof, and confirms the
decision was sound.

## raucle as the reference provider

Raucle ships `RauclePolicyProvider` as part of the agent-framework
integration package. The provider:

- Returns `name()` = `f"raucle.vcd@{RAUCLE_PROVIDER_VERSION}"` —
  an audit-record identifier (currently `0.1.0`), *not an importable
  module*. There is no `raucle.vcd` Python package; the VCD model lives
  in `paper/lean/VCD/` and the importable provider is
  `raucle.integrations.agt.RauclePolicyProvider`.
- `supports(tool, agent_id)` returns True if the tool name has a
  policy in raucle's registry (loaded at provider construction).
- `decide(...)` runs the existing `CapabilityGate.check` against the
  in-force token and the supplied arguments, returns a `PolicyDecision`
  with the policy-proof hash as `proof_artefact` and the issuer's
  published-key URL etc. as `verification_pointers`.

Implementation sketch:

```python
# raucle/integrations/agt.py  (the M2 deliverable — this module is
# shipped; the sketch below is abridged)

from agent_governance_toolkit.agent_os import IPolicyProvider, PolicyDecision

from raucle.capability import CapabilityGate
from raucle.integrations.agent_framework import get_in_force_token


class RauclePolicyProvider(IPolicyProvider):
    def __init__(
        self,
        *,
        gate: CapabilityGate,
        verification_base_url: str,
    ) -> None:
        self._gate = gate
        self._base = verification_base_url.rstrip("/")

    def name(self) -> str:
        return f"raucle.vcd@{RAUCLE_PROVIDER_VERSION}"  # 0.1.0

    def supports(self, tool: str, agent_id: str) -> bool:
        token = get_in_force_token()
        return token is not None and tool == token.tool

    def decide(self, *, tool, agent_id, arguments, context=None) -> PolicyDecision:
        token = get_in_force_token()
        if token is None:
            return PolicyDecision(allowed=False, reason="no capability token in force")
        gd = self._gate.check(token, tool=tool, agent_id=agent_id, args=dict(arguments))
        return PolicyDecision(
            allowed=gd.allowed,
            reason=gd.reason,
            proof_artefact=token.policy_proof_hash,
            verification_pointers={
                "issuer_pubkey": f"{self._base}/.well-known/raucle-issuer.pub",
                "policy_registry": f"{self._base}/.well-known/raucle-policies/",
                "lean_development": f"{self._base}/raucle-proofs",
            },
        )
```

## Backwards compatibility

The contract is additive. Existing AGT deployments using YAML / OPA /
Cedar see no change in behaviour; no provider is registered, AGT falls
through to its in-process engine. Audit records gain optional fields
only when a registered provider populates them.

A deployer who registers a provider but later removes it does not
break their audit chain — the older records continue to validate
against the published verification pointers as long as those URLs
remain live.

## Threat-model deltas

| Concern | AGT alone | AGT + raucle provider |
|---|---|---|
| Policy completeness over schema | runtime check per call | SMT-proved before any token is minted |
| Audit verifiability by third party | operator-rooted Merkle chain | content-addressed receipt + Lean theorem cite |
| Cross-organisation receipt portability | none — operator must host audit | receipt verifies offline from published key + registry |
| Trust in PDP correctness | conformance tests | Lean 4 theorems with zero `sorry`s |

## Non-goals

- Not a replacement for AGT's in-process engine. AGT retains all
  existing functionality; the provider contract only adds an *opt-in*
  delegation path.
- Not a streaming-response audit primitive. Decisions are per-call.
- Not opinionated about identity: providers receive `agent_id` as
  AGT's existing SPIFFE / Entra resolution gives it. No identity
  mapping required.

## Reference-implementation milestones

| M | Deliverable | Target |
|---|---|---|
| M1 | This proposal (design doc) | 2026-05-27 |
| M2 | `raucle.integrations.agt.RauclePolicyProvider` (reference impl, working against a mock `IPolicyProvider`) + unit tests | 3 weeks |
| M3 | Upstream PR / ADR to `microsoft/agent-governance-toolkit` proposing `IPolicyProvider`, with the raucle reference impl linked as the first concrete consumer | 4 weeks |
| M4 | If accepted upstream: AGT release ships the contract; raucle's reference impl becomes the canonical example in AGT's docs. If declined: ship the contract as an open extension, document the divergence, publish the gRPC out-of-process variant as the canonical way for non-Python PDPs to plug in. | 8–12 weeks |
| M5 | Two-provider demo: raucle's VCD PDP + Microsoft's default in-process engine running side-by-side on the same Agent Framework deployment, with audit records showing each provider's decisions | 14 weeks |

## Open questions for the upstream working group

1. **First-match vs all-match.** Should AGT consult every registered
   provider and require unanimity, or stop at the first provider whose
   `supports(...)` returns True? Raucle's preference is first-match —
   it preserves the simplest mental model — but if AGT wants
   defence-in-depth, all-match-with-veto is the obvious alternative.
2. **Synchronous vs async by default.** Raucle's gate is sub-100µs and
   sync-safe. Providers that wrap network calls (HSM-backed signers,
   external authorisation services) need async. Proposal: ship both
   `decide` (sync) and `decide_async` (async) on the interface, with
   AGT preferring sync where available.
3. **Audit-record schema versioning.** The three new fields
   (`policy_provider`, `policy_proof_artefact`, `verification_pointers`)
   need a schema version on the AGT audit record so future PDP contracts
   can add fields without breaking older verifiers.
4. **Conflict with AGT's own Cedar/OPA decisions.** If both the
   in-process engine and a registered provider make a decision for the
   same call, what wins? Proposal: in-process *deny* always wins (fail-
   closed for AGT's own policies); in-process *allow* yields to the
   provider's verdict; provider *deny* terminates the call (with both
   AGT's and the provider's reasons recorded in the audit chain).

## Why this is the right move for raucle

Three reasons:

1. **It is the canonical "with-AGT-not-against" artefact.** A reference
   PDP implementation, in raucle's own repo, that demonstrably plugs
   into AGT, is the strongest possible answer to a Microsoft customer
   asking "why not just AGT?" The answer is "raucle is the formally-
   verified PDP that AGT can call out to. You run both."
2. **It captures the standards slot before someone else writes a
   different one.** Once an in-the-wild PDP plug-in pattern emerges
   (whether through AGT's own implementation or via a third party
   shipping a different contract), the cost of changing direction
   grows fast. Submitting an ADR upstream now is cheap; submitting it
   later, after a different contract has shipped, is a fork.
3. **It is reachable as a follow-up to the Agent Framework middleware,
   not a separate effort.** The middleware (`agent-framework-middleware.md`,
   M2 in flight) already implements the gate-on-tool-call pattern at the
   Microsoft framework layer. The AGT PDP is the same primitive bound
   to AGT's policy-engine seam instead of AGT-as-middleware-peer.
   Shipping it costs roughly an additional 3 weeks on top of the
   middleware ship date.
