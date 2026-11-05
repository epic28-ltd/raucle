# Upstream PR: Carry offline-verifiable evidence through `ExternalPolicyBackend`

This document is the **ready-to-submit PR body** for an upstream
contribution to [`microsoft/agent-governance-toolkit`](https://github.com/microsoft/agent-governance-toolkit).
It is paired with the patch and tests in [`upstream-pr-files/`](upstream-pr-files/).

The broader design rationale (why a Policy Decision Point seam matters
for raucle's SMT-verified gate) lives in [`agt-pdp-contract.md`](agt-pdp-contract.md).
What follows is what goes in the GitHub PR description verbatim.

> **Note on scope.** An earlier draft of this proposal added a new
> `IPolicyProvider` ABC at `agent_os/policy_provider.py`. On reading the
> repository we found AGT already exposes the relevant seam —
> `agent_os.policies.backends.ExternalPolicyBackend`, a runtime-checkable
> Protocol that OPA and Cedar already implement — and the right change
> is much smaller: two optional fields on `BackendDecision`, propagated
> into the resulting `PolicyDecision.audit_entry`.

---

## Title

`agent_os.policies: add optional proof_artefact and verification_pointers to BackendDecision`

## Suggested branch name

`feat/backend-decision-assurance-fields`

## Summary

Adds two optional fields to `agent_os.policies.backends.BackendDecision`:

- `proof_artefact: Optional[str]` — content-address (e.g. `sha256:…`) of
  an underlying proof, if the backend's decision is derived from one.
- `verification_pointers: dict[str, str]` — named URLs at which a
  third-party verifier can fetch the deployer's published material
  (issuer public key, policy registry, theorem development, attestation
  chain) to re-check the decision offline.

`PolicyEvaluator._evaluate_flat` propagates them into the resulting
`PolicyDecision.audit_entry` when present, so downstream audit consumers
can record and verify them. The change is fully additive: existing
`OPABackend` and `CedarBackend` are untouched, the new fields default to
empty, and the audit entry omits both keys when a backend does not
supply them.

## Motivation

`ExternalPolicyBackend` is the right seam for adding new policy
substrates alongside YAML / OPA / Cedar — OPA and Cedar already
implement it. A class of deployments — particularly in regulated
finance, healthcare, and government — needs backends whose soundness is
established by methods that produce **content-addressable evidence**
beyond a simple allow/deny:

- **SMT-verified gates** that prove a policy holds over every string a
  tool's JSON Schema admits, producing a proof artefact the audit chain
  can cite.
- **Mechanically verified theorems** (e.g. Lean 4) backing the gate's
  soundness claim, where the audit record needs to name the theorem so
  an external verifier can re-check the proof offline.
- **Hardware-attested decision substrates** (TEE-rooted backends) whose
  attestation document is required in the audit record.

Today, such backends can implement `ExternalPolicyBackend` and return a
`BackendDecision` — but the evidence has nowhere to live; the receiver
only sees `(allowed, action, reason, backend, evaluation_ms)`. This PR
adds two optional carry-through fields so a deployment that wants
externally-verifiable policy decisions can have them, without changing
anything for deployments that don't.

## Goals

1. **Minimal surface.** Two optional fields on an existing dataclass.
   No new module, no new ABC.
2. **Self-describing decisions.** When present, the proof artefact and
   verification pointers travel with the decision into the audit entry,
   so a verifier reading the audit log can re-check offline without
   contacting the operator.
3. **No new dependencies.** Standard library only.
4. **Additive.** Existing backends are unchanged. Existing audit
   consumers see no new keys until a backend supplies them.

## Non-goals

- **Not a new provider abstraction.** `ExternalPolicyBackend` already
  exists and is the right seam; this PR strengthens it rather than
  duplicating it.
- **Not an audit-record schema change for `PolicyCheckResult`.** Those
  fields would belong in `audit_entry` of the integration-layer result;
  this PR only touches the policy-engine path (`evaluator.py`). The
  integration-layer wiring is a smaller follow-up if maintainers want it.
- **Not opinionated about proof format.** `proof_artefact` is a free-form
  string (convention: `sha256:…` content-address); resolution to a real
  artefact is the backend's and verifier's concern.

## Detailed design

See [`upstream-pr-files/patch/backends-assurance-fields.patch`](upstream-pr-files/patch/backends-assurance-fields.patch)
for the unified diff. The substantive changes:

```python
# agent_os/policies/backends.py
@dataclass
class BackendDecision:
    allowed: bool
    action: str = "allow"
    reason: str = ""
    backend: str = ""
    raw_result: Any = None
    evaluation_ms: float = 0.0
    error: Optional[str] = None
    proof_artefact: Optional[str] = None  # new
    verification_pointers: dict[str, str] = field(default_factory=dict)  # new
```

```python
# agent_os/policies/evaluator.py — inside _evaluate_flat's backend loop
return PolicyDecision(
    allowed=result.allowed,
    matched_rule=None,
    action=result.action,
    reason=result.reason,
    audit_entry={
        "policy": f"external:{backend.name}",
        "rule": None,
        "action": result.action,
        "backend": backend.name,
        "evaluation_ms": result.evaluation_ms,
        "context_snapshot": context,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        # High-assurance backends may carry offline-verifiable evidence;
        # propagate when present.
        **({"proof_artefact": result.proof_artefact} if result.proof_artefact else {}),
        **(
            {"verification_pointers": dict(result.verification_pointers)}
            if result.verification_pointers
            else {}
        ),
    },
)
```

### Tests

[`upstream-pr-files/tests/test_backend_decision_assurance_fields.py`](upstream-pr-files/tests/test_backend_decision_assurance_fields.py)
adds four tests:

1. `BackendDecision` defaults: new fields default to `None` / empty
   dict (unchanged audit shape for existing backends).
2. `BackendDecision` round-trip: when set, the fields are preserved.
3. End-to-end: a stub backend supplying both fields produces a
   `PolicyDecision` whose `audit_entry` contains them.
4. Compactness: a backend that does **not** supply them produces an
   `audit_entry` with neither key present (no empty values).

## Backwards compatibility

Fully additive:

- `BackendDecision`'s new fields default to `None` / empty.
- `OPABackend` and `CedarBackend` construct `BackendDecision` without
  the new fields; behaviour unchanged.
- `PolicyEvaluator` only inserts the new keys into `audit_entry` when
  the backend supplies non-empty values — audit consumers keying on
  presence are unaffected.

## Drawbacks

1. **One more concept in `BackendDecision`'s surface.** Mitigation:
   docstring explicitly notes the fields are optional and intended for
   high-assurance backends.
2. **The audit chain gains externally-verifiable structure.** We see
   this as a feature, but it does couple the audit-entry shape to the
   new optional keys going forward.

## Alternatives considered

1. **A new top-level `IPolicyProvider` ABC** alongside
   `ExternalPolicyBackend`. Rejected — duplicates an existing seam.
2. **Embed the proof artefact in `raw_result`.** Possible today, but
   leaves discovery to convention; audit consumers wouldn't know where
   to look across backends.
3. **An OPA/Rego external-data callback.** Ties high-assurance
   substrates to OPA's lifecycle and offers no native audit-chain
   integration.

## Reference implementation / future consumer

raucle ([github.com/epic28-ltd/raucle](https://github.com/epic28-ltd/raucle))
is a Verified Capability Discipline implementation — Z3-verified policy
gates with Ed25519-signed capability tokens and a Lean 4 soundness
theorem development. Its AGT integration
([`raucle/integrations/agt.py`](https://github.com/epic28-ltd/raucle/blob/main/raucle/integrations/agt.py))
will be reworked to implement `ExternalPolicyBackend` directly once
this PR lands, populating both new fields. Linked here as evidence
that the contract change is implementable and that at least one
production-track project intends to consume it; raucle is **not** part
of this PR.

## Acknowledgements

Thanks to the AGT team for the layered policy architecture — having
both YAML rules and a registered-backend chain made this a one-page
change rather than a redesign.

---

## Once accepted

1. raucle reworks `raucle.integrations.agt` to implement
   `ExternalPolicyBackend`, populating `proof_artefact` (the
   capability-receipt hash) and `verification_pointers` (issuer
   public-key URL, policy-registry URL, Lean theorem URL).
2. A smaller follow-up PR can extend `PolicyCheckResult.audit_entry`
   at the integration layer to surface the same fields to framework
   adapters.

## How to verify locally

```bash
# After applying the patch:
cd agent-governance-python/agent-os
pytest tests/test_backend_decision_assurance_fields.py -v
# expect: 4 passed
```

## How to open the PR

```bash
# fork microsoft/agent-governance-toolkit, then:
git clone git@github.com:<your-fork>/agent-governance-toolkit.git
cd agent-governance-toolkit
git checkout -b feat/backend-decision-assurance-fields

# apply the patch
git apply /path/to/raucle/docs/proposals/upstream-pr-files/patch/backends-assurance-fields.patch
cp /path/to/raucle/docs/proposals/upstream-pr-files/tests/test_backend_decision_assurance_fields.py \
   agent-governance-python/agent-os/tests/

# verify
cd agent-governance-python/agent-os
pytest tests/test_backend_decision_assurance_fields.py -v
cd ../..

# DCO sign-off required (per CONTRIBUTING.md)
git add agent-governance-python/agent-os/src/agent_os/policies/backends.py \
        agent-governance-python/agent-os/src/agent_os/policies/evaluator.py \
        agent-governance-python/agent-os/tests/test_backend_decision_assurance_fields.py
git commit -s -m "agent_os.policies: add optional proof_artefact and verification_pointers to BackendDecision"
git push origin feat/backend-decision-assurance-fields

# open PR via gh, paste the body above
```
