# ADR 0010: Enforcement failure modes and live policy watch mode

- **Status:** Proposed
- **Date:** 2026-11-26
- **Owners:** Raucle engineering
- **Parent programme:** [Enterprise Readiness Programme #108](https://github.com/epic28-ltd/raucle-agent-assurance/issues/108)
- **Implementation tracking:** [Raucle issue #344](https://github.com/epic28-ltd/raucle/issues/344)

## Context

The enterprise proposal asks for a configurable circuit breaker with `FAIL_CLOSED` and
`FAIL_SAFE` modes, plus a live policy shadow/watch mode. Raucle already has significant
related functionality, but the modes must be distinguished carefully.

### Existing implementation

- `raucle/policy_simulate.py` simulates a candidate policy over a historical receipt/traffic
  window. It returns a signed simulation receipt bound to the candidate policy hash and
  window. Applying a simulation is a separate, privileged path that re-verifies the receipt
  and checks the submitted candidate hash before writing the policy.
- `docs/spec/x6-policy-simulate.md` documents the historical simulation contract and its
  access boundaries.
- The gateway's decision path catches internal faults and denies with a named gate-fault
  receipt. Authentication and trust failures are fail-closed.
- Receipt sidecar failure is deliberately different: the enforcement decision has already
  completed, and receipt delivery failure is recorded as a named evidence-persistence
  degradation. It must not be described as fail-open enforcement.
- `tests/test_gate_chaos.py` covers named receipt/index/chain fault injection and offline
  verification of fault evidence.

Historical counterfactual replay is not live watch mode. A candidate policy is not currently
evaluated as a second, non-enforcing policy against each live request merely because the
historical simulation endpoint exists.

## Decision

### 1. Keep strict fail-closed as the enforcement default

A security dependency failure must not silently become ALLOW. The default mode remains strict:
if a required policy, trust, credential, replay/state, signer or formal-verification dependency
cannot produce a trustworthy result, the affected request is denied or refused with a named
operational status.

A circuit breaker may stop repeated calls to a failing dependency and make the outage visible;
it must not change the authorisation result from DENY/REFUSE to ALLOW.

### 2. Do not use the ambiguous name FAIL_SAFE

"Fail safe" is often interpreted as "keep the service available", which can mean authorising
when the authorisation authority is unavailable. That is not a safe default for a control plane.

If a future deployment needs bounded degraded operation, give it a precise name and contract
(for example `BOUNDED_DEGRADED`) rather than a generic `FAIL_SAFE`. It may only be considered
when all of the following hold:

- the deployment has explicitly opted in for a named tool/risk class;
- a cryptographically verified, unexpired policy snapshot is available;
- required trust roots and credential/revocation state are sufficiently fresh for the
  operation's risk;
- the degraded decision can be recorded with a named status and bounded expiry;
- operators can see the degraded state and its start/end times;
- high-risk, freshness-sensitive or otherwise ineligible operations remain denied.

This is a future option, not a recommendation to implement a permissive fallback now. The
failure-mode matrix must identify which dependencies can safely use a cached snapshot and
which always require live authoritative state.

### 3. Define circuit breakers per dependency and failure class

Do not create one global breaker that treats unrelated dependencies as equivalent. The
failure-mode matrix should cover:

- policy/configuration load and policy signature verification;
- trust registry and revocation state;
- credentials and identity;
- nonce/replay/state store;
- signer/KMS/HSM;
- SMT solver and formal-proof verification;
- receipt chain/index/sidecar;
- telemetry/OTLP/SIEM exporter;
- downstream tool execution (which is outside the gateway's direct control).

Each entry must specify: criticality, timeout, retry budget, breaker threshold, open duration,
half-open probe policy, recovery rule, named operator status and enforcement consequence.
Configuration must be validated at boot and unknown modes refused.

Telemetry loss should remain visible and should not silently alter policy decisions. Receipt
persistence failure must retain its existing explicit evidence-loss semantics; it must not be
used as a precedent for fail-open authorisation.

### 4. Add live policy watch as a separate non-enforcing evaluator

A live watch mode may evaluate the same normalized request context against a candidate policy,
but the actual enforcement decision must be made by the active policy alone.

The watch evaluator must:
- run after/beside the authoritative decision path without delaying or blocking it;
- have a strict CPU/time/memory budget and bounded queue;
- never mutate active policy, trust state, credentials, replay state or the live decision;
- never forward, retry or execute a tool call;
- identify its result as simulated/non-authoritative;
- bind each result to the candidate policy hash, active policy hash, request correlation ID,
  evaluator version and evaluation timestamp;
- emit metadata-only results by default, with explicit redaction and no raw prompt, arguments,
  credentials or secrets;
- report dropped/timeout/error counts so an incomplete sample cannot look like complete coverage.

A watch timeout or exception drops the shadow result with a visible counter; it must not
change the actual allow/deny result. The watch mode must never share mutable state with the
authoritative decision evaluator.

### 5. Keep three policy-evaluation modes distinct

| Mode | Input | Changes live decision? | Evidence |
|---|---|---:|---|
| Historical simulation | Stored, bounded historical window | No | Signed simulation receipt bound to candidate hash/window |
| Live watch/shadow | Current normalized request, candidate policy | No | Non-authoritative, metadata-only result with coverage/loss counters |
| Enforcement | Current request, active policy | Yes | Existing signed gate decision receipt |

The existing simulation/apply API remains compatible. A simulation receipt is not permission to
apply arbitrary different policy bytes; the current hash binding remains mandatory.

## Consequences

- Strict fail-closed behaviour remains the default and is not weakened for availability.
- Operators gain a precise failure matrix rather than a single ambiguous switch.
- Historical simulation and live shadow mode can coexist without confusing their evidence.
- A live shadow implementation requires bounded resource isolation and explicit sampling/coverage.
- A bounded degraded mode, if ever implemented, requires a separate risk decision and cannot
  authorise from missing or stale trust state.

## Required validation before implementation is complete

- Inject failures independently for policy, trust, credentials, replay/state, signer, solver,
  receipt persistence and telemetry.
- Prove required security dependency failures do not produce ALLOW.
- Prove telemetry exporter failure does not change enforcement decisions.
- Prove receipt sidecar loss remains separately named and cannot rewrite the completed decision.
- Prove live watch allow/deny outcomes never affect the authoritative result.
- Prove watch timeout, queue overflow and evaluator exception are bounded and observable.
- Verify historical simulation/apply receipt compatibility and candidate hash binding.
- Measure overhead under load before publishing a watch-mode latency claim.

## References

- `raucle/policy_simulate.py`
- `docs/spec/x6-policy-simulate.md`
- `raucle/gateway.py`
- `tests/test_gate_chaos.py`
- [Raucle issue #344](https://github.com/epic28-ltd/raucle/issues/344)
