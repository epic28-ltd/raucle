<p align="center">
  <img src="assets/raucle-header.png" alt="Raucle: agent trust" width="300">
</p>

<p align="center">
  <a href="https://img.shields.io/pypi/v/raucle"><img alt="PyPI" src="https://img.shields.io/pypi/v/raucle.svg"></a>
  <a href="https://pypi.org/pypi/raucle/json"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/raucle.svg"></a>
  <a href="LICENSE"><img alt="Licence" src="https://img.shields.io/badge/licence-Apache_2.0-blue.svg"></a>
  <a href="https://github.com/epic28-ltd/raucle/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/epic28-ltd/raucle/ci.yml?branch=main&label=CI"></a>
</p>

<p align="center">
  <a href="docs/getting-started/README.md"><strong>Get started</strong></a> &middot;
  <a href="#quick-start">Quick start</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#docs">Docs</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

# raucle

raucle puts a gate between your AI agent and its tools. The gate checks every tool call against a signed permission and a policy, allows or blocks it, and writes a signed receipt that an auditor can verify offline, without asking you or us.

## What it is

Regulators and auditors ask the same questions of any system: who authorised it, what was it allowed to do, and what did it do? A vendor log answers only as the vendor sees it, and you have to trust the vendor you are trying to hold accountable.

A regulator has questions about a decision your agent made last quarter. A customer is in litigation because an AI-generated action cost them money. An internal auditor needs to certify that your agent did not act outside its authorised scope between two dates. In each case the same question: *what cryptographic record proves that?*

raucle answers with a receipt. Every gate decision, allow or deny, produces a signed record. It names the issuer's key, the tool's schema, the policy proof, the chain of tokens, a hash of the arguments and the decision. With only your published keys and proofs, a third party can check a receipt offline: the signature, the schema hash, the policy proof, the token chain and the decision. The Lean proofs are checked once, by rebuilding the published development. By default a receipt stores only a hash of the arguments, so checking the arguments themselves needs the operator to disclose them.

Three parts make that work:

1. **Permission.** Each agent gets a signed capability token (see the [glossary](docs/glossary.md)). The token names which tools the agent may call, with what argument limits, and until when. A delegated token can be narrowed, and can never be widened.
2. **Gate.** Every call is checked against the token and the tool's policy. The gate denies by default, and it signs both allow and deny decisions.
3. **Receipt.** Each decision produces a signed receipt (see the [glossary](docs/glossary.md)) naming the agent, the tool, the policy proof and the decision. Anyone with your published keys can verify it offline.

## What it does not do

- It does not certify compliance. It produces evidence mapped to frameworks, and the mapping names controls as SATISFIED, PARTIAL, or OUT OF SCOPE.
- The proofs cover the gate, not the model. The gate constrains tool calls; it does not judge the model's judgement.
- A receipt covers calls that pass through the gate. It does not cover paths where raucle is not on the execution path.

## Features

| Feature | Status | Where |
|---|---|---|
| Capability tokens | Shipped | [`raucle/capability.py`](raucle/capability.py) |
| Gate (default deny, signed allow and deny) | Shipped | [`raucle/capability.py`](raucle/capability.py) |
| Policy proofs: the Z3 solver proves a tool's policy holds for every input its schema allows, or returns a breaking input | Shipped | [`raucle/prove.py`](raucle/prove.py) |
| Signed audit chain: hash-chained log with periodic signed checkpoints | Shipped | [`raucle/audit.py`](raucle/audit.py) |
| Offline verification: CLI and a browser verifier with no install and no network in the browser | Shipped | `raucle audit verify`; [`assets/verifier/x2-verifier.html`](assets/verifier/x2-verifier.html) |
| Emergency stop: revokes an agent and derived tokens; one approver per agent, two for a global halt; every transition is a signed receipt | Shipped | [`raucle/containment.py`](raucle/containment.py) |
| Content scanning: prompt injection, secrets, PII (NI numbers, NHS numbers, IBANs); tool-argument attacks: shell, path traversal, SQL, SSRF | Shipped | [`raucle/scanner.py`](raucle/scanner.py), [detection docs](docs/detection.md) |
| Trust registry, agent passport, cross-org handshake | Shipped | [`raucle/trust_registry.py`](raucle/trust_registry.py), [`raucle/passport.py`](raucle/passport.py), [`raucle/handshake.py`](raucle/handshake.py) |
| Compliance evidence packs: EU AI Act, ISO/IEC 42001, SOC 2, NCSC CAF | Shipped (an evidence map; the pack does not certify conformance) | [`raucle/compliance.py`](raucle/compliance.py) |
| Selective disclosure (conformance re-verification) | Experimental (no security review yet) | [`raucle/conformance.py`](raucle/conformance.py) |
| Hybrid post-quantum signatures: Ed25519 plus ML-DSA-65, both must verify | Shipped | [`raucle/pq.py`](raucle/pq.py) |
| Operator dashboard and live view | Shipped (open-source server) | [`raucle/server.py`](raucle/server.py) |
| SIEM forwarding | Shipped (open-source server) | [tutorial](docs/getting-started/08-siem-and-live-view.md) |
| Audit PDF export | Shipped (an HTML report you print to PDF) | [`raucle/audit_export.py`](raucle/audit_export.py) |
| Managed keys, hosted receipt store, and other hosted operations | Raucle Cloud service | [cloud.raucle.com](https://cloud.raucle.com) |

## Quick start

### Hello receipt (no framework, no LLM, no network)

This is [the five-minute tutorial](docs/getting-started/01-hello-receipt.md). Install and run:

```bash
pip install 'raucle[compliance]'
```

```python
from raucle.capability import CapabilityIssuer, CapabilityGate
from raucle.audit import HashChainSink, Ed25519Signer
import hashlib, json

issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
signer = Ed25519Signer.generate()
sink = HashChainSink("./receipts.log", signer=signer)

token = issuer.mint(
    agent_id="agent:kyc-prod",
    tool="lookup_customer",
    constraints={"starts_with": {"customer_id": "C-"}},
    ttl_seconds=300,
)

def decide(args):
    decision = gate.check(token, tool="lookup_customer", agent_id="agent:kyc-prod", args=args)
    print(f"call lookup_customer(customer_id={args['customer_id']!r})")
    print(f"  -> allowed: {decision.allowed}   reason: {decision.reason}")
    args_hash = "sha256:" + hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    sink.append({
        "agent_id": "agent:kyc-prod", "tool": "lookup_customer",
        "decision": "ALLOW" if decision.allowed else "DENY",
        "reason": decision.reason, "args_hash": args_hash,
        "policy_proof_hash": token.policy_proof_hash,
        "issuer": issuer.issuer, "key_id": issuer.key_id,
    })

decide({"customer_id": "C-1042"})
decide({"customer_id": "X-9999"})

with open("audit_pub.pem", "wb") as f:
    f.write(signer.public_key_pem())
sink.close()
```

Real output from this snippet, run on 2026-11-17 against raucle 0.23.6 from this repository:

```text
call lookup_customer(customer_id='C-1042')
  -> allowed: True   reason: ok
call lookup_customer(customer_id='X-9999')
  -> allowed: False  reason: constraint violated: customer_id='X-9999' does not start with 'C-'
```

`receipts.log` holds one JSON line per decision. The DENY chains to the ALLOW, and closing the log writes a signed checkpoint. The hashes below come from that run. They change every run, because timestamps and keys do.

```text
{"index": 0, "prev_hash": "000...000",
 "event": {"decision": "ALLOW", "tool": "lookup_customer", "reason": "ok",
           "args_hash": "sha256:72378aa1..."},
 "hash": "a6d371a649523b338cc4016775df4b85fa802e1330e1db28572fec1ff96d29a8"}
{"index": 1, "prev_hash": "a6d371a649523b33... (the ALLOW's hash)",
 "event": {"decision": "DENY", "reason": "constraint violated: customer_id='X-9999' does not start with 'C-'",
           "args_hash": "sha256:fabd19f6..."},
 "hash": "79ebfcd0c21cd5ea29dbb822de475ec111eca8305a3d08bcd8124e45ad6d5844"}
{"checkpoint": true, "merkle_root": "ed74f3bbea928ae41e0339ae6e550550ed9e43e805ff25b860d4b30916ed60a6",
 "signature": "RrjUtsChKNbMW2I4... (Ed25519)"}
```

Verify offline, with only the chain and the public key:

```text
$ raucle audit verify receipts.log --pubkey audit_pub.pem
Audit chain: VALID
  Events:               2
  Checkpoints:          1
  Valid signatures:     1
  Invalid signatures:   0
```

(Exit code 0.)

### Microsoft Agent Framework

Drop the gate into Microsoft's Agent Framework as one middleware. The imports are what most people miss: `ChatAgent` and `tool` are imported from `agent_framework` itself.

```python
from agent_framework import ChatAgent, tool
from raucle.capability import CapabilityIssuer, CapabilityGate
from raucle.audit import HashChainSink, Ed25519Signer
from raucle.integrations.agent_framework import (
    RaucleFunctionMiddleware,
    set_in_force_token,
)

issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
sink = HashChainSink("./receipts.log", signer=Ed25519Signer.generate())

agent = ChatAgent(chat_client=..., tools=[...])  # your Agent Framework agent
agent.middleware.add(RaucleFunctionMiddleware(gate=gate, sink=sink))

# Per session: mint a capability and prime it.
set_in_force_token(
    issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={"starts_with": {"customer_id": "C-"}},
        ttl_seconds=300,
    )
)
```

Real output from exercising this snippet's runtime paths against the installed `agent-framework` 1.24.0 (the repo's docs target 1.6; see the note below):

```text
agent-framework core version: 1.24.0
ALLOW path: next() called = True   (an ALLOW receipt appended)
DENY path:  short-circuited via MiddlewareTermination, carrying the refusal payload
```

The integration tests pass against the installed version: **9 passed** (`tests/test_agent_framework_real.py`, `tests/test_agent_framework_integration.py`).

> **Note.** The installed `agent-framework` in this environment is 1.24.0, while the repository docs state "verified against agent-framework 1.6+". In 1.24.0 the top-level package no longer exports `ChatAgent`, so `agent = ChatAgent(...)` binds to the version the docs target rather than to 1.24.0: TODO(owner) confirm the `ChatAgent` import against the 1.6 release and update `docs/getting-started/02-agent-framework.md` if 1.6 is no longer where that import lives. The middleware layer (`FunctionMiddleware`, `FunctionInvocationContext`, `MiddlewareTermination`, `tool`) is verified against this install through the adapter tests.

## How it works

raucle composes five primitives end to end. Each gated tool call produces an attestable receipt that chains a scanner verdict, a policy proof, a capability token, a gate decision, and a Merkle-rooted audit log (see the [glossary](docs/glossary.md)). Content scanning ([`docs/detection.md`](docs/detection.md)) is one of the gate's checks, and it is not the whole story.

The gate ([`CapabilityGate.check`](raucle/capability.py)) runs these verifications, and it denies whenever any check cannot be verified:

1. **Signature and issuer pinning.** The token must verify under a configured trusted issuer's key.
2. **Hybrid signature component.** Where the token carries an ML-DSA-65 component, that component must also verify.
3. **Revocation.** The token and every ancestor must be absent from the revocation denylist, where a resolver is present.
4. **Time bounds.** The token's `exp` and `not_before` must cover the current time.
5. **Tool binding.** The token must name exactly the tool being called.
6. **Caller identity.** The dot-delimited `agent_id` scope and the acting-for pair must match.
7. **Call arguments.** Arguments are checked against the declared schema, then against the token's constraints, and both fail closed. The task-intent check (7.6 in the code) bounds the call to an approved intent when an intent is set.
7.5. **Proof enforcement.** In strict mode the gate checks that the cited proof belongs to this tool's schema and policy.
8. **Chain verification.** Every link in the attenuation chain (see the [glossary](docs/glossary.md)) is re-verified: signature, trust, revocation, and narrowing.

Identity failures (1 to 4) belong to the token itself, and they return an authentication failure. Binding failures (5 to 8) belong to the caller's use of verified authority, and they return a receipted DENY.

## What is proved and what is only tested

| Claim | Where |
|---|---|
| Proved in Lean 4 (see the [glossary](docs/glossary.md)) | |
| A derived token cannot have more permission than its parent. | [`paper/lean/VCD/Attenuation.lean`](paper/lean/VCD/Attenuation.lean) |
| If the gate says ALLOW, the call meets the modelled constraints (`allowed_values`, `forbidden_values`, `max_value` / `min_value`, `required_present`). | [`paper/lean/VCD/Gate.lean`](paper/lean/VCD/Gate.lean) |
| Assuming the Z3 prover is sound (an explicit axiom), a call under a PROVEN proof satisfies the policy. | [`paper/lean/VCD/Composition.lean`](paper/lean/VCD/Composition.lean) |
| Enforced at runtime and tested, not yet proved | |
| `starts_with` constraints | [`raucle/capability.py`](raucle/capability.py) + tests |
| `forbidden_field_combinations` | [`raucle/capability.py`](raucle/capability.py) + tests |
| Dot-delimited `agent_id` scope, revocation, expiry | [`raucle/capability.py`](raucle/capability.py) + tests |
| Signature check, issuer pinning | [`raucle/capability.py`](raucle/capability.py) + tests |
| That the cited proof belongs to this tool's schema and policy (strict mode) | [`raucle/capability.py::_check_proof_binding`](raucle/capability.py) + tests |

The exact proof boundary lives in [`paper/lean/README.md`](paper/lean/README.md).

## Evidence the mechanism is sound

The same primitives that produce trustworthy receipts also block prompt-injection-mediated tool misuse. This is a corollary of the design, and it is not the headline. Reported across three frontier-class open-weight model generations, four AgentDojo task suites, and three attack families:

- **100% block rate** on attacker-controlled tool calls across 720 LLM-driven attempts on the AgentDojo banking suite. This is the capability gate's structural guarantee: a call outside the signed capability cannot execute. The only residual benchmark "success" is an IBAN-collision artefact, where the benchmark's oracle cannot tell a user-authorised transfer from an attacker-induced transfer to the same destination ([§6.5](paper/DRAFT.md)). On the other suites a small residual attack-success rate remains, concentrated in attacks scored on free-form model output rather than on a tool call, which sits outside the gate's tool-call boundary ([§6.2.3](paper/DRAFT.md)).
- **+27 to +58 percentage points** of benign task completion preserved versus Prompt Shields (a commercial prompt-injection filter built on a DeBERTa-based detector), at equivalent security. The paper reports that Prompt Shields collapses benign completion into the 0.0 to 36.7% range while raucle preserves 58.6 to 91.0%.
- **69 µs per-call gate latency at p50** (no chain, x86_64 EPYC-Milan; [`paper/eval/latency-x86.json`](paper/eval/latency-x86.json)). A 3-link attenuation chain costs 268 µs, and p50 is about 150 µs on Apple-M ARM64. End-to-end agent wall time with raucle is at or below the unprotected baseline on four of eight measured cohorts.
- A **static upper bound**: 0 of 2,737 catalogued AgentDojo + InjecAgent scenarios admit any attacker-controlled call. This is a guarantee over the catalogued attack arguments, and it is not an empirical attack-success measurement.

Full results, the reproducibility package, and the IEEE S&P 2027 draft live under [`paper/`](paper/).

## Who it is for

raucle is built for the agent deployments that have to survive an audit:

- **Banks and fintechs** subject to FCA / BaFin / MAS model-risk-management expectations, who need to evidence that customer-service or operations agents did not act outside their authorised scope.
- **Healthcare and clinical platforms** subject to EU AI Act high-risk obligations and equivalent national-competent-authority oversight.
- **Government and public sector** AI deployments, where the deploying organisation may need to demonstrate compliance to an oversight body it does not control.
- **Cross-organisation agent workflows**, where one party's agent delegates to another's. The receipt is the audit trail across that trust boundary.

## Integrations

raucle composes with the agent frameworks regulated organisations already deploy. "Shipped" rows have adapters and tests under [`raucle/integrations/`](raucle/integrations/). "Pattern" rows are deployable templates without a tested adapter.

| Integration | Kind | Where |
|---|---|---|
| Microsoft Agent Framework | Shipped middleware | [`raucle/integrations/agent_framework.py`](raucle/integrations/agent_framework.py) |
| Microsoft Agent Governance Toolkit (`ExternalPolicyBackend`; merged upstream 2026-05-27) | Shipped backend | [`raucle/integrations/agt_backend.py`](raucle/integrations/agt_backend.py); upstream [microsoft/agent-governance-toolkit#2610](https://github.com/microsoft/agent-governance-toolkit/pull/2610) |
| LangChain | Shipped callback handler | [`raucle/integrations/langchain.py`](raucle/integrations/langchain.py) |
| LangGraph | Shipped tool-node gate | [`raucle/integrations/langgraph.py`](raucle/integrations/langgraph.py); [walkthrough](docs/getting-started/04-langgraph.md) |
| CrewAI | Shipped tool guard | [`raucle/integrations/crewai.py`](raucle/integrations/crewai.py); [walkthrough](docs/getting-started/05-crewai.md) |
| AutoGen (agentchat 0.4 or later) | Shipped tool gate | [`raucle/integrations/autogen.py`](raucle/integrations/autogen.py) |
| OpenAI Agents SDK | Shipped guard | [`raucle/integrations/openai_agents.py`](raucle/integrations/openai_agents.py) |
| MCP clients | Shipped gateway | [tutorial](docs/getting-started/03-mcp-clients.md) |
| AWS MCP sidecar | Shipped pattern | [tutorial](docs/getting-started/08-aws-mcp.md) |
| Azure AI Foundry MCP gateway | Shipped pattern (Bicep + APIM policy) | [`deploy/foundry-mcp-sidecar/`](deploy/foundry-mcp-sidecar/) |

The [OpenClaw](#openclaw) and scanning hooks are separate; see below.

## Cross-organisation trust layer

Beyond per-call enforcement, raucle ships the primitives that make receipts portable between parties who have never exchanged keys.

| Item | What it does | Status | Link |
|---|---|---|---|
| Agent Trust Registry | An append-only, hash-chained, operator-signed directory of issuer keys; revocation is fail-closed (see the [glossary](docs/glossary.md)) | Shipped | [`raucle/trust_registry.py`](raucle/trust_registry.py); [tutorial](docs/getting-started/10-trust-registry.md) |
| Cross-org handshake | Signed request/accept/ack exchange between two organisations' agents, with replay-bound acknowledgement receipts | Shipped | [`raucle/handshake.py`](raucle/handshake.py); [tutorial](docs/getting-started/11-cross-org-handshake.md) |
| Agent passport | An issuer-countersigned, registry-anchored identity document any framework can verify offline | Shipped | [`raucle/passport.py`](raucle/passport.py); [tutorial](docs/getting-started/13-agent-passport.md) |
| Conformance re-verification with selective disclosure | Prove a receipt's hidden call arguments satisfied the policy, disclosing only the fields a verifier requests | Experimental; no security review yet | [`raucle/conformance.py`](raucle/conformance.py); [design](docs/spec/provenance/v1/conformance-reverification.md) |
| Hybrid post-quantum signatures | Ed25519 plus ML-DSA-65 on every receipt, both must verify, fail-closed on downgrade | Shipped | [`raucle/pq.py`](raucle/pq.py); [design](docs/spec/provenance/v1/pq1-hybrid.md) |
| Delegated authority with monotonic narrowing | Child tokens narrow scope and lifetime, and every receipt binds the chain | Shipped | [`raucle/capability.py`](raucle/capability.py) |
| Credential-lease receipts | An agent holds a placeholder; real secrets live in a vault and cross the network boundary at a proxy | Shipped | [spec](docs/spec/provenance/v1.2/lease-extension.md) |
| Harness findings as verifiable evidence | A red-team or QM harness reports each finding as a signed receipt citing the gate receipt that covered it | Shipped | [spec](docs/spec/provenance/v1.2/harness-findings.md) |
| Records lifecycle | Receipts carry retention schedules; disposal is a signed destruction receipt | Shipped | [`raucle/records.py`](raucle/records.py) |
| Counterfactual replay | Re-runs a recorded incident under an alternative policy and reports per action whether the stricter policy would have denied it | Shipped | [`raucle/counterfactual.py`](raucle/counterfactual.py) |
| Code authorship receipts | Coding-agent hooks sign a session-stop receipt of what the agent changed | Shipped | [`raucle/authorship.py`](raucle/authorship.py) |
| Time-source anchoring | Internal, TSA-attested, and OpenTimestamps modes for long-lived archives | Shipped | [`raucle/timestamp.py`](raucle/timestamp.py); [spec](docs/spec/time-source-v1.md) |
| Browser verifier | A static HTML page re-verifies audit packs entirely in the browser, with zero network I/O after load | Shipped | [`assets/verifier/x2-verifier.html`](assets/verifier/x2-verifier.html); [spec](docs/spec/x2-verifier-page.md) |

Selective disclosure is Layer 1 of a longer plan. The zkVM layers of that plan are research plans and are not shipped; see [`docs/roadmap-zkvm.md`](docs/roadmap-zkvm.md).

The registry, handshake, passport, and compliance modules went through nine review rounds before merging. The reviewer in those rounds was the automated codex CLI, running a find, fix, re-verify loop, and every fix carries a regression test. No human or third-party security audit has yet reviewed these modules: TODO(owner) state whether a human review is planned, so that "independent" is never attached to an automated tool round.

## Install and migration

```bash
pip install raucle
```

Optional extras:

```bash
pip install 'raucle[rules]'               # YAML rule loading (PyYAML)
pip install 'raucle[server]'              # REST API server (FastAPI + uvicorn)
pip install 'raucle[ml]'                  # Transformer-based classifier (torch, transformers)
pip install 'raucle[compliance]'          # Capability tokens, signed audit chain, receipts
pip install 'raucle[proof]'               # SMT prover for prove-a-policy (Z3)
pip install 'raucle[agent-framework]'     # Microsoft Agent Framework adapter
pip install 'raucle[all]'                 # rules + ml + server + compliance + multimodal + proof
```

The `[all]` extra bundles the engine extras and does not bundle framework adapters. Install `[agent-framework]` separately if you use the Microsoft Agent Framework integration. Python 3.10 or newer is required. The current release is 0.23.6.

### Migrating from `raucle-detect`

The project was renamed to **raucle** in v0.22.0. The library outgrew the name "detect": receipts, provenance, the trust registry, and compliance evidence are the product, and detection is one module. The detection reference material now lives in [`docs/detection.md`](docs/detection.md), covering what it detects, detection modes, custom rules, batch scanning, rule packs, input size limits, the heuristic classifier, ScanResult fields, output, tool call and session scanning, middleware, and the scanner REST API.

| Was | Now |
|---|---|
| `pip install raucle-detect` | `pip install raucle` |
| `import raucle_detect` | `import raucle`; old imports keep working through a shim with a `DeprecationWarning` |
| `raucle-detect` CLI | `raucle`; the old command remains as a deprecated alias |
| `RAUCLE_DETECT_*` env vars | `RAUCLE_*`; the legacy names remain supported |
| Go module `github.com/craigamcw/raucle/reference/provenance-go` | `github.com/epic28-ltd/raucle/reference/provenance-go`; breaking for Go imports, so update the import path |

Wire formats are unchanged. The provenance receipt `iss` identifier (`"raucle-detect/provenance"`), the receipt, audit and registry formats, the signatures, and the test vectors are frozen, so every existing receipt still verifies. The `raucle-detect` PyPI package receives one final transition release that depends on `raucle`, and no releases after that.

## OpenClaw

The `plugins/openclaw/` directory holds the Raucle plugin for OpenClaw. It runs raucle's scanning engine in front of OpenClaw's prompts, outputs, and tool calls. Install, hooks, and per-agent configuration: [`plugins/openclaw/README.md`](plugins/openclaw/README.md).

## Contributing

Contributions are welcome, especially new detection rules. See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions carry a DCO sign-off:

```bash
git commit -s -m "Add new detection rule"
```

## Security

To report a vulnerability, email **security@raucle.com**. Do not open a public issue. See [SECURITY.md](.github/SECURITY.md).

## License

raucle is licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE). You may use, modify, embed, and redistribute it, including in closed-source products and hosted services, subject to the licence's attribution and patent terms.

Apache-2.0 includes an explicit patent grant and does not grant rights to the **Raucle** name or logo; see [TRADEMARK.md](TRADEMARK.md). The five reference implementations under `reference/` are MIT-licensed. The Provenance Receipt specification is CC-BY-4.0.

> Starting with **v0.19.0**, the core package is Apache-2.0. Releases **v0.10.0 through v0.18.0** remain under the AGPL-3.0-or-later licence under which they were published. Releases before v0.10.0 remain under their previously published terms (MIT).

Copyright (c) 2026 Raucle
