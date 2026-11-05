# VCD for the Microsoft Agent Framework

**Status:** Shipped — the middleware lives in `raucle/integrations/` (originally drafted 2026-05-27).
**Authors:** Raucle.
**Target:** shipped in `raucle` ≥ v0.13.0; `microsoft/agent-framework` ≥ 1.0.

## Summary

The Microsoft Agent Framework, GA on 3 April 2026 under MIT, is the
declared strategic successor to Semantic Kernel and AutoGen. It ships a
stable three-layer middleware pipeline (`AgentMiddleware`,
`FunctionMiddleware`, `ChatMiddleware`) with a documented
`(context, call_next)` extensibility shape that fits the VCD gate's
existing model 1:1. This proposal specifies a drop-in middleware that
lets any Agent-Framework deployment produce raucle capability receipts
for every tool call its agent makes, with no architectural change to
the deployer's code beyond adding one line to the agent constructor.

A skeleton implementation ships alongside this design doc at
`raucle/integrations/agent_framework.py`.

## Why now

Three convergent timing pressures:

1. **Microsoft's stack is consolidating fast.** Agent Framework 1.0
   subsumed SK and AutoGen in a single April release. Most Microsoft
   shop AI-agent deployments built on either of those legacy frameworks
   are migrating now. The middleware contract is the single hook all
   migrating deployments will go through.
2. **The Microsoft Agent Governance Toolkit is positionally adjacent.**
   AGT (also MIT, also April 2026) covers policy enforcement and audit
   chaining but does not produce a content-addressed, offline-
   verifiable, Lean-mechanised receipt. Raucle's defensible position is
   *with* AGT, not against it: raucle as the formally-verified PDP that
   AGT can call out to. Shipping the Agent Framework middleware first
   gives raucle a working integration story to point at when
   approaching the AGT maintainers about a PDP plug-in contract
   (see Future work).
3. **Foundry MCP AI Gateway explicitly does not log tool traces.** The
   Microsoft Foundry docs name this as a current limitation. A raucle
   Agent Framework middleware fills exactly that gap for Foundry-
   deployed agents — emits the audit trace Foundry doesn't.

## What changes

### One line in the deployer's agent construction

```python
from agent_framework import ChatAgent
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.audit import HashChainSink
from raucle.integrations.agent_framework import RaucleFunctionMiddleware

issuer = CapabilityIssuer.load("issuer.key")
gate = CapabilityGate(issuer_pubkey=issuer.public_key)
sink = HashChainSink(path="./receipts.log")

agent = ChatAgent(
    chat_client=openai_client,
    instructions="...",
    tools=[lookup_customer, transfer_funds],
)
agent.middleware.add(RaucleFunctionMiddleware(gate=gate, issuer=issuer, sink=sink))
```

After this addition, every tool the agent invokes:

1. Passes through the raucle gate, which checks the in-force capability
   token against the call arguments.
2. On ALLOW, `call_next()` is invoked; the tool runs; a capability
   receipt is signed and emitted to the sink. The agent observes
   nothing different.
3. On DENY, the tool does not run; `context.result` is set to a
   structured refusal carrying the policy_proof_hash and the failed
   constraint; a denial receipt is still signed and emitted.

### The middleware contract

Per the Agent Framework Python docs (`learn.microsoft.com/python/api/agent-framework-core/agent_framework.agentmiddleware`):

```python
class FunctionMiddleware:
    async def process(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None: ...
```

`context` exposes `function` (the tool descriptor), `arguments` (the
proposed call args), `agent` (carrying `agent.id`), `is_streaming`, and
a mutable `result` field downstream middleware may inspect/replace.

### .NET parity (planned for v0.11.1)

The .NET Agent Framework exposes the same shape via DI registration:

```csharp
builder.Services.AddSingleton<IFunctionMiddleware, RaucleFunctionMiddleware>();
```

A `Raucle.AgentFramework` NuGet ships in M3 below.

## The skeleton at a glance

The implementation in `raucle/integrations/agent_framework.py`:

- Imports `agent_framework` types lazily (try/except), so installing
  `raucle` without the `agent-framework` extra does not break.
- Defines `RaucleFunctionMiddleware` with a single async `process`
  method matching the documented contract.
- Resolves the in-force capability token via a pluggable
  `TokenResolver` callable; the default resolves from a thread-local
  or asyncio-context store the deployer populates at session start.
- Maps `context.agent.id` → receipt's `agent_id`, `context.function.name`
  → `tool`, `context.arguments` → call args (canonical JSON serialised
  and SHA-256-hashed to produce `call_args_hash`).
- Calls `gate.check(token, tool, args)` synchronously inside the async
  process method (the gate is sub-100µs).
- On ALLOW: `await call_next()` then `sink.write(receipt)`.
- On DENY: short-circuits without calling `call_next()`, sets
  `context.result` to a `FunctionResult` carrying the structured
  refusal, then `sink.write(receipt)`.

Streaming support is a known limitation in the skeleton (see Open
questions).

## Backwards compatibility

- Deployers not adding the middleware are unaffected.
- Middleware is composable with AGT's policy enforcement: register the
  raucle middleware *after* AGT's middleware so the receipt records the
  decision AGT actually made. (When AGT denies, raucle observes the
  refusal and emits a receipt for it too — strictly more audit data,
  no behavioural change.)
- The middleware is namespaced to a single agent. Multi-agent
  deployments register the middleware per-agent and the receipts'
  `agent_id` field distinguishes provenance.

## Optional dependency

`pyproject.toml`:

```toml
[project.optional-dependencies]
agent-framework = ["agent-framework>=1.0"]
```

`pip install 'raucle[agent-framework]'` pulls Microsoft's package
alongside the integration layer.

## Threat-model deltas

Compared to the base raucle deployment:

| Concern | Base raucle | With Agent Framework middleware |
|---|---|---|
| Trusted dispatch path | Deployer enforces gate is the only path | Agent Framework's middleware chain enforces |
| `agent_id` provenance | Deployer-supplied | Read from `context.agent.id` (which Microsoft populates from the agent's construction) |
| Streaming results | Out-of-scope in v0.10 | Receipt covers the request, not the streamed response (see Open question 2) |
| Result mutation by downstream middleware | N/A | Documented risk: downstream middleware can alter the tool result after raucle has emitted its ALLOW receipt. Mitigation: register raucle last, or compose with a `SealedSubChain` (M4). |

## Non-goals

- Not a replacement for AGT. Composes with AGT, does not exclude it.
- Not a model-level safety layer (no constitutional classifier, no
  output filtering). raucle is the audit primitive; output-side
  defences compose orthogonally.
- Not a substitute for proper policy authoring. The gate enforces what
  the issuer's policy says; the policy itself is the deployer's
  responsibility.

## Reference-implementation milestones

| M | Deliverable | Target |
|---|---|---|
| M1 | `raucle/integrations/agent_framework.py` skeleton (this commit) | 2026-05-27 |
| M2 | Working two-tool demo: ALLOW + DENY captured by canonical AgentDojo banking scenario, run end-to-end inside Agent Framework's `ChatAgent`. Tagged in `examples/agent_framework_demo/`. | 2 weeks |
| M3 | `Raucle.AgentFramework` NuGet (.NET equivalent), with the same one-line `AddSingleton<IFunctionMiddleware>` integration. | 5 weeks |
| M4 | Streaming-safe receipt emission (content-addresses the materialised stream) + `SealedSubChain` wrapper preventing downstream-middleware result mutation. | 8 weeks |
| M5 | Compatibility-with-AGT writeup + sample deployment configuration that runs both side-by-side. | 10 weeks |

## Future work — AGT PDP plug-in contract

AGT's published architecture documents `PolicyEngine.add_constraint(...)`
and references YAML / OPA / Cedar policy adapters, but does not define a
third-party Policy Decision Point plug-in interface. Two postures
available:

1. **Adapter-alongside (M5 above).** Raucle and AGT both intercept tool
   calls via Agent Framework middleware. Raucle's PDP runs first; AGT's
   runs second. Each emits its own audit record. The deployer composes
   them via middleware registration order.
2. **PDP-upstream (separate proposal).** Propose an `IPolicyProvider`
   contract upstream to `microsoft/agent-governance-toolkit` — an
   abstract interface AGT's Agent OS calls out to for policy decisions
   it doesn't want to make in-process. Raucle ships as the canonical
   reference implementation. This is a standards-slot capture move,
   analogous to the A2A binding proposal in `vcd-a2a.md`. Park as a
   follow-on draft once M2 has shipped and we have a working raucle
   integration to point at.

## Open questions for review

1. **Token resolution.** How does the middleware know which capability
   token is in force when an agent emits a tool call? The skeleton uses
   a `TokenResolver` callable the deployer wires in. A future revision
   could read the token from a header passed through the Agent
   Framework context's `metadata` dict, if Microsoft formalises that.
2. **Streaming.** Agent Framework's `is_streaming` flag means the
   tool's response may not be a single object. The current skeleton
   covers the *call* side only — the receipt records what was
   authorised, not the materialised response. Closing this requires
   buffering the stream and content-addressing the materialisation
   (M4).
3. **AGT ordering convention.** When both raucle and AGT middlewares are
   present, the documented convention should be: AGT first (it makes
   the in-process policy decision), raucle second (it produces the
   verifiable receipt of whatever was decided). M5 publishes the
   reference configuration.

## Why this is the right move for raucle

Three reasons:

1. **The hook exists, is stable, is documented.** Unlike A2A (where the
   authorisation slot is open and time-sensitive), Agent Framework's
   middleware contract is already finalised. The integration is purely
   engineering, not standards politics. Lower risk, faster ship.
2. **It lights up the entire Microsoft ecosystem in one shim.** Foundry,
   Azure OpenAI, OpenAI, Anthropic, Ollama — all reachable through
   Agent Framework. One library, one install, one line in
   construction.
3. **It is the on-ramp every Microsoft customer recognises.** When a
   regulated-industry buyer asks *"how do I try this?"*, the answer
   becomes `pip install raucle[agent-framework]` and three
   lines in their existing agent. The friction of evaluating raucle
   drops to the floor.
