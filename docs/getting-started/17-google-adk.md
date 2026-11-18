# 17. Google ADK

**Time: 5 minutes.** raucle gates every tool call your Google ADK agent
makes against a signed capability token and records each ALLOW/DENY as a
verifiable receipt, without changing how the tool looks to the framework.

```bash
pip install 'raucle[compliance,google-adk]'
```

## Wrap your tools

ADK tools are functions with the `(args: dict, tool_context: ToolContext)`
shape. `guard_tool` returns a function with the same signature, so
`FunctionTool` (or direct registration on the `LlmAgent`) produces exactly
the tool the model would have seen:

```python
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool, ToolContext

from raucle.audit import Ed25519Signer, HashChainSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations.google_adk import guard_tool, set_in_force_token

issuer = CapabilityIssuer.generate(issuer="acme.platform")
gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
sink = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())


def transfer_funds(args: dict, tool_context: ToolContext) -> dict: ...


# agent_id binds the acting identity; an unattributed call denies.
# ADK names its agents with plain identifiers, so the raucle id is the
# joined form: billing_agent acts as agent:billing_agent.
agent = LlmAgent(
    name="billing_agent",
    model="gemini-2.0-flash",
    tools=[
        FunctionTool(
            guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing_agent")
        )
    ],
)

# Per session: bind a token scoped to what THIS task may do.
set_in_force_token(
    issuer.mint(
        agent_id="agent:billing_agent",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
        ttl_seconds=60,
    )
)
```

With no `agent_id` pinned, the identity comes from the invocation context
(the `LlmAgent` the run is executing), joined into the raucle scheme the
same way: mint the token for the joined id.

A call outside the token's signed constraints raises `CapabilityDenied`
before the function body runs, and the denial is recorded in the signed
chain. The same is true of a call with no attributable identity: it denies
rather than running attributed to a placeholder, and the deny receipt
carries an honest null `agent_id`. Because the gate evaluates arguments,
not the agent's reasoning, a prompt-injected call is denied on the same
path as any other.

Verify the evidence offline:

```bash
raucle audit verify receipts.jsonl
raucle watch receipts.jsonl --denies-only   # live SOC view
```

See the integration matrix row (`docs/integrations/matrix.md`) for the
verified version span (1.39 through 2.14 at time of writing). The
`google-adk` extra and the `crewai` extra cannot be installed in the same
environment; pick one family per deployment.

---

Next: [Production hardening](20-production-hardening.md) for the
operational checklist once agents are gated.
