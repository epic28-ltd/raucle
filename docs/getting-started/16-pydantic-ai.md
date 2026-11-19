# 16. Pydantic AI

**Time: 5 minutes.** raucle gates every tool call your Pydantic AI agent
makes against a signed capability token and records each ALLOW/DENY as a
verifiable receipt, without changing how the tool looks to the framework.

```bash
pip install 'raucle[compliance,pydantic-ai]'
```

## Wrap your tools

`guard_tool` returns a function with the original signature, so
registering it with `@agent.tool` produces exactly the tool the model
would have seen:

```python
from pydantic_ai import Agent
from pydantic_ai.tools import RunContext

from raucle.audit import Ed25519Signer, HashChainSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations.pydantic_ai import guard_tool, set_in_force_token

issuer = CapabilityIssuer.generate(issuer="acme.platform")
gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
sink = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())


def transfer_funds(ctx: RunContext, to: str, amount: int) -> str: ...


# agent_id binds the acting identity; an unattributed call denies.
# (With no agent_id pinned, the identity comes from the Agent the tool is
# registered on: give it a raucle-scheme name, Agent(..., name="agent:billing").)
agent = Agent("openai:gpt-4o", name="agent:billing")
agent.tool(guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing"))

# Per session: bind a token scoped to what THIS task may do.
set_in_force_token(
    issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
        ttl_seconds=60,
    )
)

result = agent.run_sync("pay the invoice")
```

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
verified version span (1.107 through 2.70 at time of writing). The
`pydantic-ai` extra and the `crewai` extra cannot be installed in the same
environment; pick one family per deployment.

---

Next: [Google ADK](17-google-adk.md) for the same gate on ADK agents.
