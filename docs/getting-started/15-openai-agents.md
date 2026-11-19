# 15. OpenAI Agents SDK

**Time: 5 minutes.** raucle gives the OpenAI Agents SDK both halves of its
doctrine: content guardrails (prompt-injection scanning on the way in and
out) and a capability gate around every tool call, each decision landing in
a signed, verifiable receipt chain.

```bash
pip install 'raucle[compliance,openai-agents]'
```

## Gate your tools

`guard_tool` accepts a `@function_tool`-decorated tool (or a plain
function) and returns the same tool with the gate inside it. The model sees
an identical tool; a denied call raises before the tool body runs.

```python
from agents import Agent, Runner, function_tool
from raucle.audit import Ed25519Signer, HashChainSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations.openai_agents import guard_tool, set_in_force_token

issuer = CapabilityIssuer.generate(issuer="acme.platform")
gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
sink = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())


@function_tool
def transfer_funds(to: str, amount: int) -> str:
    """Move money on the ledger."""
    ...


# agent_id binds the acting identity; an unattributed call denies.
tools = [guard_tool(transfer_funds, gate=gate, sink=sink, agent_id="agent:billing")]

agent = Agent(name="agent:billing", tools=tools)

# Per session: bind a token scoped to what THIS task may do.
set_in_force_token(
    issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
        ttl_seconds=60,
    )
)

result = await Runner.run(agent, "pay the invoice")
```

If you prefer not to pin the identity at guard time, pass it on the run
context instead and drop `agent_id`:

```python
await Runner.run(agent, "pay the invoice", context={"agent_id": "agent:billing"})
```

A call with no attributable identity denies rather than running attributed
to a placeholder, and the deny receipt carries an honest null `agent_id`.

## Scan the content too

```python
from raucle.integrations.openai_agents import input_guardrail, output_guardrail
from raucle.scanner import Scanner

scanner = Scanner()
agent = Agent(
    name="agent:billing",
    tools=tools,
    input_guardrails=[input_guardrail(scanner, sink=sink)],
    output_guardrails=[output_guardrail(scanner, sink=sink)],
)
```

Verify the evidence offline:

```bash
raucle audit verify receipts.jsonl
raucle watch receipts.jsonl --denies-only   # live SOC view
```

See the integration matrix row (`docs/integrations/matrix.md`) for the
verified version span (0.19 through 0.25 at time of writing).

---

Next: [Pydantic AI](16-pydantic-ai.md) for the same gate on Pydantic AI
agents.
