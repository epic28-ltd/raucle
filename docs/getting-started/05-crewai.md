# 5. CrewAI

**Time: 5 minutes.** raucle gates every tool call your crew makes against a
signed capability token and records each ALLOW/DENY as a verifiable receipt —
without changing how your tools look to the agent.

```bash
pip install 'raucle[compliance,crewai]'
```

## Wrap your tools

`guard_tools` returns drop-in `BaseTool`s with the same `name` /
`description` / `args_schema`, so the agent is unchanged:

```python
from raucle.audit import Ed25519Signer, HashChainSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations.crewai import guard_tools, set_in_force_token

issuer = CapabilityIssuer.generate(issuer="acme.platform")
gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
sink   = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())

# agent_id binds the acting identity the gate holds every call against.
# Bearer mode is closed: an unattributed call denies, so bind it up front.
tools = guard_tools(my_raw_tools, gate=gate, sink=sink, agent_id="agent:billing")

# Per session: bind a token scoped to what THIS task may do.
set_in_force_token(issuer.mint(
    agent_id="agent:billing", tool="transfer_funds",
    constraints={"max_value": {"amount": 100}}, ttl_seconds=60,
))

agent = Agent(role="biller", goal="...", tools=tools, ...)
Crew(agents=[agent], tasks=[...]).kickoff()
```

A call outside the token's signed constraints raises `CapabilityDenied` **before
the tool body runs** — CrewAI surfaces it to the agent, and the denial is
recorded in the signed chain. The same is true of a call with no bound caller
identity: it denies rather than running attributed to a placeholder, and the
deny receipt carries an honest null `agent_id`. Because the gate evaluates
arguments, not the agent's reasoning, a prompt-injected call is denied on the
same path as any other.

Verify the evidence offline:

```bash
raucle audit verify receipts.jsonl
raucle watch receipts.jsonl --denies-only   # live SOC view
```

See the runnable [examples/crewai_demo](../../examples/crewai_demo/) (no API key)
for injection-blocked → receipt-verified end to end.

---

Next: [SIEM export & live monitoring](08-siem-and-live-view.md) to stream these
decisions to your SOC.
