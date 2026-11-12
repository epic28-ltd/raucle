# 4. LangGraph

**Time: 5 minutes.** raucle gates every tool call your LangGraph graph
executes against a signed capability token and records each ALLOW/DENY as a
verifiable receipt — at the **tool-node layer**, so the model node, edges and
routing stay your own.

```bash
pip install 'raucle[compliance,langgraph]'
```

## Gate the tool node

`RaucleToolNode` is a drop-in `langgraph.prebuilt.ToolNode` whose tools are
gated at construction. For the built-in agent, pass `gate_tools(...)` to the
`tools=` argument instead:

```python
from langgraph.graph import StateGraph, MessagesState, START
from langgraph.prebuilt import ToolNode, tools_condition

from raucle.audit import Ed25519Signer, HashChainSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations.langgraph import RaucleToolNode, set_in_force_token

issuer = CapabilityIssuer.generate(issuer="acme.platform")
gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
sink   = HashChainSink("receipts.jsonl", signer=Ed25519Signer.generate())

builder = StateGraph(MessagesState)
builder.add_node("agent", call_model)          # your model node — never wrapped
builder.add_node("tools", RaucleToolNode(      # gated tool node
    my_tools, gate=gate, sink=sink, agent_id="agent-1",
))

# Per session: bind a token scoped to what THIS task may do.
set_in_force_token(issuer.mint(
    agent_id="agent-1", tool="transfer_funds",
    constraints={"max_value": {"amount": 100}}, ttl_seconds=60,
))
```

For `create_react_agent(model, tools=tools)`:

```python
from raucle.integrations.langgraph import gate_tools

agent = create_react_agent(model, tools=gate_tools(tools, gate=gate,
                                                   sink=sink, agent_id="agent-1"))
```

## What the gate does to a call

A call outside the token's signed constraints raises `CapabilityDenied`
**before the tool body runs**. LangGraph's ToolNode presents that denial
message to the graph as the tool response (its documented
`handle_tool_errors` contract), so the model sees
`raucle denied 'transfer_funds': ...` — and the decision is recorded in the
signed chain either way. Because the gate evaluates arguments, not the
agent's reasoning, a prompt-injected call is denied on the same path as any
other. raucle sits on the TOOL NODE layer only: nothing wraps the model node,
and graph internals are untouched.

The receipt layer is fail-closed too: a token not in force, an unbuilt agent
identity, or a receipt-sink outage all abort the call rather than let an
untracked action through.

Verify the evidence offline:

```bash
raucle audit verify receipts.jsonl
raucle watch receipts.jsonl --denies-only   # live SOC view
```

## Availability note

The adapter imports lazily (same pattern as every other integration):
installing raucle without the `langgraph` extra never breaks imports, and
without langgraph, instantiating the adapter raises a clear install hint.
LangChain `AgentExecutor` users: use the
[callback handler](../../raucle/integrations/langchain.py) instead — the two
adapters share the receipt format but bind different seams.

---

Next: [Prove a policy](06-prove-a-policy.md) to SMT-prove your policy is
sound before minting tokens against it.
