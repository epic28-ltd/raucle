# 2. Microsoft Agent Framework integration

**Time: 10 min · Pre-req: Python 3.10+, an Agent Framework agent.**

Add raucle to a Microsoft Agent Framework agent in one line of middleware.

By the end you'll have:

- raucle's `RaucleFunctionMiddleware` registered on a `ChatAgent`,
- a capability token primed for the session,
- every tool call producing a signed receipt,
- denied calls short-circuited cleanly via the framework's documented `MiddlewareTermination` path.

This is the **recommended integration** for AI-agent platforms on Microsoft's stack. The Agent Framework GA'd 2026-04-03; raucle's middleware is verified against `agent-framework` 1.6+.

---

## Step 1 — install

```bash
pip install 'raucle[agent-framework,compliance]'
```

This pulls in `agent-framework` alongside the raucle engine, plus the `compliance` extra (`cryptography`) that the capability tokens, signed audit chain, and receipts depend on.

---

## Step 2 — your existing agent (no raucle)

For comparison, here's a vanilla Agent Framework agent with one tool:

```python
from agent_framework import ChatAgent, tool


@tool(approval_mode="never_require")
def lookup_customer(customer_id: str) -> str:
    # In production, this hits your customer DB.
    return f"Customer {customer_id}: name=Alice, status=active"


agent = ChatAgent(
    chat_client=...,  # your model client
    tools=[lookup_customer],
)
```

This is the baseline. Tool calls dispatch directly. There is no record of *who* asked, *which* policy authorised it, or *what* arguments were inspected. An auditor sees nothing.

---

## Step 3 — add raucle

Five lines of changes:

```python
from agent_framework import ChatAgent, tool
from raucle.capability import CapabilityIssuer, CapabilityGate
from raucle.audit import HashChainSink, Ed25519Signer
from raucle.integrations.agent_framework import (  # NEW
    RaucleFunctionMiddleware,  # NEW
    set_in_force_token,  # NEW
)  # NEW

# Issuer + gate. In production these are persisted; we generate
# inline for the tutorial.
issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

# Receipt sink — signed, hash-chained log file.
signer = Ed25519Signer.generate()
sink = HashChainSink("./receipts.log", signer=signer)


@tool(approval_mode="never_require")
def lookup_customer(customer_id: str) -> str:
    return f"Customer {customer_id}: name=Alice, status=active"


agent = ChatAgent(chat_client=..., tools=[lookup_customer])
agent.middleware.add(  # NEW
    RaucleFunctionMiddleware(gate=gate, sink=sink),  # NEW
)  # NEW
```

That's the integration. The middleware sits between `agent.run()` and the tool dispatch; every tool call passes through it.

---

## Step 4 — prime a session token

A *session* — one user conversation, one agent invocation, one batch job — runs under one capability token. Mint it when the session opens:

```python
token = issuer.mint(
    agent_id="agent:kyc-prod",
    tool="lookup_customer",
    constraints={
        # Restrict customer-ID prefix
        "starts_with": {"customer_id": "C-"},
    },
    ttl_seconds=300,  # 5 minutes
)
set_in_force_token(token)
```

`set_in_force_token` binds the token to the current asyncio context, so concurrent sessions get independent tokens automatically. The middleware reads it on every tool call.

If your platform mints a fresh token per HTTP request, call `set_in_force_token` at the top of each request handler — same idea.

---

## Step 5 — run the agent

```python
import asyncio


async def main():
    reply = await agent.run("Look up customer C-1042 for me, please.")
    print(reply)


asyncio.run(main())
```

The agent's LLM produces a function call to `lookup_customer(customer_id="C-1042")`. The middleware:

1. Reads the in-force capability token from the context.
2. Calls `gate.check(token, tool="lookup_customer", agent_id=..., args={"customer_id":"C-1042"})`.
3. Constraint passes (`C-1042` starts with `C-`). Decision = ALLOW.
4. Appends a signed receipt to `receipts.log`.
5. Allows the framework to dispatch the actual tool.

The output is the agent's reply, exactly as before.

---

## Step 6 — see a denial

Ask for a customer ID that violates the constraint:

```python
async def main():
    reply = await agent.run("Look up customer X-9999.")
    print(reply)


asyncio.run(main())
```

The LLM still produces a function call to `lookup_customer(customer_id="X-9999")`. But:

1. The gate finds the constraint violated. Decision = DENY.
2. The middleware appends a signed DENY receipt.
3. The middleware raises `MiddlewareTermination` with a structured refusal payload — the documented Agent Framework path for short-circuiting a tool call.
4. The framework returns the refusal to the LLM.
5. The LLM produces a natural-language refusal to the user.

No PR. No prompt-engineering. The malicious call **structurally cannot execute** — the gate is on the only code path to the tool.

---

## Step 7 — read the receipts

`receipts.log` now has at least two lines (one ALLOW + one DENY). Each line is one signed receipt:

```bash
head -2 receipts.log
```

You'll see two JSON objects. Each is a hash-chained record (`index`, `timestamp`, `prev_hash`, `event`, `hash`) whose `event` carries the capability receipt:

- `agent_id`, `tool`, `decision`, `decision_reason`
- `policy_proof_hash` (cited from the token)
- `call_args_hash` (sha256 of the actual call args — the args themselves stay local)
- `index`, `prev_hash`, `hash` on the record (the hash chain — tampering anywhere shows up downstream)

The chain is anchored by periodic Ed25519-signed *checkpoint* records (signing is per-checkpoint, not per-record). To verify the chain offline, write the signer's public key to a PEM file and run `audit verify`:

```python
with open("audit_pub.pem", "wb") as f:
    f.write(signer.public_key_pem())
```

```bash
raucle audit verify receipts.log --pubkey audit_pub.pem
```

Exit 0 = the hash chain is intact and every checkpoint signature is valid.

---

## Step 8 — optionally ship receipts to Raucle Cloud

If you want a system-of-record — searchable list, audit-pack export, share-link to a regulator — keep writing to the local `HashChainSink` and upload the chain to [Raucle Cloud](https://cloud.raucle.com) out of band (e.g. a nightly job, or by tailing the log to the ingest endpoint). The hash chain and checkpoint signatures travel with the file, so the cloud just stores and indexes what you already produced.

The gate always runs locally; there is no hot-path network call. **Self-hosters can skip this entirely** — the gate and the signed audit chain work with no cloud at all.

---

## What you've built

A Microsoft Agent Framework agent where **every tool call is gated by a capability token and produces a signed receipt**. Prompt-injection attacks against the tool-call surface — instructing the LLM to call a sensitive tool with attacker-supplied arguments — are now structurally blocked, not heuristically discouraged.

The receipt is what an auditor sees. It cites the issuer, the policy proof hash, the Lean theorem identifier, the agent ID, the tool, the args hash, the decision, and a timestamp. They verify it offline with `python3 + cryptography`. No vendor trust required.

---

## Where next

- **[3. Prove a policy](06-prove-a-policy.md)** — produce a `policy_proof_hash` that demonstrates *no* string in the tool's schema can violate the constraints. Every receipt citing this proof inherits the guarantee.

If you want to share a session's receipts with a regulator — time-limited URL, no auditor login, verifier bundle download — that's [Raucle Cloud's](https://cloud.raucle.com) `Share` feature.
