"""Microsoft Agent Framework × raucle — wiring reference.

This file shows the *integration shape*. It is intentionally not a one-shot
runnable script: a live Agent Framework deployment also needs a chat
client (OpenAI, Azure, Anthropic, or a local Ollama) and the deployer's
own tool implementations. What follows is the four-line wire-up plus the
session-token binding pattern, with type-checked references to the real
``raucle.integrations.agent_framework`` API.

For the *verified behaviour* of the middleware (ALLOW path, DENY path,
no-token path, receipt content), see the unit test suite:

    tests/integrations/test_agent_framework.py

Those tests run without any host LLM and exercise the full
``RaucleFunctionMiddleware.process`` contract against a mocked Agent
Framework invocation context.

Run sequence (when adapted into a real deployment)
--------------------------------------------------

    pip install 'raucle[agent-framework]'
    python examples/agent_framework_demo/demo.py
"""

from __future__ import annotations

from pathlib import Path

from agent_framework import ChatAgent  # type: ignore[import-not-found]
from agent_framework.openai import OpenAIChatClient  # type: ignore[import-not-found]

from raucle.audit import Ed25519Signer, HashChainSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.integrations.agent_framework import (
    RaucleFunctionMiddleware,
    set_in_force_token,
)

from .tools import lookup_customer, transfer_funds

RECEIPT_LOG = Path("./receipts.log")


# ---------------------------------------------------------------------------
# Step 1 — once per process — wire up the issuer, gate, and audit sink.
# In production: the issuer key lives in an HSM, the audit sink writes to
# durable storage, and the public key is published on the deployer's
# .well-known/ for any third-party verifier to fetch.

issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc-platform")
gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
sink = HashChainSink(RECEIPT_LOG, signer=Ed25519Signer.generate())


# ---------------------------------------------------------------------------
# Step 2 — build the agent and attach raucle as a FunctionMiddleware.
# This is the only change to a deployer's existing Agent Framework code:
# one constructor call + one middleware registration.

agent = ChatAgent(
    chat_client=OpenAIChatClient(model="gpt-4o"),
    instructions="You are a KYC customer-service agent for Acme Bank.",
    tools=[lookup_customer, transfer_funds],
)
agent.middleware.add(
    RaucleFunctionMiddleware(
        gate=gate,
        sink=sink,
        lean_theorem_id="vcd.gate_soundness",
    )
)


# ---------------------------------------------------------------------------
# Step 3 — at the start of each user session, derive a capability token
# from the user's actual request and bind it to the asyncio context.
# The token authorises only the lookup_customer tool; transfer_funds is
# *not* in the token's tool set, so any attempt to call it during this
# session will be denied by the gate.

token = issuer.mint(
    agent_id="agent:kyc-prod-eu-west-1",
    tool="lookup_customer",
    constraints={"customer_id": {"allowed_pattern": r"^C-\d{4}$"}},
    ttl_seconds=60,
)
set_in_force_token(token)


# ---------------------------------------------------------------------------
# Step 4 — run the agent normally. Every tool call passes through the
# raucle middleware; each ALLOW/DENY produces a signed receipt in
# RECEIPT_LOG. The audit chain is verifiable offline by any third party
# holding the issuer's published public key.


async def converse() -> None:
    response = await agent.run("Look up customer C-1042 and refund their last transfer.")
    print(response)


if __name__ == "__main__":
    import asyncio

    asyncio.run(converse())
