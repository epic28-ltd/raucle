# Getting started with raucle

Add raucle to your agent in **under ten minutes**.

raucle gates every tool call your agent makes, produces a cryptographically-signed receipt of every decision (ALLOW or DENY), and is **structurally** safe against prompt-injection of the tool-call path — not heuristically.

This guide is task-first. Pick a path. Run the code. You'll have a working signed receipt at the end of every track.

---

## Choose your path

| If you have… | Start here | Time |
|---|---|---|
| Just curiosity / Python + nothing else | **[1. Hello, receipt](01-hello-receipt.md)** — mint a token, run the gate, verify a signed audit chain. No agent framework needed. | 5 min |
| Microsoft Agent Framework (GA April 2026) | **[2. Agent Framework](02-agent-framework.md)** — drop-in `FunctionMiddleware`. One line. | 10 min |
| Claude Desktop / Claude Code / Cursor / Cline | **[3. MCP clients](03-mcp-clients.md)** — add raucle's detection tools to your assistant with one config block. | 2 min |
| CrewAI crew | **[5. CrewAI](05-crewai.md)** — `guard_tools(...)` wraps every tool; gated + receipted, no interface change. | 5 min |
| You want to prove a policy is sound, not just configured | **[4. Prove a policy](06-prove-a-policy.md)** — SMT-backed `ProofResult`, content-addressed, citeable. | 10 min |
| You run a SOC / need a SIEM feed + live view | **[8. SIEM export & live monitoring](08-siem-and-live-view.md)** — ECS JSON to Splunk/Sentinel, `raucle watch`, and a live `/dashboard`. | 5 min |
| You deploy OpenClaw / NemoClaw | **[9. Securing OpenClaw / NemoClaw](09-openclaw-nemoclaw.md)** — the reference pattern: raucle gates tool calls + emits verifiable evidence under NemoClaw's sandbox. | 5 min |
| You verify agents across org boundaries | **[10. Trust Registry](10-trust-registry.md)** — publish your issuer key once; any org resolves and verifies it. The cross-org trust layer. | 5 min |
| Agents from different companies need to trust each other | **[11. Cross-org handshake](11-cross-org-handshake.md)** — verifiable capability-gated calls across orgs, trust resolved from the shared registry. No prior key exchange. | 5 min |
| You face an auditor / regulated procurement | **[12. Compliance evidence packs](12-compliance-evidence.md)** — one command maps your signed receipt chain to EU AI Act / ISO 42001 / SOC 2 controls. | 5 min |
| You want one agent identity that works everywhere | **[13. Agent passport](13-agent-passport.md)** — an issuer-vouched, registry-anchored identity, portable across every framework. | 5 min |
- [14. Verify a bundle offline](14-verify-a-bundle-offline.md) - third-party verification: download, verify, tamper, watch it fail.

---

## Install

```bash
# Gate, capability tokens, signed audit chain, receipts (needs cryptography):
pip install 'raucle[compliance]'

# Plus SMT prover (Z3, for prove-a-policy and counterexample extraction):
pip install 'raucle[proof]'

# Plus Microsoft Agent Framework adapter:
pip install 'raucle[agent-framework]'

# Engine extras bundle (rules + ml + server + compliance + multimodal + proof):
pip install 'raucle[all]'
```

Python 3.10+. macOS / Linux / Windows.

---

## What raucle replaces

If you've spent any time on AI agent security in 2026 you've seen the same three patterns:

- **Heuristic prompt-injection classifiers** (Lakera Guard, Microsoft Prompt Shields, AWS Bedrock policy controls). Detect-and-block. Best-case 86% recall on text. Cannot establish a bound. Their published log says *"we think it's fine"*; a regulator wants *evidence*.
- **Constitutional rules in the system prompt.** Asks the model politely. Surrenders to anything the attacker can negotiate around. Provides nothing to an auditor.
- **Permission systems retrofitted onto LLM output.** Authorise based on the model's claim about what it's about to do, after the model has been compromised.

raucle replaces **the safe part of the agent loop** — the actual tool dispatch — with a verified gate. The LLM's role shrinks to *suggesting* a tool call. The gate decides whether it runs, citing a token, a policy proof, and a Lean theorem. The receipt of that decision is what an auditor sees.

This is structural. The attack surface for tool misuse becomes 0 of 2,737 catalogued scenarios across AgentDojo and InjecAgent, with a formal upper bound proving why. The mechanism is independent of the LLM, the prompt, the attacker's vocabulary.

---

## How this guide is organised

Every tutorial ends with the same artefact: **a signed receipt printed to your terminal**, plus the exact shell command to verify its signature offline. If your receipt verifies, raucle is doing what it says.

The receipts you produce here use **your own Ed25519 keypair**, generated locally. raucle's open-source engine never phones home — there's no telemetry, no licence check, no network call on the hot path.

Optional: when you want a system-of-record for receipts (search, share with auditors, audit-pack export), [Raucle Cloud](https://cloud.raucle.com) hosts that. The runtime gate stays local.

---

## Common questions while you're here

**Does raucle replace my existing prompt-injection defence?**
No, it stacks. The heuristic shields stop *speech*; raucle stops *action*. Run shields if you've got them — they're complementary. The strongest configuration is shields + raucle.

**Does it slow my agent?**
Sub-100 µs per gate decision (p50) on commodity hardware. Indistinguishable in end-to-end agent wall time; on three of eight measured open-weight models, raucle-enabled agents finish *faster* than the no-defence baseline because the gate terminates attacker-induced reasoning loops early.

**Open-source licence?**
Apache-2.0 — permissive, with an explicit patent grant. You may use, modify, embed, and redistribute it (including in closed-source products and hosted services) under the licence's terms. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).

**Does it work without Z3 / cryptography / etc.?**
The gate and capability layer need only the standard library + the `cryptography` package. The SMT prover needs Z3 (via the `[proof]` extra). Receipt verification anywhere downstream needs only `python3 + cryptography`.

---

Ready? Start with **[1. Hello, receipt](01-hello-receipt.md)**.
