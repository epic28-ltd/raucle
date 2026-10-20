# Sovereign AI Demonstrator Deployment

This deployment runs the raucle gateway with live simulated agent traffic for
evaluator viewing: the [Sovereign AI R&D Procurement
Scheme](https://www.gov.uk/government/organisations/sovereign-ai) requires
demonstrator-stage technologies "ready to be tested in real-world operational
environments". This compose file provides that environment.

## What runs

| Service | Purpose | Port |
|---|---|---|
| `raucle-gateway` | The gate, receipts, policy engine | internal 8080 |
| `raucle-gateway` (admin) | Admin panel: dashboard, connection log, policy editor, receipts, SIEM, topology | 8091 via caddy |
| `demo-agents` | Simulated agents feeding a realistic allow/deny mix through the gateway continuously | - |
| `caddy` | TLS termination, security headers, rate limiting | 443 |

## The demo traffic

`scripts/demo_agents.py` simulates five banking agents (customer service,
payments, card management, loan officer, compliance) plus occasional
injection-style attacks. The profile is roughly:

- **~69% ALLOW** — policy-conformant calls (allowed accounts, in-bounds
  amounts, required fields present)
- **~31% DENY** — specific, visible gate reasons: allowlist violations,
  over-limit amounts, missing required fields, blacklisted destinations,
  unknown tools, agent/source mismatches

Every decision produces a receipt and a connection-log entry, so the admin
panel dashboard, live connection flow, topology view, and receipt viewer all
show continuously-updating activity.

## Read-only evaluator account

Evaluators get the `auditor` role: **stats, connections, and receipts only**.
Policies, users, configuration, and SIEM settings are 403. The account cannot
modify anything and cannot enumerate other accounts.

Create it (as admin):

```bash
curl -X POST http://localhost:8081/api/users \
  -H "Authorization: Bearer $RAUCLE_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "<evaluator-key>", "role": "auditor", "name": "Sovereign AI Evaluator"}'
```

The evaluator then logs into the admin panel with their own API key and sees
the live dashboard, connection log, and receipt browser. TOTP MFA can be
enabled on the account the same way as any user
(POST `/api/users/<key>/mfa/setup`).

## Deploy

```bash
RAUCLE_ADMIN_KEY=<admin-key> RAUCLE_DOMAIN=<domain> docker compose -f docker-compose.gateway.yml up -d --build
```

The gateway loads all six example policy sets (banking, fintech, healthcare,
insurance, ecommerce, data-ops — 80 rules) from `policies/examples/`, mounted
read-only at `/etc/raucle/policies-demo`.

## What an evaluator should look at

1. **Dashboard** (`/`) — live allow/deny/escalate counters, latency, top tools
2. **Live topology** (Connections tab) — source nodes left, gate/tools centre, destinations right, animated traffic particles; click a node to isolate its paths; the deny filter marks blocked nodes with glowing red loops
3. **Connection log** — each row is a gated call: source agent → policy applied
   → decision with reason; filterable by tool, decision, source
4. **Receipts** — the cryptographic evidence for any decision, offline-verifiable
5. **Policy editor** (admin only) — the YAML DSL as a risk officer writes it
6. **Learn mode** (admin only) — with `RAUCLE_LEARN_MODE=true`, the gate records every call it denied for having no matching policy and drafts candidate rules from the observed traffic. Fail-closed by design: learning never authorises; the operator reviews the draft, copies it into the policy editor, and deploys.

## Learn mode (onboarding a new agent)

To onboard an agent you do not yet have a policy for:

1. Set `RAUCLE_LEARN_MODE=true` and restart the gateway
2. Point the new agent at `/gate` — every call fails closed with "no policy configured", and the gate records what the agent tried to do
3. Open the **Learn** tab: observed tools, call counts, and agents
4. Click **Copy into Policy Editor** — the drafted rules appear as YAML: allow lists for low-cardinality string fields, min/max bounds (10% headroom) for numerics, required fields seen in every call
5. Review, tighten, **Save & Deploy**, then **Reload** — the agent now runs under a reviewed policy

## Authority attribution walkthrough (PR-E, October 2026)

This walkthrough shows the October 2026 authority-attribution set end to end:
human-approval receipts, the policy change ledger, the authority envelope and
the kill switch. It answers the first sentence of LASR/sovereign opportunity
Area 1: establish which agent or process initiated an action, the authority
under which it operated, and what it was permitted to use.

Conventions: the gate runs on port `8080` (internal), the admin API on
`8081` (the same paths the admin panel uses through caddy on `8091`).
`<agent-key>` is a per-agent credential issued via the agent credentials
file; `<admin-key>` is the admin API key. Every snippet below matches a
passing test in `tests/test_authority_attribution.py` and
`tests/test_ncsc_agent_controls.py`: run those suites to see identical
assertions.

### Stage 1: high-impact action escalates, and the request is receipted

```bash
curl -s -X POST http://localhost:8080/gate \
  -H "X-Api-Key: <agent-key>" -H "Content-Type: application/json" \
  -d '{"tool": "transfer_money", "args": {"from_account": "ACC-001", "amount": 500}, "agent_id": "agent:pay"}'
# {"decision": "escalate", "approval_request_id": "<id>", "receipt_id": "sha256:...", ...}
```

The approval request itself is in the receipt chain: `guardrail_verdict` is
`approval_requested` and the payload carries `x_approval` with the exact
request id, tool and agent identity.

### Stage 2: the human decides, and the decision is receipted

```bash
curl -s -X POST http://localhost:8081/api/approvals/<id>/decision \
  -H "Authorization: <admin-key>" -H "Content-Type: application/json" \
  -d '{"approved": true}'
# {"status": "approved"}
```

The decision lands in the chain as `approval_granted`, naming the approver.

### Stage 3: the bound call is the only one allowed

```bash
# the SAME call, re-submitted with the approval reference:
curl -s -X POST http://localhost:8080/gate \
  -H "X-Api-Key: <agent-key>" -H "X-Approval-Id: <id>" -H "Content-Type: application/json" \
  -d '{"tool": "transfer_money", "args": {"from_account": "ACC-001", "amount": 500}, "agent_id": "agent:pay"}'
# {"decision": "allow", "reason": "approved ..."}
```

The action receipt cites the approval in `x_gate.approval_id`. The approval
bound the EXACT arguments: resubmitting with a different amount does not ride
it (single use, exact-args binding).

### Stage 4: the kill switch, and the stop is evidence

```bash
curl -s -X POST http://localhost:8081/api/agents/agent:svc/suspend \
  -H "Authorization: <admin-key>" -H "Content-Type: application/json" \
  -d '{"reason": "incident test"}'
# {"suspended": true, "revoked": ["apikey"], "receipt_id": "sha256:..."}
```

Role separation is enforced (an operator role gets a 403 on this route), the
credential is dead immediately (subsequent calls deny as `invalid or
revoked`), and the stop itself is a receipt in the chain carrying
`x_stop` with the agent, the reason and the acting administrator.

### Stage 5: authority snapshots and receipted policy governance

```bash
# what the agent was permitted to use, signed:
curl -s http://localhost:8081/api/agents/agent:pay/authority -H "Authorization: <admin-key>"
# envelope JWS, typ: raucle/authority-envelope/v1, policies + credential state

# who changed the rules, hash-chained:
curl -s -X PUT http://localhost:8081/api/policies \
  -H "Authorization: <admin-key>" -H "Content-Type: application/json" \
  -d '{"content": "<yaml>"}'
curl -s http://localhost:8081/api/policy-ledger -H "Authorization: <admin-key>"
# entries: actor, action, sha256, prev_hash; plus integrity verdict
```

Tampering with a ledger entry is detected: the `integrity` verdict flips to
invalid, which is what makes an incident review provable rather than
suspected.

### Verify the whole matrix without reading this document

```bash
python -m pytest tests/test_ncsc_agent_controls.py -v
# 9 passed: the eight controls, receipted
```

These features ship on the main branch; the demo deployment picks them up on
the next production deploy (see the deploy checklist at the top of this
repository's operations runbook).