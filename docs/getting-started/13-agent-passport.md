# 13. Agent passport — portable identity across frameworks

An agent's capability statement says what the agent claims about itself. An
**agent passport** adds the vouch: the **issuing organisation countersigns it**,
and that issuer is resolvable in the shared [Trust Registry](10-trust-registry.md).
One portable signed file then tells any verifier, in any framework, the same
thing:

> "Org X (an issuer the registry knows) vouches that `agent:billing.bot` holds
> key K and may use tools/models Z, until time T."

```bash
pip install 'raucle[compliance]'
```

## Issue (the org, once per agent)

```bash
# The org's issuer key is published to the registry; it signs the passport.
raucle passport issue agent-statement.json \
  --issuer-key org.key.pem --issuer "Org X" --ttl 2592000 --out agent.passport.json
```

```python
from raucle.passport import issue_passport

passport = issue_passport(
    agent.statement, issuer_signer=org_signer, issuer="Org X", ttl_seconds=30 * 86400
)
passport.save("agent.passport.json")
```

## Verify (anyone, in any framework)

```bash
raucle passport verify agent.passport.json --registry https://trust.example.com/registry.jsonl
# VALID  agent:billing.bot  (issuer: Org X)
#   allowed tools: lookup_invoice, send_email
```

```python
from raucle.passport import verify_passport

v = verify_passport(passport.to_dict(), registry=shared_registry)
if v.valid:
    # trust v.agent_id <-> v.key_id, enforce v.allowed_tools / v.allowed_models
    ...
```

The same passport works wherever the agent runs — LangChain, CrewAI, Agent
Framework, MCP, A2A. Each integration verifies it once against the registry,
then enforces the agent's declared scope.

## Fail-closed by construction

`verify_passport` is invalid (never silently trusted) when:

- the **issuer is unknown or revoked** in the registry (resolves to no active key),
- the **issuer signature** does not verify,
- the passport has **expired**,
- the **version** or any **statement field** was tampered (the whole body is signed,
  so editing `allowed_tools` to add `transfer_funds` breaks verification).

Revoking the issuer's key in the registry invalidates every passport it signed,
everywhere, with no per-passport coordination.

---

Built on the [Trust Registry](10-trust-registry.md) (P1) and the existing
`AgentIdentity` / `CapabilityStatement`. This is the cross-framework identity
layer platforms adopt.
