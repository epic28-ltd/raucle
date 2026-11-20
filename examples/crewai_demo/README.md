# CrewAI × raucle — prompt injection caught, receipt verified

A **fully runnable** demo (no API key, no network, ~2s) showing what raucle adds
to a CrewAI crew:

1. **A legitimate tool call passes the gate** — pay a $45 invoice to the
   expected payee; the in-force capability token allows exactly that.
2. **A prompt-injected tool call is blocked** — a poisoned task description tells
   the agent to wire $9,900 to an attacker; the gate denies it *before the tool
   body runs*.
3. **Both decisions are independently verifiable offline** — the signed,
   hash-chained receipt log replays for any third party; rewriting the `DENY`
   receipt to claim `ALLOW` breaks verification.

```bash
pip install 'raucle[compliance,crewai]'
python examples/crewai_demo/demo.py
```

## How it works

`guard_tools([...], gate=gate, sink=sink, agent_id="agent:demo.invoice-bot")`
wraps each CrewAI `BaseTool` in a tool with an **identical** `name` /
`description` / `args_schema`, so the agent sees no difference. On every call
the wrapper:

1. resolves the in-force capability token (`set_in_force_token(...)`),
2. asks the gate to ALLOW/DENY the call **with these arguments** (a call
   with no bound caller identity denies: bearer mode is closed, so the
   `agent_id` you pass at wrap time is what makes calls attributable),
3. emits a signed receipt,
4. delegates to the real tool on ALLOW, or raises `CapabilityDenied` on DENY.

CrewAI's `BaseTool.run` calls `_run` directly with no exception swallowing, so a
denied call genuinely blocks execution — no fail-open trap (unlike langchain's
callback layer, which needs `raise_error`; see
[`tests/test_langchain_integration.py`](../../tests/test_langchain_integration.py)).

The agent's decisions are scripted so the demo is deterministic and self-tests
in CI ([`tests/test_crewai_integration.py`](../../tests/test_crewai_integration.py)),
but every call goes through the real CrewAI tool machinery. That's the point:
**the gate never trusts the agent's reasoning** — a poisoned task and a
legitimate one take the same path, and only the signed constraints decide.
