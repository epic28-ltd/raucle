# 9. Securing OpenClaw / NemoClaw deployments

OpenClaw is the most-deployed open-source agent of 2026 — and the one with the
most-publicised security incidents. NVIDIA's **NemoClaw** wraps it in an
OS-level sandbox (**OpenShell**: network/filesystem isolation + an interactive
approve/deny TUI for external access) and local inference. That stops a
sandboxed process from reaching the network it shouldn't — but, by NVIDIA's own
docs, it does **not** produce a verifiable audit trail, does **not** gate
individual tool calls by their arguments, and explicitly notes that *"no sandbox
offers complete protection against advanced prompt injection."*

That is exactly the layer raucle adds. They stack — they don't compete.

```
┌─────────────────────────────────────────────────────────────┐
│ OpenClaw agent                                                │
│   │ tool call: transfer_funds(to=…, amount=…)                │
│   ▼                                                            │
│ ── raucle capability gate ──  ALLOW / DENY (signed receipt)   │  ← argument-level,
│   │  decision recorded; injection cannot widen the token      │     structurally
│   ▼                                                            │     injection-proof
│ OpenShell sandbox (NemoClaw) ──  egress approve / deny        │  ← OS / network
│   │  host:port allowed?                                        │     boundary
│   ▼                                                            │
│ external service                                              │
└─────────────────────────────────────────────────────────────┘
       raucle receipts ──► SIEM (Splunk / Sentinel / Elastic) + live dashboard
```

| Concern | OpenShell / NemoClaw | raucle |
|---|---|---|
| Enforcement boundary | OS sandbox + network egress (host/port) | The **tool call**, by argument — any tool, not just network |
| Prompt-injection posture | Sandbox; "not complete protection" (their words) | **Structural** on the tool-call surface — the gate never reads the model's reasoning |
| Audit trail | Approve/deny in a TUI; no signed record | **Ed25519-signed, hash-chained, offline-verifiable receipts** |
| SOC / SIEM feed | — | ECS JSON-lines + syslog ([SIEM export](../../raucle/siem.py)) + live dashboard |
| Runs fully local / no telemetry | yes (the whole point of NemoClaw) | **yes** — zero-dependency core, on-device, nothing leaves the host |

The local-first match matters: NemoClaw exists so *no data leaves the device*.
raucle's core has no runtime dependencies and no telemetry — the gate, the
receipts, and the dashboard all run on the same host. Adding raucle does not
re-introduce a cloud dependency.

## Wiring it in

raucle ships an OpenClaw plugin (gateway-level, fires before the LLM, agents
cannot disable it from a conversation — see the [OpenClaw Plugin section of the
README](../../README.md)). Point its audit sink at a [`SIEMSink`](../../raucle/siem.py)
to get the signed evidence chain *and* the SOC feed from one configuration:

```python
from raucle.audit import Ed25519Signer, HashChainSink
from raucle.siem import SIEMSink

# Signed evidence chain (authoritative) + SIEM operational stream, one sink.
sink = SIEMSink(
    "/var/log/raucle/agent-siem.jsonl",  # Splunk/Sentinel/Elastic tail this
    inner=HashChainSink(
        "/var/log/raucle/receipts.jsonl",  # tamper-evident, offline-verifiable
        signer=Ed25519Signer.generate(),
    ),
    syslog_address=("siem.internal", 514),  # optional: also stream to a collector
)
```

See [SIEM export & live monitoring](08-siem-and-live-view.md) for the SIEM
field mapping, the `raucle watch` terminal view, and the `/dashboard`
web view.

## What raucle does *not* do here

Be precise about the boundary, the same way NemoClaw is about theirs:

- raucle does **not** sandbox the process or filter network egress — that is
  OpenShell's job. Run both.
- raucle gates the **modelled** tool-call surface structurally; free-form model
  *output* (not mediated by a tool call) is out of scope — see the
  [OWASP mapping](../standards/owasp-agentic-top10-mapping.md).

## Honest status note

NemoClaw is NVIDIA's, and is **alpha / early preview** (announced GTC, March
2026); its policy/extension formats may still change. raucle integrates today at
the OpenClaw plugin + audit-sink layer described above. A deeper
policy-decision-point bridge into OpenShell's approval flow is tracked as a
[proposal](../proposals/), not yet a shipped integration — we will not pin to an
alpha interface until it stabilises.
