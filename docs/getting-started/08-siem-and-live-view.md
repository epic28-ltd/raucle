# 8. SIEM export & live monitoring

Every gate decision and scan verdict raucle makes can flow three ways at once,
off the **same** event stream:

1. the **signed, hash-chained receipt log** — the tamper-evident evidence (always on when a sink is configured);
2. a **SIEM-normalised JSON-lines file** (and/or syslog) your SOC ingests natively;
3. a **live view** — a terminal tail or a browser dashboard — for watching decisions as they happen.

The signed chain is authoritative; the SIEM stream and the live view are
operational copies built from it, so turning them on never weakens the evidence.

## SIEM export

[`SIEMSink`](../../raucle/siem.py) is a drop-in `audit_sink`: it maps each
event to an [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)-style
document (which Splunk, Microsoft Sentinel, Elastic, and QRadar parse without a
custom connector) and **tees** into the signed `HashChainSink`:

```python
from raucle.audit import Ed25519Signer, HashChainSink
from raucle.siem import SIEMSink
from raucle.scanner import Scanner

sink = SIEMSink(
    "raucle-siem.jsonl",  # SOC tails this (one ECS doc per line)
    inner=HashChainSink(
        "receipts.jsonl",  # signed evidence chain
        signer=Ed25519Signer.generate(),
    ),
    syslog_address=("siem.example", 514),  # optional RFC 5424 / UDP mirror
)
scanner = Scanner(
    audit_sink=sink
)  # also works as the sink for the capability gate / LangChain handler
```

Field mapping (the original event is preserved verbatim under `raucle.*`):

| raucle event | `event.category` | `event.action` | `event.outcome` | key fields |
|---|---|---|---|---|
| Gate decision | `iam` | `capability-gate-decision` | `success` (ALLOW) / `failure` (DENY) | `user.id`=agent, `rule.name`=tool, `event.reason` |
| Scan verdict | `intrusion_detection` | `scan` / `scan_output` / … | `success` (CLEAN) / `failure` | `event.severity` 1/5/9, `rule.name`=matched rules |

Point a Splunk universal forwarder, Sentinel AMA, or Filebeat at the file and
every decision streams in as structured JSON. The SIEM file is an operational
copy — for disputes, verify the signed `receipts.jsonl` with
`raucle audit verify`, which is what an auditor can check offline.

## Live terminal view

Tail any audit-chain or SIEM file with colourised, SOC-friendly output:

```bash
raucle watch receipts.jsonl              # live, follows new events
raucle watch raucle-siem.jsonl --denies-only   # only DENY / non-CLEAN
raucle watch receipts.jsonl --no-follow  # print existing events and exit
```

```
2026-06-10T10:00:01  ALLOW  gate  agent:demo.invoice-bot       transfer_funds
2026-06-10T10:00:02  DENY   gate  agent:demo.invoice-bot       transfer_funds  (constraint violated: to …)
2026-06-10T10:00:03  MALICIOUS   scan  scan  [PI-001,PI-004]
```

## Live web dashboard

The REST server exposes a self-contained live dashboard (no build step, no
external assets) fed by Server-Sent Events:

```bash
export RAUCLE_DETECT_AUDIT_PATH=./receipts.jsonl    # enables the live view
raucle serve
# open http://localhost:8000/dashboard
```

- `GET /dashboard` — live table of decisions (newest first) + running allow/deny/scan counters
- `GET /events` — raw SSE stream (replays the last 50 events, then live) for piping into your own UI

When an API key is configured (`RAUCLE_DETECT_API_KEY`), the dashboard and
stream also accept `?access_token=<key>` (constant-time checked) because the
browser `EventSource` API cannot send an `Authorization` header. `/health`
stays open; everything else still requires the bearer token.

---

Next: [Securing OpenClaw / NemoClaw deployments](09-openclaw-nemoclaw.md) — the
reference pattern for the most-deployed open-source agent of 2026.
