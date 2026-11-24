# Raucle plugin for OpenClaw

OpenClaw is an open-source personal AI agent framework by Peter Steinberger: a Claude-like assistant with claws. This plugin points OpenClaw's typed hooks at a local raucle scanner. It scans inbound prompts, outbound messages, and tool call arguments, and it blocks MALICIOUS content. The plugin issues no capability receipts; it calls the scanning API in [`raucle/server.py`](../../raucle/server.py) and keeps a bounded, plugin-local decision log of its own hook outcomes. The gate-based receipts live in the main raucle package.

## Quick install

```bash
# 1. Install the scanning engine
pip install "raucle[server,rules]"

# 2. Copy the plugin
cp -r plugins/openclaw/ ~/.openclaw/extensions/raucle/

# 3. Enable it (one command)
openclaw config set plugins.allow+=raucle \
  plugins.load.paths+=~/.openclaw/extensions/raucle \
  plugins.entries.raucle.enabled=true \
  plugins.entries.raucle.config.mode=standard \
  plugins.entries.raucle.config.blockOnMalicious=true

# 4. Restart
openclaw gateway restart
```

Or add it to `openclaw.json` directly:

```json
{
  "plugins": {
    "allow": ["raucle"],
    "load": { "paths": ["~/.openclaw/extensions/raucle"] },
    "entries": {
      "raucle": {
        "enabled": true,
        "config": {
          "mode": "standard",
          "blockOnMalicious": true
        }
      }
    }
  }
}
```

With that done, every agent behind the gateway is scanned. No per-agent configuration is needed.

## Minimum host version and typed registration

The plugin registers every hook through OpenClaw's TYPED hook API (`api.on(...)`). The internal `api.registerHook(...)` system never invokes underscore hook names such as `before_tool_call` - a registration made there is a silent no-op on the typed runner - so the plugin refuses activation on hosts that lack the typed surface instead of degrading silently. The typed API exists since OpenClaw v2026.4.22; `package.json` pins `openclaw.install.minHostVersion: ">=2026.4.22"`. The tool gate registers with NO matcher restriction, so every registered tool is covered; restrict matchers are a coverage hole and are never used.

## Failure modes: `failureMode` (default `closed`)

Scanner unavailability is not silently equivalent to a clean verdict. The posture is configurable:

| failureMode | Scanner error behaviour | Trade-off |
|---|---|---|
| `closed` (default) | The protected operation is BLOCKED with the hook's native shape (tool call: explicit block decision; outbound: cancel; inbound: block instruction injection) | Protection survives detection-layer outages; a dead scanner stops gated traffic until it recovers |
| `open` | The operation continues, with the same named advisory logged | Availability first; unscreened traffic passes while the scanner is down |

Every scanner failure emits a NAMED advisory carrying the reason class (`timeout`, `connection-refused`, `malformed-response`, `http-500`, `process-dead`, `auth-refused`) and the active failureMode, so an operator can always tell detection unavailability from a clean verdict.

**Host default warning:** OpenClaw's hook runner defaults to FAIL-OPEN for `before_tool_call` (only `before_agent_run` and `before_channel_ingress` default fail-closed on the shared runner), so a thrown handler error or timeout does NOT reliably block the tool call. This plugin therefore never relies on exception-based blocking: every failure path in closed mode returns an EXPLICIT block decision object, and operators who need fail-closed MUST set the plugin's `failureMode` to `closed` - the host default will not save them.

## Local scanner trust

The plugin never talks to an unauthenticated local scanner:

- The `ServerManager` holds a per-boot scan secret (`crypto.randomUUID`), or the operator-configured `config.scanSecret` for a standalone service started with `RAUCLE_PLUGIN_SCAN_SECRET=<the same value>`.
- Every scan request and the identity probe carry the secret in the `X-Raucle-Scan-Token` header. The spawned scanner receives the secret via the `RAUCLE_PLUGIN_SCAN_SECRET` environment variable (Python side: 401 without the header, 403 on a wrong value, constant-time compare).
- An already-answering service on the port is adopted ONLY when it passes the secret-protected `GET /identity` probe AND returns the schema-strict raucle identity body (`kind: "raucle"`, `status: "ok"`, version, mode, `rules_loaded`). Any other body shape or a failed secret check is refused: the manager spawns its own scanner instead. Loopback binding (`127.0.0.1`) is unchanged.
- Wrong-secret scanner failures classify as `auth-refused` and block under `failureMode: closed` like any other detection unavailability.

The scanner side of the design lives in [`raucle/server.py`](../../raucle/server.py) (`RAUCLE_PLUGIN_SCAN_SECRET`, the `/identity` endpoint, and the header enforcement on `/scan*`).

## Bounded hook work and receipts

- Each scan carries a deadline (`scanTimeoutMs`, default 10000 ms, clamped to at most 12000 ms) that fires BEFORE the host's 15 second `before_tool_call` budget, so the plugin's explicit decision still reaches the host instead of being cut off by the host's timeout. The deadline aborts the pending scan and, when the host has cancelled the owning tool call (`ctx.abortSignal`), the plugin stops its own work.
- A scan arriving after the deadline (or after the host timed the hook out) is DISCARDED: it never writes a receipt implying the call proceeded. The plugin's decision log entries bind to the ACTUAL final outcome: `receipt.issued` is true only when the call's final state was actually known here, with `receipt.bound` of `allowed`/`denied`; sealed-timeout and discarded entries bind nothing.
- Scanner verdict and ruleset identity are recorded as SEPARATE fields from any authorisation evidence (`scanner.verdict` vs `outcome`/`coverageState`/`receipt`): a CLEAN verdict never appears as an authorisation decision and vice versa. Authorisation fields use the host's own vocabulary (`allowed`/`denied`/`unknown` x `enforced`/`unknown`, `plugin_hook_*` reason codes), and any unknown coverage state renders as UNAUTHORISED in plugin evidence - never as an allow-equivalent.

The plugin's decision log is bounded (ring buffer, 256 entries) and plugin-local. It is not a signed receipt chain: capability receipts stay in the raucle gate.

## What it does

Hooks in [`index.ts`](index.ts) (all registered through the typed API):

| Hook | Action |
|---|---|
| `before_prompt_build` | Scans every inbound message; injects a security warning for SUSPICIOUS, hard blocks MALICIOUS |
| `message_sending` | Scans outbound agent responses for data leakage; closed mode cancels on scanner failure |
| `before_tool_call` | Validates tool arguments before execution (shell injection, path traversal, SQLi, SSRF); closed mode blocks on scanner failure |
| `llm_output` | Monitors large LLM outputs for anomalies |

`src/server-manager.ts` starts or finds the local raucle HTTP server that the hooks call, under the trust rules above.

## Per-agent sensitivity

Override detection sensitivity for specific agents:

```json
"agentOverrides": {
  "ciso": { "mode": "strict" },
  "main": { "mode": "standard" },
  "sandbox": { "mode": "strict", "scanToolCalls": true }
}
```

Modes: `strict` (fewest false negatives), `standard` (balanced), `permissive` (fewest false positives). You can also toggle `scanInbound`, `scanOutbound`, and `scanToolCalls` globally or per agent. `failureMode`, `scanTimeoutMs` and `scanSecret` are global (they shape the plugin's posture, not per-agent sensitivity).

## Post-startup verification

A configured plugin is not proof of active enforcement. After every start/reload, check that the plugin is actually running and armed:

```bash
openclaw plugins inspect raucle --runtime --json
```

Expect `before_tool_call` (and the other hooks) to appear under `typedHooks`, enabled, with `matcher: null` (all tools). In the gateway log, a healthy start emits:

```
[raucle] STARTUP: hooks=4(before_prompt_build,...) scanner=reachable secret=sha256:<16 hex chars> failureMode=closed
```

Under `failureMode: closed`, a scanner that never becomes ready REFUSES activation (fail-loud, named `ACTIVATION REFUSED` in the log): tool calls then stay blocked with the explicit refusal reason instead of passing unscreened. Under `failureMode: open` the same failure logs a warning and traffic passes unscreened - availability over protection.

The same summary includes the boot-secret fingerprint (`sha256:` prefix of the first 16 digest chars): match it against the spawned scanner's environment (`RAUCLE_PLUGIN_SCAN_SECRET`) to verify both sides run the same secret.

## Tamper protection

Agents cannot disable raucle by editing their own configuration. The design:

- The plugin runs at the gateway level, so agents cannot reach the plugin process.
- Hooks fire before the agent sees the prompt: the scan completes before the LLM is called.
- Configuration lives in `openclaw.json`, owned by the gateway process.
- The raucle server runs as a separate process on a fixed port, and the plugin will only talk to a service that proves it holds the per-boot scan secret, so agents cannot stop, spoof or modify it.

To stop agents using their tools to edit `openclaw.json`, add the config file to your sandbox deny list or set `exec.security` appropriately. The plugin itself has no mechanism for an in-conversation agent to disable it.
