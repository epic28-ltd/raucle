# Raucle plugin for OpenClaw

OpenClaw is an open-source personal AI agent framework by Peter Steinberger: a Claude-like assistant with claws. This plugin points OpenClaw's hooks at a local raucle scanner. It scans inbound prompts, outbound messages, and tool call arguments, and it blocks MALICIOUS content. The plugin issues no capability receipts; it calls the scanning API in [`raucle/server.py`](../../raucle/server.py). The gate-based receipts live in the main raucle package.

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

## What it does

Hooks in [`index.ts`](index.ts):

| Hook | Action |
|---|---|
| `before_prompt_build` | Scans every inbound message; injects a security warning for SUSPICIOUS, hard blocks MALICIOUS |
| `message_sending` | Scans outbound agent responses for data leakage |
| `before_tool_call` | Validates tool arguments before execution (shell injection, path traversal, SQLi, SSRF) |
| `llm_output` | Monitors large LLM outputs for anomalies |

Each hook registers a named scan (for example `raucle.inbound-scan`) around OpenClaw's event emitter. [`src/server-manager.ts`](src/server-manager.ts) starts or finds the local raucle HTTP server that the hooks call.

## Per-agent sensitivity

Override detection sensitivity for specific agents:

```json
"agentOverrides": {
  "ciso": { "mode": "strict" },
  "main": { "mode": "standard" },
  "sandbox": { "mode": "strict", "scanToolCalls": true }
}
```

Modes: `strict` (fewest false negatives), `standard` (balanced), `permissive` (fewest false positives). You can also toggle `scanInbound`, `scanOutbound`, and `scanToolCalls` globally or per agent.

## Tamper protection

Agents cannot disable raucle by editing their own configuration. The design:

- The plugin runs at the gateway level, so agents cannot reach the plugin process.
- Hooks fire before the agent sees the prompt: the scan completes before the LLM is called.
- Configuration lives in `openclaw.json`, owned by the gateway process.
- The raucle server runs as a separate process on a fixed port, so agents cannot stop or modify it.

To stop agents using their tools to edit `openclaw.json`, add the config file to your sandbox deny list or set `exec.security` appropriately. The plugin itself has no mechanism for an in-conversation agent to disable it.
