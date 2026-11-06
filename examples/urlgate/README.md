# urlgate — config-only adoption demo (EPIC O3)

`raucle urlgate` is a transparent, loopback-only gate proxy: stock
OpenAI/Anthropic SDK clients adopt Raucle receipts with **zero code
changes** — you only point their `base_url` at the proxy.

## 1. Start the gate

```bash
raucle urlgate \
  --listen 127.0.0.1:8095 \
  --upstream https://api.openai.com \
  --policy urlgate-policies.yaml \
  --receipts-dir urlgate-receipts
```

* `--policy` is a service-scoped gate policy YAML. If the file is absent
  it is created with a conservative allow policy — edit it to taste.
* Gated traffic is chat/completions and messages POSTs; everything else
  (e.g. `GET /v1/models`) passes through untouched.

## 2. Point any stock SDK client at it

OpenAI Python SDK:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8095/v1",
    api_key="sk-...",  # your real key; forwarded unchanged
)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hello"}],
)
# Every gated call now has a signed receipt in urlgate-receipts/
```

OpenAI JS SDK: `new OpenAI({ baseURL: "http://127.0.0.1:8095/v1", apiKey: "sk-..." })`.

Anthropic SDK: `base_url="http://127.0.0.1:8095"` (`/v1` is appended by the SDK).

curl: `curl http://127.0.0.1:8095/v1/chat/completions -H "Authorization: Bearer sk-..." ...`

## 3. What you get

* One signed provenance receipt per gated call (allow **and** deny),
  written to `urlgate-receipts/` (or `--receipts` JSONL).
* DENY returns an upstream-shaped error body (`{"error": {...}}` /
  `{"type": "error", ...}`) with HTTP 403 and an `X-Raucle-Receipt`
  header — stock clients fail through their normal error contract.
* Streaming (SSE) is proxied byte-identically.

## Honest limits

* Bodies pass through unmodified: the proxy attests that policy was
  consulted and a receipt minted; it does not verify upstream response
  content.
* Loopback-only posture by default — bind to `127.0.0.1:8095` unless you
  know what you are doing.
