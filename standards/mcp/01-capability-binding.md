# Control Pattern: Capability Binding for the Model Context Protocol (`mcp-cap:v1`)

**Status:** Draft profile, 2026-06-12. Additive, backward-compatible.
**Depends on:** [`cap:v1` capability tokens](../owasp-ai-exchange/01-capability-token.md),
[Provenance Receipt v1](../../docs/spec/provenance/v1.md).
**Reference implementation:** `raucle/mcp_auth.py` (Apache-2.0);
the credential-custody MCP server in `raucle/broker/` is a conforming server.

## What this profile addresses

The Model Context Protocol (MCP) defines how a client lists (`tools/list`) and
invokes (`tools/call`) tools exposed by an MCP server. It does **not** define an
authorization model: nothing in the protocol states *which principal* may call a
tool *with which arguments*, and a tool result carries no verifiable evidence of
the decision. In practice that leaves authorization to ad-hoc server logic and
leaves clients/auditors with no portable way to (a) know a tool is gated before
calling it, or (b) verify, after the fact, that a call was authorised.

`mcp-cap:v1` is a small, additive convention that closes both gaps **without a
protocol change**, by using MCP's reserved `_meta` field:

1. A server **advertises** that a tool is capability-gated, and under which
   trust anchor, in the tool's `tools/list` entry.
2. A server **attaches a signed-decision reference** to each `tools/call`
   result.

Non-aware clients ignore `_meta` and behave exactly as today; aware clients
enforce and verify.

> **Scope, honestly.** This profile governs the *authorization decision and its
> evidence at the MCP interface*. It is **not** credential custody. Gating
> `tools/call` controls what the model *asks* a server to do; it does not
> control what a server holding a long-lived downstream credential *can* do on
> its own (at startup, on a timer, via non-tool paths). Custody must live at the
> downstream credential / egress point — see
> [`raucle-mcp-gateway.md`](../../docs/proposals/raucle-mcp-gateway.md). A
> conforming server SHOULD also hold custody there; this profile specifies the
> interface binding only.

## Threat model addition over base cap:v1

Base `cap:v1` assumes the caller and the gate share a process. At the MCP
boundary the caller (client/model) and the gate (server) are separated by
JSON-RPC, so:

- A client cannot tell a gated tool from an ungated one → it cannot fail closed
  on a tool it *requires* to be gated, nor avoid presenting a token to a server
  that will not honour it. **Mitigation:** the `tools/list` annotation (§1).
- A tool result is just data → an auditor cannot bind it to an authorisation
  decision. **Mitigation:** the result receipt reference (§2), resolvable to a
  signed Provenance/audit receipt verifiable offline.

## 1. Gated-tool annotation (`tools/list`)

A server that gates a tool MUST add a `raucle` object under that tool's `_meta`:

```json
{
  "name": "transfer_funds",
  "description": "Transfer funds to an account.",
  "inputSchema": { "...": "..." },
  "_meta": {
    "raucle": {
      "version": "mcp-cap:v1",
      "gated": true,
      "issuer_key_id": "9f1c2a3b4d5e6f70",
      "required_constraints": ["allowed_values", "max_value"],
      "policy_proof_hash": "sha256:…"
    }
  }
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `version` | string | yes | `mcp-cap:v1`. |
| `gated` | boolean | yes | `true` if a valid `cap:v1` token is required to call this tool. |
| `issuer_key_id` | string | yes if gated | The `cap:v1` `key_id` (first 16 hex of SHA-256 over the issuer Ed25519 public PEM) the presented token MUST be signed by — the **trust anchor**. |
| `required_constraints` | array<string> | yes if gated | `cap:v1` constraint keys the token MUST carry. Lets a client reject a tool whose authorisation surface is weaker than its policy demands. |
| `policy_proof_hash` | string | optional | SHA-256 of a `proof:v1` artefact certifying the constraints are complete over `inputSchema`. |

**Client rule (fail-closed).** Before calling a tool a client MUST run the
check in §3. A tool whose `_meta.raucle.gated` is true but whose `issuer_key_id`
is absent, malformed, or not in the client's trusted set MUST NOT be called.

## 2. Decision receipt (`tools/call` result)

On every `tools/call` it gates, a server MUST add a `raucle` object under the
result's `_meta`:

```json
{
  "content": [{ "type": "text", "text": "{\"status\": \"ok\"}" }],
  "isError": false,
  "_meta": {
    "raucle": {
      "version": "mcp-cap:v1",
      "decision": "ALLOW",
      "receipt_id": "sha256:1d4f…",
      "token_id": "cap:7b2e9a01c4d5f6a7b8c9d0e1"
    }
  }
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `version` | string | yes | `mcp-cap:v1`. |
| `decision` | string | yes | `ALLOW` or `DENY`. |
| `receipt_id` | string | yes | Reference to the **signed** receipt the server recorded in its audit chain (content-addressed id or chain index). The `decision` here is a convenience copy; the authoritative, offline-verifiable record is that signed receipt. |
| `token_id` | string | optional | `token_id` of the presented token, for correlation. |
| `reason` | string | denials only | Human-readable denial reason. MUST NOT contain signed material, credentials, or lower-layer request bytes. |

A DENY is an MCP **tool-level error** (`isError: true`), not a JSON-RPC protocol
error — the model should see it and may react, but it carries no signed material.

## 3. Client verification (fail-closed)

```python
from raucle.mcp_auth import verify_tool_annotation

ok, reason = verify_tool_annotation(tool, trusted_key_ids={"9f1c2a3b4d5e6f70"})
if not ok:
    raise PermissionError(reason)  # do not call a gated tool you cannot anchor
```

A conforming client MUST:

1. Treat a tool with no `_meta.raucle` as ungated (callable).
2. Reject a `gated: true` tool whose `version` is unrecognised, whose
   `issuer_key_id` is missing/malformed, or whose anchor it does not trust.
3. After a call, resolve `result._meta.raucle.receipt_id` against the server's
   published receipt log and verify the signed receipt before treating the call
   as authorised evidence.

## Where the token travels

`mcp-cap:v1` does not mandate a single token-transport; a server MUST document
one of:

- **Out-of-band session binding** (the reference servers' default): the client
  establishes the in-force `cap:v1` token with the server at session setup; each
  `tools/call` is evaluated against it. Simplest; no per-call token plumbing.
- **Per-call token**: the client includes the `cap:v1` token at
  `params._meta.raucle.token`. Required for stateless / multi-tenant servers.

In both cases the server evaluates the call arguments against the token's signed
constraints using the `cap:v1` gate semantics, unchanged.

## Conformance

A conforming **server** MUST: annotate every gated tool per §1; emit a §2
receipt referencing a signed audit record for every gated `tools/call`;
fail closed (DENY) on a missing/invalid token. A conforming **client** MUST
implement §3.

Reference: `raucle/mcp_auth.py` provides
`tool_capability_annotation()`, `receipt_meta()`, and `verify_tool_annotation()`;
`tests/test_mcp_auth.py` is the conformance test for the block shapes and the
fail-closed client check.

## Interoperability test vectors

A conforming implementation MUST reproduce these `_meta.raucle` blocks:

- **V1 — gated annotation:** `tool_capability_annotation(issuer_key_id="9f1c2a3b4d5e6f70", required_constraints=["allowed_values","max_value"])`.
- **V2 — ALLOW receipt:** `receipt_meta(decision="ALLOW", receipt_id="sha256:1d4f", token_id="cap:7b2e")`.
- **V3 — DENY receipt:** `receipt_meta(decision="DENY", receipt_id="sha256:9a0b", reason="amount over max")`.
- **V4 — untrusted anchor:** `verify_tool_annotation` of a V1-style tool with an `issuer_key_id` outside the trusted set MUST return `(False, …)`.

## Open questions for review

1. **Token transport.** Should `mcp-cap:v2` standardise the per-call
   `params._meta.raucle.token` placement, or leave it server-documented?
2. **Receipt resolution.** Should the profile define a `resources/` URI scheme
   for fetching a `receipt_id` over MCP itself, so a client needs no side channel?
3. **Manifest integrity.** The `tools/list` annotation is only as trustworthy as
   the channel. Should the profile require the server's tool manifest to be
   signed (a `cap:v1`-keyed manifest signature)?

## What we ask of the MCP maintainers / OWASP AI Exchange

Adopt `_meta.raucle` as a registered, additive authorization-binding convention
(or bless an equivalent), so MCP tool authorization and its evidence are
portable across servers and clients rather than per-vendor.
