# EE proxy runtime (v1): enterprise LLM endpoint proxy over the OSS gate

Status: accepted 18 November 2026. EPIC Q lane Q-7b (content-plane DLP,
Q7). The receipts this runtime produces are specified by
[provenance/v1.2/content-dlp.md](provenance/v1.2/content-dlp.md); the
session rules it exercises are specified by
[session-behavioural-rules-v1.md](session-behavioural-rules-v1.md); the
advisory middleware vocabulary it reuses is specified by
[advisory-middleware-v1.md](advisory-middleware-v1.md).

## What this component is

An in-path HTTP proxy for traffic destined for LLM endpoints. The
gateway is a tool-call gate and never sees prompt or response content
(Q1 spec pass, section 0; this remains true). Content-plane controls
need a component in the content path: this runtime is that component.
It accepts agent or application traffic aimed at model endpoints,
consults the OSS gate for every gated call, runs content scanning and
advisory redaction on request and response payloads, forwards approved
requests upstream, evaluates response-side rules, and returns responses
carrying receipt-backed provenance headers.

The architectural precedent is the shipped OSS urlgate
(`raucle/urlgate.py`, EPIC O3: single upstream, service-scoped policy,
receipts per gated call, upstream-shaped deny bodies, byte-identical
SSE pass-through) and the C2 injection proxy (credential injection
sidecar, EPIC C2). This runtime generalises that shape from one
upstream and one policy to a registry of routes, each with its own
policy profile, DLP posture and provenance surface.

## Licence split (the ruled boundary)

The licence boundary (owner ruling, 17 November 2026; EPIC Q recast):
EPIC Q features are EE and closed unless the OSS repository is required
for them to work. The boundary test: a thing that mints, verifies or
denies inside the gate, or extends the receipt schema, is an OSS
prerequisite; a thing that operates, visualises, connects or classifies
is EE.

Applied here:

| Concern | Home | Why |
|---|---|---|
| This specification document | OSS, public | It is design language and wire contract, not runtime code. Customers and third parties must be able to read what the closed component claims, and the verifier rules it relies on are already public. Precedent: content-dlp.md ships the EE proxy's receipt contract in the OSS spec tree. |
| Receipt minting, policy evaluation, session rules, tamper seal | OSS gate (already shipped) | Mint/verify/deny inside the gate. The proxy never takes any of these over. |
| `x_dlp` schema + offline verifier rules + test vectors | OSS (already shipped, Q-7a) | Extends the receipt schema. |
| Redaction engine + scanner + advisory middleware vocabulary | OSS (already shipped, Q-7c) | Pattern libraries are shared evidence vocabulary; the EE scanner adds enterprise classes (for example issuer-aware PAN) on top, never a fork of the core. |
| The proxy runtime itself (listeners, route registry, normalisation, forwarding, DLP orchestration, config loader) | EE, closed | Operates and connects. It sits in the customer's content path; per Q5 it deploys inside the customer cloud estate with no phone-home. |
| Per-route policy configuration UI, route health surfaces | EE fleet console | Operates and visualises. |
| Provenance verification of the receipts this proxy produces | OSS verifier, free forever | The R10/R11 line: verification is never the paid surface. |

This spec requires **no OSS code change**. Every OSS surface the
runtime needs already exists on main and is listed under OSS surfaces
consumed, each with its justification. If a future revision finds a
rule impossible without a gate-side hook, that hook must be argued as
an OSS prerequisite against the boundary test in its own PR; this
document then records it here with its justification. Nothing in this
spec invents new gateway semantics.

## Terms

- **Route**: one configured path prefix plus its policy profile, DLP
  posture, upstream and receipt wiring.
- **Route registry**: the ordered set of routes loaded from the
  versioned configuration schema at boot.
- **Policy profile**: a named gate configuration (policy file, seal,
  receipt store, gate tool, agent identity). One gateway instance is
  built per profile; routes reference profiles by id.
- **Canonical request / canonical response**: the runtime's
  normalised internal records of one call (shapes below). Everything
  downstream (scanning, gating, receipt citation) reads the canonical
  shape, never raw sockets.
- **DLP scan**: one pattern-engine pass over one direction of one
  call's payload text, producing matched classes, span counts and
  digests (bounded disclosure, x_dlp).
- **Session identity**: the caller-declared `X-Raucle-Session` header
  value; bounded exactly as the gate request requires (1 to 128
  characters, validated by the existing gate pattern). Absent means no
  continuity is declared; the runtime never fabricates one.
- **Provenance headers**: the response headers naming the receipts
  minted for the call.

## Architecture (request path, response path)

Request path, in evaluation order:

1. **Listener and router.** The request target must be RFC 9112
   origin-form (the urlgate SSRF posture: absolute-form,
   authority-form and asterisk-form targets are refused with a named
   error; the upstream host is never client-controlled). The router
   matches the path against the route registry by longest prefix.
   No match: fail closed, named error `unknown_route`, no upstream
   contact, no receipt (no gate decision was evaluated; there is
   nothing to attest).
2. **Normalisation.** The canonical request record is built: method,
   path, route id, session identity (header, optional), trace id
   (header, optional), model name (when the parsed body carries one),
   content digest of the request bytes, and the body bytes themselves.
   The record never copies credential headers into evidence surfaces.
3. **Gate consultation.** One `check_tool_call` per gated call on the
   route's profile instance, with the route's tool and agent identity,
   `source="ee-proxy"`, `destination` = the route's upstream, plus the
   declared session id and trace id. Session rules evaluate exactly as
   the OSS session behavioural spec describes (deny-only tier; no
   session id means no evaluation). Deny or escalate: the upstream is
   never contacted; the caller receives the upstream-shaped error body
   with HTTP 403 and the gate receipt (urlgate contract). Allow: the
   gate receipt id is retained for citation.
4. **Request-side DLP (when the route configures it).** The request
   payload text is scanned with the OSS pattern engine over the
   route's configured classes. Block classes matched: the call is
   refused (HTTP 403, upstream-shaped error) and one `x_dlp` receipt
   with `action=blocked`, `direction=egress_to_model`, citing the gate
   receipt, is minted **through** `RaucleGateway.emit_dlp_finding`.
   Redact classes matched: matched spans are collared
   (`[REDACTED:<class>]`, the shared OSS redaction engine) and the
   redacted payload is what is forwarded; the `x_dlp` receipt carries
   `action=redacted` with both digests. No classes matched: no `x_dlp`
   receipt (no receipt inflation, the urlgate HEAD/OPTIONS precedent).
5. **Forward.** The approved (and possibly redacted) request is
   forwarded to the route upstream over TLS. The client Authorization
   header is replaced by the route credential (read from a named
   environment variable at forward time; the config never holds
   secret values, the ADR-EE-0004 target pattern). A route may opt in
   to forwarding client credentials verbatim; the default is replace.
   `Accept-Encoding` is pinned to identity so scanned bytes equal
   forwarded bytes.

Response path, in evaluation order:

1. **Normalisation.** The canonical response record: status, header
   subset, content digest, body bytes.
2. **Response-side DLP (when configured).** Same engine, direction
   `ingress_from_model`. Block classes matched: the payload is not
   delivered; the caller receives the named DLP block error with the
   `x_dlp` receipt. Redact classes matched: collared spans are
   delivered and the receipt records both digests. The model has
   already consumed the prompt at this point; the block still prevents
   the sensitive material reaching the caller, and the honest
   asymmetry (request-side block prevents the call; response-side
   block prevents the delivery) is stated in the product copy, not
   hidden.
3. **Response taint.** The route may map matched classes to taint
   tags. Matched tags are recorded through
   `RaucleGateway.record_chain_output` against the call's trace id, so
   subsequent gated calls on the same trace evaluate the existing
   `deny_from_chain_taint` policy rules. Tags are non-empty strings;
   the gateway's fail-closed malformed-tag posture applies unchanged.
   This is the existing OSS data-flow machinery, fed by the content
   plane; nothing new is invented.
4. **Decoration.** The response returns with the provenance headers.

## Canonical shapes

Canonical request (internal, v1):

```
{
  "method": "POST",
  "path": "/v1/chat/completions",
  "route_id": "openai-prod-eu",
  "session_id": "",            # caller-declared, optional, bounded 1-128
  "trace_id": "",              # caller-declared, optional
  "model": "gpt-4o",           # when the parsed body carries one
  "content_sha256": "sha256:...",
  "streaming": false
}
```

Canonical response (internal, v1):

```
{
  "status": 200,
  "content_sha256": "sha256:...",
  "streaming": false
}
```

The bytes themselves are held only for the life of the call and never
enter a receipt, a log line or a finding (bounded disclosure: digests,
class names, counts and identifiers only). Body text extraction reads
the parsed JSON payload's content-bearing fields (messages, input,
prompt and equivalent top-level text fields); fields it does not
understand are not scanned and the coverage statement says so.

## Route registry and configuration schema (ee-proxy-routes/v1)

The configuration file carries a mandatory versioned schema id.
`schema_id: ee-proxy-routes/v1` loads; anything else is refused at
boot with a named error (unknown schema ids never load on guesswork).

```
schema_id: ee-proxy-routes/v1

profiles:
  - id: prod-chat
    policy_file: /etc/ee-proxy/policies/prod-chat.yaml
    policy_seal_file: /etc/ee-proxy/policies/prod-chat.seal.json
    receipt_store_dir: /var/lib/ee-proxy/receipts/prod-chat
    tool: llm.chat
    agent_id: agent:ee-proxy-prod-chat

routes:
  - id: openai-prod-eu
    path_prefix: /openai-eu/
    upstream: https://api.openai.eu
    profile: prod-chat
    credential_env: OPENAI_EU_API_KEY
    allow_streaming: false
    dlp:
      request:
        block_classes: [secret_bearer]
        redact_classes: [pii_card, pii_email, pii_national_id]
      response:
        block_classes: []
        redact_classes: [pii_card, pii_email]
      response_taint_tags:
        pii_card: [dlp:pii_card]
        secret_bearer: [dlp:secret_bearer]
```

Validation rules, all enforced at load; violation is a named boot error:

1. `schema_id` present and exactly `ee-proxy-routes/v1`.
2. Route ids unique; profile ids unique.
3. Every route's `profile` names a declared profile; `upstream` is
   `https` (cleartext upstreams are refused); `path_prefix` starts
   with `/`; no route prefix equals another route's prefix (distinct
   prefixes only; ambiguity is a load error, longest prefix wins
   matching between unequal prefixes).
4. DLP classes inside the wired redaction vocabulary
   (`pii_card`, `pii_email`, `pii_national_id`, `secret_bearer`; the
   `pci_pan` class belongs to the enterprise scanner and is refused
   here until it is wired there). A class may not appear in both
   `block_classes` and `redact_classes` for the same direction.
5. `response` DLP classes configured with `allow_streaming: true` is
   a load error: a streamed response cannot be scanned before
   delivery, so the coverage would be false. Streaming is permitted
   only on routes with no response-side DLP, and the runtime refuses
   `stream: true` requests with a named error (`streaming_not_allowed`)
   on routes that declare `allow_streaming: false`.
6. `response_taint_tags` keys must be wired classes; tag values
   non-empty strings.
7. Policy files must load and their session rules must compile (the
   gate's named `session_rule_errors` posture): a profile whose policy
   fails to compile refuses the boot. A tampered seal (out-of-band
   edit after activation) is not a load-time error; at request time
   every route on that profile denies fail-closed with the named
   `policy_tampered` status, exactly as the gate behaves in-process.

## Per-route policy selection

One gateway instance is built per profile (routes sharing a profile
share the instance). Consequences, stated honestly:

- Session window state is keyed `(session_id, agent_id)` per instance
  (the Q-2 shape). A session whose traffic crosses two profiles has
  two independent windows; per-route session rules see only their own
  profile's window. The docs must say this; it is not hidden.
- Receipt stores are per profile. The fleet console reads org receipt
  indexes read-only (ADR-EE-0004 posture); the operator declares which
  stores a given org's view covers.
- Unknown profile at load: boot error. Unknown route at request: fail
  closed (`unknown_route`), no receipt, no upstream contact.

## Advisory redaction integration (Q-7c surfaces)

The runtime reuses the OSS advisory vocabulary and engines verbatim:
the redaction classes, collar format, self-reflag guarantees and
bounded-disclosure findings shape are the shipped Q-7c surface. The
composition differs from the in-process middleware in one deliberate
respect, and the difference is the point of this component:

- **In-process middleware** (assistant side): advisory by
  construction, fail-open, never enforcement (advisory-middleware-v1).
- **This runtime** (content plane, in path): the route's DLP posture
  is an operator-configured content control. Block classes refuse the
  call or the delivery; redact classes modify the payload. Every
  decision is receipted through the gate machinery. The word
  "advisory" still applies to what the scan claims (a pattern match,
  not a semantic understanding); it does not describe the consequence,
  which is a real refusal or a real rewrite, receipted either way.

The runtime itself never mints receipts. All receipts come from
`check_tool_call` (the gated call) and `emit_dlp_finding` / the gate's
finding emitters (scan and advisory findings). The ADR-EE-0004
posture (evidence is minted through the gate, never by operator
tooling) carries over unchanged.

## Provenance headers (wire contract)

| Header | Value | When |
|---|---|---|
| `X-Raucle-Receipt` | gate receipt id for the call | every gated call, allow and deny |
| `X-Raucle-Decision` | `allow` or `deny` | every gated call |
| `X-Raucle-Tool` | gate tool name | gate denies (urlgate contract) |
| `X-Raucle-Route` | route id | every routed response, including fails |
| `X-Raucle-Dlp-Receipt` | comma-joined `x_dlp` receipt ids | when a scan minted receipts |
| `X-Raucle-Passthrough` | `streaming-unscanned` | streamed responses on routes with no response DLP (named marker: no response scan ran) |

A streamed response on a route with no response-side DLP passes
through byte-identical (SSE framing intact, urlgate posture) and is
marked: the receipt set for that call makes no response-scan claim.

Error bodies are upstream-shaped (OpenAI and Anthropic error shapes,
the urlgate contract) so stock SDK clients fail through their normal
error path, with the raucle error code in the message. Nothing
replaces a fabricated upstream response: every failure returns a named
error, and the caller can always tell a proxy refusal from an
upstream answer.

## Failure postures (fail-closed defaults)

| Failure class | Posture | Named error |
|---|---|---|
| Unknown route | refuse, no upstream, no receipt, method and path logged only | `unknown_route` (HTTP 404) |
| Gate evaluation exception | refuse (HTTP 502), upstream untouched; the gateway's own failure paths receipt where they can | `gate_failure` |
| Gate deny or escalate | refuse (HTTP 403), upstream untouched, receipted | upstream-shaped deny body |
| DLP block class matched (request) | refuse (HTTP 403), `x_dlp` receipt `blocked` via the gate, citing the gate receipt | `dlp_block` |
| DLP block class matched (response) | payload withheld (HTTP 403), `x_dlp` receipt `blocked` | `dlp_block` |
| Scanner or redaction engine failure | refuse (HTTP 503): a configured content control never silently skips. Deliberate contrast with the in-process middleware's fail-open posture; that layer has no authority, this one has a configured job | `dlp_scan_unavailable` |
| Policy load failure (profile) | boot refuses | named policy error |
| Policy tampered (seal divergence) | every route on the profile denies fail-closed until re-sealed | `policy_tampered` (the gate's own status) |
| Upstream connection failure or 5xx | HTTP 502 named error; the gate allow receipt already minted stands (it attests the decision, not the delivery); no synthetic success | `upstream_unavailable` |
| Session window state | the Q-2 posture carries over unchanged: in-process memory, boot replay from the receipt index, replay fault never blocks boot and windows start empty (the documented restart residual) | logged, never fabricated |
| Invalid configuration | boot refuses before the listener binds | per validation rule |
| Malformed session or trace header | refused (HTTP 400). A header that fails the gate's bound cannot be silently dropped: the caller believes continuity was declared | `invalid_session_header` / `invalid_trace_header` |

## Threat model deltas

- **New asset: prompt and response content in runtime memory.** The
  gate never sees content; this component must. Mitigations: content
  lives only for the call's lifetime, never enters receipts, logs or
  findings (digests only); the component is closed-source but
  customer-hosted (Q5): the content never leaves the customer estate,
  and there is no phone-home.
- **New asset: upstream credentials.** Config names environment
  variables, never values (ADR-EE-0004 target pattern). Client
  Authorization headers are replaced by default so a client cannot
  spend its own credentials on a route it should not reach.
- **SSRF.** Origin-form targets only; upstream hosts come from
  config; `https` upstreams only. The urlgate posture, restated
  because a route registry multiplies the destinations.
- **Downgrade and framing.** `Accept-Encoding: identity` pinned; SSE
  framing preserved; no content-length lies.
- **Receipt inflation.** Unknown routes, unscanned streams and clean
  scans mint nothing. Receipts attest decisions and scans that
  happened, never activity that did not.
- **Bypass.** An agent that calls the model endpoint directly,
  outside the proxy, is unobserved by this component. That is the
  standing D4 posture (unsanctioned-AI capture stays gateway-side);
  the coverage statement declares the proxy's span honestly.
- **Content-like field leakage.** The `x_dlp` verifier already
  refuses content-like fields in signed extensions; the runtime never
  puts content in one.
- **Multi-tenant misrouting.** Route ids, profile references and
  receipt stores are config-validated unique and non-ambiguous; a
  misconfigured registry refuses to boot rather than misroute.

## Honest limitations

- Pattern detection is not semantic understanding; evasion is a stated
  limit, not an incident (advisory-middleware-v1 wording carries over).
- Streamed responses are not response-scanned; routes that need
  response DLP must be non-streaming, and the runtime enforces the
  pairing at load and at request time.
- Body text extraction covers the declared content-bearing fields of
  the parsed payload; unknown fields are not scanned.
- Coverage exists only where traffic actually flows through a route;
  direct-to-model calls are out of scope for this component.
- Session windows are per profile instance and in-process; the Q-2
  restart residual (bounded by index replay, gradual_extraction can
  undercount) applies per instance.
- `pci_pan` is refused in route config until the enterprise scanner
  wires it; the OSS redaction vocabulary is deliberately a subset of
  the `x_dlp` vocabulary.
- The proxy holds content in memory; a host compromise of the proxy
  process sees content. That is inherent to any in-path DLP and is why
  the component is customer-estate-only, closed, and separately
  hardened at deploy time.

## OSS surfaces consumed (all existing; justification per surface)

| Surface | Status | Why it is sufficient (no OSS change) |
|---|---|---|
| `RaucleGateway.check_tool_call(..., session_id=...)` | shipped (Q-1) | The per-call decision, receipt mint and session-rule evaluation for one profile instance. Per-route selection is achieved by building one instance per profile from config, which is composition, not a gate change. |
| `RaucleGateway.emit_dlp_finding(...)` | shipped (Q-7a) | The only minting surface for scan receipts. Closed vocabularies match the verifier; the runtime is a client, exactly as content-dlp.md specifies. |
| `RaucleGateway.record_chain_output(...)` | shipped (EPIC O1) | Feeds response taint into the existing data-flow rules; no new rule class. |
| `raucle.redaction` (engine, classes) | shipped (Q-7c) | The shared redaction vocabulary and collar semantics, imported not forked (ADR-EE-0001 never-harvest rule). |
| `raucle.scanner` / pattern engine | shipped | Prompt-side scanning over route-configured classes. |
| Session window engine + receipt index v3 | shipped (Q-1/Q-2) | Session continuity, boot replay and per-session rules with zero proxy-side additions. |
| `ProvenanceVerifier` | shipped | Offline verification of every receipt this runtime produces, free, forever. |

## Verification

Every receipt named in the provenance headers verifies offline through
the standard OSS verifier with no proxy and no scanner present: gate
receipts as ordinary v1 receipts (schema v3 session fields when
declared), `x_dlp` receipts per content-dlp.md rules (structure,
vocabulary, digest shape, redaction consistency, chain membership),
and advisory findings per the x_finding anti-fabrication re-check. A
third party holding the chain can prove what was gated, what was
scanned (by digest), which classes matched, what the policy decided
and that redaction changed the delivered content, without ever
holding the content. That is the acceptance shape of this component's
evidence, and it inherits from shipped machinery: this document adds
no verification semantics.
