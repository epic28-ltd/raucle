# Advisory middleware: redaction adapters (v1)

Status: accepted 17 November 2026. EPIC Q lane Q-7c.

## What this layer is

The `raucle.middleware.RaucleMiddleware` layer is an **advisory** layer
for in-process assistant-side observation. It runs session-windowed
scans around an agent loop's input, output and tool-call surfaces. With
EPIC Q lane Q-7c it gains OPTIONAL data-plane redaction and bounded-
disclosure advisory findings.

What it is NOT, categorically and by construction:

- it is **never enforcement**. It returns `(allowed, result)` from
  heuristic scanning but nothing in this layer holds gate authority;
  decisions that change agent behaviour belong to the deterministic
  gate (`RaucleGateway.check_tool_call`);
- it **never mints gate receipts**. Receipts minted here are findings
  (evidence class), not decisions;
- it is **fail-open by design**. Any failure inside the advisory paths
  (scan, redaction, emission) is logged and swallowed: the agent loop
  keeps running and unredacted content passes through. In deliberate
  contrast, the deterministic gate is fail-closed. This lane is not the
  gate and must never be marketed as one.

## Redaction (versioned config, default OFF)

Configure `redaction_classes` on the middleware (default `None`: hooks
stay byte-compatible and nothing is ever redacted). Wired classes are a
declared subset of the x_dlp matched-class vocabulary
(`docs/spec/provenance/v1.2/content-dlp.md`):

| class | detector |
|---|---|
| `pii_card` | PAN-shape digit runs validated by Luhn |
| `pii_email` | email-shape token |
| `pii_national_id` | UK National Insurance number shape |
| `secret_bearer` | bearer-token and credential key/value shapes |

`pci_pan` is deliberately not wired here: issuer-aware PAN heuristics
belong to the enterprise scanner. Unknown classes are refused at
configuration time (fail-fast), never silently ignored.

When configured:

- `post_process` replaces matched spans in assistant responses and tool
  results with `[REDACTED:<class>]` collars BEFORE the adapter hands
  content back into the agent loop. The returned text is the redacted
  text. Collar spans can never re-flag: a second pass over redacted
  content is byte-identical and rescans clean (guarantee tests mirror
  the raucle-agent-assurance PRIV-01 self-reflag pattern).
- `pre_tool_call` redacts matched spans in the serialized argument text
  recorded into the session window (so matched content does not
  accumulate in session state) and, when a citation is bound, emits an
  advisory finding. The caller's argument dict is never modified and
  the allow/deny decision is unchanged; the middleware has no
  authority over the call itself.

The detectors are pattern-based, honestly declared: pattern-matched and
Luhn-validated, not semantic. Content that matches no wired pattern
passes. This is defence in depth, not a guarantee.

Findings carry per-class span counts and sha256 digests (of the
pre-redaction content and the redacted content) only. Matched values
never enter a finding. This is the x_dlp bounded-disclosure rule,
applied to the x_finding emission.

## Advisory findings

With a gateway client reference wired (an object exposing
`emit_finding`), the middleware mints one advisory finding per matched
class through `RaucleGateway.emit_finding`:

- `harness` is always `middleware-advisory`;
- `test_id` is the redaction class (or, for non-redaction sessions, the
  session scanner alert class);
- `verdict` is `confirmed` (the middleware observed what it reports);
- `cited_receipt` is the RELATED tool-call gate receipt when one is
  bound to the call's `trace_id` via `record_trace_receipt`; the
  recorded gate decision rides as `actual_decision`, so the offline
  verifier re-checks the middleware's claim against the cited receipt.

Emission is best effort: a gateway failure is logged and the hook keeps
running. A finding is minted only when a citation is bound: the offline
verifier refuses findings that cite a receipt not in the chain, so an
uncited finding would be unverifiable evidence rather than advisory
evidence. Uncited redactions are logged locally (counts and digests)
and no receipt is minted.

## Honest coverage statement

- coverage exists ONLY where the middleware is in-process. An agent
  loop that bypasses `post_process` / `pre_tool_call` (direct SDK calls,
  framework-internal retries, streaming paths) is unobserved;
- the layer observes at the call boundary it is given, nothing more;
- the redaction detectors are patterns, not semantics; evasion is a
  stated limit, not an incident;
- receipts minted here are advisory evidence class: they prove what the
  middleware observed and can be replay-verified offline, but they are
  NOT gate receipts and MUST never be shown or sold as enforcement
  decisions. Copy must never describe findings as "blocking".

## Verification

`tests/test_advisory_middleware.py`: redaction applies collars
configured, off-by-default byte compatibility, collar self-reflag
guarantee, unchanged tool-call decisions and taint behaviour, best-
effort emission (gateway failure, hostile content never serialised into
findings, no gateway, no citation), fail-open on scan and redaction
failure, and the acceptance leg: an advisory finding for a redacted
response verifies offline through `ProvenanceVerifier` and cites the
related tool-call gate receipt bound by `trace_id`.
