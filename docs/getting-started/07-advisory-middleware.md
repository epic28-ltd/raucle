# Advisory middleware: observed, receipted, never enforcing

The `RaucleMiddleware` layer sits inside an agent loop in-process. It
observes what flows through the loop, runs session-windowed heuristic
scans, and, when you ask it to, redacts sensitive content in the data
plane before the content lands back in the loop.

One label, stated plainly: **this layer is advisory. It never
enforces.** It never blocks a call, never mints a gate receipt, and
never replaces the deterministic gate. When something fails inside the
advisory layer, it fails OPEN: the agent loop keeps running. The gate
(`check_tool_call`) is the component with authority, and it is
fail-closed. Do not confuse the two, and do not let anyone sell you one
as the other.

## The middleware in one minute

```python
from raucle.middleware import RaucleMiddleware

mw = RaucleMiddleware(mode="standard")

# Scan user input (unchanged prompt comes back)
prompt, result = mw.pre_process("What is the capital of France?", session_id="s1")

# Gate the tool call (the gate does the deciding)
allowed, result = mw.pre_tool_call("search", {"query": "raucle receipts"}, session_id="s1")

# Scan the response before it goes back
output, result = mw.post_process(llm_response, session_id="s1")
```

Every scan can fire `on_alert` / `on_block` callbacks and every turn is
tracked in a rolling session window (default 20 turns, TTL eviction).

## Advisory redaction (optional, off by default)

Versioned config on the middleware:

```python
from raucle.middleware import RaucleMiddleware

mw = RaucleMiddleware(
    mode="standard",
    redaction_classes=[
        "pii_card",
        "pii_email",
        "pii_national_id",
        "secret_bearer",
    ],
)
```

With classes configured, `post_process` replaces matched spans with
collars and returns the REDACTED text:

```python
output, result = mw.post_process("Your card is 4111 1111 1111 1111.")
# output == "Your card is [REDACTED:pii_card]."
```

Default behaviour is unchanged: without `redaction_classes`, output
comes back byte-identical. Unknown classes are refused at
configuration time. The detectors are patterns (cards are Luhn-validated),
not semantics; content matching no pattern passes. That limit is
declared, not hidden. `[REDACTED:<class>]` collars never re-flag: a
second pass over redacted content changes nothing.

The middleware never blocks and never modifies tool-call arguments. It
is observation plus data-plane hygiene, and only where it is wired
in-process.

## Advisory findings (optional, best effort)

When you also wire a gateway client and bind gate receipts to traces,
redactions become replay-verifiable evidence:

```python
# after a gated tool call your integration made:
mw.record_trace_receipt("trace-1", gate_result["receipt_id"], gate_result["decision"])

output, result = mw.post_process(llm_response, trace_id="trace-1")
```

Each matched class becomes an `x_finding` finding minted through
`RaucleGateway.emit_finding`, harness `middleware-advisory`. Findings
carry class names, counts and sha256 digests only; matched content
never enters a finding. The finding cites the related gate receipt, and
the offline verifier re-checks that claim, so the middleware cannot
invent evidence about what the gate did.

Two honest limits:

- emission is best effort. A gateway that is down is logged, not
  thrown; the loop keeps running either way;
- findings are minted only when a receipt citation is bound. The
  verifier refuses findings that cite a receipt not in the chain, so
  uncited redactions stay local logs, not receipts.

Coverage exists only where the middleware is in-process. A path that
bypasses the hooks is unobserved.

## Reading the evidence class correctly

Receipts minted here are advisory evidence: proof of what the
middleware observed, verifiable offline, useful in an audit pack. They
are NOT gate receipts and never carry a gate decision of their own.
Nothing in this lane is "blocking": enforcement vocabulary belongs to
the gate's documentation, and the full formal statement is
[the advisory middleware spec](../spec/advisory-middleware-v1.md).
