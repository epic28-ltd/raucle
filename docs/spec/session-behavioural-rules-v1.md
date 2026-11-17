# Session behavioural rules v1

Policy-side contract for deterministic session rules (EPIC Q1). This
doc covers the POLICY and EVALUATION layer. The receipt side unchanged:
session observations ride ordinary signed gate receipts (schema v3
carries `session_id`), and any session-rule deny additionally emits an
ordinary `x_finding` receipt (harness `session-monitor`, test id = rule
id, citing the triggering gate receipt) which verifies offline through
the standard verifier. There is no new receipt extension.

## Where evaluation runs

Session rules evaluate inside the gateway pre-check chain, in the
only-ever-DENY tier: after the policy-bytes tamper check, before any
feature that could widen authority. A session rule can therefore only
refuse a call; it can never widen one. Absent `session_id` on the
request means session rules do not evaluate at all - the gateway never
fabricates session continuity.

## Rule kinds (v1)

| kind | fires when | notes |
| --- | --- | --- |
| `repeated_deny_storm` | >= `threshold` denies for the same tool pattern within `window_seconds` | patterns are fnmatch |
| `runaway_tool_loop` | >= `threshold` calls of the same tool within the window with no receipted success between them | |
| `gradual_extraction` | >= `threshold` decisions touching destinations of a given `destination_class` within the window | content-free; rides the existing destination_class field |
| `forbidden_tool_chain` | the last `threshold` tools in the window exactly match the declared ordered sequence | config-declared list |
| `scope_drift` | >= `threshold` calls to tools outside the rule's declared known set within the window | |

Common rule fields: `id`, `kind`, `threshold`, `window_seconds`,
optional `tool_patterns` (fnmatch), optional `tool` / `agent_id` scoping
consistent with policy rule conventions. Evaluation order is
declaration order; when several rules match one call, the first
declared wins. With `action: deny` (the only v1 action), the denial
is fail-closed, receipted, and its reason names the rule id plus window
evidence counters (counts and tool names) - never arguments or content.

## Policy configuration

Session rules live in the policy file under `session_rules:`, compiled
by the same policy pipeline as ordinary rules. Malformed rules are
named errors in the policy load (`session_rule_errors`), never silently
skipped; a policy whose session rules failed to compile makes session'd
calls fail closed with a named reason until the config is corrected. A
declared window wider than the gateway's session window TTL is refused
as a configuration error rather than evaluated against stale state.
Session-rule definitions ride the policy-bytes tamper seal: an
out-of-band edit to a session-rule file makes every session'd decision
fail closed (`policy_tampered`) until the file is re-sealed, and each
session-rule deny binds the rule content digest as its ruleset hash.

## Window state and its honest limits

The gateway keeps one in-memory window per `(session_id, agent_id)`
holding content-free decision summaries (decision, tool, timestamp,
trace id, destination class). The state is bounded by configuration:
`RAUCLE_SESSION_WINDOW_TTL_SECONDS` (window TTL), `..._MAX_KEYS`
(distinct sessions) and `..._MAX_ENTRIES` (entries per session) - the
gateway never grows window state unboundedly. On boot, active windows
are replayed from the receipt index (`(session_id, iat)` query) bounded
by the same TTL and key cap.

Stated limits:

- Window state is process memory. A restart mid-session resets
  counters; the boot replay bounds the loss to the indexed recent
  history.
- Replayed rows carry no `destination_class` (the projection does not
  index it), so `gradual_extraction` can undercount after a restart. It
  can never fabricate a deny from data the index does not hold.
- Findings are subject to the standard `x_finding` anti-fabrication
  re-check: a session-monitor finding whose cited gate receipt is
  missing, or whose reported actual decision mismatches the cited
  receipt, makes the chain invalid with a named error.

## What session rules are not

They are not content inspection (the gateway never sees prompt or
response text), not anomaly scoring (deterministic rules only in v1),
and not an escalation path (deny-only in v1; escalation to approval is
a named follow-up). Deployment honesty: coverage exists only where
callers declare `session_id`; the docs and product copy must say so.
