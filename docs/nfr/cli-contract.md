# CLI contract — exit codes and command surface (NFR operability)

This is the operator-facing stability contract for the `raucle` CLI and its
auxiliary tooling. It is guarded by `tests/test_nfr_cli_contract.py`, which
fails if a command documented here disappears from the parser, if a command
exists that this contract does not account for, or if any exit code
documented below is no longer returned anywhere in the CLI implementation.
Semantics are hand-written from the code; the guard tests keep them honest.

## Exit codes

One global vocabulary applies to every `raucle` subcommand:

| Code | Meaning | Returned when |
| --- | --- | --- |
| 0 | success | The command did what it was asked to do. Healthy states only: e.g. `canary observe` exiting cleanly when the canary has NOT yet leaked is still 0 (not-leaked and healthy-store are both "no incident"). |
| 1 | expected failure / input error | Missing file, unreadable input, malformed JSON, missing optional extra, config error, OR a detector outcome that is not malicious but not clean. `scan`: any prompt SUSPICIOUS → 1. |
| 2 | adversarial / refusal / detection outcome | `scan`: any prompt MALICIOUS → 2. `prove`: policy REFUTED or UNDECIDED → 2 (CI treats "not proven" as failure). Refusal-class outcomes that are not exceptions. Also argparse usage errors (argparse's own convention). |
| 130 | interrupted | `KeyboardInterrupt` or `BrokenPipeError` caught in the top-level dispatcher: the process exits as if killed by SIGINT, without a traceback. |

Rules the codebase is held to:

- Expected user errors print one line `error: ...` to stderr and return
  1/2 — never a raw traceback. Genuinely unexpected errors STILL RAISE so
  operators get a stack trace.
- Exit codes are the automation boundary: pipelines may only rely on the
  codes in the table above; stderr text may change between releases,
  codes may not without a documented contract change here.
- `raucle-detect` remains a deprecated alias; same exit-code contract.

## Command surface (guarded)

Every subcommand below must exist as a parser choice and must map its
outcomes onto the table above. (Per-command semantic detail lives in the
docstrings of the `_cmd_*` handlers in `raucle/cli.py`.)

| Command | One-line contract |
| --- | --- |
| scan | 0 clean, 1 suspicious, 2 malicious |
| scan-image | as scan (image path) |
| scan-pdf | as scan (PDF path) |
| scrub | 0 clean text, 2 when hidden unicode is found (1 not used by scrub) |
| agents | key issue/revoke/list; 1 on lookup/auth errors |
| canary | mint: 0. observe: the CURRENT quirk, documented so it can never be silently changed — observe returns 0 when the canary IS observed in outputs (finding reported) and 1 when unobserved; no exit code distinguishes a leaked credential from a quiet run beyond this mapping |
| serve | runs until stopped; 1 on bind/config failure |
| urlgate | proxy loop; 1 on config failure |
| rules | list/fuzz; 1 on rule-store errors |
| audit | chain verify/build; 2 on tamper evidence, 1 on missing input |
| watch | streams; 1 on unreadable source |
| registry | publish/resolve/verify; 2 on missing subcommand, 1 on integrity failures (dispatcher) |
| counterfactual | replay under alternative policy; 1 on malformed record |
| records | lifecycle ops; 1 on state conflicts |
| timestamp | TSA anchor ops; 1 on token failure |
| containment | hold/resume/status; 1 on missing subcommand, state errors and refused transitions (ContainmentError path) |
| compliance | map receipts→controls; 1 on unreadable chain |
| passport | issue/verify; 2 on invalid passport, 1 on registry failure |
| verify-receipt | 0 valid receipt, 2 unverified/tampered, 1 bad input |
| authorship | sign session-stop receipts; 2 on verifier failure |
| audit-export | build signed report; 1 on chain error |
| audit-pack | build/verify custody pack; 2 on verification failure |
| demo | verify shipped demo bundle; 0 VERIFIED, 1 on tamper/pin mismatch, 2 on missing bundle |
| mcp | MCP bundle ops; 1 on schema errors |
| provenance | emit/verify receipts; 2 on verification failure |
| feed | publish/verify/subscribe feeds; 2 on signature failure |
| prove | 0 proven, 2 refuted/undecided (CI gate), 1 build error |
| cap | capability mint/verify; 2 on cap violation |

## Honesty notes

- The `canary`: two healthy exit paths noted explicitly because "leaked" is
  the only non-zero outcome — a silent canary is GOOD here.
- The per-command table is a stability contract, not new behaviour: each row
  summarises the exit codes the handlers already return. Where a command has
  richer outcome mapping than one row can carry, that row documents only the
  guarantees above (0/1/2/130 vocabulary).
- The guard test checks presence of each code in the implementation and
  parity of the command list with the parser — it cannot and does not check
  that every handler maps EVERY outcome described; that is covered by the
  command suites (`tests/test_cli_exit_codes.py` and the per-feature
  suites).
- `tools/benchmarks/nfr.py` documents its own codes (0 OK, 2 build error,
  3 write error) and is NOT part of the `raucle` CLI contract above.
