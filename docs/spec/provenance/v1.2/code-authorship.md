Code authorship receipts (code_authorship / x_authorship)

Status: SHIPPED (30 October 2026). Evidence layer per the amended boundary
(strategy sections 16.3 and 16.4): the format, the offline verifier and the
test vectors are public. The hook runs on the developer's own machine and
nothing is sent anywhere.

## The problem

Ask "who wrote this code" at a SOC 2 audit or for EU AI Act Article 12 log
coverage and today the answer is the version history, which records content
but not the working session: which files changed during an assistant-driven
session, what tools ran, what state the repository was in. Existing
tooling (Obsigna's obsigna-hook pattern, Signet's CI guides) signs
attestations after the fact through a service; raucle signs a receipt
locally, at session stop, with the developer's own key, and anyone can
verify it offline with no vendor involvement. This matches the standing
position: raucle stays the accountability layer, never a platform in the
loop.

## The extension block

A code_authorship receipt is an authority receipt (guardrail_scan shape,
ruleset hash bound to the extension, as the x_compliance, x_finding and
lease receipts are) carrying one x_authorship extension:

    {
      "git": {
        "head": "<commit id at stop>",
        "branch": "<branch name>",
        "dirty": <count of changed paths>
      },
      "files": [
        {
          "path": "<repo-relative path>",
          "status": "<git status letter: M, A, D, R, ?...>",
          "before": "<sha256 of the blob at HEAD, empty when new>",
          "after": "<sha256 of the working-tree bytes, empty when deleted>"
        }
      ],
      "commands": {
        "tool_calls": <total count>,
        "tools": {"<tool name>": <count>, ...},
        "tool_entries": [
          {"tool": "<tool name>", "args_digest": "<sha256 of the args>"}
        ]
      }
    }

Design rules:

- Bounded disclosure. Receipts record paths and digests only. Command text,
  argument values, prompts and model output never enter the evidence, so a
  receipt cannot leak a secret the session handled.
- Digests bound both directions: `before` ties the receipt to the state of
  the file when the session started (HEAD), `after` to the state at stop.
  A file edited after the stop, or an edit made outside the recorded
  session, fails against its recorded digest.
- Caps bound size and disclosure together: at most MAX_FILES (500) file
  entries and MAX_TOOL_CALLS (2000) tool entries are stored. Surplus is
  counted in the `dirty` and `tool_calls` totals, never dropped silently
  by the verifier (a count exceeding the stored entries fails
  verification).
- Degradation is honest: an absent or unparseable transcript leaves
  `tool_calls` at zero and the receipt is still valid; evidence shrinks,
  the receipt never blocks the session stop.

## Emission

`raucle authorship sign --repo PATH [--transcript PATH] --key KEY [--out P]`
collects the evidence (git porcelain with -z, per-file blob digests via
`git show HEAD:<path>`, tool calls parsed from a Claude Code transcript
JSONL) and signs the receipt. The hook script
`integrations/hooks/raucle_session_stop.py` (stdlib-only) wires the same
command to Claude Code's Stop hook or any Codex lifecycle hook that can run
a command, passing the hook stdin's `cwd` and `transcript_path`. The hook
always exits zero: authorship evidence must never block a session stop.
Receipts accumulate at `.raucle/authorship/stop-<n>.jsonl`. Add that
directory to .gitignore; receipts are evidence about the session, not part
of the codebase.

## The verifier's offline check

`raucle authorship verify <receipt> --pubkey KEY` re-checks the receipt
with no raucle store, no clock service and no network:

1. Envelope integrity: the receipt_hash recomputes from the JWS bytes.
2. Chain verification: the standard ProvenanceVerifier (signature, DAG,
   taint) runs over the one-receipt chain, exactly as it does for gate
   receipts. Any tampered byte fails by signature or by hash mismatch.
3. Key binding against the verifier-supplied public key: a key whose id
   differs from the receipt's key id is refused.
4. Extension semantics: guardrail_scan operation present, x_authorship
   present, every file entry carries a path and well-formed digests, every
   tool entry carries a tool name and a digest, the git head is a valid
   object id when present, and the tool call count never exceeds the
   recorded entries.

Failures are named, per the standing bounded-disclosure rule: the verifier
reports failure classes (hash mismatch, malformed entry, key mismatch),
never quoting the offending value.

## The honest scope

Emission is the hook's claim: the receipt records what the hook observed
about the working tree and the transcript, signed under the developer's
key. It proves that these contents, bounded by these digests, existed at
signing time under this key. It does not prove who typed what, and a
developer with the key can sign anything; that is identical to the trust
model of every git commit and stronger than any attest-after service,
because verification is independent of the signer.

## Test vectors

tests/test_code_authorship.py: collection (modified, new, deleted files,
transcript tool calls), sign/verify roundtrip, verification through the
standard chain verifier with no authorship code, tampered payload, wrong
key, missing key, hook end to end over a subprocess, missing transcript
degradation.