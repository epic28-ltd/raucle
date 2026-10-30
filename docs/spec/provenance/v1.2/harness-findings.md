# Harness findings extension (x_finding)

Status: SHIPPED (30 October 2026). Evidence layer per the amended boundary
(strategy sections 16.3 and 16.4): the format, the verifier checks and the
test vectors are public; harness integrations live in the public adapters.

## The problem

Red-team and security harnesses (QM is MIT and free, Pentagon-class runners
the same) produce findings: claims about what a target system did under
test. Today those claims are the harness's own log lines. A third party,
including the buyer's auditor, must take the harness's word. This extension
makes every reported finding a signed receipt that CITES the gate receipt
covering the tested request, so the claim is replay-verifiable offline: the
harness can no longer lie about what happened and still produce verifiable
evidence.

raucle stays the accountability layer beneath the harness. It is not a
competitor harness and does not run tests; it records what the harness
observed, bound to what the gate actually decided.

## The extension block

An x_finding receipt is an authority receipt (guardrail_scan shape, ruleset
hash bound to the extension, as lease and revocation receipts are):

    {
      "action": "reported",
      "finding_id": "finding_<sha256 of (harness, test_id, cited receipt)[:16]>",
      "harness": "qm",
      "test_id": "exfil:oversized-export",
      "verdict": "confirmed" | "refuted" | "expected_pass",
      "cited_receipt": "<receipt_hash of the gate receipt covering the request>",
      "repro": {
        "tool": "<tool called>",
        "args_digest": "<digest of the request args>",
        "expected_decision": "allow" | "deny",
        "actual_decision": "allow" | "deny"
      },
      "detected_at": "<unix int>",
      "note": "<free text, optional>"
    }

Design rules:

- Emission is the harness's CLAIM. `RaucleGateway.emit_finding()` records
  what the harness says without checking it against the store, deliberately.
  Enforcement lives in the offline verifier, where the auditor checks it.
- The verdict vocabulary is closed (confirmed, refuted, expected_pass).
  An arbitrary status word is refused at emission; the verifier has
  semantics for exactly these three.
- The finding id is deterministic in (harness, test_id, cited receipt):
  the same harness run over the same requests replays to the same findings
  ledger.

## The verifier's replay check

The chain verifier re-checks every finding with no harness present:

1. The cited receipt must exist in the chain. A finding citing a ghost
   receipt fails with "cites receipt ... not in the chain".
2. The decision the harness reports as observed must match the decision
   the cited receipt actually recorded (its guardrail_verdict). A finding
   claiming the gate denied a call the chain shows was allowed fails with
   "misreports the cited receipt".

These are the same offline guarantees a delegation or lease receipt gets:
the evidence is checked, not trusted.

## Acceptance (pinned by tests/test_harness_findings.py)

- A QM-class run over the gate: an allowed request, a denied request, a
  confirmed finding (expected deny, observed allow) citing the allowed
  receipt, a refuted finding citing the denied receipt, and an
  expected_pass finding, all verify offline as one chain.
- A finding that misreports the gate's decision fails verification with a
  named error.
- A finding citing a receipt not in the chain fails verification with a
  named error.
- The verdict vocabulary is closed at emission.
- Repeated emission of the same (harness, test_id, cited receipt) yields
  the same finding id.