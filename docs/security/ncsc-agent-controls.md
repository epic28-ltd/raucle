# NCSC agent-control matrix: controls mapped to receipted evidence

The NCSC's agentic AI deployment guidance (May 2026) sets the bar plainly:

> "If you cannot understand, monitor or contain an agent's actions, it is not
> ready for deployment."

This document is the machine-checkable half of that conversation. Each named
control is mapped to a workflow in the running product and to the receipt
artefact that proves it, and each row has a passing test in
`tests/test_ncsc_agent_controls.py`. A reader does not have to trust the
table: run the suite and the controls re-verify themselves.

The mapping deliberately reuses the authority-attribution fixtures
(`tests/test_authority_attribution.py`), so the matrix cannot drift from the
product behaviour it claims to evidence: a change to any of these flows fails
here too.

Run it yourself:

```bash
python -m pytest tests/test_ncsc_agent_controls.py -v
# 9 passed: one completeness check, one test per control
```

## The matrix

| # | NCSC control theme (agentic AI guidance) | Shipped raucle answer | Receipt artefact asserted | Test |
|---|---|---|---|---|
| 1 | Least privilege: agents hold no standing authority | Authority enters through per-use issued credentials and TTL-scoped, tool-scoped policy; authority was in the request, not on the machine | Allow receipt binds the acting agent and tool in `x_gate` | `test_control_1_least_privilege` |
| 2 | Limit scope | Out-of-policy tools, unknown tools and out-of-constraint arguments are denied, and the denial is itself receipted | Deny receipts (`sha256:` ids) for out-of-scope and unknown-tool calls | `test_control_2_scoped_denial` |
| 3 | Monitor behaviour | Every decision, allow or deny or escalate, is a signed, hash-chained receipt that verifies offline with the standard `ProvenanceVerifier` | Chain report `valid`; the receipt id returned to the caller is inside the verified chain | `test_control_3_signed_chain` |
| 4 | Named accountability: someone who can stop it | Role separation (operator suspend is a 403), admin suspend, immediate credential revocation, and the stop is evidence: actor, reason, receipt id | Stop receipt carries `x_stop` with `agent_id`, `reason`, `actor`; subsequent calls deny as revoked | `test_control_4_named_stop` |
| 5 | High-impact actions need a human | `require_approval_when` escalates; the human decision is a receipt naming the approver; the approval binds the exact arguments and is consumed once | Request, decision (approver) and action receipts (`x_approval`, `x_gate.approval_id`) | `test_control_5_human_approval` |
| 6 | Prove the authority held and what could be used | Authority envelope: a signed snapshot of the agent's policies and credential state | Envelope JWS `typ: raucle/authority-envelope/v1`, tools listed, credential state | `test_control_6_envelope` |
| 7 | Tamper-evident records for incident readiness | Policy ledger detects a forged actor; receipts bind a ruleset hash, so an action without its receipt is provable | Ledger integrity flips to invalid on tampering | `test_control_7_tamper_detection` |
| 8 | Traceable governance: who changed the rules | Every policy edit is a hash-chained ledger entry with actor, action, sha256 and prev_hash | Ledger entry fields; integrity valid when untouched | `test_control_8_policy_ledger` |

## What this does and does not claim

- The matrix maps controls named in the NCSC guidance's deployment test and its surrounding control areas, as evidenced by the product's own test suite. It is not a certification and not an attestation; it is the evidence layer a certification body or assessor can re-run.
- Raucle is the agent governance layer: it does not replace endpoint hardening, network resilience or user training. The wider CAF v3.2 mapping, including what is out of scope, is maintained separately in `docs/security/ncsc-caf-mapping.md`.
- Receipts carry hybrid Ed25519 plus ML-DSA-65 (FIPS 204) signatures, so this evidence remains verifiable against future cryptographic adversarial capability; see `docs/security/quantum-readiness.md`.

## Receipt anatomy referenced above

- `guardrail_verdict`: the decision (allow, deny, escalate, approvals granted or requested)
- `x_gate`: the bound tool, acting agent, reason; `approval_id` when the action rode an approval
- `x_approval`: requests and human decisions (bound exact args, approver, single use)
- `x_stop`: the emergency stop (agent, reason, actor)
- the authority envelope: `typ: raucle/authority-envelope/v1`