# Compliance evidence pack v1 (spec)

Status: SPEC (agent-authored, 30 October 2026). Build target: after the LASR
submission window (5 to 6 November 2026). Companion to the strategy doc's
section 17 (30 October 2026) and the research reports cited below.

## The problem

The buyer of an agent gate is rarely the developer who installs it. It is the
person who must answer a supervisor, an auditor or a certification body: prove
what the agents did, prove who authorised it, prove the record has not been
tampered with, and prove all of it to someone who has no reason to trust the
vendor. The receipts already answer the first two questions offline. The pack
turns those answers into the named artefacts the buyer's regime actually asks
for, and binds them with a certificate the buyer's auditor can check.

## What already ships (verified against the repo this session)

- `raucle/compliance.py`: a framework registry (`eu-ai-act`, `iso-42001`,
  `soc2`), control evaluators (signed logs, access control, monitoring,
  human oversight, robustness), `build_report()` mapping a receipt chain to a
  framework's controls, and markdown rendering.
- CLI: `raucle compliance report --chain ... --framework ...`.
- The offline verifier (`raucle/provenance.py`) over the whole receipt chain.
- The why() query (raucle-cloud): receipt id to complete decision, reason,
  rule, and authority chain walked to root.

Nothing in this spec reinvents any of that. The pack builds on them.

## The pack

One command produces a bundle directory:

    raucle compliance pack --chain receipts.jsonl --framework dora \
        --operator-key operator.pem --out pack-dora-2026-11/

The bundle contains:

- `report.md`: the existing compliance report rendering, unchanged.
- `coverage.json`: machine-readable control results, unchanged shape, plus
  the citations per control (regulation text URL).
- `extracts.jsonl`: bounded decision extracts, one line per control
  evidence point. Bounded disclosure as the /gate route already practises:
  field names and digests, never secret material. Each extract cites the
  receipt id it came from so the auditor can pull the full receipt from the
  chain.
- `retention.json`: the chain's observed time span (first and last receipt
  timestamps, count), measured against the regime's retention expectation.
  The EU AI Act deployer duty (Article 26(6)) keeps logs for at least six
  months; DORA's RTS leaves the period to the entity's risk assessment, so
  the pack records the span and states the expectation rather than grading
  what the entity must decide.
- `certificate.json`: the verification certificate, below.

## The verification certificate

The certificate is itself a signed receipt, so the auditor needs nothing from
raucle to check it: the public verifier over the chain, plus the certificate's
own signature. Extension block `x_compliance`:

    {
      "action": "certified",
      "pack_hash": "<sha256 of coverage.json + extracts.jsonl + retention.json>",
      "chain_digest": "<sha256 of the receipt chain file>",
      "framework": "dora",
      "controls_covered": ["RTS-12(2)(c)", "RTS-12(2)(d)", ...],
      "receipt_count": <int>,
      "chain_span": {"first": "<iso8601>", "last": "<iso8601>"},
      "verifier_result": "valid",
      "generated_at": "<unix int>"
    }

Rules:

- The certificate is emitted through the existing authority-receipt machinery
  (guardrail_scan shape, ruleset hash bound to the extension, as the lease and
  revocation receipts already do).
- `verifier_result` states only what the verifier actually returned. A chain
  that fails verification gets `verifier_result: "invalid"` and the pack says
  so on its first line. The pack never upgrades a failed chain.
- The certificate verifies offline with the standard chain verifier. No
  account, no trust in the vendor, no call home.

## New frameworks

### dora

Market shorthand calls it "DORA Article 12". The logging obligation is
Article 12 of Commission Delegated Regulation (EU) 2024/1774 (the RTS to the
DORA ICT risk framework), not Article 12 of DORA itself; the pack's control
ids use `RTS-12(...)` to stay precise. DORA (Regulation (EU) 2022/2554)
applies since 17 January 2025 to banks, insurers, investment firms, payment
institutions and crypto-asset service providers
(https://www.eiopa.europa.eu/digital-operational-resilience-act-dora_en).

Controls, with sources:

- `RTS-12(2)(c)`: logging of access control, identity management and ICT
  operations events. Evidence: every gate receipt is an access-control event
  for a non-human identity; the pack counts identity-attributed decisions
  (allow and deny) and cites the receipt ids.
- `RTS-12(2)(d)`: protection of logs "against tampering, deletion, and
  unauthorised access at rest, in transit and, where relevant, in use"
  (https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774).
  Evidence: the chain verifier result (signature verification over every
  receipt, parent links, taint monotonicity). This is the control our signed
  chain answers most directly: tampering is detectable, not merely
  discouraged.
- `RTS-12(4)`: retention period proportionate to the entity's risk
  assessment. Evidence: retention.json states the observed span; the pack
  does not invent a number the regulation leaves to the entity.
- FSB expectations (supervisory guidance, not statute): attribution of
  actions to specific agents and the ability to know "whether it acted
  within its permissions throughout this chain of steps"
  (https://www.fsb.org/uploads/P151026-1.pdf). Evidence: the why() answers
  in extracts.jsonl, each showing the delegation chain and the rule that
  decided.

### soc2-aiuc1

The AICPA and AIUC announced the combined SOC 2 + AIUC-1 offering on 19
October 2026; AIUC-1 is described as the first standard for AI agent safety,
security and reliability, with full launch expected early 2027
(https://www.aicpa-cima.com/news/article/auditors-meet-urgent-demand-for-ai-assurance-with-new-offering-from-aicpa-and-aiuc).
Practitioner guidance stresses "the quality of retained evidence before the
examination begins" and a SOC 2 to AIUC-1 crosswalk
(https://schneiderdowns.com/our-thoughts-on/a-new-ai-assurance-offering-signals-a-more-structured-market-for-ai-controls).

The pack ships as `soc2-aiuc1` built on the existing `soc2` evaluators plus
the agent-specific layers: attribution (every action carries an acting
identity), least privilege (narrowing invariant evidence: child scopes never
wider than parent), revocation (cascade events in the chain), and evidence
integrity (the certificate). Before the build, pin the exact AIUC-1 control
list from the published standard: the consortium's control text is behind the
AICPA material and this spec will not guess it. That pinning is a research
action in the build session, and the evaluator maps only the controls the
text actually names.

## Public and private (the amended boundary)

Per strategy sections 16.3 and 16.4 (SonarSource boundary):

- Public (this repo): the framework registry, control evaluators, the pack
  format, the x_compliance certificate format, verifier support, test
  vectors. An auditor must be able to check the mapping and the certificate
  without trusting the vendor, so the mapping is evidence, not operations.
- Private (raucle-cloud): the pack generation workflows (scheduled packs,
  the managed bundling, delivery to the customer's auditor, retention
  storage), the auditor portal, enterprise reporting surfaces.

## CLI surface

    raucle compliance pack --chain CHAIN --framework {dora,eu-ai-act,iso-42001,soc2,soc2-aiuc1}
        [--operator-key PEM] [--out DIR] [--cert-out PATH]

`--operator-key` signs the certificate with the operator's key when given;
without it the pack renders unauthenticated (the report marks this) and the
caller can sign later. Exit code is non-zero if the chain fails verification.

## Acceptance tests

1. A green chain produces a bundle whose certificate verifies with the
   standard offline verifier, and whose pack_hash recomputes from the
   bundle files.
2. A tampered chain (one receipt byte flipped) produces a non-verifying
   certificate with verifier_result "invalid", and the command exits
   non-zero.
3. The dora pack on a chain with signed gate receipts reports RTS-12(2)(d)
   as satisfied by signature verification, not by assertion.
4. extracts.jsonl contains no secret material and no full constraint
   values, only the bounded disclosure fields; every line cites a receipt
   id that exists in the chain.
5. retention.json states the observed span; for eu-ai-act the pack flags a
   span under six months as below the Article 26(6) expectation.
6. The existing `compliance report` behaviour is unchanged (regression).

## Phasing

- Phase 1 (the build session): the dora framework, the pack command, the
  certificate, the tests above. This is the whole of the first build.
- Phase 2: soc2-aiuc1 once the control list is pinned; the auditor portal
  in raucle-cloud (drop a chain, get a signed verification report, no
  account).
- Phase 3: align the certificate format with the IETF compliance-receipts
  drafts and aim this verifier at reference implementation status.

## Sources

- DORA and the RTS logging standard:
  https://eur-lex.europa.eu/eli/reg/2022/2554/oj and
  https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774
- FSB Sound Practices (October 2026):
  https://www.fsb.org/uploads/P151026-1.pdf
- NCSC agentic AI guidance (August 2026):
  https://www.ncsc.gov.uk/sites/default/files/2026-08/Managing-the-cyber-risk-of-agentic-AI_0.pdf
- AICPA/AIUC announcement (19 October 2026):
  https://www.aicpa-cima.com/news/article/auditors-meet-urgent-demand-for-ai-assurance-with-new-offering-from-aicpa-and-aiuc
- Gartner spending forecast (16 September 2026):
  https://www.gartner.com/en/newsroom/press-releases/2026-09-16-gartner-forecasts-worldwide-ai-spending-to-grow-49-point-5-percent-in-2026
- Full landscape with primary sources:
  ~/Projects/research-2026-10-30-regulatory-buyer-evidence.md (this path is
  internal; the regulation URLs above are the citable form)