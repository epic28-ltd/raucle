# Advisor classifier (v1): optional LLM advisory detector beside the deterministic gate

Status: accepted 18 November 2026. EPIC Q lane Q1a (design slice; owner GO 17
November 2026, "advisory classifier layer yes"). The finding shape this
document specifies rides the existing `x_finding` machinery
([provenance/v1.2/harness-findings.md](provenance/v1.2/harness-findings.md));
the content vantage it requires is the EE proxy runtime
([ee-proxy-runtime-v1.md](ee-proxy-runtime-v1.md)). This specification
requires no OSS code change; every OSS surface it names is shipped on main.

## What this component is

An optional LLM classifier, hosted in the customer estate, running BESIDE the
deterministic gate. It classifies agent content planes (prompt and response
payloads that flow through the EE proxy) for suspected jailbreak attempts,
prompt injection and intent drift, and reports each suspicion as an ADVISORY
finding: a signed `x_finding` receipt citing the gate receipt that covered
the classified call. It never enforces, never decides, never widens or
narrows anything. Detection quality depends entirely on the model the
customer points it at (BYOM per Q5); integrity depends on nothing the
classifier does.

The gate is a tool-call gate and never sees prompt or response content, so
the classifier has nothing to classify until a content vantage hands it
payload text. In v1 that vantage is the EE proxy runtime: its routes already
normalise request and response payloads and retain the gate receipt id for
each call. The classifier is a consumer of those normalised payloads, not a
component of the gate and not a module of the proxy's in-path evaluation.

## Motivation (the evidence line)

Two independent evidence strands rule the design:

1. LLM judges are probabilistic detectors. The ScopeJudge study
   (Dreadnode, July 2026; arXiv:2607.07774) tested eight runtime LLM judges
   against 4,897 offensive security tool calls: the best judge still missed
   more than 1 in 10 tool-scope violations. A verdict like that cannot anchor
   a receipt a third party verifies. A receipt is a reproducible,
   deterministic claim; a classifier score is neither, and even pinned
   temperature and seed do not make model inference a deterministic decision
   surface (provider-side version drift, hardware nondeterminism).
2. Verdicts without receipts are platform-attested evidence. The Drata and
   AGT teardowns (30 October 2026) recorded the same gap from the other
   side: governance products whose evidence is trustworthy only through the
   vendor's platform, with no published crypto spec and no offline
   verification path a third party can run.

So the composition is fixed by evidence, not preference: the deterministic,
declarative rules stay the receipted, fail-closed enforcement path; the
classifier is an advisory DETECTOR beside that path, and its findings feed
the rule-authoring loop (H1 Trust Ladder, I1 counterfactual replay, z3 proof
status) where a human promotes a rule before it enforces. This is also the
honest answer to the Varonis Atlas teardown (17 November 2026): their session
policies imply an LLM classifier watching for jailbreaks, but no captured
screen shows the engine, and nothing in a staged demo proves the classifier's
verdicts are evidence. Raucle can run the same detection class and still
prove what happened, because the classifier only ever adds advisory findings
to a chain the gate owns.

## Terms

- **Advisor**: one configured classifier instance. It has an `advisor_id`, a
  model endpoint, a disclosed model family and a versioned prompt.
- **Content vantage**: the component that sees payload text. In v1 the EE
  proxy runtime is the only vantage; its normalised request and response
  records (ee-proxy-runtime-v1 canonical shapes) are the advisor's inputs.
- **Dispatch**: one bounded handoff from the vantage to the advisor: the
  payload text, the direction, the citation (gate receipt id and recorded
  decision), and the session and trace ids the call declared. Dispatches are
  asynchronous and bounded; the advisor never blocks the proxy path.
- **Advisory finding**: one `x_finding` receipt minted through
  `RaucleGateway.emit_finding`, reporting one suspected category over one
  cited gate receipt.
- **Advisory row**: the EE-side record the fleet console and investigation
  board consume: the structured finding metadata plus the receipt hashes.
  QUAL-01 evaluator pattern (advisory, reviewer status, abstains by
  default); never a gate artefact.
- **Rule candidate**: a pointer from a finding to a deterministic rule shape
  the operator might author. A pointer, never a rule: no candidate is ever
  applied, loaded or evaluated without the human promotion path below.

## The ADVISORY-ONLY invariant

Stated as an invariant, enforced by the EE runtime, testable by anyone:

INVARIANT (Q1a): the advisor classifier never participates in enforcement.

1. It calls exactly one gateway surface: `RaucleGateway.emit_finding`. It
   never calls `check_tool_call`, never mints or attenuates capability
   tokens, never writes policy, never revokes.
2. No allow or deny path reads advisor output. A classification changes no
   gate decision, and advisor unavailability degrades detection quality
   only; the gate, the proxy's content controls and every receipt they mint
   are byte-for-byte what they were before the advisor existed (additivity).
3. Advisor findings are evidence-class receipts, never gate receipts. They
   carry the `x_finding` extension and a `finding_confirmed` verdict; they
   have no allow or deny semantics and never count as gate coverage.
4. The only route from an advisory finding to an enforcement rule is the
   human promotion path: operator-authored candidate, Trust Ladder training
   stage, proof status, counterfactual simulation, explicit approval,
   receipted activation. No automated promotion exists.
5. Named test hook for the EE runtime to enforce
   (`services/ee-advisor/tests/test_advisory_only_invariant.py`): (a) an
   import and AST guard that the advisor module reaches no enforcement
   surface; (b) a full classification round trip leaves the gate decision
   bytes unchanged; (c) an unknown category or band from the model produces
   no finding and never a deny; (d) planted secret material passed through
   the classifier appears nowhere in the minted receipt, digests only; (e)
   unparsable model output mints nothing; (f) no code path runs from an
   advisory finding to an active rule without the human promotion step
   (the feed loop ends at a human-approved, receipted promotion, never an
   automatic enrolment).

## The advisory finding shape (rides the EXISTING findings pipeline)

Verified against the shipped code on main: `RaucleGateway.emit_finding`
(raucle/gateway.py) accepts `harness`, `test_id`, `verdict`, `cited_receipt`,
`expected_decision`, `actual_decision`, `tool`, `args_digest` and `note`, and
builds the `x_finding` extension itself. `ProvenanceVerifier._verify_harness_finding`
(raucle/provenance.py) re-checks every finding offline: the cited receipt
must exist in the chain and the reported `actual_decision` must match the
cited receipt's recorded `guardrail_verdict`. The shipped
`raucle/middleware.py` (`ADVISORY_HARNESS = "middleware-advisory"`) is the
precedent: an advisory detector mints findings through this surface with a
bounded metadata note, and uncited observations mint nothing. The advisor
follows that precedent exactly. No new extension, no schema change.

Field mapping (the v1 advisory finding, on the existing x_finding shape):

| Advisory field | Rides as | Rule |
|---|---|---|
| advisor identity | `harness` = `advisor:<advisor_id>` | free string, already the finding-id input, so two advisors flagging the same call mint distinct findings |
| category | `test_id` | one value from the closed v1 vocabulary below; the runtime validates BEFORE emission and refuses unknown categories (no finding, named log) |
| verdict | `verdict` = `confirmed` | the advisor observed what it reports; the anti-fabrication re-check covers the claim against the cited receipt |
| cited gate receipt | `cited_receipt` | mandatory; the gate receipt covering the classified call, retained by the vantage |
| observed gate decision | `repro.actual_decision` and `repro.expected_decision` | copied verbatim from the cited receipt's recorded decision; the advisor makes no counterfactual claim, so expected is pinned to the recorded value |
| evidence digest | `repro.args_digest` | sha256 of the exact payload text classified; NEVER content |
| classified surface | `repro.tool` | the gated tool name from the cited receipt |
| confidence band | `note` (bounded grammar) | one of low, medium, high; banded by design: a float is both noise and illegal in signed canonical JSON, which rejects floats |
| model family disclosure | `note` | the operator-configured disclosure string, verbatim |
| prompt revision | `note` | the versioned prompt identifier the classification ran under |
| rule candidates | `note` | comma-joined candidate ids, or `none`; pointers only |

The `note` grammar is bounded and deterministic (the middleware precedent):

```
advisory classifier finding; advisor_id=<id>; band=<low|medium|high>;
model_family=<disclosed>; prompt_revision=<rev>; rule_candidates=<ids>|none;
bounded disclosure: digests and vocabulary only, never content
```

Emission rules:

- One finding per (advisor, category, cited receipt). The finding id is
  deterministic in those inputs (the shipped rule), so re-classifying the
  same material under the same category replays to the same finding id;
  consumers key on the receipt hash, and the determinism is the replay
  property harness findings already have.
- A finding is minted only when a citation is bound. The offline verifier
  refuses findings citing receipts not in the chain, so an uncited
  classification would be unverifiable evidence; uncited observations are
  logged locally (counts and digests) and mint nothing, exactly as the
  advisory middleware behaves.
- Emission is best effort: a gateway failure is logged and swallowed; it
  never raises into the vantage path.
- Nothing suspected, or a band below the configured minimum, mints nothing.
  Receipts attest classifications that happened, never activity that did not.

### Category vocabulary (closed v1 set)

Chosen from the Atlas categories the deterministic rules cannot see, mapped
to content planes:

| Category | Atlas lineage | What it means |
|---|---|---|
| `suspected_jailbreak` | the Atlas demo's LLM session monitor (owner recollection; no capture shows the engine) | payload text attempting to break the model's or agent's instructions |
| `suspected_injection` | Atlas prompt-injection policies; the D3 injection panel vocabulary | payload text attempting to make the agent follow attacker instructions carried in content |
| `suspected_intent_drift` | Atlas Session Purpose Drift / Intent Drift Detection | content semantics drifting from the session's declared purpose |

Reserved: the vocabulary grows only with an `ee-advisor` schema version bump,
the same rule the `x_dlp` vocabulary uses. The growth direction (Atlas
categories whose content-plane variants have no deterministic observables,
such as cross-turn evasion and unsafe outcome trajectories) is recorded
here, but no v2 names are bound now. Unknown categories are refused at
emission by the EE runtime; the OSS verifier does not and must not re-check
this vocabulary (the classifier vocabulary is EE by the boundary test).

### Delineation from the deterministic session rules

The Q-2 session rules already cover the tool-call-observable variants of
the Atlas categories: repeated-deny-storm (cross-turn evasion),
runaway-tool-loop, gradual-extraction, forbidden_tool_chain and scope-drift
(the tool-call variant of purpose drift). The advisor adds the content-plane
suspicions those rules cannot see and duplicates none of their enforcement
semantics. Where both fire on the same behaviour, the deterministic rule
enforced and the advisor only observed; the board shows both with their
evidence classes labelled, and the deterministic finding wins every
contradiction by construction.

Session semantics: the advisor holds no session state. A finding's session
correlation comes from its cited receipt's `x_gate.session_id` (Q-1, receipt
index v3), so clustering per session is a read over receipts the gate
already minted. The deterministic engine owns session semantics; the advisor
borrows them by citation.

## The rule-authoring feed loop

The only path from a classifier suspicion to an enforcement rule:

1. The advisor mints the advisory finding (evidence class, above).
2. The EE advisory row lands: a QUAL-01-shaped Evaluation entity through the
   pinned investigation-UI intake (deterministic UUID5 id, sha256 evidence
   references naming the finding receipt and the cited gate receipt). The
   row carries the structured metadata: advisor id, category, band, model
   family disclosure, prompt revision, rule candidates.
3. The fleet console clusters rows by (category, session, advisor) and
   shows band mix and rule candidates, labelled advisory.
4. The operator authors a candidate deterministic rule from a cluster: a
   PolicyRule, a SessionRule or an intent narrowing. The advisory finding is
   the motivation, never the rule text. The candidate is born at the Trust
   Ladder training stage.
5. Proof status computes on the candidate (z3: PROVEN, REFUTED or
   UNDECIDED), and the counterfactual simulate machinery (I1 / X6) replays
   the org's historical chains under the candidate with a bounded,
   receipted diff.
6. Explicit operator approval promotes the rule: a receipted activation.
   THE PROMOTION IS THE DETERMINISTIC RECEIPTED STEP. The advisor
   contributed evidence; the enforcement semantics were authored, proved,
   simulated and approved by determinate machinery and a human.
7. After promotion the deterministic rule enforces, and the advisor keeps
   observing: later findings on the same patterns become confirmation the
   rule works, or refutation evidence it does not. The loop closes.

No step in 1 to 3 has any write path into policy, and no code path exists
from an advisory finding to an active rule that skips step 6.

## BYOM contract (ee-advisor/v1)

The configuration is versioned and loaded fail-closed; anything else is a
named boot error. The schema mirrors `ee-proxy-routes/v1` conventions.

```
schema_id: ee-advisor/v1

advisors:
  - id: primary-advisor
    endpoint: https://models.internal.example/v1
    credential_env: ADVISOR_MODEL_KEY
    model_family_disclosed: vllm:llama-3.3-70b-instruct
    temperature: "0.0"
    seed: "1234"
    categories: [suspected_jailbreak, suspected_injection, suspected_intent_drift]
    min_band: medium
    prompt_revision: advisor-prompt-v1
    timeout_seconds: 10
```

Validation rules, all enforced at load; violation is a named boot error:

1. `schema_id` present and exactly `ee-advisor/v1`; unknown schema ids never
   load on guesswork.
2. Advisor ids unique.
3. `endpoint` is `https`, or `http` on a loopback host (the shipped
   HttpGateClient posture: https enforced for non-loopback endpoints).
4. `credential_env` is an environment variable NAME, read at call time; the
   configuration never holds credential values (the ADR-EE-0004 pattern,
   auditable by grep).
5. `model_family_disclosed` is a non-empty string. It is an operator
   disclosure, not a verified fact; the finding records what was disclosed,
   and the honesty note below says what that is worth.
6. `temperature` and `seed` are either a declared value in string form or
   the literal `unknown`. Declaring `unknown` is honest and allowed: it
   states the operator cannot pin the model endpoint's sampling behaviour,
   and the docs say what that means for reproducibility (nothing is
   reproducible either way; see honest limitations).
7. `categories` is a non-empty subset of the closed v1 vocabulary; an
   unknown category refuses the load.
8. `min_band` is one of low, medium, high.
9. `prompt_revision` is required: prompts are versioned configuration, and
   every finding names the revision it ran under.
10. `timeout_seconds` is bounded (1 to 60).

The advisor is model-agnostic: vLLM, Ollama, Azure OpenAI, Bedrock or any
OpenAI-compatible endpoint the customer runs, per-install configuration, no
hosted inference dependency, no phone-home. If the configured endpoint is a
third-party API, the operator has chosen that trust boundary for classified
content; the deployment honesty says so plainly.

## Failure postures (fail-open, advisory by contract)

| Failure | Posture |
|---|---|
| Model endpoint unreachable or slow | no finding, named log, the vantage path never blocked; dispatch queue is bounded and overflow drops with a counter, never backpressure |
| Unparsable model output | no finding, named log; never a deny, never a fabricated band |
| Unknown category or band in model output | refused at emission, no finding, named log (closed vocabulary) |
| No citation bound | no receipt (the middleware precedent), local log only |
| `emit_finding` raises | no finding, logged; never re-raised into the vantage path |
| Advisor service down | detection degrades to absent; the gate and the proxy's content controls are unaffected; surfaced as an honest coverage state in the console, never as a zero claim |

The deliberate contrast with the EE proxy (fail-closed for its configured
content controls) stands: the advisor has no authority, so its failures
cost detection only.

## Threat model deltas

- **Compromised or misbehaving classifier.** The worst case is noise and
  steering. A malicious endpoint can cause false findings (board noise,
  wasted operator attention) or false absences (missed detection). It
  cannot mint a gate receipt, alter a decision, or widen authority: it
  holds no write surface into the deterministic path. A fabricated finding
  must cite a real gate receipt and report its recorded decision honestly
  or it self-invalidates at verification; the residual is a truthful
  finding about real traffic with a wrong category, which is noise plus a
  steering attempt.
- **Steering via rule candidates.** Candidates are pointers only; promotion
  requires an operator-authored rule, proof status, counterfactual replay
  and explicit approval. A poisoned candidate cannot activate without an
  operator action. The residual is named, not hidden: a patient malicious
  classifier could still try to social-engineer an operator through
  clustered false positives; the ladder's evidence requirements and the
  advisory labelling are the mitigation, and a promotion that traces to
  poisoned evidence is detectable in the activation audit trail.
- **Prompt injection into the classifier.** Classified content is
  attacker-controlled. The model's output is parsed as data into the
  closed category and band vocabulary; unparsable output mints nothing.
  Model output never flows into policy text: candidates are pointers, the
  operator authors rules.
- **Content assets.** Payload text lives in the advisor process for the
  dispatch and classification lifetime only; it never enters findings,
  logs or configuration (digests, categories, bands and identifiers only).
  Egress to the configured model endpoint is what classification means;
  the endpoint is customer-chosen (BYOM) and inside the estate by default.
- **Disclosure.** `model_family_disclosed` is an operator claim; nothing
  verifies it. A false disclosure is a configuration-integrity matter for
  the customer, recorded honestly here.
- **Receipt inflation.** Abstentions, below-threshold bands, clean
  classifications and uncited observations mint nothing.
- **Downgrade and removal.** The advisor cannot weaken the deterministic
  path, and removing it restores exactly the pre-advisor behaviour.

## Honest limitations

- **Probabilistic evidence class.** A classifier verdict is not
  reproducible in general, and pinned temperature and seed do not change
  that. The ScopeJudge study (arXiv:2607.07774) measured the best of eight
  runtime judges missing more than 1 in 10 tool-scope violations; that
  number is the caveat this evidence class carries, and advisory-only is
  the evidence-backed posture, not a compromise.
- **Detection quality depends on the customer's chosen model.** Stated
  plainly in EE docs and deployment copy: a weak model degrades detection,
  never integrity.
- **Coverage exists only where a content vantage exists.** In v1 that is
  the EE proxy's configured routes. Calls that bypass the proxy are
  unobserved by the advisor (the standing bypass posture); a gate-only
  deployment has nothing for the advisor to classify.
- **False positives are expected** at every band; findings feed triage, not
  judgements.
- **The offline verifier re-checks anti-fabrication only.** It proves the
  cited receipt is real and honestly reported; it cannot judge whether the
  classification was semantically right. The category vocabulary is
  enforced at EE emission, not by the OSS verifier; that split is the
  boundary test working as ruled, and this document states it rather than
  blurring it.
- **Latency.** Classification is asynchronous; a finding lands after the
  fact. The advisor observes; it does not intervene.

Also stated plainly, mirroring the vocabulary confession above: the verifier re-checks NO category vocabulary for x_finding findings, and x_finding carries NO content-field guard - the sibling x_dlp schema enforces one fail-closed; for advisory findings the never-content rule is emission-side discipline in this contract, honoured by the EE emitter and pinned by the advisory-only invariant test (d), not by the OSS verifier.

## Licence split (the ruled boundary)

The boundary test (owner ruling, 17 November 2026): a thing that mints,
verifies or denies inside the gate, or extends the receipt schema, is an OSS
prerequisite; a thing that operates, visualises, connects or classifies is
EE. Applied:

| Concern | Home | Why |
|---|---|---|
| This specification document | OSS, public | Design language and wire contract over the EXISTING x_finding schema. Customers and third parties must be able to read what the closed component claims. Precedent: ee-proxy-runtime-v1.md and advisory-middleware-v1.md ship in this tree. |
| `x_finding` schema, `emit_finding`, offline anti-fabrication re-check | OSS, already shipped (EPIC D) | Mints and verifies inside the gate; this lane extends nothing. |
| The advisor runtime (dispatch intake, prompt construction, model invocation, vocabulary validation, band mapping, finding emission) | EE, closed | Classifies and operates. |
| `ee-advisor/v1` configuration + credentials | EE, closed | Operates and connects; credential env NAMES only (ADR-EE-0004). |
| Advisory rows, cluster views, console surfaces | EE | Visualises. |
| Candidate rule authoring, Trust Ladder stages, proof status, counterfactual simulate, receipted activation | OSS surfaces, already shipped (H1, I1, X6), consumed by EE UI | The promotion machinery is deterministic and receipted; the advisor only feeds it. |
| Offline verification of advisor findings | OSS verifier, free forever | The R10/R11 line: verification is never the paid surface. |

Validated against the boundary test: nothing in Q1a mints, verifies or
denies inside the gate, and nothing extends the receipt schema. The
alternative design (a new `x_advisor` extension with verifier-rechecked
category and band vocabularies) was rejected deliberately: it would put
classifier semantics inside the frozen verifier, the wrong side of the
boundary test, to gain re-checks the evidence class does not need. The
verifier's job here is anti-fabrication (the cited receipt is real and
honestly reported), and that is already shipped.

If a future revision finds a rule impossible without a gate-side hook, that
hook must be argued as an OSS prerequisite against the boundary test in its
own PR; this document then records it with its justification. Nothing here
invents gateway semantics.

## OSS surfaces consumed (all existing; justification per surface)

| Surface | Status | Why it is sufficient (no OSS change) |
|---|---|---|
| `RaucleGateway.emit_finding(...)` | shipped (EPIC D) | The only minting surface for advisory findings. `harness`, `test_id` and `note` are free strings carrying advisor identity, category and the bounded metadata grammar; the verdict vocabulary is closed at emission; the cited receipt is mandatory. |
| `ProvenanceVerifier._verify_harness_finding` | shipped (EPIC D) | Offline anti-fabrication for free: a finding citing a ghost receipt or misreporting the decision fails with a named error. |
| `raucle/middleware.py` advisory emission pattern | shipped (Q-7c) | The precedent this spec follows: bounded note grammar, uncited observations mint nothing, best-effort emission. |
| `x_gate.session_id` + receipt index v3 | shipped (Q-1) | Session correlation for clusters, read from receipts the gate already minted; the advisor holds no session state. |
| EE proxy canonical request/response records | specified (Q-7b) | The content vantage: payload text, direction and citation per call. The advisor is a consumer of the proxy's normalisation, not a new content path. |
| H1 policy ladder + I1/X6 simulate + proof status | shipped | The promotion machinery: candidate rules, counterfactual replay and receipted activation already exist; the feed loop composes them. |

## Verification

What a third party holding the chain can prove offline, with no advisor, no
model and no proxy present: for every advisory finding, the cited gate
receipt exists in the chain; the decision the finding reports is the
decision the cited receipt recorded; the finding is signed by the gate
identity; the finding id re-derives from (harness, test_id, cited receipt);
and through the cited receipt's `x_gate`, which session and agent the
classification rode with. What no one can prove offline: that the
classification was semantically right. That asymmetry is the design: the
receipt anchors WHAT WAS CLAIMED AND OVER WHAT TRAFFIC, and the honesty
about the claim's quality lives in the band, the disclosure and this
document's limitations, not in a cryptographic promise.
