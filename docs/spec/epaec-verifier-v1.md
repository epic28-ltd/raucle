# EP-AEC verifier v1 (`raucle/epaec.py`)

Status: implemented. Companion module to the provenance receipt machinery.
No compliance claims are made here or anywhere else in raucle; this
document only records what our verifier checks and where each check comes
from in the draft it targets.

## What it is

`raucle/epaec.py` verifies **other implementers'** Authorization Evidence
Chains against `draft-schrock-ep-authorization-evidence-chain-00`:

- it parses an EP-AEC chain object (draft Section 3) — `@version` pinned to
  `EP-AEC-v1`, an `action` object, an optional `action_digest`, a
  non-empty `components` array (`type`, `evidence`, optional `label`),
  and a Boolean `requirement` string;
- it binds every component receipt to the same canonical action digest
  (recomputed over the JCS/canonical-JSON form of `action`, reusing
  `raucle.nelson14.canonicalise_body` — the shared RFC 8785 canonicaliser
  — so digests are byte-identical across implementations);
- it evaluates the chain's requirement expression **fail-closed** with a
  bounded parser (draft Section 5): an operator outside the grammar, an
  unparseable token sequence, or a requirement that exceeds the parser's
  length/depth bounds fails the chain with a named reason; unknown
  identifiers evaluate false;
- it produces a deterministic verification object: per-component
  `VALID` / `INVALID` / `UNVERIFIED` with a named reason for anything not
  `VALID`, a satisfaction list, `decision` (`ALLOW`/`DENY` per the
  draft) and `overall` (`PASS`/`FAIL`); the bytes are canonical and
  stable (`epaec.result_bytes`).

## The fail-closed walk — check → draft mapping

| Verifier check | Draft reference | Failure named | Effect |
| --- | --- | --- | --- |
| chain is a JSON object | §4 step 1 | `BAD_CHAIN_TYPE` | DENY |
| `@version` is exactly `EP-AEC-v1` | §3, §4 step 1 | `BAD_VERSION` | DENY |
| `action` present and an object | §3, §4 step 1 | `BAD_ACTION` | DENY |
| `components` non-empty array, each with non-empty `type`, `evidence`, string `label` | §3, §4 step 1 | `BAD_COMPONENT`, `DUPLICATE_COMPONENT_TYPE` | DENY |
| `requirement` present and non-empty | §3, §4 step 1 | `BAD_REQUIREMENT` | DENY |
| unknown top-level fields rejected, never ignored | §4 step 1 discipline | `UNKNOWN_CHAIN_FIELD` | DENY |
| `action_digest`, when present, equals the recomputed canonical digest | §3, §4 step 2 | `ACTION_DIGEST_MISMATCH`, `BAD_ACTION_DIGEST` | DENY (fatal) |
| canonical digest recomputed over JCS form of `action` | §3 ("components reference the same action by digest"), §4 step 2 | `BAD_ACTION` | DENY |
| no verifier registered for a component type | §4 step 3a, §7 (an unconfigured type is unsatisfied, never assumed) | component `UNVERIFIED` / reason `no verifier registered for type` | unsatisfied |
| verifier exception | §4 step 3b, step 5 | component `INVALID` / `verifier raised: …` | unsatisfied |
| verified only if `valid` **and** bound digest equals the chain digest | §4 step 3c (cross-binding defense) | component `INVALID` / reason `binds a different action`, or `receipt rejected: <code>` | unsatisfied |
| satisfied component adds `type` and `label` to the satisfied set | §4 step 3d | — | feeds §4 step 4 |
| requirement is a bounded AND/OR/parentheses/IDENT expression; unknown identifier false | §5 | `REQUIREMENT_UNBALANCED`, `REQUIREMENT_PARSE_ERROR`, `BAD_REQUIREMENT_TOKEN`, `REQUIREMENT_TOO_LONG`, `REQUIREMENT_DEPTH_EXCEEDED` | DENY |
| any unexpected error at any step | §4 step 5 | the named code above | DENY |

The walker never raises: every failure path returns a `DENY`/`FAIL` result
with a machine-readable reason, so audit tooling sees the same shape as a
pass.

## Requirement-expression limits

Draft §5 requires a bounded parser, not a general-purpose evaluator. Our
limits, enforced before evaluation:

- `_MAX_REQUIREMENT_LEN = 1024` characters — anything longer is
  `REQUIREMENT_TOO_LONG`;
- `_MAX_DEPTH = 16` nesting levels of parentheses — anything deeper is
  `REQUIREMENT_DEPTH_EXCEEDED`;
- the grammar is exactly `expr := term (('AND' | 'OR') term)*`, `term :=
  '(' expr ')' | IDENT`, folded left-associatively (the draft's grammar
  states no AND-over-OR precedence, so `a OR b AND c` is evaluated as
  `(a OR b) AND c` — see `tests/test_epaec.py::test_left_associative_mixed_precedence`);
- identifiers match `[A-Za-z0-9@._-]+` after tokenisation; every other
  character is a named token error.

## Component verifiers and the JWS receipt profile

Component verification is delegated, not reimplemented:

- the relying party configures verifiers keyed by component `type`
  (§7, verifier trust — keys and verifiers are pinned explicitly);
  the reference verifier for the JWS receipt profile is
  `epaec.make_receipt_verifier(jwk_for)`;
- `epaec.verify_receipt_jws(compact, jwk)` delegates `drp-receipt`-typed
  receipts **verbatim** to `raucle.nelson14.verify_jws` (strict header /
  alg / JCS / raw R||S signature checks) — raucle does not maintain a
  second JWS path for those;
- other ES256 receipts of this profile are verified with the same
  `raucle.nelson14` ES256 primitive plus a JCS payload-equivalence check
  (`RECEIPT_NON_CANONICAL`); `alg: none` and non-ES256 algorithms are
  rejected out of profile;
- a receipt binds an action iff its body carries `actionDigest:
  "sha256:<hex>"` — that value is what step 3c compares against the
  chain digest.

## Composition with existing raucle verify primitives

- canonical JSON / digest: `raucle._canon` + `raucle.nelson14.canonicalise_body`
  (shared RFC 8785 / UTF-16 ordering profile — the byte-identity invariant the
  draft's §7 cross-binding defense rests on);
- JWS parse/signature: `raucle.nelson14.parse_jws`, `verify_jws`,
  `_es256_verify`, `_es256_sign`;
- receipt issuance for tests/vectors: `epaec.sign_receipt_jws`.

## Conformance vectors (for N10)

`tests/vectors/epaec-v1.json` is the corpus vector set: eight issued
chains (self-contained, ES256-signed once at generation time — ECDSA is
randomised, so verification never re-signs) with expected
decision/overall/statuses/reasons. Regenerate with
`python tools/make_epaec_vectors.py`. Vectors covered:

`valid_e2e`, `valid_or_expression`, `tampered_digest`,
`cross_binding`, `unknown_operator`, `unexpected_character`,
`unknown_identifier_falsy`, `missing_verifier`.

## Scope and non-claims

- We verify chains per the -00 draft's algorithm. We make no compliance
  claim about EP-AEC generally, and this verifier targets -00 only.
- EP-AEC composes point-in-time evidence; freshness and revocation
  remain the relying party's policy (draft §7) — out of scope here.
- The executor's separate AUTHORIZED decision is out of scope by
  construction (the verifier returns ALLOW/DENY on the presented chain,
  nothing more).
