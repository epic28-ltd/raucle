# Receipts v1.2: content DLP extension (x_dlp)

Status: accepted 17 November 2026. Backwards compatible: receipts without
the extension are unaffected.

## What it binds

An in-path content scanner (an enterprise LLM endpoint proxy sitting between
an agent and a model or tool) inspects prompt and response traffic for
sensitive material: card numbers, email addresses, national identifiers,
bearer tokens. Every scan decision is a receipt carrying an `x_dlp`
extension, minted by the proxy through the gateway's authority-receipt
emitter. The gateway never sees the content and never runs the scanner; it
is the evidence layer that makes the scanner's claim replay-verifiable
offline.

The extension carries digests, class names and counts only. It never
carries content:

- no matched values, snippets or excerpts of any kind;
- digests instead of content (the scanned payload and, after redaction, the
  redacted payload both appear only as sha256 digests);
- route identifiers describing the endpoints, never the payload.

A third party can prove: what was scanned (by digest), in which direction,
which pattern classes matched, how many spans matched, what the policy
decided and, on redaction, that the effective outbound content differed
from the scanned content - without ever holding the content.

## The extension block

    x_dlp = {
      "action": "blocked" | "redacted" | "allowed_with_findings",
      "scan_id": "scan:<hex>",
      "route": {"source": "<source identifier>", "destination": "<destination identifier>"},
      "direction": "egress_to_model" | "ingress_from_model" | "egress_to_tool",
      "content_sha256": "sha256:<digest of the scanned content>",
      "matched_classes": ["pii_card", "pii_email", ...],
      "span_counts": {"pii_card": 2, "pii_email": 1},
      "rule_id": "<the policy rule applied>",
      "redacted_content_sha256": "sha256:<digest of the post-redaction content>",
      "cited_receipt": "<receipt_hash, present when the scan ran through the gate path>"
    }

Field rules:

- **direction** is the closed vocabulary `egress_to_model`,
  `ingress_from_model`, `egress_to_tool`. An arbitrary direction is
  refused.
- **matched_classes** is a bounded, versioned vocabulary
  (`_DLP_MATCHED_CLASSES` in the verifier: `pii_card`, `pii_email`,
  `pci_pan`, `secret_bearer`, `pii_national_id`). Unknown classes fail
  verification; the vocabulary grows only with a schema-version bump so
  older verifiers fail-closed on newer chains rather than silently widening
  disclosure.
- **span_counts** keys must draw from the same vocabulary and be
  non-negative integers. A class with a span count should appear in
  `matched_classes`; `span_counts` without a matching class entry is a
  structural error.
- **redacted_content_sha256** is present if and only if
  `action = "redacted"`; a redaction without the post-redaction digest (or
  a non-redaction action carrying one) fails verification.
- **cited_receipt** is optional: a scan that ran inline through the gate
  path cites the gate receipt covering the request. A citation must name a
  receipt present in the chain, like every other extension citation.
- **digests** are sha256-shaped: the `sha256:` prefix plus 64 hex
  characters. The scanned content never appears in the receipt, and the
  emitting proxy computes `content_sha256` as the sha256 of the exact bytes
  it inspected; a test fixture passes a payload separately and the digest
  is checked against a locally computed sha256 of those bytes, so the
  digest binds the actual inspected content, not a placeholder.

## Disclosure boundary (bounded disclosure)

Counts, digests, class names and endpoint identifiers only. The class
vocabulary is pattern classes, never match samples. The verifier itself
never receives content: it re-checks structure, vocabulary, count sanity,
digest shape and chain membership from the signed payload alone. A payload
carrying a content-like field (`matched_value`, `content`, `snippet`,
`match_text`, `excerpt`, `sample`, `verbatim`) fails verification with a
named error, so a leaky emitter cannot hide content inside a signed
extension.

## Homes (the 16.3 split)

- Evidence layer (this document, the verifier rules, the test vectors):
  OSS, public.
- Proxy runtime, redaction engine, per-route policies: enterprise edition
  (EE), built closed. The gateway method `emit_dlp_finding` is the OSS
  emitter surface: a client mints receipts through it; it performs no
  scanning itself and never receives content - only the already-mined
  extension fields.

## Verification rules (offline, no scanner required)

The chain verifier re-checks every `x_dlp` receipt with no scanner present:

1. Structure: every required field present and of the right shape; action
   and direction inside their closed vocabularies; `redacted_content_sha256`
   consistent with the action; digests sha256-shaped; span counts
   non-negative integers agreeing with `matched_classes`.
2. Vocabulary: matched classes and span-count keys inside the versioned
   bounded list; unknown classes fail.
3. No content-like fields anywhere in the extension block (fail-closed
   against leaking matched values into signed evidence).
4. Chain membership: a cited receipt must exist in the chain; a scan citing
   a ghost receipt fails with a named error.

Receipts without `x_dlp` verify exactly as before; the check is additive.

## Emission

`RaucleGateway.emit_dlp_finding(...)` mints an `x_dlp` authority receipt
(guardrail_scan shape, `verdict` naming the action, `ruleset_hash` bound to
the extension, as `x_finding`, `x_lease` and revocation receipts are). The
proxy is the scanner's client; it validates nothing the verifier does not
re-check offline, and it refuses an action, a direction or a matched class
outside the bounded vocabularies at emission, mirroring the verifier's
closed sets.

## Test vectors

tests/test_dlp_receipts.py: a valid receipt (with a cited decision receipt)
verifies offline through ProvenanceVerifier; structural violations fail
with named errors (missing field, bad digest shape, unknown class,
content-like field present); citation membership enforced; tamper of the
x_dlp payload fails; a legacy chain with no x_dlp verifies unchanged;
content_sha256 equals a locally computed sha256 of a separately supplied
fixture payload.
