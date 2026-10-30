# Time source v1: the three-mode model

Status: accepted 30 October 2026. Companion to the provenance receipts
specification (v1, v1.2 extensions). Backwards compatible: receipts
without an `x_timestamp` extension are unaffected.

Most vendors hide the time-source trust question. Raucle states it. Every
receipt carries a time; this document says where that time comes from,
what it can prove, and what it cannot. There are three modes and they are
documented, not discovered.

## Mode 1: internal (the default)

The receipt's `iat` and the gate's recorded timestamps come from the host
clock under a documented discipline. No extension is added to the
receipt; the evidence claim is:

  "This decision was recorded at host time T, on a clock disciplined by D,
  operating to a stated bound of B."

Discipline contract (the operator's statement, kept with the deployment
documentation and the compliance evidence pack):

- Disciplined clock source: NTP (pool or internal stratum) or NTS. chrony
  is the reference implementation; `chronyc tracking` provides the live
  evidence (last offset, root delay, root dispersion, stratum).
- Bound: a LAN-hosted chrony client typically holds within 100 ms of its
  source; an NTS pool client within low hundreds of milliseconds. The
  operator states the bound they operate to and carries it in the pack;
  the evidence claim is bounded by it, never by "the true time".
- What internal mode can claim: the ordering and approximate wall-clock
  time of decisions, protected against tampering by the signature chain.
- What internal mode cannot claim: independence from the host. An
  attacker with host control can set the clock; the chain still proves
  what was recorded, not when it truly happened. That gap is why the
  other two modes exist.

## Mode 2: TSA-attested (RFC 3161)

An external timestamp authority stamps a digest the operator supplies.
The TSA is CUSTOMER-CHOSEN; raucle is TSA-agnostic by design: the wire
format is RFC 3161, so any conformant TSA works. This is a deliberate
differentiator against every competitor with a vendor-locked time source.

Hash-only, always: the TimeStampReq carries a SHA-256 digest and nothing
else. No payload material, no arguments, no policy content ever reaches
the TSA. This matches the privacy-by-default receipts design; a TSA sees
a 32-byte value it cannot invert.

### Landscape (facts from the 30 October 2026 research; verify prices
before quoting any of them to a buyer)

- EU QTSPs whose tokens carry the eIDAS Art 41 presumption of correctness
  for EU buyers: TrustPro (IE, granted 2023), Adobe Qualified Timestamp
  CA, Entaksi, Namirial, AlfaTrust (qtsa.eu, hash-only, 1.2M-stamp packs,
  24-month validity).
- Indicative pricing at volume: around EUR 0.02 to 0.15 per timestamp
  (InfoCert/Aruba lots via the Openapi API; the low end with own
  batching). SSL.com C2PA TSA: free tier 2,500 timestamps per year.
  Entrust: contract-priced.
- Sigstore timestamp-authority: open source, self-hostable RFC 3161 TSA.
  Vendor-free, fits the raucle positioning and the existing Sigstore
  narrative. NOT eIDAS-qualified by default: a self-hosted Sigstore TSA
  gives you a cryptographically sound third-party time attestation, not
  the Art 41 legal presumption. For a regulated EU buyer who needs the
  presumption, the QTSP route is the add-on; for a sovereign or
  cost-sensitive deployment, the self-hosted route is the default.
- Monetisation (the F2 decision): QTSP anchoring is sold as pass-through
  plus margin for EU buyers; the self-hosted mode uses the Sigstore TSA
  (no margin, no vendor).

### The anchor receipt (x_timestamp)

Anchoring is a ledger event, receipted like every other lifecycle event.
The anchor binds a digest to an RFC 3161 token and cites the receipt it
anchors:

```
x_timestamp = {
    "mode": "tsa",
    "digest": "sha256:<sha256 over the EXACT cited ledger line bytes>",
    "parent_receipt": "<receipt_hash of the chain head being anchored>",
    "tsa": "<the TSA endpoint the operator chose>",
    "nonce": <52-bit positive integer>,
    "token": "<base64 DER TimeStampToken, embedded>",
    "gen_time": "<TSTInfo genTime, ISO 8601>",
    "serial": <TSTInfo serialNumber>,
    "policy": "<TSTInfo policy OID>",
}
```

The anchor digest is sha256 over the exact cited ledger line bytes as
they live in the JSONL file. Consequence: chain exports MUST preserve
lines verbatim, or the anchor no longer re-derives and must be re-minted
against the re-serialised chain. The export tooling preserves lines;
auditors re-anchoring a re-serialised copy must stamp it fresh.

Anchors are appended to the chain they cite (append-only ledger
discipline). Per-receipt stamping of every gate decision is possible but
economically wrong at EUR 0.02 to 0.15 per token; the designed cadence is
periodic (for example hourly or daily) anchoring of the chain head, which
attests the entire history before it.

### Verification rules (offline, no TSA contact)

The chain verifier re-checks every x_timestamp it walks:

1. The recorded digest must bind the receipt's own `input_hash`
   (mismatch: "digest does not bind the receipt input_hash").
2. The cited parent must exist EARLIER in the chain being verified
   (mismatch: "cites receipt not in the chain"; ghost-citing fails like
   x_finding).
3. The digest must re-derive from the cited raw ledger line ("digest does
   not re-derive from the cited ledger line").
4. The embedded TimeStampToken must pass its own re-check, each failure
   named: CMS structure is SignedData with TSTInfo; the message imprint
   equals the recorded digest; the nonce matches; the RFC 3161 mandatory
   signed attributes are present (contentType, messageDigest) and
   consistent; genTime falls inside the TSA certificate's validity
   window; the TSA signature verifies (RSA PKCS1v15, ECDSA or Ed25519
   over the SET-encoded signed attributes); an optional pinned TSA key
   must match the token's signer key.
5. The recorded gen_time must equal the token's genTime (a post-hoc edit
   of the recorded field fails).

Fail-closed on the parser: a receipt claiming a TSA token in an install
without the `raucle[timestamp]` extra (asn1crypto) verifies INVALID with
a named error. An attestation that cannot be re-checked never verifies as
attested; bad evidence is never upgraded.

Standalone verification of the anchor file (no chain supplied) checks the
operator signature, the token re-check and the internal digest
consistency, and records that the parent cite was "not re-checked
(standalone)". Supply the chain for the full check; the CLI accepts it.

### Bounded disclosure

Anchor reports and the retimestamp plan carry hashes, digests, timestamps
and the TSA URL only. No receipt contents, no policy text, no arguments.
The token itself contains only the digest, so embedding it leaks nothing.

## Mode 3: OpenTimestamps

Vendor-neutral blockchain anchoring for long-horizon archives. The
`x_timestamp` block carries `mode: "opentimestamps"`, the same digest and
cite, and the .ots proof (base64 in the `ots` field).

Bounded claim, stated exactly: the receipt proves the anchoring event was
recorded and binds the digest and the cite; the .ots proof itself
verifies against the Bitcoin chain externally (OpenTimestamps tooling,
network access required). The offline verifier re-checks the digest
consistency, the re-derivation from the cited ledger line and the cite;
it does NOT claim the proof verifies and it does NOT verify Bitcoin.

No eIDAS Art 41 presumption attaches to an OpenTimestamps anchor. This
is documented, never claimed: a .ots proof is evidence of inclusion in
the Bitcoin chain at a block time; it is not a qualified timestamp and no
EU legal presumption of accuracy or integrity follows from it. Buyers who
need the presumption use Mode 2 with a QTSP; Mode 3 exists because a
blockchain anchor has no vendor, no expiry and no per-stamp cost.

## Dependency decision record (deliberate)

- The TimeStampReq encoder is hand-rolled stdlib DER. The request is a
  fixed shape raucle fully controls; building it needs no ASN.1 library
  and the zero-mandatory-dependency rule is preserved. The test suite
  cross-checks the emitted bytes against the asn1crypto reference
  encoding, so the hand encoder cannot silently drift.
- The response is EXTERNAL NETWORK INPUT. Hand-parsing arbitrary CMS
  SignedData is how verification bugs are born, so the parse uses
  asn1crypto: pure Python, no compiled dependencies, MIT licensed, the
  standard CMS parser for Python tooling. It only PARSES; the actual
  signature verification stays in the already-required `cryptography`
  package, so no new crypto primitive enters the trust path.
- Nonces are generated at 52 bits, inside the portable safe-integer
  range the canonical JSON contract enforces (RFC 3161 permits up to
  160 bits; raucle receipts must stay portable across the reference
  verifiers, so the stricter bound applies to minted anchors).
- Install with the extra: `pip install "raucle[timestamp]"`. Installs
  without it can still BUILD requests (stdlib only); they cannot verify
  token-bearing receipts, which fail closed with a named error.

## Long-lived archives: retimestamping and countersigning

TSA certificates expire. A token's cryptographic proof survives its
certificate's expiry, but the natural reading of "qualified at the time"
weakens as the cert ages and revocation evidence goes stale. Long-lived
archives need a maintenance cadence, planned against the G3 retention
records (raucle/records.py: gate receipts carry `retention_until` when
`retention_days` is configured; disposal is the receipted x_destruction
flow).

The rule: the archive horizon is the latest `retention_until` any
receipt claims. Every TSA-attested anchor must remain inside a
certificate that outlives the horizon; when it does not, the SAME DIGEST
is re-stamped (a fresh token attests the identical head line bytes) and
the new anchor receipt is appended. Countersigning the old receipt with
the new token is the same operation: the old evidence is never replaced,
only re-attested, so the archive holds a chain of independent
attestations over one immutable fact.

`raucle timestamp plan --chain FILE` walks the ledger, re-checks every
anchor offline, and reports:

- the archive horizon (the latest retention_until, G3 pairing);
- every anchor with its TSA certificate's not-after date, whether the
  token still re-checks, and a RESTAMP REQUIRED flag with a restamp-by
  date (certificate expiry minus a 30-day safety window);
- the unanchored retained tail: records with a retention schedule but no
  covering anchor.

Guidance for operators: run the plan on the retention schedule cadence
(G3), not on the certificate cadence; the plan tells you which anchor
expires first, and re-stamping before the window closes keeps every
attestation continuously qualified. Mode 3 anchors never expire in this
sense (the Bitcoin block is permanent) but never gain the presumption;
the two modes compose for very long horizons: OTS for permanence, QTSP
for legal weight, re-stamped on the plan's schedule.

## Test fixtures

tests/test_timestamping.py. The mock TSA is a self-hosted
Sigstore-TSA-style service: a real HTTP server on a live socket issuing
real RFC 3161 CMS tokens (RSA over signedAttrs, mandatory attributes
present, critical timeStamping EKU). Fixtures cover: the hash-only
canonical request; the granted round trip; rejection status naming the
failure; imprint, nonce and signature tampering; pinned-key mismatch;
genTime outside the certificate validity window; the anchor round trip
standalone and appended; token tamper inside a legitimately re-signed
receipt (the token re-check is the only failure); ghost-citing; recorded
gen_time tamper; the OTS bounded claim and its digest tamper; the
missing-extra fail-closed path; the retimestamp plan against G3
retention stamps; and the CLI surface (stamp, verify, plan) including a
non-zero exit on a corrupt token.

## Appendix: asn1crypto implementation notes

Recorded because they cost a day to learn and the next implementer should
not pay again:

- Field access is snake_case (`message_imprint`, `cert_req`); integer
  enums return names (`version.native == "v1"`).
- `cms.SignedData` resolves the `encap_content_info` spec dynamically by
  version: v1 parses as PKCS#7-shaped ContentInfo (content bare after
  the [0] tag), later versions as EncapsulatedContentInfo (content is an
  OCTET STRING). Both shapes are handled by looking at the bytes after
  unwrapping [0].
- `ParsableOctetString.native` returns the PARSED value (a dict for a
  TSTInfo), not the octets; the exact embedded bytes (needed for the
  messageDigest attribute check) come from unwrapping the [0]-tagged dump
  twice: [0] tag, then the OCTET STRING TLV.
- A nested `signed_attrs` dump carries the IMPLICIT [0] tag; the
  signature is over the SET OF encoding, so re-tag: 0x31 plus the chunk
  body (RFC 5652 5.3).
- The signer sid must byte-match the certificate's own DER (build both
  sides from the same certificate); an asn1crypto-rebuilt Name does not
  necessarily byte-match a cryptography-built certificate name.
- `tsp.TimeStampResp` types the token as required on both build and
  parse; RFC 3161 rejections omit it, so emit and parse via a lenient
  subclass with the field optional.
- Native names: PKIStatus "rejection" (not "rejected"); PKIFailureInfo
  "unaccepted_extensions" (plural); signingTime values want a cms.Time
  object, not a datetime.