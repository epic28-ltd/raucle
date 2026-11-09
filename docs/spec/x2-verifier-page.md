# X2 slice 1: the static offline verifier page

Status: implemented (`assets/verifier/x2-verifier.html`, `tests/test_x2_verifier.py`).

## What ships

One self-contained HTML page — no build step, no toolchain, no CDN, no
JavaScript dependencies. All verifier logic is inline (`script
x2-verifier-core`, the part tests exercise; plus a browser-only DOM-wiring
block). It runs entirely in-browser against WebCrypto: SHA-256 digests and
Ed25519 (imported from the pack's bundled PEM SPKI keys). No Rust/WASM toolchain
was vendored — WebCrypto already covers every algorithm the classical
provenance profile uses, and a pure-JS core keeps the page auditable in one file
(with `node --check`-able source and a vm-runnable acceptance harness).

## What a reader can verify with it

- an **audit pack** (`PACK.json`-headed directory, drag-dropped: pack kind,
  Ed25519 index signature over the canonical index, every member's sha256 vs
  the index, path containment, unindexed-extra rejection, the manifest's
  Ed25519 signature + signer-id self-consistency + index/manifest signer
  agreement, and the receipt chain against the bundled pubkeys) — the same
  checks 0–3 `raucle.audit_pack.verify_pack` performs server-side;
- a bare **receipt chain** (`*.jsonl`) plus PEM keys;
- a **single pasted receipt** against a pasted PEM.

Every receipt gets a per-line verdict (green/red) with **named failure reasons**
mirroring the Python verifier's vocabulary: non-canonical header/payload,
unexpected alg/typ/crit/header keys, kid↔agent_key_id binding, missing key
id (fail-closed — an unknown key is a denial, never a pass-through; a pasted
receipt without a key shows "signature unstated", still hash-green), hash
mismatch, tampered member, dangling DAG parent, duplicate JSON keys, unknown
envelope fields. The page renders the full **verification recipe** it used, so
any reader can reproduce the checks by hand.

## Deliberate scope cut: PQ

Receipts declaring the `raucle/pq1` profile, and packs that declare
`require_pq`, are **denied with that named reason**. The ML-DSA-65 leg cannot
be verified in the browser today; a partially verified hybrid must never be
reported as verified, so the browser verifier refuses that class outright
(fail-closed). WebCrypto also does not offer ML-DSA, so this is not fixable
without vendoring a PQ implementation — a later slice, not a degradation.

Reproducibility (check 4 in `verify_pack`: byte-rebuilding `report.html`/the
manifest body) is also out of scope: it would mean shipping the report builder
into the page. The page checks the signed material (index, manifest, chain),
which is the part whose *verification* semantics can diverge from the server;
it labels the reproducibility leg "not performed here" in the recipe.

## Trust invariants

- **No network after load.** There are no external references at all — no
  `src=`, no `href=`, no absolute URL, and the shipped HTML contains none of
  the network-API literals (fetch/XHR/WebSocket/EventSource/sendBeacon/…),
  asserted by `test_no_network_literals_in_shipped_page`. Comments count: an
  editor cannot name a dial without the gate catching it.
- **Vendored assets are hash-pinned.** `assets/verifier/ASSET-HASHES.json` pins
  the sha256 of the page and of every committed fixture-pack member;
  `test_vendored_assets_match_hash_manifest` fails the suite on any drift, and
  `scripts/x2_asset_hashes.py` regenerates it after a deliberate change.
- **Fixture-verified in headless CI.** `tests/test_x2_verifier.py` first runs
  `node --check` over every shipped script block (the browser's own parse gate
  — one syntax error kills the whole core), then drives
  `tests/verifier_harness/x2_harness.mjs`, which extracts the core block from
  the SHIPPED page and vm-runs it against the committed fixture pack
  (`assets/verifier/fixtures/fixture-pack/`, itself pinned and re-verified with
  the real `raucle` verifier by a separate test so the fixture cannot rot).
  Named-clean must verify; each doctored variant (tampered member, forged
  manifest, rewritten index, unindexed file, doctored header, dangling parent,
  missing keys, corrupt PEM, wrong custodian pin, correct pin) must deny with
  the expected named reason. The acceptance test therefore exercises the page's
  own logic, not a parallel reimplementation.

## What the verdict means (and does not)

A green pack verdict means *internally consistent*: every byte checks out
against the keys the pack itself carries. It does NOT prove the pack came from
the real custodian — anyone can rebuild and self-sign their own pack. Pinning
the custodian's audit key id out of band is the trust anchor; the page accepts
an optional pin and, when supplied, additionally reports
`signer_trusted` true/false against `verify_pack`'s semantics. This is the same
doctrine the Python verifier documents and it is surfaced verbatim in the page's
recipe section.
