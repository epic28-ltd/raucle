# Demo bundle — one-command verifiable custody evidence

This directory ships a real, offline-verifiable audit pack: one allowed
DynamoDB read and one capability-denied attempt, recorded as signed receipts and
bundled into a self-contained audit pack.

| File | Role |
|---|---|
| `PACK.json` | Signed index: member digests, signer id, verify instructions |
| `chain.jsonl` | The receipt chain of record (JWS per receipt) |
| `manifest.json` | Signed manifest binding the evidence to the report |
| `report.html` | Human-readable rendering, covered by the manifest signature |
| `pubkeys/*.pem` | The public keys the chain verifies against |

## Verify it in one command

From the repository root:

```bash
raucle demo verify
```

This wraps the fully-offline `audit-pack verify` (signature, integrity, chain,
reproducibility — nothing phones home) and additionally computes the canonical
bundle digest. Exit 0 with `RESULT: VERIFIED`; exit non-zero on any tamper.

Against a downloaded copy:

```bash
raucle demo verify /path/to/demo-bundle --pinned sha256:<published digest>
```

## The published-value mechanism

The bundle digest (`raucle-demo-bundle-digest/v1`: sha256 over the sorted
member digests declared in `PACK.json`, plus `PACK.json` itself) is published
**outside the bundle** — currently in this repository's CI workflow
(`.github/workflows/ci.yml`, job `demo-bundle-verify`), which re-verifies the
pack and compares the computed digest to a pinned literal on every commit.
Downstream adopters can pin the same value wherever they pin dependencies.

Why outside: a doctoring PR could edit both bundle and any pin stored *inside*
it. An external pin means the repin is a separate, reviewable change; repins
must name the cause (which change made the old value stale). Evidence-scope
only: documentation alongside the bundle does not move the digest, so an
editorial edit never triggers a repin while any evidence-member change does.

## Rebuilding the bundle

```bash
PYTHONPATH=. python scripts/build_demo_bundle.py
```

The script regenerates a real gate chain and pack (fresh keys per run — a
deliberate property: the demo pack is data, not a security trust anchor), and
verifies the rebuilt pack offline before publishing. A rebuild therefore
requires re-pinning the published value in the same reviewable series, never
silently.
