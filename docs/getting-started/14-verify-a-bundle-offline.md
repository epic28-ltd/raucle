# 14. Verify a receipt bundle offline (third-party verification)

Anyone can verify Raucle's evidence on their own machine, with no account, no
network and nothing sent anywhere. This guide uses the bundle committed at
`docs/demo-bundle/` in this repository: a real receipt chain (one allowed
 DynamoDB read, one capability-denied attempt) assembled into a
self-contained, signed audit pack. Verify it exactly as an auditor would.

## What a bundle is

| File | Role |
|---|---|
| `PACK.json` | Signed index: member digests, signer id, verify instructions |
| `chain.jsonl` | The receipt chain of record (JWS per receipt) |
| `manifest.json` | Signed manifest binding the evidence to the report |
| `report.html` | Human-readable rendering, covered by the manifest signature |
| `pubkeys/*.pem` | The public keys the chain verifies against |

## Verify (about 1 minute)

Install the open core once (PyPI or from source):

```bash
pip install raucle==0.23.0      # or: pip install -e . in a clone of this repo
```

Then, against the bundle you downloaded (for this demo bundle, the
repository clone works directly):

```bash
$ python -m raucle.cli audit-pack verify docs/demo-bundle
audit pack: docs/demo-bundle
  index signature             PASS
  integrity (member hashes)   PASS
  manifest signature          PASS
  signer (not pinned)         603db302b076c824 [internal consistency only]
  receipt chain (offline)     PASS (3 receipts)
  manifest reproducible       PASS
  RESULT: VERIFIED
```

`RESULT: VERIFIED` means: every member's bytes match the signed index, the
manifest signature verifies against the bundled audit public key, the receipt
chain verifies against the bundled operator identity alone, and the report
reproduces byte-identically from the evidence. The machine that produced the
pack takes no part in the verification; there is nothing to phone home to
because nothing is called.

## Tamper with it and watch it fail

Flip a single byte in the bundled chain and the verification refuses:

```bash
$ python - <<'EOF'
from pathlib import Path
p = Path("docs/demo-bundle/chain.jsonl")
data = bytearray(p.read_bytes())
data[len(data) // 2] ^= 0x01
p.write_bytes(bytes(data))
EOF
$ python -m raucle.cli audit-pack verify docs/demo-bundle
  ...
  manifest reproducible       FAIL
  RESULT: REJECTED
    - hash mismatch for chain.jsonl (tampered)
```

(Do that to a COPY; restoring `git checkout -- docs/demo-bundle/chain.jsonl`
puts the bundle back.)

## What this proves, and what it does not

- The pack proves the recorded chain: which agent acted, under which
  capability, with what outcome, and that the record set has not changed
  since assembly.
- It proves it offline: the verifier reads the bundle and nothing else.
- It does not by itself prove the underlying agent's real-world deployment
  was in scope; that is what capability statements, registry entries and the
  gateway's live receipts add when the buyer runs their own estate.
- The chain carries hybrid Ed25519 + ML-DSA-65 (FIPS 204) signatures where
  configured; `require_pq` is recorded in `PACK.json`, so a buyer can
  require post-quantum signing in the pack they accept.

## Verify your own evidence

For evidence produced in your own deployment, pass your chain file to
`audit-pack build` (with your public keys and manifest key) and hand the
resulting directory to your third party. The receipt formats that the
verifier checks are published and specified in `docs/spec/provenance/`; the
verifier is part of this open-source core, so a pack can always be checked
without trusting the party that produced it.