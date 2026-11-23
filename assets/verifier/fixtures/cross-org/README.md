# X2 cross-org fixture set

Inputs a third party holds in cross-org verification:

- `chain.jsonl` — the receipt chain signed by ORG A's agent key.
- `registry.jsonl` — the Trust Registry artifact (operator-signed
  append-only log) publishing org A's key and capability statement.
- `log-inclusion.json` — the transparency log's inclusion proof for
  the leaf receipt's digest (the riding key is convenience material
  only, never verification input).

The out-of-band anchors (committed here so tests can pin them):

- `registry-operator.pem` — the registry operator public key; pin it
  to authenticate the registry artifact.
- `log-operator.pem` — the log operator public key; pin it to
  authenticate the inclusion proof's checkpoint.

Regenerate with `scripts/x2_cross_org_fixtures.py`, then re-pin with
`scripts/x2_asset_hashes.py`.
