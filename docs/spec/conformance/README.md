# raucle-conformance/v1 — machine-checkable conformance record

The gateway exposes a build-pinned conformance badge at:

```
GET /.well-known/raucle-conformance
```

## What it is

The response is the committed artifact
`docs/spec/conformance/conformance.json` served verbatim: a record of which
published vector suites (under `standards/test-vectors/` and
`docs/spec/provenance/v1/test-vectors.json`) currently pass against this
build. Suites are checked by re-running their pytest targets (see
`scripts/gen_conformance_data.py`).

## Build pinning

The artifact is generated and committed; a CI job
(`Standards conformance data (S4)`) re-runs the generator and requires
byte-equality with the committed file. A digest over the canonical record
(`data_digest`, sha256, excluding the field itself) lets consumers verify the
artifact independently. Any vector, implementation, or suite change must
re-generate and commit the file in the same reviewable series — a silent
claim change is impossible.

## Schema

`raucle-conformance-v1.schema.json` in this directory. Top-level fields:

| Field | Meaning |
|---|---|
| `schema_version` | Always `raucle-conformance/v1` |
| `tool_version` | `raucle.__version__` of the generating build |
| `all_passed` | True only if every suite passed |
| `suites[]` | Per-suite: `id`, `title`, `source` (pytest target), `vectors` (published vector count or null), `passed` |
| `data_digest` | Canonical sha256 of the record minus this field |

## Availability

503 (with an explanatory detail) when the artifact is absent — a deployment
built without conformance data claims nothing, rather than 200-with-lies.

## Suites covered

| Suite | Source |
|---|---|
| `provenance-receipt-v1` | `tests/test_spec_conformance.py` (canonical Provenance Receipt v1 vectors) |
| `nelson14-delegation-gate` | `tests/nelson14_vectors.py` |
| `epaec-v1` | `tests/test_epaec_vectors.py` |
| `eqr-v1` | `tests/test_eqr_gate.py` (eqr:v1 vectors in `standards/test-vectors/`) |
| `dataflow-v1` | `tests/test_dataflow_rules.py` (dataflow:v1 vector) |
