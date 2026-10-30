# Raucle designs

Design documents for shipped or planned features, adjacent to the
specifications under [docs/spec/](../spec/). Designs carry the reasoning
about how a mechanism should be built and what it deliberately does not
do; the specs carry the on-wire formats.

| Design | Status | Scope |
|---|---|---|
| [Audit-export artifact (v1)](audit-export-v1.md) | Shipped (v0.17 primitives) | Examiner-facing signed audit reports |
| [WORM receipt archive (H3)](worm-archive.md) | Design only, not implemented | S3 Object Lock compliance-mode receipt archive, retention and recovery design |