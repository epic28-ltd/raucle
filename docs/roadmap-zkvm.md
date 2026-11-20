# Roadmap: zkVM proofs of gate conformance

This document is a roadmap, not a description of shipped behaviour. Only Layer 1 is shipped today.

The conformance re-verification module ([`raucle/conformance.py`](../raucle/conformance.py)) is Layer 1 of a three-layer plan toward proving, with zero disclosure, that a receipt chain's calls satisfied a policy. The layers:

- **Layer 1 (shipped)**: field-level commitments with selective disclosure. A verifier re-checks a receipt's hidden call arguments against a policy, disclosing only the requested fields. The commitment leaves are JCS-canonical, ordered by UTF-16 ordering, and hash-joined with SHA-256 throughout; the construction is deliberately zk-portable. Per-constraint verdicts (SATISFIED, VIOLATED, UNKNOWN) are re-derived independently of the operator's runtime and fail closed. Design: [conformance-reverification spec](spec/provenance/v1/conformance-reverification.md).
- **Layer 2 (planned, not built)**: zkVM proof of the gate check. Port the constraint checker to a zkVM guest (RISC Zero or SP1). A proof then attests that a gate check over committed inputs produces a given decision, and Layer 1 disclosures remain available for spot audits. The zkVM guest would not need Lean's proofs; the guest would attest to the runtime checker, which is code rather than a model. Layer 1 disclosures remain useful for spot audits.
- **Layer 3 (not built)**: end-to-end zero-disclosure audit. A chain verifier checks zkVM proofs of gate conformance over whole chains without learning any argument value.

Treat Layers 2 and 3 as research plans. The [conformance spec](spec/provenance/v1/conformance-reverification.md) records the current boundary.
