# VCD-A2A: Capability Discipline for the Agent-to-Agent Protocol

**Status:** Draft proposal, 2026-05-18; PROMOTED to programme 2026-10-29
(ractive workstream in raucle-cloud; the receipt format the extension cites is
now receipts v1.1 with delegated-authority binding: see
docs/spec/provenance/v1/delegation-extension.md).
**Authors:** Raucle.
**Target:** A2A protocol extension submission, [a2a-protocol.org](https://a2a-protocol.org/).

## Summary

The Agent-to-Agent (A2A) protocol, GA April 2025 and at 150+ adopting organisations by April 2026, defines how independently-deployed agents discover each other (via Agent Cards), negotiate capabilities (via Skills), and exchange messages (via JSON-RPC over HTTPS). A2A's published security analysis identifies *authorisation creep* — the absence of a per-skill, per-call, attenuating authorisation primitive — as one of its named open issues. The protocol mandates OAuth 2.0 for authentication but does not mandate, or even define, a uniform authorisation layer.

This proposal extends A2A with **Verified Capability Discipline** (VCD): each A2A skill invocation must carry a VCD capability receipt whose constraints are satisfied by the call arguments and whose attenuation chain terminates at a recognised root issuer. The extension is incremental — agents not implementing the extension are unaffected — and produces a portable, cryptographically-verifiable record of every cross-agent action.

## Why now

Three convergent timing pressures:

1. **A2A adoption is past the critical threshold.** Once Google, Microsoft, Anthropic, or one of the major framework vendors writes a per-skill OAuth profile themselves, the standards slot for "the authorisation layer of A2A" closes permanently. As of mid-2026 there is no incumbent.
2. **The audit story is missing.** Regulated industries are evaluating A2A for inter-organisational agent workflows (e.g., a bank's customer-service agent delegating to a payment processor's settlement agent). The current OAuth-only model produces no per-call record an auditor can verify; this is a known blocker for FCA / BaFin / MAS pilots.
3. **VCD has the artefact.** Capability receipts (paper §7.5) are already a public-key-verifiable record of *who authorised what, against what verified policy, with what attenuation chain*. The receipt format maps to A2A's existing extension points without protocol surgery.

## What changes

### Agent Cards — three new optional fields

```jsonc
{
  "name": "payments-agent",
  "description": "Settles transfers and refunds for the example.com payments network",
  "version": "1.4.2",
  "url": "https://payments.example.com/.well-known/agent.json",
  "skills": [
    {
      "id": "settle_transfer",
      "name": "Settle a transfer",
      "description": "Move funds from a source IBAN to a destination IBAN",
      "tags": ["payments"],
      "inputSchema": { /* JSON Schema as today */ },

      // NEW — VCD extension fields:
      "vcd": {
        "schemaHash":      "sha256:9f8e...",
        "policyProofHash": "sha256:4b78...",
        "issuerKey":       "ed25519:MCowB...",
        "leanTheoremId":   "vcd_payments_settle_v1"
      }
    }
  ],

  // NEW — VCD root issuer for receipts emitted by this agent:
  "vcdRootIssuer": {
    "key":         "ed25519:MCowB...",
    "keyId":       "kid_payments_2026_05",
    "rotationDoc": "https://payments.example.com/.well-known/vcd-rotations.json"
  }
}
```

Backwards-compatible: agents without `vcd` fields are full-featured A2A participants without VCD authorisation. Agents with `vcd` fields *also* publish capability receipts.

### Call-time — receipt in the JSON-RPC envelope

A2A skill invocation today:

```jsonc
{
  "jsonrpc": "2.0", "id": 17,
  "method": "skills/settle_transfer",
  "params": { "src": "DE89...", "dst": "GB29...", "amount": 4.00 }
}
```

With VCD-A2A:

```jsonc
{
  "jsonrpc": "2.0", "id": 17,
  "method": "skills/settle_transfer",
  "params": { "src": "DE89...", "dst": "GB29...", "amount": 4.00 },
  "vcdReceipt": {
    "issuerCert":       "...PEM Ed25519 cert...",
    "schemaHash":       "sha256:9f8e...",
    "policyProofHash":  "sha256:4b78...",
    "leanTheoremId":    "vcd_payments_settle_v1",
    "attenuationChain": ["tok_root_2026_05_15", "tok_user_emma_smith", "tok_session_xyz"],
    "callArgsHash":     "sha256:...",
    "decision":         "ALLOW",
    "timestamp":        "2026-05-18T09:14:22Z",
    "signature":        "ed25519:..."
  }
}
```

The recipient agent's gate, holding only the root issuer's public key (from `vcdRootIssuer` in the caller's Agent Card, or pre-pinned), can verify the receipt before acting.

### Cross-agent attenuation

When agent A calls agent B which then calls agent C, A's token must attenuate into a child for B, which must further attenuate into a grandchild for C. The chain is the audit trail: at C, the receipt's `attenuationChain` enumerates [A's root, A→B token, B→C token]. A's root issuer key is the only secret any verifier needs to recognise.

The attenuation primitive itself is unchanged from §3.2 of the paper:
- A child's lifetime cannot exceed its parent's.
- A child's constraints can only narrow (intersection / min / max of value sets).
- A child's `agent_id` must be a prefix-extension of its parent's.

### Discovery — the `.well-known/vcd.json` companion

Agents publishing VCD receipts also publish a companion descriptor:

```jsonc
// https://payments.example.com/.well-known/vcd.json
{
  "rootIssuerKey":      "ed25519:MCowB...",
  "keyId":              "kid_payments_2026_05",
  "rotationDoc":        "https://payments.example.com/.well-known/vcd-rotations.json",
  "policyRegistry":     "https://payments.example.com/.well-known/vcd-policies/",
  "leanDevelopment":    "https://github.com/example-payments/payments-vcd-proofs",
  "schemaRegistry":     "https://payments.example.com/.well-known/vcd-schemas/"
}
```

The Lean development URL is the load-bearing piece: an external auditor downloads the published Lean proofs, builds them locally, and confirms the cited theorem actually closes. The receipt's `leanTheoremId` names which theorem applied.

## Backwards compatibility

- Agents without VCD support exchange `Agent Card` and skill calls without the new fields, identically to today.
- A VCD-supporting agent calling a non-VCD agent: emits a receipt for its own audit log, sends the JSON-RPC call without the `vcdReceipt` field.
- A non-VCD agent calling a VCD-required agent: the gate rejects with `vcdRequired: true` and the recipient's required-issuer info; the caller can upgrade.
- The protocol's `requiredAuth` field is extended with a value `vcd-1.0` to declare mandatory VCD on a skill.

## Threat model deltas vs. base A2A

Where base A2A reduces to "the network connection is authenticated", VCD-A2A adds:

| Threat | Base A2A | VCD-A2A |
|---|---|---|
| Caller forges a call to a sensitive skill | OAuth scope check (if implemented; not mandated) | Receipt's attenuation chain must verify against a root the recipient recognises |
| Caller widens its delegated authority | No structural prevention | Attenuation invariants prevent broadening (mechanised in Lean) |
| Recipient executes a call outside the cited policy | No detection mechanism | Recipient verifies `policyProofHash` against the cited schema before acting |
| Audit of cross-org agent action | No portable record | Receipt is the record; verifiable without contacting the issuer |
| Stolen short-lived OAuth token replay | Token TTL only | Receipt's `callArgsHash` binds the specific call; replay against a different argument fails |

## Non-goals

- VCD-A2A does **not** define an inter-agent transport. A2A's HTTPS / mTLS guidance is unchanged.
- VCD-A2A does **not** define a UI for human-in-the-loop policy authoring. That is application-specific.
- VCD-A2A does **not** mandate any particular licensing of agent implementations. The protocol extension itself is intended to be released under a permissive licence suitable for inclusion in the A2A spec.

## Open questions for the A2A working group

1. **Should `vcdReceipt` be a top-level JSON-RPC envelope field or scoped under `params._meta`?** The latter is more conservative; the former is more discoverable.
2. **Should the `policyRegistry` and `schemaRegistry` be content-addressed by default?** A signed Merkle tree of all published policies would let auditors verify the receipt against a *specific historical* policy state.
3. **Is there appetite for a mandatory `vcd-1.0` profile for skills marked with a `regulated: true` tag?** Banking, healthcare, government A2A skills would benefit from a profile that *requires* a receipt rather than treating it as optional.
4. **Cross-cloud root distribution.** Should `vcdRootIssuer` keys be distributable via a (DNS-anchored, TLSA-style) global registry, or via per-organisation `.well-known/` publication? The latter is simpler; the former is harder to spoof at scale.

## Reference implementation plan

| Milestone | Deliverable | Target |
|---|---|---|
| M1 | Receipt format frozen; Go and Python reference encoders/verifiers in `raucle` | 2 weeks |
| M2 | A2A adapter in `raucle.a2a` — wraps an A2A agent server, injects `vcdReceipt`, verifies on receipt | 6 weeks |
| M3 | Two-agent demo: travel-booking agent delegates to payments agent across a published Agent Card boundary | 8 weeks |
| M4 | Draft A2A protocol extension PR, with reference implementation links | 12 weeks |
| M5 | AgentDyn benchmark run with VCD-A2A enabled across all cross-agent scenarios | 16 weeks |

## Why this is the right move for raucle

Three reasons:

1. **The standards slot exists right now and will not exist in 12 months.** Google or Microsoft will write a per-skill OAuth profile if no one else does. A first-mover capability-based proposal, with a reference implementation and an empirical benchmark, has a credible path to becoming the A2A authorisation profile.
2. **The receipt artefact is raucle's strongest differentiator and A2A is the largest distribution channel for it.** Once an A2A agent emits VCD receipts, every downstream agent and tool that wants to verify them needs raucle (or a compatible implementation). The technique becomes infrastructure.
3. **The work is incremental on top of the existing v0.10 capability primitive.** Receipts are already content-addressed and signed; the A2A binding is a serialisation format and a transport adapter, not new cryptography.

---

## Addendum: 29 October 2026 (promotion note)

1. The receipt artefact this proposal depends on shipped on 29 October:
   receipts v1.1 bind the full delegated-authority chain (capability id,
   parent chain, issuer, attenuation, chain digest) into every gate receipt,
   verifier-enforced. The A2A extension can now cite a public, offline-verifiable
   format instead of a proposal promise.
2. The coordination market validates the deployment surface: YC's QM (July
   2026, harness-agnostic by design) and Pentagon ("org code") coordinate
   agents without per-call verifiable authorisation; their harness adapters
   (raucle-cloud) double as the A2A reference implementations.
3. Credential-broker entrants (OneCLI, Alter, Agentic Fabriq, Clawvisor)
   vault and inject secrets but produce no third-party-verifiable delegation
   evidence: the credential-lease extension (lease receipts chained to
   delegation hops) is raucle's differentiator in the same standards slot.
4. Sequencing: (a) receipt-format alignment check against the live A2A
   extension points this week; (b) a public discussion artefact only after
   the LASR submission (5-6 Nov); (c) formal submission to a2a-protocol.org
   = Craig's action, never agent-sent.
