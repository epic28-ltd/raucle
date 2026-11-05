# AIMS alignment note (P1.4d)

Status: aligned with draft-ietf-wimse-aims-01 (2026-11-02). This is a
terminology alignment note, not a conformance statement: nothing here
asserts or claims that the raucle agent registry conforms to, complies
with, or implements the draft or any other specification. The draft is a
WG internet-draft and may change materially between revisions; nothing in
this note imposes requirements on a third party or carries any legal
weight. British spellings throughout.

## What the draft says, briefly

draft-ietf-wimse-aims-01 ("AI Identity Management System") defines the
Agent Identity Management System (AIMS) as a conceptual model: the set of
functions needed to establish, maintain and evaluate the identity and
permissions of an agent workload. It does not define a product, protocol
or deployment architecture. Its core terms are:

- Agent Identifier: unique identifier for every agent. The draft names
  the WIMSE identifier (a URI identifying a workload within a trust
  domain; SPIFFE IDs are named as a mature instance of that model) as the
  primary identifier.
- Agent Credentials: cryptographic binding between the agent identifier
  and attributes of the agent (WIT, WIC, X.509-SVID, WIT-SVID,
  JWT-SVID formats).
- Agent Credential Provisioning: provisioning credentials to the agent at
  runtime, closely tied to posture assessment mechanisms.
- Agent Authentication: how the agent authenticates to LLMs, tools and
  servers (transport layer, e.g. mTLS; application layer, e.g. WIMSE
  Proof Tokens and HTTP message signatures).
- Agent Authorization: how access decisions are made (OAuth 2.0 flows,
  downscoping, transaction tokens).
- Agent Monitoring, Observability and Remediation: correlating events
  across agents, tools and resources; reconstructing execution chains.
- Agent Authentication and Authorization Policy: the configuration and
  rules governing each of the functions above.

## Scope of the comparison

The raucle agent registry (`raucle/agent_registry.py`, schema
`agent-descriptor/v1`, P1.4a) stores signed, offline-verifiable agent
enrolment records. It covers a *slice* of the AIMS conceptual model: the
identity-issuance and credential-record layer. It deliberately does not
aim to cover authentication protocols, authorisation grants or
observability, and this note does not treat their absence as a
shortcoming. Each descriptor field below is mapped to the closest AIMS
term; where no sensible mapping exists the table says so explicitly
("no AIMS counterpart") rather than stretching a term.

## Field table: agent-descriptor/v1 to AIMS terminology

| Descriptor field | Description | Closest AIMS term | Mapping notes |
| --- | --- | --- | --- |
| `version` | Descriptor schema version (`agent-descriptor/v1`) | No AIMS counterpart | Schema-versioning discipline (fail-closed on unknown versions) is the registry's own; AIMS names no descriptor format. |
| `agent_id` | Stable agent identifier | Agent Identifier | The draft's primary identifiers are WIMSE/SPIFFE URIs naming a workload within a trust domain; the registry's free-string `agent_id` plays the same role (unique, stable across the credential's life) but is not a URI and lives in no trust-domain namespace. Gap: no URI form or trust-domain scoping in v1. |
| `operator` | The human operator that enrolled the agent | No direct AIMS counterpart | The draft frames agents acting on behalf of a user, a system or themselves; the operator-of-record as an issuer-side attribute is the registry's own enrolment concept. |
| `operator_binding` | Name of the agent's operator identity | Agent Credentials (partially) | Nearest to the draft's "cryptographic binding between the agent identifier and attributes of the agent": `operator_binding` names the operator identity side of the binding. It is a name, not a key binding; the actual cryptographic binding lives in the Ed25519 signature. |
| `status` | Lifecycle state (`enrolled` / `retired`) | Agent Credential Provisioning (partially) | Echoes provisioning lifecycle (issue, rotate, revoke); the append-only retire discipline corresponds in spirit to revocation. The draft mandates no particular lifecycle states. |
| `attested_manifest_hash` | SHA-256 digest of the agent's agent card/manifest | No cryptographic counterpart; nearest concept is posture assessment | The draft lets an AIMS incorporate posture assessment mechanisms before issuing credentials, with no required evidence format. The registry's attested manifest hash is exactly that kind of deployment-chosen evidence: byte-comparable, signed over, but its soundness is admission's story (P1.4c), not the registry's. |
| `attested_manifest_kind` | Kind of artefact digested (agent card, manifest, agent JSON) | No direct AIMS counterpart | Describes the posture evidence's format, which the draft explicitly leaves open ("does not require any particular posture assessment mechanism, evidence format, or verifier architecture"). |
| `framework` | The agent framework (free string) | No direct AIMS counterpart | Framework provenance is not named in the draft; it rides the descriptor as enrolment metadata for verifier-side display and admission decisions. |
| `framework_version` | The framework version (free string) | No direct AIMS counterpart | As above. |
| `delegation_ceilings.max_hops` | Maximum delegation hops | Agent Authorization (partially) | Related in spirit to the draft's delegation and downscoping semantics (bounds on how far delegated authority may extend), but the registry carries ceilings on the identity record, not on OAuth tokens. No specific AIMS named counterpart. |
| `delegation_ceilings.max_scope` | Maximum tools a delegation may carry | Agent Authorization (partially) | As above; a coarse analogue of token scope minimisation (the draft's SHOULD for requesting minimum scopes). |
| `delegation_ceilings.lease_ceilings` (`max_ttl_seconds`, `max_active_leases`) | Lease-model limits the delegated receipt machinery enforces | Agent Authorization (partially) | Rough analogue of short-lived, downscoped tokens bound to a transaction; the lease model is the registry's own, not the draft's. |
| `issued_at` | Epoch seconds at issuance | Agent Credentials (lifecycle attributes) | Every AIMS credential format (WIT, X.509-SVID, etc.) carries time validity claims; this is the registry's equivalent timestamp. |
| `issuer_key_id` | First 16 hex of SHA-256 over the issuer public key | Agent Credentials (partially) | Nearest to credential key binding: identifies which issuer key signed. The draft's credentials bind a key to a workload identifier; here the key identifies the issuer (operator side), not the agent. |
| `issuer_signature` | Ed25519 signature over the canonical body | Agent Credentials | The cryptographic binding itself: possession of the issuer key vouches that the operator enrolled the record, verifiable offline. The draft's analogues bind agent keys; this signature binds the issuer's attestation, so it is a different side of the same idea. |

Gaps with no mapping, in summary: `version`, the attestation evidence
shape (`attested_manifest_kind`, `framework`, `framework_version`), and
the operator-of-record fields have no direct AIMS counterpart; the AIMS
Agent Identifier's URI/trust-domain form is absent from `agent_id`; the
registry does not touch Agent Authentication protocols (mTLS, WPTs,
HTTP message signatures), Agent Authorization grants (OAuth flows,
transaction tokens) or Monitoring/Observability/Remediation at all,
which is honest scope rather than an omission to fix here.

## How to talk about this note

Say "aligned with draft-ietf-wimse-aims-01 (2026-11-02)" when citing it.
Do not describe the registry or this note as conformant or as making any
compliance assertion; the note is repo-internal documentation that
records an honest terminology mapping, and the draft may change between
revisions without warning.
