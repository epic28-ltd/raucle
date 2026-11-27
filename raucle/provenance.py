"""AI Provenance Graph — cryptographic chain-of-custody for the agentic stack.

Every step in a multi-agent / multi-tool workflow emits a signed receipt
binding ``(agent_id, parent_receipts, operation, input_hash, output_hash,
taint, timestamp)``.  Receipts compose into a Merkle DAG so that given any
output one can reconstruct the entire causal chain back to the original
user input and verify that nothing in the chain has been tampered with.

This is the LLM-equivalent of certificate transparency + SBOM + DNSSEC,
fused for AI workflows.

Usage::

    from raucle.provenance import (
        AgentIdentity, ProvenanceLogger, Operation
    )

    identity = AgentIdentity.generate(
        agent_id="agent:billing-summariser",
        allowed_models=["claude-sonnet-4-6"],
        allowed_tools=["lookup_invoice", "send_email"],
    )
    logger = ProvenanceLogger(agent=identity, sink_path="chain.jsonl")

    # Root: untrusted user input enters the chain
    h1 = logger.record_user_input(
        text="Summarise May invoices and email the finance team.",
        taint={"external_user"},
    )

    # Model call, descends from user input — inherits taint
    h2 = logger.record_model_call(
        parents=[h1],
        model="claude-sonnet-4-6",
        input_text="...",
        output_text="...",
    )

    # Tool call, descends from the model call
    h3 = logger.record_tool_call(
        parents=[h2],
        tool="send_email",
        input_args={"to": "finance@…", "body": "…"},
        output={"status": "queued", "id": "msg_123"},
    )

    # Walk the DAG later
    from raucle.provenance import ProvenanceVerifier
    v = ProvenanceVerifier(public_keys={identity.key_id: identity.public_key_pem()})
    report = v.verify_chain("chain.jsonl")
    print(report.valid, report.errors)

Design notes
------------
- Hashes only, never content. Receipts never embed the raw prompt/output —
  only ``sha256(text)``. Privacy by default.
- Taint is a monotonic string set. Once a chain carries ``external_user``
  taint, every descendant carries it unless an explicit ``sanitisation``
  operation removes specific tags.
- Receipts are compact JWS (EdDSA, Ed25519). Same crypto as the v0.4.0
  verdict-receipt and audit-checkpoint primitives.
- The receipt's own *hash* (sha256 of the compact JWS string) is what
  descendants cite in their ``parents`` list. Hashes are deterministic
  given the signed bytes, so the DAG is content-addressed.
"""

from __future__ import annotations

import base64
import datetime as dt
import errno
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from raucle.bilateral import BILATERAL_OUTCOMES as _BILATERAL_OUTCOMES
from raucle.bilateral import bilateral_signing_input, sign_bilateral_outcome  # noqa: F401

from . import registry as _registry
from ._canon import make_duplicate_key_rejecter as _make_duplicate_key_rejecter
from ._canon import reject_lone_surrogates as _reject_lone_surrogates
from ._canon import reorder_keys_utf16 as _reorder_keys_utf16
from ._canon import utf16_key as _utf16_key

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


class Operation(str, Enum):
    """The kind of step a receipt represents."""

    USER_INPUT = "user_input"
    """A raw input entering the agentic graph (a user message, a fetched URL,
    a document from email, a retrieved RAG chunk). The root of every chain."""

    MODEL_CALL = "model_call"
    """An LLM invocation. Records model name, prompt hash, completion hash."""

    TOOL_CALL = "tool_call"
    """An agent invoked a tool / function. Records tool name, args hash,
    result hash."""

    RETRIEVAL = "retrieval"
    """A retrieval-augmented-generation step. Records corpus identifier and
    retrieved-chunks hash. Carries an inherent ``rag:<corpus>`` taint."""

    GUARDRAIL_SCAN = "guardrail_scan"
    """A guardrail scanned an input or output. Auto-emitted by ``Scanner``
    when an agent identity is configured. Records verdict + ruleset hash so
    downstream consumers can prove the scan actually ran."""

    AGENT_HANDOFF = "agent_handoff"
    """One agent passed work to another. Distinct from a tool call because
    the callee is itself an autonomous agent with its own identity."""

    SANITISATION = "sanitisation"
    """An explicit step that removes specific taint tags from its descendants.
    The only operation permitted to shrink the taint set."""

    MERGE = "merge"
    """A confluence point — N parents combine into one receipt. Used when an
    agent assembles results from multiple tool calls or sub-agents."""


#: Operations permitted to have empty parents (chain roots) — spec v1 §3/§6.
_ROOTABLE_OPS = {Operation.USER_INPUT.value, Operation.GUARDRAIL_SCAN.value}

#: Payload fields REQUIRED for each operation (spec v1 §4.2). A verifier MUST
#: reject a receipt missing any required field for its operation type.
_REQUIRED_FIELDS_BY_OP: dict[str, tuple[str, ...]] = {
    Operation.USER_INPUT.value: ("input_hash",),
    Operation.MODEL_CALL.value: ("input_hash", "output_hash", "model"),
    Operation.TOOL_CALL.value: ("input_hash", "output_hash", "tool"),
    Operation.RETRIEVAL.value: ("input_hash", "output_hash", "corpus"),
    Operation.GUARDRAIL_SCAN.value: ("input_hash", "ruleset_hash", "guardrail_verdict"),
    Operation.AGENT_HANDOFF.value: ("output_hash",),
    Operation.SANITISATION.value: ("input_hash", "output_hash", "tool", "corpus"),
    Operation.MERGE.value: ("output_hash",),
}


def _structural_errors(receipt: ProvenanceReceipt) -> list[str]:
    """Per-receipt structural validity per spec v1 §3/§4.2/§6.

    Checks the root rule (only ``user_input`` may have empty parents), the
    ``merge`` arity rule (>= 2 parents), and the required-fields-per-operation
    table. Returns a list of human-readable error strings (empty == valid).
    """
    errs: list[str] = []
    op = receipt.operation.value
    # Operations permitted to root a chain (empty parents): user_input, and a
    # standalone guardrail_scan (an entry-point scan of incoming external
    # content). Mid-chain operations (model_call/tool_call/retrieval/
    # agent_handoff/sanitisation/merge) MUST cite >= 1 parent.
    if not receipt.parents and op not in _ROOTABLE_OPS:
        errs.append(
            f"{op} receipt has empty parents but is not a permitted chain root "
            f"(only user_input or guardrail_scan may root a chain)"
        )
    if op == Operation.MERGE.value and len(receipt.parents) < 2:
        errs.append(f"merge receipt must have >= 2 parents, has {len(receipt.parents)}")
    for fld in _REQUIRED_FIELDS_BY_OP.get(op, ()):
        if not getattr(receipt, fld, ""):
            errs.append(f"{op} receipt missing required field {fld!r}")
    # Spec v1 §4.2/§4.3.1: parents and taint MUST be sorted by UTF-16 code unit
    # and unique — part of the canonical contract; unsorted/duplicate entries
    # indicate a non-conformant emitter.
    for name in ("parents", "taint"):
        seq = list(getattr(receipt, name, []) or [])
        if seq != sorted(seq, key=_utf16_key):
            errs.append(f"{name} must be sorted in UTF-16 code-unit order (§4.3.1)")
        if len(seq) != len(set(seq)):
            errs.append(f"{name} must not contain duplicates")
    return errs


def _validate_receipt_strict(receipt: ProvenanceReceipt) -> None:
    """The single documented strict per-receipt contract (§3.3).

    A receipt is fully valid only when ALL of the following hold. The first
    five are enforced inside :meth:`ProvenanceReceipt.from_jws` with
    ``strict=True`` (they need the raw JWS bytes); this function adds the
    structural layer, so a standalone ``from_jws(strict=True)`` is structurally
    complete and not merely cryptographically/canonically sound.

    Enforced by ``from_jws(strict=True)`` (cryptographic / canonical / header):
      1. JOSE header: exact ``alg``/``typ``/``crit``/``kid``/``raucle/v1``, no
         extra keys.
      2. Canonical (JCS) byte-equality of header and payload.
      3. Payload ``typ`` literal and non-empty ``iss``.
      4. Duplicate-key rejection in header and payload.
      5. ``header.kid`` bound to ``payload.agent_key_id``.

    Enforced here (structural, spec v1 §3/§4.2/§6):
      6. Root rule (only ``user_input``/``guardrail_scan`` may have empty
         parents); ``merge`` arity (>= 2 parents).
      7. Required-fields-per-operation.
      8. ``parents``/``taint`` sorted by UTF-16 code unit (§4.3.1) and unique.

    Raises
    ------
    ValueError
        On the first structural violation (joined into one message).

    Note: cross-receipt DAG invariants (topological order, taint monotonicity,
    capability-statement conformance) are chain-level and remain in
    :meth:`ProvenanceVerifier.verify_chain`; they require the whole graph and
    cannot be checked from a single receipt.
    """
    errs = _structural_errors(receipt)
    if errs:
        raise ValueError("; ".join(errs))


# ---------------------------------------------------------------------------
# Utilities — canonical JSON, base64url, Ed25519
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


#: Portable integer range for v1 signed/hashed material. JavaScript numbers are
#: IEEE-754 doubles, so the TS reference can only represent integers exactly up
#: to 2^53-1; Go/Rust/C# use 64-bit ints. To guarantee a value round-trips
#: byte-identically across ALL five implementations we restrict integers to the
#: JS safe-integer range (the most restrictive). Python ints are unbounded, so
#: without this a large Python-valid integer would sign here but be unrepresentable
#: (or lossy) in the TS port — a cross-language canonical divergence (§8.10 #6).
_MAX_SAFE_INT = 2**53 - 1
_MIN_SAFE_INT = -(2**53 - 1)
_SHA256_PREFIX = "sha256:"

# ---------------------------------------------------------------------------
# Evidence-level and trust-mode vocabulary (lane Q16, additive metadata).
#
# The receipt's own claim about its evidence rides the payload root under
# the x_ extension namespace (x_evidence) so every reference verifier keeps
# accepting it. Verifiers treat the field as INFORMATIONAL: it never
# upgrades a verdict, absence on legacy receipts is tolerated, and a
# producer claiming a level above what it can prove (executor_attested on
# an app-recorded receipt) verifies like any other receipt, no extra trust
# granted. See docs/security-model.md, "Receipts, evidence levels and
# trust modes".
# ---------------------------------------------------------------------------

#: A /gate decision receipt: the gate observed and signed the decision.
EVIDENCE_GATE_OBSERVED = "gate_observed"
#: An application-recorded tool_call receipt: the executing application
#: reports its own tool outcome (self-attested, not independently witnessed).
EVIDENCE_SELF_REPORTED = "self_reported"
#: The executor-attested claim value: what an app COULD self-claim, never a
#: verifier-granted level (the W1/AEC programme is registered, not shipped).
EVIDENCE_EXECUTOR_ATTESTED = "executor_attested"

#: Trust mode of a resolved capability statement: self-signed in the OSS
#: mode (distributed alongside the agent key). The default honest label.
TRUST_MODE_SELF_ASSERTED = "self_asserted"
#: Trust mode of a separately vouched statement (a registry-anchored
#: passport countersigned by an issuer the verifier resolves).
TRUST_MODE_AUTHORITY_ISSUED = "authority_issued"
_TRUST_MODES = frozenset({TRUST_MODE_SELF_ASSERTED, TRUST_MODE_AUTHORITY_ISSUED})

_DLP_ACTIONS = frozenset({"blocked", "redacted", "allowed_with_findings"})
_DLP_DIRECTIONS = frozenset({"egress_to_model", "ingress_from_model", "egress_to_tool"})
# Bounded, versioned matched-class vocabulary (v1.2 content DLP spec,
# docs/spec/provenance/v1.2/content-dlp.md). The list grows only with a
# schema-version bump so older verifiers fail closed on unknown classes
# instead of silently widening the disclosure boundary.
_DLP_MATCHED_CLASSES = frozenset(
    {"pii_card", "pii_email", "pci_pan", "secret_bearer", "pii_national_id"}
)
# Content-like field names that must never appear in a signed x_dlp block:
# counts, digests, class names and route identifiers only (bounded
# disclosure), so a leaky emitter cannot hide matched values in evidence.
_DLP_FORBIDDEN_CONTENT_FIELDS = frozenset(
    {"matched_value", "content", "snippet", "match_text", "excerpt", "sample", "verbatim"}
)
_DLP_REQUIRED_FIELDS = (
    "action",
    "scan_id",
    "route",
    "direction",
    "content_sha256",
    "matched_classes",
    "span_counts",
    "rule_id",
)

# Receipts v1.2 (K3): the shared bounded-disclosure sweep for the two new
# signed surfaces (x_gate.counterfactual and the v1.2 x_revocation kind).
# The DLP set is the historical core; the additions name the argument and
# token material those surfaces must never carry. Content-like field names
# fail with a named error wherever they appear, so a leaky emitter cannot
# hide values inside signed evidence.
_FORBIDDEN_FIELD_NAMES = frozenset(
    _DLP_FORBIDDEN_CONTENT_FIELDS
    | {
        "args",
        "arguments",
        "call_args",
        "constraint_values",
        "constraints",
        "credentials",
        "secret",
        "token",
        "token_bytes",
    }
)
# Receipts v1.2 (K3): the counterfactual block's version anchor and the
# closed decision vocabulary. Spec: docs/spec/provenance/v1.2/
# counterfactual-evidence.md.
_COUNTERFACTUAL_VERSION = "counterfactual/v1"
_COUNTERFACTUAL_DECISIONS = frozenset({"allow", "deny"})
_COUNTERFACTUAL_FIELDS = frozenset(
    {"version", "ruleset_hash", "decision", "rule_id", "rule_kind", "session", "evaluated_at"}
)
_COUNTERFACTUAL_SESSION_FIELDS = frozenset(
    {"session_id", "window_seconds", "participant", "window_evidence"}
)
# Receipts v1.2 (EPIC W lane W2): the tool_definition block's version
# anchor, the closed field set and the closed vantage vocabulary. Spec:
# docs/spec/provenance/v1.2/definition-drift.md. The vantage stays a
# single honest value ("none": the gate sees requests, not served
# definitions) until the in-path MCP gateway exists; anything else is
# detection theatre, not this surface.
_TOOL_DEFINITION_VERSION = "tool-definition/v1"
_TOOL_DEFINITION_FIELDS = frozenset(
    {"version", "definition_digest", "definition_manifest", "definition_vantage"}
)
_TOOL_DEFINITION_VANTAGES = frozenset({"none"})
# The reload-drift finding's harness and test id: the gateway's reload
# path emits definition_changed findings, and the verifier's chain-end
# pin pass accepts a receipted transition as the signed evidence that
# observed drift was recorded, never silently applied.
_TOOL_SCHEMA_HARNESS = "tool-schema"
_DEFINITION_CHANGED_TEST_ID = "definition_changed"
# Receipts v1.2 (EPIC W lane W1): the x_state extension's version
# anchor, the closed field set and the literal absent sentinel. Spec:
# docs/spec/provenance/v1.2/state-verification.md. Evidence-at-mint from
# adapters: the runtime hashes the read-back (raw bytes sha256) and the
# gateway binds the digest to the write's receipt id; absence is the
# literal sentinel, never a fake digest. Content never rides the block:
# the shared forbidden-field sweep covers this surface too.
_STATE_EVIDENCE_VERSION = "state-evidence/v1"
_X_STATE_FIELDS = frozenset(
    {
        "version",
        "pairing_id",
        "read_tool",
        "evidence_digest",
        "handle",
        "field_classes",
        "state_evidence",
        "cited_receipt",
    }
)
_STATE_ABSENT_SENTINEL = "absent"
# The missing-evidence advisory finding's harness and test id: the
# middleware's fail-open lane emits state_evidence_missing findings
# whenever a covered write's read-back failed or was skipped.
_STATE_VERIFICATION_HARNESS = "state-verification"
_STATE_EVIDENCE_MISSING_TEST_ID = "state_evidence_missing"
# Receipts v1.2 (K3): the v1.2 revocation-kind block's version anchor, the
# closed kind and reason-class vocabularies and the closed field set.
# Spec: docs/spec/provenance/v1.2/revocation-receipts.md.
_REVOCATION_VERSION = "revocation/v1"
_REVOCATION_KINDS = frozenset({"capability", "lease", "receipt"})
_REVOCATION_REASON_CLASSES = frozenset(
    {
        "compromise",
        "owner_departure",
        "scope_correction",
        "policy_change",
        "operational",
    }
)
_REVOCATION_V12_FIELDS = frozenset(
    {
        "version",
        "kind",
        "revoked_ids",
        "revoked_hashes",
        "root",
        "actor",
        "reason_class",
        "reason",
        "revoked_at",
    }
)


def _is_sha256_digest(value: Any) -> bool:
    """Whether *value* carries the sha256:<64 hex> digest shape."""
    return (
        isinstance(value, str)
        and value.startswith(_SHA256_PREFIX)
        and re.fullmatch(r"[0-9a-f]{64}", value[len(_SHA256_PREFIX) :]) is not None
    )


def _reject_floats(obj: Any) -> None:
    """Raise if *obj* contains a float, an integer outside the safe range, or a
    string with an unpaired UTF-16 surrogate.

    The v1 payload schema uses only strings, integers, and arrays. Floats are
    rejected (not serialised) so the canonical bytes stay identical across the
    five reference implementations, and integers are bounded to the JS
    safe-integer range so every value is exactly representable in all of them.
    ``bool`` is an ``int`` subclass and is allowed (it serialises as
    ``true``/``false``, not a number).
    """
    if isinstance(obj, float):
        raise ValueError(
            "canonical JSON: floats are not permitted in v1 signed/hashed material "
            "(use integers; float canonicalisation is not cross-implementation stable)"
        )
    if isinstance(obj, bool):
        pass  # bool is an int subclass but serialises as a JSON boolean
    elif isinstance(obj, int) and not (_MIN_SAFE_INT <= obj <= _MAX_SAFE_INT):
        raise ValueError(
            f"canonical JSON: integer {obj} is outside the portable safe-integer "
            f"range [{_MIN_SAFE_INT}, {_MAX_SAFE_INT}] (not representable in all "
            f"reference implementations)"
        )
    elif isinstance(obj, str):
        _reject_lone_surrogates(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                _reject_lone_surrogates(k)
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)


def _canonical_json(obj: Any) -> bytes:
    """Serialise *obj* with sorted keys, no whitespace, UTF-8 — for hashing.

    Object keys are ordered by UTF-16 code unit (RFC 8785 / JCS §3.2.3), not by
    Python's native code-point order, so the signed/hashed bytes are
    byte-identical across the TS/Go/Rust/C# reference encoders even for non-BMP
    keys (see ``_utf16_key``). allow_nan=False rejects NaN/Infinity;
    ``_reject_floats`` additionally rejects *all* floats.
    """
    _reject_floats(obj)
    return json.dumps(
        _reorder_keys_utf16(obj),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def authorization_block(cap: dict[str, Any]) -> dict[str, Any]:
    """Receipts v1.1: the delegated-authority binding for a presented capability.

    Builds the ``x_gate.authorization`` block: the presented capability id,
    its parent id (nullable), the issuing issuer/key, whether the capability
    is attenuated, and a SHA-256 ``chain_digest`` over the chain's canonical
    form. Absent capability (a plain agent call) emits no block: those
    receipts stay byte-identical to v1.
    """
    digest_material = {
        "capability_id": str(cap.get("token_id", "")),
        "issuer": str(cap.get("issuer", "")),
        "key_id": str(cap.get("key_id", "")),
        "parent_id": cap.get("parent_id"),
    }
    return {
        **digest_material,
        "attenuated": cap.get("parent_id") is not None,
        "chain_digest": _sha256_hex(_canonical_json(digest_material)),
    }


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: The single JOSE ``alg`` value accepted for provenance receipts.
_EXPECTED_ALG = "EdDSA"
#: Fixed JOSE/payload ``typ`` for v1 receipts (spec v1 §4.1).
_EXPECTED_TYP = "provenance-receipt/v1"
#: The critical-header marker every genuine receipt carries. Verifiers must
#: understand every entry in ``crit``; this is the only one we understand.
_RAUCLE_V1 = "raucle/v1"
_UNDERSTOOD_CRIT = {_RAUCLE_V1}

#: The post-quantum hybrid profile (docs/spec/provenance/v1/pq1-hybrid.md).
#: Receipts declaring this in crit carry a single-segment signature slot
#: over the raw component concatenation (Ed25519 64 B || ML-DSA-65 3309 B)
#: and are verified fail-closed under both keys. The legacy four-segment
#: dot-form receipts stay verify-only during the deprecation window.
_PQ1_PROFILE = "raucle/pq1"
_PQ1_ALG = "ml-dsa-65"


def _has_mldsa() -> bool:
    """True when this runtime can verify ML-DSA-65 signatures."""
    try:
        from raucle.pq import pq_available

        return pq_available()
    except Exception:
        return False


def _jws_declares_pq1(jws: str) -> bool:
    """True when a receipt JWS's header declares the pq1 profile.

    Segment-count agnostic: both the current three-segment Compact form
    (single-segment signature slot over the raw component concatenation)
    and the legacy four-segment dot-form receipts declare pq1 in the
    header. Fail-closed: undecodable headers return False.
    """
    try:
        parts = jws.split(".")
        header = json.loads(_b64url_decode(parts[0]), object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, TypeError):
        return False
    return isinstance(header, dict) and header.get(_PQ1_PROFILE) == _PQ1_ALG


#: Prefix marking a sanitisation receipt's ``corpus`` removed-taint claim
#: (``"removed:<tag1>,<tag2>,…"``), used at both build and verify time.
_REMOVED_PREFIX = "removed:"


#: Shared duplicate-key-rejecting ``object_pairs_hook`` (see ``_canon``).
_reject_duplicate_keys = _make_duplicate_key_rejecter("JSON object")


def hash_text(text: str) -> str:
    """Hash an input or output string for receipt inclusion."""
    return _SHA256_PREFIX + _sha256_hex(text.encode("utf-8"))


def hash_obj(obj: Any) -> str:
    """Hash an arbitrary JSON-serialisable object for receipt inclusion."""
    return _SHA256_PREFIX + _sha256_hex(_canonical_json(obj))


# Mirror the hardened capability gate grammar: dots must sit between
# alphanumerics (no trailing/double dots), so the identifier model is shared
# across the gate and the provenance layer.
_AGENT_ID_RE = re.compile(r"^agent:[a-z0-9](?:[a-z0-9_\-]|\.(?=[a-z0-9])){0,126}[a-z0-9]?$")


def _validate_agent_id(agent_id: str) -> None:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(
            f"agent_id {agent_id!r} must match {_AGENT_ID_RE.pattern!r} "
            "(lowercase, alphanumeric + _-./, 1-128 chars, prefix 'agent:')"
        )


# ---------------------------------------------------------------------------
# Agent identity + capability statement
# ---------------------------------------------------------------------------


_CAP_STMT_KNOWN_FIELDS = frozenset(
    {
        "agent_id",
        "key_id",
        "public_key_pem",
        "allowed_models",
        "allowed_tools",
        "data_classifications",
        "sanitisation_authority",
        "attestation",
        "issuer",
        "issued_at",
        "expires_at",
        "signature",
    }
)


def _cap_stmt_req_str(d: dict[str, Any], name: str) -> str:
    v = d.get(name)
    if not isinstance(v, str) or not v:
        raise ValueError(
            f"capability statement: {name} must be a non-empty string, got {type(v).__name__} {v!r}"
        )
    return v


def _cap_stmt_opt_str(d: dict[str, Any], name: str) -> str:
    v = d.get(name, "")
    if v is not None and not isinstance(v, str):
        raise ValueError(
            f"capability statement: {name} must be a string or absent, got {type(v).__name__} {v!r}"
        )
    return v if v is not None else ""


def _cap_stmt_opt_int(d: dict[str, Any], name: str, default: int = 0) -> int:
    v = d.get(name, default)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(
            f"capability statement: {name} must be an integer, got {type(v).__name__} {v!r}"
        )
    return v


def _cap_stmt_opt_int_or_none(d: dict[str, Any], name: str) -> int | None:
    v = d.get(name)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(
            f"capability statement: {name} must be an integer or null, got {type(v).__name__} {v!r}"
        )
    return v


def _cap_stmt_opt_str_list(d: dict[str, Any], name: str) -> list[str]:
    v = d.get(name, [])
    if not isinstance(v, list):
        raise ValueError(
            f"capability statement: {name} must be a list, got {type(v).__name__} {v!r}"
        )
    for item in v:
        if not isinstance(item, str):
            raise ValueError(
                f"capability statement: {name} must be a list of strings, "
                f"got {type(item).__name__} {item!r}"
            )
    return v


#: The OPTIONAL ``attestation`` binding (EPIC H3): the key set a statement's
#: hardware-attestation reference may carry. Intra-package duplication with
#: ``raucle.tee`` is deliberate; tee imports provenance, never the reverse.
_STATEMENT_ATTESTATION_KEYS = frozenset({"platform", "measurement", "attestation_ref", "simulated"})


def _parse_statement_attestation(d: dict[str, Any]) -> dict[str, Any] | None:
    """Parse the OPTIONAL capability-statement ``attestation`` binding.

    Fail closed on any shape drift: the binding rides the signed statement,
    so a malformed block must refuse to parse, never default through.
    """
    raw = d.get("attestation")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError(
            f"capability statement: attestation must be an object, got {type(raw).__name__}"
        )
    unknown = set(raw) - _STATEMENT_ATTESTATION_KEYS
    if unknown:
        raise ValueError(f"capability statement: attestation unknown field(s) {sorted(unknown)}")
    for name in ("platform", "measurement", "attestation_ref"):
        value = raw.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"capability statement: attestation {name} must be a non-empty string")
    if not isinstance(raw.get("simulated"), bool):
        raise ValueError("capability statement: attestation simulated must be a boolean")
    return {
        "platform": raw["platform"],
        "measurement": raw["measurement"],
        "attestation_ref": raw["attestation_ref"],
        "simulated": raw["simulated"],
    }


@dataclass
class CapabilityStatement:
    """Signed declaration of what an agent is permitted to do.

    Distributed alongside the agent's public key. Enforced producer-side by
    :class:`ProvenanceLogger`, and — when the statements are supplied to
    :class:`ProvenanceVerifier` — independently cross-checked verifier-side
    so that emitted receipts only invoke permitted models / tools.

    Lives outside the receipt body so receipts stay compact — receipts
    cite the capability statement by ``key_id``.
    """

    agent_id: str
    key_id: str
    public_key_pem: str
    allowed_models: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    data_classifications: list[str] = field(default_factory=list)
    sanitisation_authority: list[str] = field(default_factory=list)
    """Taint tags this key is authorised to clear via a SANITISATION receipt.

    Empty (the default) means the key may not clear ANY tag. A literal
    ``"*"`` entry authorises clearing any tag (use sparingly). This field is
    NOT part of the receipt wire format; it lives only in the capability
    statement and is enforced verifier-side.
    """
    issuer: str = "raucle"
    issued_at: int = 0
    expires_at: int | None = None
    # EPIC H3 slice 1: the OPTIONAL hardware-attestation binding (TEE):
    # exactly {"platform", "measurement", "attestation_ref", "simulated"}.
    # None keeps the signed body byte-identical to pre-H3 statements.
    attestation: dict[str, Any] | None = None
    signature: str = ""  # base64 over the body

    def body(self) -> dict[str, Any]:
        """Return the canonical body that gets signed (excludes ``signature``).

        ``sanitisation_authority`` and ``attestation`` are included only when
        non-empty / not None so that statements signed before those fields
        existed continue to verify byte-for-byte (backward-compatible
        serialisation).
        """
        body: dict[str, Any] = {
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "allowed_models": sorted(self.allowed_models, key=_utf16_key),
            "allowed_tools": sorted(self.allowed_tools, key=_utf16_key),
            "data_classifications": sorted(self.data_classifications, key=_utf16_key),
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        if self.sanitisation_authority:
            body["sanitisation_authority"] = sorted(self.sanitisation_authority, key=_utf16_key)
        if self.attestation is not None:
            body["attestation"] = self.attestation
        return body

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CapabilityStatement:
        if not isinstance(d, dict):
            raise ValueError(f"capability statement: must be a JSON object, got {type(d).__name__}")

        unknown = set(d) - _CAP_STMT_KNOWN_FIELDS
        if unknown:
            raise ValueError(f"capability statement: unknown field(s) {sorted(unknown)}")

        return cls(
            agent_id=_cap_stmt_req_str(d, "agent_id"),
            key_id=_cap_stmt_req_str(d, "key_id"),
            public_key_pem=_cap_stmt_req_str(d, "public_key_pem"),
            allowed_models=_cap_stmt_opt_str_list(d, "allowed_models"),
            allowed_tools=_cap_stmt_opt_str_list(d, "allowed_tools"),
            data_classifications=_cap_stmt_opt_str_list(d, "data_classifications"),
            sanitisation_authority=_cap_stmt_opt_str_list(d, "sanitisation_authority"),
            attestation=_parse_statement_attestation(d),
            issuer=_cap_stmt_req_str(d, "issuer"),
            issued_at=_cap_stmt_opt_int(d, "issued_at"),
            expires_at=_cap_stmt_opt_int_or_none(d, "expires_at"),
            signature=_cap_stmt_opt_str(d, "signature"),
        )

    def permits_model(self, model: str) -> bool:
        if not self.allowed_models:
            return True  # empty means unrestricted
        return model in self.allowed_models

    def permits_tool(self, tool: str) -> bool:
        if not self.allowed_tools:
            return True
        return tool in self.allowed_tools

    def permits_sanitising(self, tag: str) -> bool:
        """Whether this key is authorised to clear taint *tag*.

        Unlike :meth:`permits_model` / :meth:`permits_tool`, an empty
        ``sanitisation_authority`` is *deny-all*, not allow-all: clearing a
        taint tag is a privileged act and must be explicitly granted. A
        literal ``"*"`` entry authorises clearing any tag.
        """
        if "*" in self.sanitisation_authority:
            return True
        return tag in self.sanitisation_authority


class AgentIdentity:
    """An Ed25519 keypair + signed capability statement.

    Acts as the agent's "TLS certificate" — receipts emitted by this agent
    carry its ``key_id`` so verifiers know which public key to check.

    Parameters
    ----------
    agent_id : str
        Stable identifier, must match ``^agent:[a-z0-9_\\-./]+$``.
    private_key : cryptography Ed25519 private key object
    statement : CapabilityStatement
        The signed capability statement for this identity. Must already be
        signed — use :meth:`generate` or :meth:`load` to build a fresh one.
    """

    def __init__(
        self,
        agent_id: str,
        private_key: Any,
        statement: CapabilityStatement,
    ) -> None:
        _validate_agent_id(agent_id)
        self.agent_id = agent_id
        self._private_key = private_key
        self.statement = statement

    @classmethod
    def generate(
        cls,
        agent_id: str,
        *,
        allowed_models: list[str] | None = None,
        allowed_tools: list[str] | None = None,
        data_classifications: list[str] | None = None,
        issuer: str = "raucle",
        ttl_seconds: int | None = None,
    ) -> AgentIdentity:
        """Generate a fresh keypair + self-signed capability statement."""
        _validate_agent_id(agent_id)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = _sha256_hex(pub_pem)[:16]
        now = int(dt.datetime.now(dt.timezone.utc).timestamp())
        stmt = CapabilityStatement(
            agent_id=agent_id,
            key_id=key_id,
            public_key_pem=pub_pem.decode("ascii"),
            allowed_models=allowed_models or [],
            allowed_tools=allowed_tools or [],
            data_classifications=data_classifications or [],
            issuer=issuer,
            issued_at=now,
            expires_at=(now + ttl_seconds) if ttl_seconds else None,
        )
        # Self-sign the statement with the agent's own key for OSS mode.
        # In commercial deployments the issuer's key would sign instead.
        sig = priv.sign(_canonical_json(stmt.body()))
        stmt.signature = base64.b64encode(sig).decode("ascii")
        return cls(agent_id=agent_id, private_key=priv, statement=stmt)

    @classmethod
    def load(
        cls,
        private_key_pem: bytes,
        statement: CapabilityStatement,
        *,
        password: bytes | str | None = None,
    ) -> AgentIdentity:
        """Load an identity from a stored PEM + statement.

        ``password`` supports encrypted PKCS8 PEMs. Pass ``None`` for
        unencrypted keys (the default, preserving backward compatibility).
        """
        from cryptography.hazmat.primitives import serialization

        pw = password.encode("utf-8") if isinstance(password, str) else password
        priv = serialization.load_pem_private_key(private_key_pem, password=pw)
        return cls(agent_id=statement.agent_id, private_key=priv, statement=statement)

    @property
    def key_id(self) -> str:
        return self.statement.key_id

    def public_key_pem(self) -> bytes:
        return self.statement.public_key_pem.encode("ascii")

    def private_key_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceReceipt:
    """A decoded provenance receipt.

    The wire form is a compact JWS string (``header.payload.sig``).
    :meth:`to_jws` and :meth:`from_jws` are the canonical (de)serialisers.
    The ``receipt_hash`` field is the sha256 of the compact JWS string;
    descendants cite it in their ``parents`` list.
    """

    agent_id: str
    agent_key_id: str
    operation: Operation
    parents: list[str] = field(default_factory=list)
    input_hash: str = ""
    output_hash: str = ""
    model: str = ""
    tool: str = ""
    corpus: str = ""
    ruleset_hash: str = ""
    guardrail_verdict: str = ""
    #: Lane Q16 (additive): the receipt's OWN claim about its evidence
    #: level - "gate_observed" on /gate decision receipts, "self_reported"
    #: on application-recorded tool_call receipts. Informational only:
    #: verifiers never upgrade a verdict from it and receipts without the
    #: field (the legacy shape) verify unchanged. Rides the payload root
    #: under the x_ extension namespace so the four reference
    #: implementations keep accepting it.
    x_evidence: str = ""
    taint: list[str] = field(default_factory=list)
    tenant: str | None = None
    issued_at: int = 0
    #: x_bilateral executor co-signature block (v1.2). Rides the signed
    #: payload root; None means the receipt has no bilateral leg and
    #: verifies exactly as before (additive extension).
    x_bilateral: dict[str, Any] | None = None

    # Set after sign() / from_jws() — not part of the signed payload itself.
    jws: str = ""
    receipt_hash: str = ""

    def payload(self) -> dict[str, Any]:
        """Return the canonical signed-payload dict for this receipt."""
        out: dict[str, Any] = {
            "iss": "raucle-detect/provenance",
            "typ": _EXPECTED_TYP,
            "iat": self.issued_at,
            "agent_id": self.agent_id,
            "agent_key_id": self.agent_key_id,
            "operation": self.operation.value,
            "parents": sorted(self.parents, key=_utf16_key),
            "taint": sorted(self.taint, key=_utf16_key),
        }
        if self.input_hash:
            out["input_hash"] = self.input_hash
        if self.output_hash:
            out["output_hash"] = self.output_hash
        if self.model:
            out["model"] = self.model
        if self.tool:
            out["tool"] = self.tool
        if self.corpus:
            out["corpus"] = self.corpus
        if self.ruleset_hash:
            out["ruleset_hash"] = self.ruleset_hash
        if self.guardrail_verdict:
            out["guardrail_verdict"] = self.guardrail_verdict
        if self.x_evidence:
            out["x_evidence"] = self.x_evidence
        if self.tenant is not None:
            out["tenant"] = self.tenant
        if self.x_bilateral is not None:
            out["x_bilateral"] = self.x_bilateral
        return out

    def sign(self, identity: AgentIdentity, hybrid: Any = None) -> str:
        """Sign with *identity* and populate ``jws`` + ``receipt_hash``.

        With *hybrid* (a :class:`raucle.pq.HybridSigner`), the receipt is
        signed under the ``raucle/pq1`` profile instead: the header pins
        the PQ profile in ``crit``, and the signature slot is ONE
        base64url segment over the raw concatenation of the Ed25519 and
        ML-DSA-65 signatures (Compact-JWS-conformant; see raucle/pq.py).
        Both must verify; there is no downgrade path (see docs/spec/
        provenance/v1/pq1-hybrid.md).

        Returns the compact JWS string for convenience.
        """
        header = {
            "alg": _EXPECTED_ALG,
            "typ": _EXPECTED_TYP,
            "kid": identity.key_id,
            "crit": [_RAUCLE_V1],
            "raucle/v1": "provenance",
        }
        if hybrid is not None:
            from raucle.pq import pq1_header

            header = pq1_header(header, hybrid.pq_key_id)
        signing_input = (
            _b64url_encode(_canonical_json(header))
            + "."
            + _b64url_encode(_canonical_json(self.payload()))
        ).encode("ascii")
        if hybrid is not None:
            sig = hybrid.sign_both(signing_input)
        else:
            sig = _b64url_encode(identity.sign(signing_input))
        self.jws = signing_input.decode("ascii") + "." + sig
        self.receipt_hash = _SHA256_PREFIX + _sha256_hex(self.jws.encode("ascii"))
        return self.jws

    def to_jws(self) -> str:
        if not self.jws:
            raise ValueError("receipt has not been signed yet — call sign() first")
        return self.jws

    #: Hard caps on untrusted JWS input. Real receipts are well under 8 KiB;
    #: these bounds simply stop a hostile producer from forcing the parser to
    #: allocate unbounded memory (decompression-bomb-style) before any
    #: signature has been checked.
    MAX_JWS_BYTES = 64 * 1024
    MAX_PAYLOAD_BYTES = 32 * 1024

    @classmethod
    def _enforce_strict_payload(
        cls, header_b64: str, payload: dict[str, Any], payload_bytes: bytes
    ) -> None:
        """Enforce strict-mode payload and header checks (spec v1 §4.2/§4.3)."""
        cls._enforce_header(header_b64, expected_kid=payload.get("agent_key_id"))
        # Spec v1 §4.2: the payload typ is a fixed literal and iss must be a
        # non-empty issuer identifier. (The header typ is enforced in
        # _enforce_header; the payload carries its own typ that MUST agree.)
        if payload.get("typ") != _EXPECTED_TYP:
            raise ValueError(f"payload typ {payload.get('typ')!r} must be {_EXPECTED_TYP!r}")
        if not isinstance(payload.get("iss"), str) or not payload.get("iss"):
            raise ValueError("payload missing required non-empty 'iss'")
        # Spec v1 §4.3: header and payload are JCS-canonical (sorted keys, no
        # insignificant whitespace). The signature binds the on-wire bytes,
        # but without this a non-canonical encoding (spaces / unsorted keys)
        # would still verify, breaking the canonical contract and admitting
        # byte-different receipts for the same logical content (round-5 F3).
        header_bytes = _b64url_decode(header_b64)
        try:
            header_obj = json.loads(header_bytes, object_pairs_hook=_reject_duplicate_keys)
        except ValueError as exc:
            raise ValueError(f"malformed JOSE header: {exc}") from exc
        if _canonical_json(header_obj) != header_bytes:
            raise ValueError("JOSE header is not canonical JSON (JCS)")
        if _canonical_json(payload) != payload_bytes:
            raise ValueError("JWS payload is not canonical JSON (JCS)")

    @classmethod
    def from_jws(
        cls, jws: str, *, strict: bool = False, validate_structure: bool = True
    ) -> ProvenanceReceipt:
        """Parse a compact JWS string back into a receipt.

        Does NOT verify the signature — use :class:`ProvenanceVerifier`
        for verification.

        Parse hardening (always on): the raw JWS and decoded payload are
        length-capped, and payloads containing duplicate object keys are
        rejected (a JSON ambiguity attackers can exploit to smuggle a value
        past one parser that a differently-behaving parser would see).

        When *strict* is True the JOSE header is additionally enforced:
        ``alg`` must be the expected ``EdDSA`` value, and ``crit`` must be
        exactly ``["raucle/v1"]`` with that critical parameter understood —
        any unknown ``crit`` entry is rejected. :class:`ProvenanceVerifier`
        always parses in strict mode. The non-strict default preserves the
        published test vectors and the cross-language conformance path
        (which reconstructs receipts from a payload-only stub header).
        """
        if len(jws) > cls.MAX_JWS_BYTES:
            raise ValueError(f"JWS too large: {len(jws)} bytes > {cls.MAX_JWS_BYTES} cap")
        try:
            parts = jws.split(".")
        except ValueError as exc:  # pragma: no cover - split does not raise
            raise ValueError("malformed JWS — expected dot-separated segments") from exc
        # v1 receipts: header.payload.sig (3 segments). pq1 hybrid receipts:
        # header.payload.<ed25519>.<ml-dsa-65> (4 segments; the signature slot
        # itself carries a joining dot — see raucle/pq.py).
        if len(parts) == 3:
            header_b64, payload_b64, _sig_b64 = parts
        elif len(parts) == 4:
            header_b64, payload_b64, _sig_b64 = (
                parts[0],
                parts[1],
                parts[2] + "." + parts[3],
            )
        else:
            raise ValueError(
                f"malformed JWS — expected three or four dot-separated segments, got {len(parts)}"
            )

        payload_bytes = _b64url_decode(payload_b64)
        if len(payload_bytes) > cls.MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"JWS payload too large: {len(payload_bytes)} bytes > {cls.MAX_PAYLOAD_BYTES} cap"
            )
        payload = json.loads(payload_bytes, object_pairs_hook=_reject_duplicate_keys)

        if strict:
            cls._enforce_strict_payload(header_b64, payload, payload_bytes)

        receipt = cls(
            agent_id=payload["agent_id"],
            agent_key_id=payload["agent_key_id"],
            operation=Operation(payload["operation"]),
            parents=list(payload.get("parents", [])),
            input_hash=payload.get("input_hash", ""),
            output_hash=payload.get("output_hash", ""),
            model=payload.get("model", ""),
            tool=payload.get("tool", ""),
            corpus=payload.get("corpus", ""),
            ruleset_hash=payload.get("ruleset_hash", ""),
            guardrail_verdict=payload.get("guardrail_verdict", ""),
            x_evidence=payload.get("x_evidence", ""),
            taint=list(payload.get("taint", [])),
            tenant=payload.get("tenant"),
            issued_at=payload.get("iat", 0),
            x_bilateral=payload.get("x_bilateral"),
        )
        receipt.jws = jws
        receipt.receipt_hash = _SHA256_PREFIX + _sha256_hex(jws.encode("ascii"))
        # §3.3: a strict standalone parse is also structurally validated, so a
        # malformed receipt (bad root rule, missing required field, unsorted
        # parents/taint) is rejected here rather than silently parsing. The
        # chain verifier opts out (validate_structure=False) so it can report
        # each structural error per-line instead of raising on the first.
        if strict and validate_structure:
            _validate_receipt_strict(receipt)
        return receipt

    @classmethod
    def _enforce_header(cls, header_b64: str, expected_kid: str | None = None) -> None:
        """Validate the JOSE header of an untrusted receipt.

        Enforces ``alg == "EdDSA"`` and ``crit == ["raucle/v1"]`` with the
        sole critical parameter understood. Rejects unknown ``crit`` entries
        (RFC 7515 §4.1.11: a recipient that does not understand a listed
        critical header MUST reject the JWS). When *expected_kid* is supplied,
        the header ``kid`` must equal it — spec v1 §3 binds ``kid`` to the
        payload ``agent_key_id``, and the TS/Go/Rust/C# verifiers all enforce
        this; without it the Python verifier would ACCEPT bytes the four
        sibling implementations REJECT (round-3 #6 cross-impl divergence).
        """
        try:
            header = json.loads(
                _b64url_decode(header_b64), object_pairs_hook=_reject_duplicate_keys
            )
        except ValueError as exc:
            raise ValueError(f"malformed JOSE header: {exc}") from exc
        if not isinstance(header, dict):
            raise ValueError("JOSE header must be a JSON object")

        alg = header.get("alg")
        if alg != _EXPECTED_ALG:
            raise ValueError(f"unexpected JWS alg {alg!r} — only {_EXPECTED_ALG!r} is accepted")

        cls._enforce_crit(header)

        if header.get(_PQ1_PROFILE) == _PQ1_ALG:
            pqk = header.get("pqk")
            if not isinstance(pqk, str) or len(pqk) != 16:
                raise ValueError("pq1 receipts must pin a 16-hex-char 'pqk' (ML-DSA-65 key id)")

        if expected_kid is not None:
            kid = header.get("kid")
            if kid != expected_kid:
                raise ValueError(
                    f"JOSE header kid {kid!r} does not match payload agent_key_id "
                    f"{expected_kid!r} (spec v1 §3)"
                )

        # Spec v1 §4.1: typ and the raucle/v1 profile marker are fixed literals.
        # alg/kid/signature are the security-critical checks; these add
        # defence-in-depth + spec conformance (a JWT lib can't be tricked into
        # treating this as some other token type). Checked last so crit/kid
        # violations surface with their specific diagnostics first.
        if header.get("typ") != _EXPECTED_TYP:
            raise ValueError(
                f"unexpected JOSE typ {header.get('typ')!r} — must be {_EXPECTED_TYP!r}"
            )
        if header.get(_RAUCLE_V1) != "provenance":
            raise ValueError(
                f"JOSE header 'raucle/v1' must be 'provenance', got {header.get('raucle/v1')!r}"
            )
        # Spec v1 §4.1: reject any header key not in the fixed set. A vendor
        # extension is only permitted if it is ALSO listed in crit (and crit must
        # be exactly ['raucle/v1'] here, so in practice no extras are allowed).
        allowed_header_keys = {"alg", "typ", "kid", "crit"} | set(header.get("crit") or [])
        # pq1 hybrid receipts pin their ML-DSA key id in the header; the key
        # is part of the profile, so it is allowed when the profile is
        # declared (docs/spec/provenance/v1/pq1-hybrid.md).
        if header.get(_PQ1_PROFILE) == _PQ1_ALG:
            allowed_header_keys |= {_PQ1_PROFILE, "pqk"}
        extra = set(header) - allowed_header_keys
        if extra:
            raise ValueError(f"unexpected JOSE header key(s): {sorted(extra)}")

    @staticmethod
    def _enforce_crit(header: dict[str, Any]) -> None:
        """Validate the JWS ``crit`` array (RFC 7515 §4.1.11).

        ``crit`` must be exactly ``["raucle/v1"]``: present, a list of strings,
        containing no parameter the verifier does not understand, including the
        understood marker, and every named parameter actually present.
        """
        crit = header.get("crit")
        if crit is None:
            raise ValueError("JOSE header missing required 'crit' parameter")
        if not isinstance(crit, list) or not all(isinstance(c, str) for c in crit):
            raise ValueError("JOSE header 'crit' must be a list of strings")
        understood = set(_UNDERSTOOD_CRIT)
        if header.get(_PQ1_PROFILE) == _PQ1_ALG:
            understood |= {_PQ1_PROFILE}
        unknown = set(crit) - understood
        if unknown:
            raise ValueError(f"unknown critical header parameter(s): {sorted(unknown)}")
        if not _UNDERSTOOD_CRIT.issubset(crit):
            raise ValueError(f"JOSE header 'crit' must include {sorted(_UNDERSTOOD_CRIT)}")
        for param in crit:
            if param not in header:
                raise ValueError(f"critical header parameter {param!r} named in 'crit' but absent")

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["receipt_hash"] = self.receipt_hash
        d["jws"] = self.jws
        return d


# ---------------------------------------------------------------------------
# Logger — emits receipts and writes them to a chain sink
# ---------------------------------------------------------------------------


class ProvenanceLogger:
    """High-level API for emitting provenance receipts.

    Wraps an :class:`AgentIdentity` and a JSONL file (or any object with
    ``.write(str)`` + ``.flush()``). Each ``record_*`` method signs a receipt,
    appends it to the sink, and returns the receipt's hash so callers can
    pass it as a parent to the next step.

    Parameters
    ----------
    agent : AgentIdentity
        Identity whose key signs every emitted receipt.
    sink_path : str | Path, optional
        Append-only JSONL path. Mutually exclusive with *sink_file*.
    sink_file : file-like, optional
        Pre-opened file-like object to write to. The logger never closes it.
    tenant : str, optional
        Tenant label written into every receipt. Useful in multi-tenant SaaS.
    """

    def __init__(
        self,
        agent: AgentIdentity,
        sink_path: str | Path | None = None,
        sink_file: Any | None = None,
        tenant: str | None = None,
        quantum_mode: str = "off",
        pq_private_key: Any = None,
    ) -> None:
        if (sink_path is None) == (sink_file is None):
            raise ValueError("exactly one of sink_path or sink_file must be provided")
        if quantum_mode not in ("off", "strict"):
            raise ValueError(f"quantum_mode must be 'off' or 'strict', got {quantum_mode!r}")
        self._agent = agent
        self._tenant = tenant
        self._hybrid: Any = None
        if quantum_mode == "strict":
            from cryptography.hazmat.primitives.asymmetric.mldsa import (
                MLDSA65PrivateKey,
            )

            from raucle.pq import (
                HybridSigner,
                PQUnavailable,
                pq_key_id_from_public_key,
            )

            try:
                if pq_private_key is not None:
                    if not isinstance(pq_private_key, MLDSA65PrivateKey):
                        raise TypeError(
                            "pq_private_key must be an MLDSA65PrivateKey "
                            "(generate with raucle.pq.pq_generate and persist the "
                            "seed; a fresh key every restart changes pqk and "
                            "splits the chain's key identity)"
                        )
                    self._hybrid = HybridSigner(
                        ed25519_private=agent._private_key,
                        pq_private=pq_private_key,
                        pq_key_id=pq_key_id_from_public_key(pq_private_key.public_key()),
                    )
                else:
                    self._hybrid = HybridSigner.from_ed25519(agent._private_key)
            except PQUnavailable as exc:
                raise RuntimeError(
                    "quantum_mode='strict' requires ML-DSA-65 support; "
                    "this runtime's cryptography build has none"
                ) from exc
        if sink_path is not None:
            sink_path = Path(sink_path)
            # Pre-load any existing receipts so taint inheritance keeps working
            # across logger restarts on the same chain file.
            self._taint_by_hash: dict[str, set[str]] = {}
            if sink_path.exists():
                self._load_existing_taints(sink_path)
            self._file = open(sink_path, "a", encoding="utf-8")  # noqa: SIM115
            self._owns_file = True
        else:
            self._taint_by_hash = {}
            self._file = sink_file
            self._owns_file = False

    def _load_existing_taints(self, path: Path) -> None:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    # Taint is read from the SIGNED JWS, never the envelope: the
                    # minimal envelope no longer mirrors payload fields, and even
                    # when it did those copies were unsigned/untrusted.
                    jws = raw.get("jws")
                    if not jws:
                        continue
                    receipt = ProvenanceReceipt.from_jws(jws)
                    if receipt.receipt_hash:
                        self._taint_by_hash[receipt.receipt_hash] = set(receipt.taint)
                except (ValueError, KeyError):
                    continue

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._owns_file:
            self._file.close()

    def __enter__(self) -> ProvenanceLogger:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def agent(self) -> AgentIdentity:
        return self._agent

    # ------------------------------------------------------------------
    # Recording API
    # ------------------------------------------------------------------

    def record_user_input(
        self,
        text: str,
        *,
        taint: set[str] | None = None,
    ) -> str:
        """Record an untrusted input entering the graph (chain root)."""
        receipt = self._build(
            operation=Operation.USER_INPUT,
            parents=[],
            input_hash=hash_text(text),
            taint=set(taint or {"external_user"}),
        )
        return self._emit(receipt)

    def record_model_call(
        self,
        *,
        parents: list[str],
        model: str,
        input_text: str,
        output_text: str,
        extra_taint: set[str] | None = None,
    ) -> str:
        """Record an LLM invocation descending from one or more parents."""
        self._check_model_permission(model)
        receipt = self._build(
            operation=Operation.MODEL_CALL,
            parents=parents,
            model=model,
            input_hash=hash_text(input_text),
            output_hash=hash_text(output_text),
            taint=self._inherit_taint(parents, extra_taint),
        )
        return self._emit(receipt)

    def record_tool_call(
        self,
        *,
        parents: list[str],
        tool: str,
        input_args: Any,
        output: Any,
        extra_taint: set[str] | None = None,
    ) -> str:
        """Record a tool / function invocation.

        Lane Q16: receipts minted by this application-recorded path carry
        ``x_evidence`` = ``self_reported`` (the executing application's own
        attestation, additive informational metadata).
        """
        self._check_tool_permission(tool)
        receipt = self._build(
            operation=Operation.TOOL_CALL,
            parents=parents,
            tool=tool,
            input_hash=hash_obj(input_args),
            output_hash=hash_obj(output),
            taint=self._inherit_taint(parents, extra_taint),
            x_evidence=EVIDENCE_SELF_REPORTED,
        )
        return self._emit(receipt)

    def record_retrieval(
        self,
        *,
        parents: list[str],
        corpus: str,
        query: str,
        retrieved_chunks: Any,
        corpus_trusted: bool = False,
    ) -> str:
        """Record a retrieval step (RAG / vector store).

        By default adds a ``rag:<corpus>`` taint, marking the result as
        derived from third-party / external data. Set *corpus_trusted=True*
        only when the corpus has been independently attested.
        """
        extra: set[str] = set()
        if not corpus_trusted:
            extra.add(f"rag:{corpus}")
        receipt = self._build(
            operation=Operation.RETRIEVAL,
            parents=parents,
            corpus=corpus,
            input_hash=hash_text(query),
            output_hash=hash_obj(retrieved_chunks),
            taint=self._inherit_taint(parents, extra),
        )
        return self._emit(receipt)

    def record_guardrail_scan(
        self,
        *,
        parents: list[str],
        scanned_text: str,
        verdict: str,
        ruleset_hash: str,
        scan_target: str = "input",
    ) -> str:
        """Record that a guardrail scanned an input or output.

        Auto-emitted by :class:`Scanner` when an agent identity is wired in.
        Lets downstream consumers prove the guardrail actually ran.
        """
        receipt = self._build(
            operation=Operation.GUARDRAIL_SCAN,
            parents=parents,
            input_hash=hash_text(scanned_text),
            ruleset_hash=ruleset_hash,
            guardrail_verdict=verdict,
            taint=self._inherit_taint(parents, {f"guardrail-scan:{scan_target}"}),
        )
        return self._emit(receipt)

    def record_agent_handoff(
        self,
        *,
        parents: list[str],
        target_agent_id: str,
        handoff_payload: Any,
    ) -> str:
        """Record that this agent passed work to another agent."""
        _validate_agent_id(target_agent_id)
        receipt = self._build(
            operation=Operation.AGENT_HANDOFF,
            parents=parents,
            input_hash=hash_obj({"target": target_agent_id}),
            output_hash=hash_obj(handoff_payload),
            taint=self._inherit_taint(parents, None),
        )
        return self._emit(receipt)

    def record_sanitisation(
        self,
        *,
        parents: list[str],
        removed_taints: set[str],
        sanitiser_id: str,
        input_text: str,
        output_text: str,
    ) -> str:
        """Record an explicit sanitisation step.

        The only operation permitted to *shrink* the taint set. The removed
        tags are listed explicitly so verifiers can audit the claim.
        """
        inherited = self._inherit_taint(parents, None)
        remaining = inherited - removed_taints
        receipt = self._build(
            operation=Operation.SANITISATION,
            parents=parents,
            tool=sanitiser_id,
            input_hash=hash_text(input_text),
            output_hash=hash_text(output_text),
            taint=remaining,
        )
        # Stash the claim in a structured way via the corpus field — slightly
        # abusive but avoids inventing a new payload field for one operation.
        # The removed tags are a set (verifiers parse order-independently, §4.2);
        # producers SHOULD emit them in UTF-16 code-unit order (§4.3.1) for
        # canonical determinism, which we do here.
        receipt.corpus = _REMOVED_PREFIX + ",".join(sorted(removed_taints, key=_utf16_key))
        return self._emit(receipt)

    def record_merge(
        self,
        *,
        parents: list[str],
        output: Any,
        extra_taint: set[str] | None = None,
    ) -> str:
        """Record a confluence — N parents combine into one descendant."""
        if len(parents) < 2:
            raise ValueError("merge requires at least 2 parents")
        receipt = self._build(
            operation=Operation.MERGE,
            parents=parents,
            output_hash=hash_obj(output),
            taint=self._inherit_taint(parents, extra_taint),
        )
        return self._emit(receipt)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build(
        self,
        *,
        operation: Operation,
        parents: list[str],
        taint: set[str],
        input_hash: str = "",
        output_hash: str = "",
        model: str = "",
        tool: str = "",
        corpus: str = "",
        ruleset_hash: str = "",
        guardrail_verdict: str = "",
        x_evidence: str = "",
    ) -> ProvenanceReceipt:
        return ProvenanceReceipt(
            agent_id=self._agent.agent_id,
            agent_key_id=self._agent.key_id,
            operation=operation,
            parents=list(parents),
            input_hash=input_hash,
            output_hash=output_hash,
            model=model,
            tool=tool,
            corpus=corpus,
            ruleset_hash=ruleset_hash,
            guardrail_verdict=guardrail_verdict,
            x_evidence=x_evidence,
            taint=sorted(taint),
            tenant=self._tenant,
            issued_at=int(dt.datetime.now(dt.timezone.utc).timestamp()),
        )

    def _emit(self, receipt: ProvenanceReceipt) -> str:
        receipt.sign(self._agent, hybrid=self._hybrid)
        # §8.1 minimal envelope: write ONLY {receipt_hash, jws}. The JWS already
        # carries the canonical, signed payload — mirroring payload fields into
        # the envelope (the old to_dict() format) created unsigned, unvalidated
        # duplicates a reader could be tricked into trusting. The verifier
        # rejects any other top-level field.
        self._file.write(
            json.dumps(
                {"receipt_hash": receipt.receipt_hash, "jws": receipt.jws}, ensure_ascii=False
            )
            + "\n"
        )
        self._file.flush()
        self._taint_by_hash[receipt.receipt_hash] = set(receipt.taint)
        return receipt.receipt_hash

    def _inherit_taint(
        self,
        parents: list[str],
        extra: set[str] | None,
    ) -> set[str]:
        """Compute the inherited taint set from parents + any extra tags.

        Looks up each parent's taint in the in-memory map populated as
        receipts are emitted. Unknown parents (e.g. from a sibling logger
        on the same chain) contribute nothing — the verifier catches the
        broken link separately.
        """
        result: set[str] = set(extra or set())
        for parent_hash in parents:
            result.update(self._taint_by_hash.get(parent_hash, set()))
        return result

    def _check_model_permission(self, model: str) -> None:
        if not self._agent.statement.permits_model(model):
            raise PermissionError(
                f"agent {self._agent.agent_id} not permitted to call model {model!r}; "
                f"allowed: {self._agent.statement.allowed_models}"
            )

    def _check_tool_permission(self, tool: str) -> None:
        if not self._agent.statement.permits_tool(tool):
            raise PermissionError(
                f"agent {self._agent.agent_id} not permitted to call tool {tool!r}; "
                f"allowed: {self._agent.statement.allowed_tools}"
            )


# ---------------------------------------------------------------------------
# Verifier : walks the DAG and checks integrity
# ---------------------------------------------------------------------------


class ProvenanceVerifierBoundsExceeded(ValueError):
    """Named refusal (lane Q19): an untrusted bundle exceeded a verifier
    resource bound.

    The message names the limit hit, the observed value and the cap, so an
    auditor (or a caller matching on the report's errors) can tell exactly
    which bound refused the bundle. ``verify_chain`` converts every refusal
    into a named report error and an invalid verdict: the verifier refuses
    the bundle, it never silently grades past a bound.
    """

    def __init__(self, limit: str, observed: Any, cap: Any, detail: str) -> None:
        self.limit = limit
        self.observed = observed
        self.cap = cap
        self.detail = detail
        super().__init__(
            f"ProvenanceVerifierBoundsExceeded: {detail} "
            f"(limit={limit!r}, observed={observed!r}, cap={cap!r})"
        )


@dataclass(frozen=True)
class ProvenanceVerifierBounds:
    """The verifier's resource-contract defaults (lane Q19, Finding 67).

    An untrusted evidence bundle must not exhaust an auditor's verifier:
    verification runs under fixed bounds with named refusals. The defaults
    align with the existing receipt-size patterns:

    - ``max_bundle_bytes``: 256 KiB, byte-for-byte the simulate/manifest
      pasted-input cap family (``raucle.demo_scenarios._MAX_MANIFEST_BYTES``
      and the panel's client-side 256 KiB refusal): a chain file is the same
      class of untrusted pasted bundle.
    - ``max_parents``: 256, the 256 family again, comfortably above any
      observed fan-out and below the ~420-parent ceiling the 32 KiB payload
      cap implies, so an oversize parent array refuses with this named
      bound rather than drifting into a payload parse cap.
    - ``max_depth``: 256, an order of magnitude above the chain-graph
      composition query windows (``raucle.chain_graph._MAX_DEPTH = 20``,
      a query bound, not a verification bound) while still refusing
      deep-chain probes by name.
    - ``max_nodes``: 1024, the same order as ``MAX_CHAIN_RECORDS``; with
      default bundle bytes the byte bound binds first, so this is the tail
      bound that bites when an operator raises the byte bound.

    Every bound is env-overridable for operators with genuinely deep
    chains (``RAUCLE_VERIFY_MAX_BUNDLE_BYTES``, ``RAUCLE_VERIFY_MAX_PARENTS``,
    ``RAUCLE_VERIFY_MAX_DEPTH``, ``RAUCLE_VERIFY_MAX_NODES``;
    ``RAUCLE_DETECT_*`` legacy names keep working via the shared env
    helper). The bounds are ON by default (fail-closed posture, stated in
    docs/security-model.md); ``RAUCLE_VERIFY_BOUNDS=off`` restores the
    legacy unbounded verifier for the documented migration window. A
    malformed or ambiguous env value is refused, never defaulted through.
    """

    max_bundle_bytes: int = 256 * 1024
    max_parents: int = 256
    max_depth: int = 256
    max_nodes: int = 1024

    @classmethod
    def from_env(cls) -> ProvenanceVerifierBounds | None:
        """Resolve the bounds from the environment.

        Returns ``None`` when the operator disabled the bounds (documented
        migration window). Unset bounds fall through to the defaults; a
        malformed value raises; a security control must not silently
        default through a mistyped configuration.
        """
        from raucle._env import env as _env

        mode = _env("VERIFY_BOUNDS")
        if mode is not None:
            cleaned = mode.strip().lower()
            off_values = {"off", "0", "false", "no"}
            on_values = {"on", "1", "true", "yes", ""}
            if cleaned in off_values:
                return None
            if cleaned not in on_values:
                raise ValueError(
                    f"env RAUCLE_VERIFY_BOUNDS {mode!r} is not a recognised "
                    f"verifier-bounds mode (off values: {sorted(off_values)}); "
                    "the verifier refuses an ambiguous opt-out"
                )
        kwargs: dict[str, int] = {}
        for name, attr in (
            ("VERIFY_MAX_BUNDLE_BYTES", "max_bundle_bytes"),
            ("VERIFY_MAX_PARENTS", "max_parents"),
            ("VERIFY_MAX_DEPTH", "max_depth"),
            ("VERIFY_MAX_NODES", "max_nodes"),
        ):
            raw = _env(name)
            if raw is None or raw.strip() == "":
                continue
            try:
                value = int(raw.strip())
            except ValueError:
                raise ValueError(
                    f"env RAUCLE_{name} {raw!r} is not an integer; the verifier "
                    "refuses a malformed resource bound (fail-closed)"
                ) from None
            if value < 0:
                raise ValueError(
                    f"env RAUCLE_{name} {raw!r} is negative; resource bounds "
                    "are non-negative integers"
                )
            kwargs[attr] = value
        return cls(**kwargs)


@dataclass
class VerificationReport:
    """Outcome of verifying a provenance chain."""

    valid: bool
    receipt_count: int
    signature_failures: int = 0
    parent_link_failures: int = 0
    taint_monotonicity_failures: int = 0
    capability_violations: int = 0
    unauthorised_sanitisations: int = 0
    tampered_receipts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Receipts v1.2 (K3): one row per counterfactual block that passed its
    # structural re-check, stating honestly whether the recorded decision
    # was re-run. A chain verifier holds neither the alternative ruleset
    # (named only by digest) nor the stored input, so the row says not
    # re-run rather than guessing or upgrading the claim.
    counterfactual_evidence: list[dict[str, Any]] = field(default_factory=list)
    # Lane Q16 (additive, informational): the trust mode of every capability
    # statement the verifier actually resolved while checking a chain,
    # keyed by agent_key_id. ``self_asserted`` is the honest default (the
    # statement rides alongside the agent key, self-signed); a caller that
    # resolved a statement through a passport marks it ``authority_issued``
    # at construction. The modes never change any check outcome; the field
    # is omitted from to_dict() when empty so the v1.0 report body stays
    # byte-stable for consumers that pin it.
    capability_trust_modes: dict[str, str] = field(default_factory=dict)
    # Lane Q19 (diagnostics only): the bounded ancestry traversal's work
    # counters. ``traversal_receipts_expanded`` counts receipts whose
    # memoised depth was computed; ``traversal_edges_examined`` counts
    # parent adjacency entries examined. Read as attributes: the keys are
    # deliberately absent from to_dict() so the v1.0 report body stays
    # byte-stable for pack reproducibility and fixture digests.
    traversal_receipts_expanded: int = 0
    traversal_edges_examined: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "valid": self.valid,
            "receipt_count": self.receipt_count,
            "signature_failures": self.signature_failures,
            "parent_link_failures": self.parent_link_failures,
            "taint_monotonicity_failures": self.taint_monotonicity_failures,
            "capability_violations": self.capability_violations,
            "unauthorised_sanitisations": self.unauthorised_sanitisations,
            "tampered_receipts": self.tampered_receipts,
            "errors": self.errors,
        }
        # Receipts v1.2 (K3): the row set is OPTIONAL evidence. Emitting
        # the key on a chain with no v1.2 blocks would change the report
        # body shape for every existing consumer (pack reproducibility,
        # bundles, fixture digests), so when empty the key is omitted
        # and the v1.0 shape is byte-preserved.
        if self.counterfactual_evidence:
            d["counterfactual_evidence"] = self.counterfactual_evidence
        if self.capability_trust_modes:
            d["capability_trust_modes"] = dict(self.capability_trust_modes)
        return d


def _canonicalise_chain_path(path: str | Path) -> Path:
    """Canonicalise a caller-supplied chain path, refusing non-files.

    pythonsecurity:S8707 CLI-input pattern (the engine-proven recipe from
    raucle/policy_regression): the path is resolved exactly once and any
    shape that does not name an existing regular file is refused
    fail-closed with the verifier's named ``FileNotFoundError`` before any
    read happens. No containment comparison: the flow is read-only over
    the chain file it is handed, so only existence is asserted.

    Extracted verbatim from the former inline block at ``verify_chain``'s
    first use (python:S3776); behaviour is unchanged.
    """
    chain_path = Path(path).expanduser().resolve()
    if not chain_path.is_file():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(chain_path))
    return chain_path


@dataclass
class _ChainCollectors:
    """Cross-receipt collectors threaded through the per-line extension
    re-checks and read by the chain-end pin passes. The dicts and sets
    are created once per verify run and mutated in place; the bundle
    only holds the references (python:S107: the bundle replaces the
    eleven-parameter collector tail of ``_verify_receipt_extensions``)."""

    revoked_ids: set[str]
    revocation_lines: dict[str, int]
    lease_grants: dict[str, dict[str, Any]]
    receipts_by_hash: dict[str, ProvenanceReceipt]
    raw_lines_by_hash: dict[str, str]
    intent_constraint_values: set[str]
    tool_definition_latest: dict[str, dict[str, Any]]
    tool_definition_drift: dict[str, int]
    state_evidence_by_write: dict[str, dict[str, Any]]
    covered_writes: dict[str, dict[str, Any]]
    gate_tools_by_hash: dict[str, str]


class ProvenanceVerifier:
    """Verify a provenance chain end-to-end.

    Up to four classes of check, all of which must pass for ``valid=True``:

    1. **Signature** — every receipt's JWS verifies against the agent
       public key identified by its ``agent_key_id``.
    2. **DAG integrity** — every ``parent`` referenced by a receipt actually
       exists in the chain. The receipt's stored hash matches a recompute
       from the JWS bytes (tampering detection).
    3. **Taint monotonicity** — non-sanitisation receipts carry a taint set
       that is a superset of the union of their parents' taint sets.
       Sanitisation receipts may shrink the set, but only by tags listed in
       their ``removed:…`` claim.
    4. **Capability conformance** *(only when ``capabilities`` is supplied)* —
       every receipt's ``model`` / ``tool`` is permitted by the issuing
       agent's :class:`CapabilityStatement`. This is the verifier-side
       cross-check; without the statements the verifier cannot perform it
       (the producer-side check in :class:`ProvenanceLogger` is cooperative
       and a malicious producer can skip it).
    5. **Resource bounds** (lane Q19): an untrusted bundle is verified under
       fixed bounds (bundle bytes, parents per receipt, ancestry graph
       depth, total receipts) with named refusals
       (:class:`ProvenanceVerifierBoundsExceeded`, naming the limit hit and
       the observed value). Defaults align with the existing receipt-size
       patterns and are documented in docs/security-model.md; operators
       override them with ``RAUCLE_VERIFY_MAX_*``, or restore the legacy
       unbounded verifier with ``RAUCLE_VERIFY_BOUNDS=off`` (bounds ON by
       default, fail-closed). The ancestry walk is memoised (visit-set
       keyed caching): shared ancestors resolve once per verify call, the
       work counters ride the report as diagnostics, and no verdict
       changes for honest chains.

    Parameters
    ----------
    public_keys : dict[str, bytes]
        Mapping ``key_id -> PEM-encoded public key bytes``.
    capabilities : dict[str, CapabilityStatement], optional
        Mapping ``agent_key_id -> CapabilityStatement``. When provided, the
        verifier independently confirms each receipt only invoked permitted
        models/tools. Omit to skip capability conformance (signature/DAG/taint
        still run).
    executor_keys : dict[str, bytes], optional
        Mapping ``executor_key_id -> PEM-encoded Ed25519 public key bytes``
        for the x_bilateral extension: the tool/execution side that
        co-signs outcomes. Receipts carrying x_bilateral that name a key
        id absent here or whose co-signature does not verify FAIL (v1.2
        bilateral-outcomes); receipts without the block are untouched.
    state_pairings : dict[str, dict[str, Any]], optional
        Mapping ``pairing_id -> bounded pairing row`` for the x_state
        extension (v1.2 state-verification): the deployment's
        write-to-read pairing registry, the same constructor-carried
        state pattern as ``executor_keys``. When provided, the chain-end
        pass re-checks pairing linkage and coverage: a covered write
        receipt with neither evidence nor the absent sentinel marks
        INVALID with a named reason. Without it the x_state blocks stay
        structural (the off-deployment residual, nothing fabricated).
    capability_trust_modes : dict[str, str], optional
        Lane Q16, INFORMATIONAL: mapping ``agent_key_id -> trust mode`` for
        the supplied capability statements, ``self_asserted`` (default for
        every statement marked neither) or ``authority_issued`` (the
        statement was resolved through a separately vouched, registry-
        anchored passport). Unknown mode names are refused here, fail-closed;
        the labels never change any check outcome and the report carries
        them under ``capability_trust_modes`` only when statements were
        actually resolved.
    """

    def __init__(
        self,
        public_keys: dict[str, bytes],
        capabilities: dict[str, CapabilityStatement] | None = None,
        pq_public_keys: dict[str, bytes | str] | None = None,
        require_pq: bool = False,
        executor_keys: dict[str, bytes] | None = None,
        state_pairings: dict[str, dict[str, Any]] | None = None,
        capability_trust_modes: dict[str, str] | None = None,
    ) -> None:
        from cryptography.hazmat.primitives import serialization

        self._keys: dict[str, Any] = {
            kid: serialization.load_pem_public_key(pem) for kid, pem in public_keys.items()
        }
        # Separate namespace from agent keys: execution-side co-signers.
        # Unknown executor keys fail closed (the bilateral leg never verifies).
        self._exec_keys: dict[str, Any] = {
            kid: serialization.load_pem_public_key(pem)
            for kid, pem in (executor_keys or {}).items()
        }
        self._caps: dict[str, CapabilityStatement] = dict(capabilities or {})
        # Lane Q16: informational trust-mode labels for the supplied
        # statements. The vocabulary is validated here (fail-closed on a
        # mistyped label) but the modes never influence any check below:
        # they exist so the verify verdict can HONESTLY say how each
        # resolved statement was vouched instead of letting a cryptographic
        # self-signature imply organisational authorisation.
        self._trust_modes: dict[str, str] = {}
        for kid, mode in (capability_trust_modes or {}).items():
            if mode not in _TRUST_MODES:
                raise ValueError(
                    f"unknown trust mode {mode!r} for {kid!r}; expected "
                    f"{TRUST_MODE_SELF_ASSERTED!r} or {TRUST_MODE_AUTHORITY_ISSUED!r}"
                )
            self._trust_modes[kid] = mode
        # ML-DSA-65 keys for pq1 hybrid receipts: pq_key_id -> PEM bytes.
        # A pq1 receipt whose pqk is not in this mapping fails closed.
        self._pq_keys: dict[str, Any] = {}
        for kid, pem in (pq_public_keys or {}).items():
            try:
                from raucle.pq import pq_public_key_from_pem

                self._pq_keys[kid] = pq_public_key_from_pem(
                    pem.decode("ascii") if isinstance(pem, bytes) else pem
                )
            except Exception:
                # ML-DSA unavailable in this runtime: remember the id as
                # known-but-unloadable so pq1 receipts fail with a clear
                # PQUnavailable error at verify time rather than silently
                # downgrading.
                self._pq_keys[kid] = None
        # Quantum-strict mode (mirrors AuditVerifier): every receipt in
        # the chain MUST be a pq1 hybrid (4-segment JWS). A chain whose
        # PQ fields were stripped verifies classically otherwise - the
        # field-stripping downgrade this closes leaves no in-band trace,
        # so strict mode is the only complete answer. Packs declare
        # require_pq in their index; verification enforces the pack's
        # own statement about itself.
        self._require_pq = bool(require_pq)
        # EPIC W lane W1: the deployment's pairing registry (pairing_id
        # -> bounded row) and the covered write tools derived from it.
        # Constructor-carried state, like executor_keys: without it the
        # x_state checks are structural only.
        self._state_pairings: dict[str, dict[str, Any]] = dict(state_pairings or {})
        self._state_write_tools: set[str] = {
            str(row.get("write_tool") or "")
            for row in self._state_pairings.values()
            if row.get("write_tool")
        }
        # Lane Q19: verifier resource bounds. Defaults plus RAUCLE_VERIFY_MAX_*
        # operator overrides; RAUCLE_VERIFY_BOUNDS=off restores the legacy
        # unbounded verifier for the documented migration window. None here
        # disables every added pass (bounds, memoised traversal, cycle
        # refusal) and reproduces the pre-Q19 verdict behaviour exactly.
        self._bounds = ProvenanceVerifierBounds.from_env()

    @staticmethod
    def _parse_chain_line(
        line: str, line_no: int, report: VerificationReport
    ) -> dict[str, Any] | None:
        """Parse one JSONL envelope line. Returns the raw envelope dict or None on error."""
        try:
            # Reject duplicate keys in the JSONL envelope wrapper too —
            # not just the inner JWS payload. A wrapper like
            # {"jws": <evil>, "jws": <good>, "receipt_hash": ...} would
            # otherwise let two parsers disagree on which receipt the
            # line carries (envelope smuggling, §8.10 #3).
            raw = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            # §8.1 envelope dimension: the wrapper carries exactly
            # {receipt_hash, jws}. Reject any other top-level field
            # (unless a registered x-raucle- versioned extension) — an
            # unknown field is envelope malleability we never validate.
            extra = _registry.unknown_envelope_fields(set(raw))
            if extra:
                raise ValueError(f"unknown envelope field(s): {sorted(extra)}")
            return raw
        except (ValueError, KeyError) as exc:
            report.errors.append(f"line {line_no}: malformed record: {exc}")
            report.valid = False
            return None

    def _verify_capability_conformance(
        self, receipt: ProvenanceReceipt, line_no: int, report: VerificationReport
    ) -> None:
        """Check capability conformance for a receipt (when statements supplied)."""
        if not self._caps:
            return
        stmt = self._caps.get(receipt.agent_key_id)
        if stmt is None:
            report.capability_violations += 1
            report.errors.append(
                f"line {line_no}: no capability statement supplied for "
                f"agent_key_id={receipt.agent_key_id} — unknown key rejected"
            )
            report.valid = False
            return
        if not self._verify_statement(stmt, receipt.agent_key_id):
            report.capability_violations += 1
            report.errors.append(
                f"line {line_no}: capability statement for "
                f"{receipt.agent_key_id} failed signature/key-binding verification"
            )
            report.valid = False
            return
        # Lane Q16: the statement resolved, so the verdict names how it was
        # vouched (informational only, never an input to any check).
        report.capability_trust_modes.setdefault(
            receipt.agent_key_id,
            self._trust_modes.get(receipt.agent_key_id, TRUST_MODE_SELF_ASSERTED),
        )
        # Identity binding: the receipt's agent_id must be the
        # identity the capability statement (and thus the key)
        # speaks for. (round-3 #5 identity spoof).
        if receipt.agent_id != stmt.agent_id:
            report.capability_violations += 1
            report.errors.append(
                f"line {line_no}: receipt agent_id {receipt.agent_id!r} does not "
                f"match capability statement agent_id {stmt.agent_id!r} for "
                f"{receipt.agent_key_id}"
            )
            report.valid = False
        # Expiry: an expired capability statement must not
        # authorize receipts issued at/after it expired (round-3 #4).
        if (
            stmt.expires_at is not None
            and receipt.issued_at
            and receipt.issued_at >= stmt.expires_at
        ):
            report.capability_violations += 1
            report.errors.append(
                f"line {line_no}: capability statement for {receipt.agent_key_id} "
                f"expired at {stmt.expires_at} but receipt issued at "
                f"{receipt.issued_at}"
            )
            report.valid = False
        if receipt.model and not stmt.permits_model(receipt.model):
            report.capability_violations += 1
            report.errors.append(
                f"line {line_no}: model {receipt.model!r} not permitted by "
                f"capability statement for {receipt.agent_key_id}"
            )
            report.valid = False
        if receipt.tool and not stmt.permits_tool(receipt.tool):
            report.capability_violations += 1
            report.errors.append(
                f"line {line_no}: tool {receipt.tool!r} not permitted by "
                f"capability statement for {receipt.agent_key_id}"
            )
            report.valid = False

    def _verify_dag_and_taint(
        self,
        receipts_by_hash: dict[str, ProvenanceReceipt],
        report: VerificationReport,
    ) -> None:
        """Second pass: DAG integrity + taint monotonicity."""
        for h, receipt in receipts_by_hash.items():
            for parent_hash in receipt.parents:
                if parent_hash not in receipts_by_hash:
                    report.parent_link_failures += 1
                    report.errors.append(f"receipt {h}: parent {parent_hash} not found in chain")
                    report.valid = False
            self._check_taint(receipt, receipts_by_hash, report)

    def _verify_ancestry_bounds(
        self,
        receipts_by_hash: dict[str, ProvenanceReceipt],
        report: VerificationReport,
    ) -> None:
        """Lane Q19: the bounded, memoised ancestry pass.

        Iterative (explicit worklist, so a deep chain never reaches
        Python's recursion limit) and memoised: each receipt's ancestry
        depth is computed exactly once and cached by receipt hash, so
        shared subgraphs resolve once per verify call and every parent
        adjacency entry is examined exactly once. Two named refusals can
        fire during the walk, each raising
        :class:`ProvenanceVerifierBoundsExceeded`:

        - ``graph_depth``: a receipt's ancestry depth (longest cited
          parent path from this bundle's resolvable receipts) exceeds
          ``max_depth``; observed is the offending depth.
        - ``cycle``: the walk's in-flight set (grey state) is re-entered
          by a cited parent, i.e. the parent graph is not acyclic. Honest
          chains cannot reach this through the public API: receipt hashes
          are content-derived, so a true cycle would need a hash fixed
          point; the detector is defensive (a forged or corrupted map
          must terminate with a named refusal, never spin).

        Raises :class:`ProvenanceVerifierBoundsExceeded`; ``verify_chain``
        converts a refusal into a named report error and an invalid
        verdict, and stops the walk (a bounded walk refuses, it does not
        grade every receipt of a refused bundle). Mutates the report's
        traversal counters in place; with bounds disabled the pass is a
        no-op and the counters stay zero (legacy behaviour).
        """
        bounds = self._bounds
        if bounds is None:
            return
        state: dict[str, int] = {}
        depth_memo: dict[str, int] = {}
        for start in sorted(receipts_by_hash):
            if state.get(start, _white) == _black:
                continue
            _walk_ancestry_from(start, receipts_by_hash, state, depth_memo, bounds, report)

    def _validate_chain_record(
        self, raw: dict[str, Any], line_no: int, report: VerificationReport
    ) -> ProvenanceReceipt | None:
        """Parse + validate one chain record: JWS parse, stored-hash
        tamper check, signature, require_pq strict mode, structural
        rules. Appends errors to the report; returns the receipt or
        None when the record cannot be used."""
        try:
            # With validate_structure disabled: the chain verifier reports each
            # structural error per-line below (via _structural_errors)
            # rather than raising on the first, so callers see the full
            # set of problems in one report.
            receipt = ProvenanceReceipt.from_jws(raw["jws"], strict=True, validate_structure=False)
        except (ValueError, KeyError) as exc:
            report.errors.append(f"line {line_no}: malformed record: {exc}")
            report.valid = False
            return None

        # Tampering: recomputed hash must match the stored one
        if raw.get("receipt_hash") != receipt.receipt_hash:
            report.tampered_receipts.append(receipt.receipt_hash)
            report.errors.append(f"line {line_no}: receipt_hash mismatch — record tampered")
            report.valid = False

        # Signature verify
        if not self._verify_signature(receipt):
            report.signature_failures += 1
            report.errors.append(
                f"line {line_no}: signature verification failed for "
                f"agent_key_id={receipt.agent_key_id}"
            )
            report.valid = False

        # require_pq strict mode: every receipt must be pq1 hybrid (a
        # header that declares the profile - the three-segment Compact
        # emission or the legacy four-segment dot form). A classical-only
        # receipt in a chain that declares quantum-safe emission fails
        # closed - this is the ProvenanceVerifier mirror of AuditVerifier's
        # strict mode and closes the field-stripping downgrade for pack
        # verification: stripping the PQ component leaves a fully
        # valid-looking v1 receipt, and only strict mode catches it.
        if self._require_pq and not _jws_declares_pq1(receipt.jws):
            report.errors.append(
                f"line {line_no}: require_pq: receipt is not a "
                "raucle/pq1 hybrid receipt (no ML-DSA-65 component)"
            )
            report.valid = False

        # Structural validity per operation (spec v1 §4.2/§6): required
        # fields, root rule, merge arity. A tool_call with no parents and
        # no output_hash, etc., is malformed and must be rejected.
        for serr in _structural_errors(receipt):
            report.errors.append(f"line {line_no}: {serr}")
            report.valid = False

        # Lane Q19: per-receipt fan-out bound, named per-line like the
        # structural errors so an auditor can find every offending receipt;
        # the rest of the bundle still grades.
        if self._bounds is not None and len(receipt.parents) > self._bounds.max_parents:
            report.errors.append(
                f"line {line_no}: "
                + str(
                    ProvenanceVerifierBoundsExceeded(
                        "parent_count",
                        len(receipt.parents),
                        self._bounds.max_parents,
                        "receipt parent array exceeds the verify fan-out bound",
                    )
                )
            )
            report.valid = False

        return receipt

    def _verify_receipt_extensions(
        self,
        raw: dict[str, Any],
        line_no: int,
        receipt: ProvenanceReceipt,
        report: VerificationReport,
        collectors: _ChainCollectors,
    ) -> None:
        """v1.1/v1.2 extension re-checks for one receipt (extracted from
        verify_chain): one helper per extension family, called in the
        historical order so the per-line error sequence is unchanged.
        The collectors travel as one bundle (python:S107) and mutate
        in place, as does *report*."""
        decoded, x_gate_payload = self._decode_gate_payload(raw)
        self._verify_delegated_authority_digest(x_gate_payload, line_no, report)
        self._verify_lease_extension(
            decoded,
            line_no,
            report,
            collectors.lease_grants,
            collectors.revoked_ids,
            collectors.revocation_lines,
        )
        self._verify_cascade_revocation(
            x_gate_payload,
            decoded,
            line_no,
            report,
            collectors.revoked_ids,
            collectors.revocation_lines,
            collectors.receipts_by_hash,
            collectors.intent_constraint_values,
        )
        self._verify_task_intent(
            x_gate_payload, receipt, line_no, report, collectors.intent_constraint_values
        )
        self._verify_harness_finding(decoded, line_no, report, collectors.receipts_by_hash)
        self._verify_time_anchor(
            decoded, line_no, report, collectors.receipts_by_hash, collectors.raw_lines_by_hash
        )
        self._verify_bilateral(decoded, line_no, receipt, report)
        self._verify_x_dlp(decoded, line_no, report, collectors.receipts_by_hash)
        self._verify_counterfactual(decoded, x_gate_payload, receipt, line_no, report)
        self._verify_tool_definition(
            x_gate_payload, line_no, report, collectors.tool_definition_latest
        )
        self._collect_tool_definition_drift(decoded, line_no, collectors.tool_definition_drift)
        self._verify_x_state(
            decoded,
            line_no,
            report,
            collectors.receipts_by_hash,
            collectors.state_evidence_by_write,
        )
        self._collect_state_coverage(
            x_gate_payload,
            receipt,
            line_no,
            collectors.covered_writes,
            collectors.gate_tools_by_hash,
        )

    def _collect_tool_definition_drift(
        self,
        decoded: Any,
        line_no: int,
        tool_definition_drift: dict[str, int],
    ) -> None:
        """Receipts v1.2 (EPIC W lane W2): record where each tool's last
        receipted ``definition_changed`` finding sits in the chain (last
        write wins: lines verify in chain order). The chain-end pin pass
        uses the position to tell a receipted transition from silent
        drift. Mutates *tool_definition_drift* in place."""
        finding = decoded.get("x_finding") if isinstance(decoded, dict) else None
        if not isinstance(finding, dict):
            return
        if (
            finding.get("harness") != _TOOL_SCHEMA_HARNESS
            or finding.get("test_id") != _DEFINITION_CHANGED_TEST_ID
        ):
            return
        repro = finding.get("repro")
        tool = str(repro.get("tool") or "") if isinstance(repro, dict) else ""
        if tool:
            tool_definition_drift[tool] = line_no

    def _verify_tool_definition(
        self,
        x_gate_payload: dict[str, Any],
        line_no: int,
        report: VerificationReport,
        tool_definition_latest: dict[str, dict[str, Any]],
    ) -> None:
        """Invariant (receipts v1.2, EPIC W lane W2): a gate receipt's
        optional tool_definition block re-checks offline - the version
        gate, the closed field set, the closed vantage vocabulary and
        the sha256-shaped digest, all per line. The pin discipline is a
        CHAIN-END pass (see _verify_tool_definition_pins): only the
        LATEST block per tool must re-derive from the on-disk manifest
        (the deployment's registry state), because a changed definition
        legitimately leaves superseded digests on earlier receipts -
        that is the drift evidence the reload path receipts. No content:
        the block is swept by the shared forbidden-field sweep. Receipts
        without the block are untouched (additive extension). Mutates
        *report* and *tool_definition_latest* in place."""
        block = x_gate_payload.get("tool_definition") if isinstance(x_gate_payload, dict) else None
        if block is None:
            return
        if not isinstance(block, dict):
            report.errors.append(
                f"line {line_no}: tool_definition must be an object, got {type(block).__name__}"
            )
            report.valid = False
            return

        self._forbidden_field_sweep(block, "tool_definition", line_no, report)
        _tool_definition_closed_fields(block, line_no, report)
        _tool_definition_known_values(block, line_no, report)
        digest = block.get("definition_digest")
        _record_tool_definition_latest(
            x_gate_payload, block, digest, line_no, tool_definition_latest
        )

    def _verify_tool_definition_pins(
        self,
        tool_definition_latest: dict[str, dict[str, Any]],
        tool_definition_drift: dict[str, int],
        report: VerificationReport,
    ) -> None:
        """Invariant (receipts v1.2, EPIC W lane W2, chain-end pass): the
        LATEST tool_definition block per tool must re-derive from the
        on-disk manifest it names, and a readable manifest must declare
        the tool - that is the deployment's registry state answering for
        the chain's final decisions. Earlier blocks may carry superseded
        digests: definition drift is exactly what the reload path
        receipts, and a verifier that recomputed HISTORICAL blocks
        against the CURRENT manifest would refute its own drift
        evidence. One exception, fail-closed in both directions: when
        the chain carries a receipted ``definition_changed`` finding for
        the tool AFTER the latest block, the digest divergence is signed
        evidence of an observed, recorded transition (a reload with no
        gate call since), so the recompute is excused; a diverging
        manifest with NO receipted transition is silent drift and fails
        with a named error. An unreadable manifest is the documented
        off-deployment residual: no recompute, the blocks stay
        structural, never a fabricated result. Mutates *report* in
        place."""
        for tool in sorted(tool_definition_latest):
            self._verify_one_tool_definition_pin(
                tool, tool_definition_latest[tool], tool_definition_drift, report
            )

    @staticmethod
    def _read_definition_manifest(manifest: str) -> Any:
        """The manifest's parsed entries when the file reads as JSON,
        else None (no recompute is possible; the off-deployment
        residual, never a crash)."""
        try:
            return json.loads(Path(manifest).read_text(encoding="utf-8"))
        except Exception:
            return None

    def _verify_one_state_evidence_pin(
        self,
        write_hash: str,
        bound: dict[str, Any],
        gate_tools_by_hash: dict[str, str],
        report: VerificationReport,
    ) -> None:
        """Linkage and presence re-check for one paired x_state claim
        (EPIC W lane W1 chain-end pass).

        Verbatim extraction of the per-write body of
        ``ProvenanceVerifier._verify_state_evidence_pins``
        (cognitive-complexity decomposition, S3776): same checks, same
        error strings, no behaviour change; the loop ``continue`` rides
        on ``return`` inside the extracted body, and the tool linkage
        and field-class presence re-checks ride on
        :meth:`_verify_state_tool_linkage` and
        :meth:`_verify_state_field_classes`.
        """
        pairing_id = str(bound.get("pairing_id") or "")
        if not pairing_id:
            return
        row = self._state_pairings.get(pairing_id)
        if row is None:
            report.errors.append(
                f"line {bound['line_no']}: x_state cites pairing {pairing_id!r} "
                "not in the pairing registry"
            )
            report.valid = False
            return
        self._verify_state_tool_linkage(
            write_hash, bound, row, pairing_id, gate_tools_by_hash, report
        )
        self._verify_state_field_classes(bound, row, report)

    def _verify_state_tool_linkage(
        self,
        write_hash: str,
        bound: dict[str, Any],
        row: dict[str, Any],
        pairing_id: str,
        gate_tools_by_hash: dict[str, str],
        report: VerificationReport,
    ) -> None:
        """The cited receipt's tool is the pairing's write tool, and the
        block's read tool is the pairing's read tool (EPIC W lane W1).

        Verbatim extraction of the tool-linkage section inside
        ``ProvenanceVerifier._verify_one_state_evidence_pin``
        (cognitive-complexity decomposition, S3776): same checks, same
        error strings, no behaviour change.
        """
        cited_tool = gate_tools_by_hash.get(write_hash)
        row_write_tool = str(row.get("write_tool") or "")
        if cited_tool is None or row_write_tool != cited_tool:
            report.errors.append(
                f"line {bound['line_no']}: x_state pairing {pairing_id!r} binds "
                f"write tool {row_write_tool!r}, but the cited receipt's tool "
                f"is {cited_tool!r}"
            )
            report.valid = False
        read_tool = str(bound.get("read_tool") or "")
        row_read_tool = str(row.get("read_tool") or "")
        if read_tool and row_read_tool != read_tool:
            report.errors.append(
                f"line {bound['line_no']}: x_state read tool {read_tool!r} is not "
                f"the pairing's read tool {row_read_tool!r}"
            )
            report.valid = False

    def _verify_state_field_classes(
        self,
        bound: dict[str, Any],
        row: dict[str, Any],
        report: VerificationReport,
    ) -> None:
        """Evidence-carrying claims re-check every required field class
        name is present (a presence re-check, deliberately dumb).

        Verbatim extraction of the field-class presence loop inside
        ``ProvenanceVerifier._verify_one_state_evidence_pin``
        (cognitive-complexity decomposition, S3776): same conditions,
        same error string, no behaviour change.
        """
        if bound.get("state") == "evidence":
            present = set(bound.get("field_classes") or [])
            for required_class in row.get("require_field_classes") or []:
                if required_class not in present:
                    report.errors.append(
                        f"line {bound['line_no']}: x_state field_classes is "
                        f"missing required class {required_class!r} (presence "
                        "re-check, digest-blind)"
                    )
                    report.valid = False

    def _verify_one_tool_definition_pin(
        self,
        tool: str,
        record: dict[str, Any],
        tool_definition_drift: dict[str, int],
        report: VerificationReport,
    ) -> None:
        """Re-derive one tool's LATEST tool_definition pin against the
        manifest it names (EPIC W lane W2 chain-end pass).

        Verbatim extraction of the per-tool body of
        ``ProvenanceVerifier._verify_tool_definition_pins``
        (cognitive-complexity decomposition, S3776): same checks, same
        error strings, no behaviour change; the loop ``continue`` rides
        on ``return`` inside the extracted body, and the manifest lookup
        and digest re-derivation ride on
        :meth:`_tool_definition_manifest_row` and
        :meth:`_rederive_tool_definition_digest`.
        """
        manifest = str(record["manifest"] or "")
        digest = record["digest"]
        line_no = int(record["line_no"])
        if not manifest or digest is None:
            return
        row = self._tool_definition_manifest_row(tool, manifest, line_no, report)
        if row is None:
            return
        finding_line = tool_definition_drift.get(tool)
        if finding_line is not None and finding_line > line_no:
            # The divergence is receipted: a definition_changed finding
            # later in the chain records the observed transition, so
            # the manifest's newer state is signed evidence, never
            # silent drift.
            return
        self._rederive_tool_definition_digest(tool, row, digest, line_no, report)

    def _tool_definition_manifest_row(
        self,
        tool: str,
        manifest: str,
        line_no: int,
        report: VerificationReport,
    ) -> dict[str, Any] | None:
        """Read the pinned manifest and find the tool's registry entry.

        Verbatim extraction of the manifest read and row lookup inside
        ``ProvenanceVerifier._verify_one_tool_definition_pin``
        (cognitive-complexity decomposition, S3776): same read, same
        error string, same order, no behaviour change. Returns the row,
        or None when the entries are unreadable or the tool is
        undeclared (the undeclared case still reports; the caller
        returns on None either way, exactly as the loop ``continue``
        did).
        """
        entries = self._read_definition_manifest(manifest)
        if not isinstance(entries, list):
            return None
        row = next(
            (r for r in entries if isinstance(r, dict) and r.get("name") == tool),
            None,
        )
        if row is None:
            report.errors.append(
                f"line {line_no}: tool_definition manifest {manifest!r} "
                f"does not declare the receipt's tool {tool!r}"
            )
            report.valid = False
            return None
        return row

    def _rederive_tool_definition_digest(
        self,
        tool: str,
        row: dict[str, Any],
        digest: Any,
        line_no: int,
        report: VerificationReport,
    ) -> None:
        """Digest-blind re-derivation against the registry's schema.

        Verbatim extraction of the digest recheck inside
        ``ProvenanceVerifier._verify_one_tool_definition_pin``
        (cognitive-complexity decomposition, S3776): same check, same
        error string, no behaviour change.
        """
        if isinstance(row.get("inputSchema"), dict):
            from raucle.tool_schema import _definition_digest

            if _definition_digest(row["inputSchema"]) != digest:
                report.errors.append(
                    f"line {line_no}: tool_definition digest does not re-derive "
                    f"from the manifest's registered schema for tool {tool!r}"
                )
                report.valid = False

    def _verify_bilateral(
        self,
        decoded: Any,
        line_no: int,
        receipt: ProvenanceReceipt,
        report: VerificationReport,
    ) -> None:
        """Invariant (v1.2, bilateral-outcomes): a receipt whose signed
        payload carries ``x_bilateral`` must bind the executor co-signature
        that covers the outcome and the receipt's own output_hash, under a
        key registered in ``executor_keys``. Fail-closed: a missing,
        unknown-key, non-verifying co-signature, or an outcome outside the
        closed vocabulary never verifies — nothing about the executor's
        claim is inferred. Receipts without the block are untouched
        (additive extension). Mutates *report* in place."""
        xb = decoded.get("x_bilateral") if isinstance(decoded, dict) else None
        if xb is None:
            return
        if not isinstance(xb, dict):
            report.errors.append(
                f"line {line_no}: x_bilateral must be an object, got {type(xb).__name__}"
            )
            report.valid = False
            return

        outcome = xb.get("outcome")
        if outcome not in _BILATERAL_OUTCOMES:
            report.errors.append(
                f"line {line_no}: x_bilateral outcome {outcome!r} outside the closed "
                f"vocabulary {list(_BILATERAL_OUTCOMES)}"
            )
            report.valid = False

        output_hash = xb.get("output_hash")
        if not receipt.output_hash or output_hash != receipt.output_hash:
            report.errors.append(
                f"line {line_no}: x_bilateral output_hash {output_hash!r} does not "
                f"bind the receipt's own output_hash {receipt.output_hash!r}"
            )
            report.valid = False

        executor_key_id = xb.get("executor_key_id")
        signature = xb.get("signature")
        if not signature or not isinstance(signature, str):
            # Fail-closed: an outcome claim without the executor's signature
            # over it is an unsigned claim, never silently accepted.
            report.errors.append(
                f"line {line_no}: x_bilateral carries no executor signature "
                f"(fail-closed: the outcome would otherwise be inferred)"
            )
            report.valid = False
        if not executor_key_id or not isinstance(executor_key_id, str):
            report.errors.append(f"line {line_no}: x_bilateral names no executor key id")
            report.valid = False
        elif executor_key_id not in self._exec_keys:
            report.errors.append(
                f"line {line_no}: no executor key registered for "
                f"{executor_key_id!r} (fail-closed: unknown executor)"
            )
            report.valid = False
        if (
            signature
            and isinstance(signature, str)
            and executor_key_id
            and isinstance(executor_key_id, str)
            and executor_key_id in self._exec_keys
            and outcome in _BILATERAL_OUTCOMES
        ):
            from cryptography.exceptions import InvalidSignature

            try:
                self._exec_keys[executor_key_id].verify(
                    base64.b64decode(signature),
                    bilateral_signing_input(executor_key_id, outcome, str(xb.get("output_hash"))),
                )
            except (InvalidSignature, ValueError, TypeError):
                report.errors.append(
                    f"line {line_no}: x_bilateral executor signature does not verify "
                    f"over the bilateral binding (outcome {outcome!r}, "
                    f"executor {executor_key_id!r})"
                )
                report.valid = False

    def _verify_x_dlp(
        self,
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        receipts_by_hash: dict[str, ProvenanceReceipt],
    ) -> None:
        """Invariant (EPIC Q, lane Q-7a): a content-scanner DLP receipt
        (x_dlp) carries digests, class names and counts only, never
        content. Offline re-check with no scanner present: required
        fields, closed action/direction vocabularies, sha256-shaped
        digests, non-negative span counts agreeing with matched_classes,
        redaction/action consistency, the bounded matched-class
        vocabulary, and chain membership of any cited receipt. A payload
        carrying a content-like field (matched_value, snippet, ...) fails
        with a named error, so a leaky emitter cannot hide matched values
        inside signed evidence. Receipts without the block are untouched
        (additive extension, historical order preserved). Mutates *report*
        in place."""
        x_dlp = decoded.get("x_dlp") if isinstance(decoded, dict) else None
        if x_dlp is None:
            return
        if not isinstance(x_dlp, dict):
            report.errors.append(
                f"line {line_no}: x_dlp must be an object, got {type(x_dlp).__name__}"
            )
            report.valid = False
            return

        _x_dlp_vocabulary_errors(x_dlp, line_no, report)
        _x_dlp_digest_shapes(x_dlp, line_no, report)
        _x_dlp_redaction_consistency(x_dlp, line_no, report)
        classes = _x_dlp_matched_classes(x_dlp, line_no, report)
        _x_dlp_span_counts(x_dlp, classes, line_no, report)
        _x_dlp_bounded_disclosure(x_dlp, line_no, report, receipts_by_hash)

    def _verify_x_state(
        self,
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        receipts_by_hash: dict[str, ProvenanceReceipt],
        state_evidence_by_write: dict[str, dict[str, Any]],
    ) -> None:
        """Invariant (receipts v1.2, EPIC W lane W1): a state-verified
        write receipt (x_state) carries digests, a handle and
        field-presence names only, never read-back content. Offline
        re-check with no runtime present: the version gate, the closed
        field set, the literal absent sentinel, the sha256 digest
        shapes, the sentinel/evidence consistency and the cited write
        receipt's existence EARLIER in the chain (evidence follows the
        write, never pre-dates it). Digest-blind by design: the
        transport carries digests, never bytes, so no recompute
        exists to perform - the binding is the verifiable claim.
        Receipts without the block are untouched (additive extension,
        historical byte shapes preserved). Mutates *report* and
        *state_evidence_by_write* in place."""
        x_state = decoded.get("x_state") if isinstance(decoded, dict) else None
        if x_state is None:
            return
        if not isinstance(x_state, dict):
            report.errors.append(
                f"line {line_no}: x_state must be an object, got {type(x_state).__name__}"
            )
            report.valid = False
            return

        # Bounded disclosure: no content-like field anywhere in the block.
        self._forbidden_field_sweep(x_state, "x_state", line_no, report)
        _x_state_closed_set(x_state, line_no, report)
        cited = _x_state_cited_receipt(x_state, line_no, report, receipts_by_hash)
        state = _x_state_sentinel_semantics(x_state, line_no, report)
        _x_state_digest_shape(x_state, line_no, report)
        _x_state_handle_shape(x_state, line_no, report)
        _x_state_field_classes_shape(x_state, line_no, report)
        _x_state_collector(x_state, cited, state, line_no, state_evidence_by_write)

    def _collect_state_coverage(
        self,
        x_gate_payload: dict[str, Any],
        receipt: ProvenanceReceipt,
        line_no: int,
        covered_writes: dict[str, dict[str, Any]],
        gate_tools_by_hash: dict[str, str],
    ) -> None:
        """Receipts v1.2 (EPIC W lane W1): record every gate receipt's
        tool, and every ALLOWED receipt for a pairing-covered write
        tool, so the chain-end pass can name the write receipts that
        claimed success with no state evidence. Denied calls never
        executed, so no read-back is owed. Mutates the collectors in
        place."""
        if not isinstance(x_gate_payload, dict):
            return
        tool = str(x_gate_payload.get("tool") or "")
        if not tool:
            return
        gate_tools_by_hash[receipt.receipt_hash] = tool
        if (
            self._state_write_tools
            and tool in self._state_write_tools
            and str(receipt.guardrail_verdict) == "allow"
        ):
            covered_writes[receipt.receipt_hash] = {"tool": tool, "line_no": line_no}

    def _verify_state_evidence_pins(
        self,
        state_evidence_by_write: dict[str, dict[str, Any]],
        covered_writes: dict[str, dict[str, Any]],
        gate_tools_by_hash: dict[str, str],
        report: VerificationReport,
    ) -> None:
        """Invariant (receipts v1.2, EPIC W lane W1, chain-end pass):
        with the deployment's pairing registry, every ALLOWED gate
        receipt for a covered write tool must have a bound x_state
        receipt carrying evidence or the absent sentinel - neither
        present marks the write receipt INVALID with a named reason
        (the false-success class, checkable). Every x_state receipt
        with a pairing_id re-checks the linkage: the pairing exists,
        the cited write receipt's tool is the pairing's write tool,
        the block's read tool is the pairing's read tool, and every
        require_field_classes name is present in field_classes (a
        presence re-check, deliberately dumb). Without the registry
        this pass is the documented off-deployment residual: nothing
        is fabricated, linkage simply cannot be re-checked. Mutates
        *report* in place."""
        if not self._state_pairings:
            return
        for write_hash in sorted(state_evidence_by_write):
            self._verify_one_state_evidence_pin(
                write_hash, state_evidence_by_write[write_hash], gate_tools_by_hash, report
            )
        for write_hash in sorted(covered_writes):
            if write_hash in state_evidence_by_write:
                continue
            record = covered_writes[write_hash]
            report.errors.append(
                f"line {record['line_no']}: state evidence missing for "
                f"pairing-covered write receipt {write_hash} (tool "
                f"{record['tool']!r}): neither evidence nor the absent sentinel "
                "is present"
            )
            report.valid = False

    def _forbidden_field_sweep(
        self, block: Any, surface: str, line_no: int, report: VerificationReport
    ) -> None:
        """Receipts v1.2 (K3): the shared bounded-disclosure sweep. A
        content-like field name anywhere inside a signed block (any
        depth, object key or list element) fails with a named error, so
        a leaky emitter cannot hide argument or token material inside
        evidence. Mutates *report* in place."""
        stack = [block]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in _FORBIDDEN_FIELD_NAMES:
                        report.errors.append(
                            f"line {line_no}: {surface} carries content-like field "
                            f"{key!r} (bounded disclosure: identifiers, digests and "
                            f"counts only, never content)"
                        )
                        report.valid = False
                    stack.append(value)
            elif isinstance(node, (list, tuple)):
                stack.extend(node)

    @staticmethod
    def _session_rule_kinds() -> frozenset[str]:
        """The closed session-rule kind vocabulary (lazy import: the
        check runs per receipt, not at module load)."""
        from raucle.policy import SESSION_RULE_KINDS

        return frozenset(SESSION_RULE_KINDS)

    def _verify_counterfactual(
        self,
        decoded: Any,
        x_gate_payload: dict[str, Any],
        receipt: ProvenanceReceipt,
        line_no: int,
        report: VerificationReport,
    ) -> None:
        """Invariant (receipts v1.2, K3): a receipt's optional
        counterfactual block re-checks structurally offline - the version
        gate, the closed field set, the closed decision and rule-kind
        vocabularies, the sha256-shaped ruleset digest, evaluated_at
        never later than the receipt's own iat, session coherence with
        the receipt's own session id, and the exact two-key
        window_evidence shape. The recorded decision is not re-run: this
        verifier holds neither the alternative ruleset (named only by
        digest) nor the stored input, so a structurally valid block earns
        one evidence row that says not re-run, honestly, and the chain
        stays valid. Receipts without the block are untouched (additive
        extension). Mutates *report* in place."""
        cf = x_gate_payload.get("counterfactual")
        if cf is None:
            return
        if not isinstance(cf, dict):
            report.errors.append(
                f"line {line_no}: counterfactual must be an object, got {type(cf).__name__}"
            )
            report.valid = False
            return

        errors_before = len(report.errors)
        self._forbidden_field_sweep(cf, "counterfactual", line_no, report)
        _counterfactual_required_fields(cf, line_no, report)
        _counterfactual_vocabularies(cf, line_no, report)
        _counterfactual_evaluated_at(decoded, cf, line_no, report)
        _counterfactual_rule_fields(cf, line_no, report)
        session_kinds = self._session_rule_kinds()
        _counterfactual_rule_kind_vocab(cf, session_kinds, line_no, report)

        # Session coherence: the block cites the receipt's own session, and
        # the window evidence is exactly the closed two-key shape.
        session = cf.get("session")
        if session is not None:
            self._verify_counterfactual_session(session, x_gate_payload, line_no, report)

        decision = cf.get("decision")
        if len(report.errors) == errors_before:
            report.counterfactual_evidence.append(
                {
                    "receipt": receipt.receipt_hash,
                    "decision": decision,
                    "re_run": False,
                    "note": (
                        "counterfactual recorded at decision time by the gate "
                        "machinery; not re-run at verification (the alternative "
                        "ruleset is named only by digest and the stored input is "
                        "not held)"
                    ),
                }
            )

    def _verify_counterfactual_session(
        self,
        session: Any,
        x_gate_payload: dict[str, Any],
        line_no: int,
        report: VerificationReport,
    ) -> None:
        """Receipts v1.2 (K3): the counterfactual session block re-check -
        closed field set, the receipt's own session id, a positive integer
        window, the closed participant vocabulary and the exact two-key
        window_evidence shape (non-negative integer counters, string tool
        names). Mutates *report* in place."""
        if not isinstance(session, dict):
            report.errors.append(
                f"line {line_no}: counterfactual session must be an object, "
                f"got {type(session).__name__}"
            )
            report.valid = False
            return

        _counterfactual_session_field_sets(session, line_no, report)
        own_session_id = x_gate_payload.get("session_id") or ""
        cited_session_id = session.get("session_id")
        if cited_session_id is not None and cited_session_id != own_session_id:
            report.errors.append(
                f"line {line_no}: counterfactual session cites session id "
                f"{cited_session_id!r}, not the receipt's own session id "
                f"{own_session_id!r}"
            )
            report.valid = False
        _counterfactual_session_window(session, line_no, report)
        _counterfactual_session_participant(session, line_no, report)
        _counterfactual_window_evidence(session, line_no, report)

    def _decode_gate_payload(self, raw: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        """Invariant: x_gate lives INSIDE the signed JWS payload, not in the
        envelope (the envelope carries only {receipt_hash, jws}); an absent
        or malformed JWS yields an empty payload, so v1.0 receipts carry no
        extension checks. Returns (decoded JWS payload, the x_gate dict)."""
        # NB the previous `raw.get("x_gate")` was always empty - the
        # v1.1 digest re-check never fired; found by the A1 tests.
        x_gate_payload: dict[str, Any] = {}
        decoded: Any = None
        jws_str = raw.get("jws") if isinstance(raw, dict) else None
        if isinstance(jws_str, str) and jws_str.count(".") >= 2:
            seg = jws_str.split(".")[1]
            seg += "=" * (-len(seg) % 4)
            try:
                decoded = json.loads(base64.urlsafe_b64decode(seg))
                if isinstance(decoded, dict):
                    x_gate_payload = decoded.get("x_gate") or {}
            except (ValueError, TypeError):
                x_gate_payload = {}
        return decoded, x_gate_payload

    def _verify_delegated_authority_digest(
        self, x_gate_payload: dict[str, Any], line_no: int, report: VerificationReport
    ) -> None:
        """Invariant (v1.1): the delegated-authority chain_digest re-derives
        from the authorization block's own fields; a mismatch means the
        binding was tampered with or malformed. Mutates *report* in place."""
        auth = x_gate_payload.get("authorization")
        if auth:
            # Recompute the digest from the BLOCK's own fields (the
            # emitted block stores capability_id; authorization_block()
            # itself expects a token dict with token_id - reusing it
            # here would recompute over empty material).
            from raucle.provenance import _canonical_json, _sha256_hex

            expected_digest = _sha256_hex(
                _canonical_json(
                    {
                        "capability_id": auth.get("capability_id", ""),
                        "issuer": auth.get("issuer", ""),
                        "key_id": auth.get("key_id", ""),
                        "parent_id": auth.get("parent_id"),
                    }
                )
            )
            if auth.get("chain_digest") != expected_digest:
                report.errors.append(
                    f"line {line_no}: authorization chain_digest mismatch "
                    f"(tampered or malformed delegated-authority binding)"
                )
                report.valid = False

    def _verify_lease_extension(
        self,
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        lease_grants: dict[str, dict[str, Any]],
        revoked_ids: set[str],
        revocation_lines: dict[str, int],
    ) -> None:
        """Invariant (C1): a lease redemption cites a prior grant in the same
        chain, falls inside that grant's TTL window (the receipt's own iat
        is the redemption moment), never widens the granted scopes, and
        answers for the lease's revocation state at the moment of use: a
        revocation collected from an earlier line stops later redemptions
        (the temporal doctrine of A3). Grants and revocations collect as
        the walk proceeds, so both only bite later lines; the lease's own
        ``revoked`` event feeds the shared revocation collector, so an
        ``x_lease`` revoked event and an ``x_revocation`` block citing the
        lease id are the same revocation evidence. Mutates *report*,
        *lease_grants*, *revoked_ids* and *revocation_lines* in place."""
        # (x_lease rides the payload root, like x_revocation.)
        lease = decoded.get("x_lease") if isinstance(decoded, dict) else None
        if isinstance(lease, dict):
            # Bounded disclosure: the block carries handles, the grant
            # pairing, scope names and digests only, never content.
            self._forbidden_field_sweep(lease, "x_lease", line_no, report)
            action = lease.get("action")
            lid = str(lease.get("lease_id", ""))
            if action == "granted":
                lease_grants[lid] = lease
            elif action == "revoked":
                revoked_ids.add(lid)
                revocation_lines[lid] = line_no
            elif action == "redeemed":
                self._verify_lease_redemption(
                    decoded,
                    line_no,
                    report,
                    lease,
                    lid,
                    lease_grants.get(lid),
                    revoked_ids,
                    revocation_lines,
                )

    def _verify_lease_redemption(
        self,
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        lease: dict[str, Any],
        lid: str,
        grant: dict[str, Any] | None,
        revoked_ids: set[str],
        revocation_lines: dict[str, int],
    ) -> None:
        """Invariant (C1, redemption leg): a redemption must cite a grant
        collected from an EARLIER line, fall inside that grant's TTL
        window (the receipt's own iat is the redemption moment), never
        widen the granted scopes, and not follow the lease's revocation.
        Every refusal is named - pairing_absent, lease_revoked,
        lease_expired, scope_exceeded - so a failure names its class.
        Mutates *report* in place."""
        if grant is None:
            report.errors.append(
                f"line {line_no}: lease {lid!r} redeemed with no lease grant (pairing_absent)"
            )
            report.valid = False
            return
        if lid in revoked_ids:
            report.errors.append(
                f"line {line_no}: lease {lid!r} redeemed after revocation at "
                f"line {revocation_lines[lid]} (lease_revoked)"
            )
            report.valid = False
        redeemed_at = int(decoded.get("iat", 0))
        window_end = int(grant.get("granted_at", 0)) + int(grant.get("ttl_seconds", 0))
        if redeemed_at > window_end:
            report.errors.append(
                f"line {line_no}: lease {lid!r} redeemed after "
                f"lease expired (lease_expired, window ended {window_end})"
            )
            report.valid = False
        grant_scopes = grant.get("scopes") or {}
        redeem_scopes = lease.get("scopes") or {}
        if redeem_scopes and grant_scopes:
            from raucle.capability import _assert_narrowing

            try:
                _assert_narrowing(grant_scopes, redeem_scopes)
            except ValueError as exc:
                report.errors.append(
                    f"line {line_no}: lease {lid!r} redeemed beyond its "
                    f"granted scope (scope_exceeded: {exc})"
                )
                report.valid = False

    def _verify_cascade_revocation(
        self,
        x_gate_payload: dict[str, Any],
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        revoked_ids: set[str],
        revocation_lines: dict[str, int],
        receipts_by_hash: dict[str, ProvenanceReceipt],
        intent_constraint_values: set[str],
    ) -> None:
        """Invariant (A3): temporal cascade, single pass - a receipt minted
        AFTER a revocation of its cited authority is invalid; one minted
        BEFORE it remains valid evidence. Revocation events collect as the
        walk proceeds, so they only bite later lines. Receipts v1.2 (K3):
        a block carrying ``version`` is the v1.2 kind and takes the full
        structural re-check first (closed field set, kind and reason-class
        vocabularies, chain-linkage digests, the revoked_at binding, the
        shared bounded-disclosure sweep and the reason's class-level
        rule); a block without ``version`` is the shipped v1.0 shape and
        takes no v1.2 check (rule 4: revocations minted before this
        document are valid and stay valid). Mutates *report*,
        *revoked_ids* and *revocation_lines* in place."""
        auth_block_now = x_gate_payload.get("authorization") or {}
        cited_now = {
            auth_block_now.get("capability_id"),
            auth_block_now.get("parent_id"),
        }
        cited_now.discard(None)
        hit = revoked_ids.intersection(cited_now)
        if hit:
            first = min(hit)
            report.errors.append(
                f"line {line_no}: cited authority {first} "
                f"was revoked at line {revocation_lines[first]}"
            )
            report.valid = False
        revocation = None
        if isinstance(decoded, dict):
            revocation = decoded.get("x_revocation")
        if revocation and isinstance(revocation, dict):
            if "version" in revocation:
                self._verify_v12_revocation_block(
                    revocation,
                    decoded,
                    line_no,
                    report,
                    receipts_by_hash,
                    intent_constraint_values,
                )
            for rid in revocation.get("revoked_ids") or []:
                revoked_ids.add(rid)
                revocation_lines[rid] = line_no

    def _verify_v12_revocation_block(
        self,
        revocation: dict[str, Any],
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        receipts_by_hash: dict[str, ProvenanceReceipt],
        intent_constraint_values: set[str],
    ) -> None:
        """Invariant (receipts v1.2, K3): the versioned revocation block
        re-checks structurally offline - the version gate, the closed
        field set, the closed kind and reason-class vocabularies, the
        chain linkage (revoked_hashes keys exactly equal the revoked ids,
        every value a sha256 digest), revoked_at never later than the
        receipt's own iat, receipt-kind citations resolving in this chain,
        the shared bounded-disclosure sweep, and the reason staying at
        class level (never quoting a constraint value the chain's intent
        receipts disclose). Fail-closed: an unknown version, kind or
        reason class refuses with a named error, never a skip. Mutates
        *report* in place."""
        self._forbidden_field_sweep(revocation, "x_revocation", line_no, report)
        _revocation_v12_fields(revocation, line_no, report)
        kind = _revocation_v12_vocabularies(revocation, line_no, report)
        ids_ok = _revocation_ids_shape(revocation, line_no, report)
        _revocation_hashes_linkage(revocation, ids_ok, line_no, report)
        _revocation_v12_timestamp(revocation, decoded, line_no, report)
        _revocation_v12_bounded_reason(revocation, line_no, report, intent_constraint_values)
        _revocation_v12_receipt_citations(
            revocation, kind, ids_ok, line_no, report, receipts_by_hash
        )

    def _verify_task_intent(
        self,
        x_gate_payload: dict[str, Any],
        receipt: ProvenanceReceipt,
        line_no: int,
        report: VerificationReport,
        intent_constraint_values: set[str],
    ) -> None:
        """Invariant (v1.2, defence-in-depth): an ALLOW receipt must fall
        inside the approved tool scope and satisfy the intent constraints,
        re-checked deterministically over the bounded disclosure. A DENY
        for an out-of-intent attempt is the enforcement working, not a
        violation. The block's disclosed constraint values are collected
        for the revocation reason's class-level rule (a revocation
        receipt retained for the life of the archive must never quote
        them). Mutates *report* in place."""
        intent = x_gate_payload.get("intent")
        if intent is not None:
            self._collect_intent_constraint_values(x_gate_payload, intent_constraint_values)
        if intent is not None and x_gate_payload.get("decision") == "allow":
            gate_tool = x_gate_payload.get("tool") or receipt.tool
            intent_tools = intent.get("tools")
            if intent_tools is not None and gate_tool not in intent_tools:
                report.errors.append(
                    f"line {line_no}: ALLOW receipt tool {gate_tool!r} "
                    f"outside intent scope (approved tools: {intent_tools})"
                )
                report.valid = False
            intent_constraints = intent.get("constraints")
            check = x_gate_payload.get("intent_check") or {}
            satisfied = check.get("satisfied_fields") or {}
            if intent_constraints and satisfied:
                from raucle.capability import _check_constraints as _icc

                why = _icc(intent_constraints, satisfied)
                if why:
                    report.errors.append(
                        f"line {line_no}: ALLOW receipt violates intent constraint ({why})"
                    )
                    report.valid = False

    def _collect_intent_constraint_values(
        self, x_gate_payload: dict[str, Any], intent_constraint_values: set[str]
    ) -> None:
        """Receipts v1.2 (K3): collect the constraint VALUES an intent
        receipt discloses - the intent's declared constraint values and
        the intent check's satisfied field values - so the revocation
        reason's class-level rule can refuse a reason that quotes them.
        Values only, never field names: a reason naming a field names the
        schema, not the chain's disclosed material. Mutates
        *intent_constraint_values* in place."""
        intent = x_gate_payload.get("intent")
        if isinstance(intent, dict):
            constraints = intent.get("constraints")
            if isinstance(constraints, dict):
                self._collect_string_values(constraints, intent_constraint_values)
        check = x_gate_payload.get("intent_check")
        if isinstance(check, dict):
            satisfied = check.get("satisfied_fields")
            if isinstance(satisfied, dict):
                self._collect_string_values(satisfied, intent_constraint_values)

    @staticmethod
    def _collect_string_values(node: Any, out: set[str]) -> None:
        """Every non-empty string value anywhere in *node*, at any depth."""
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                stack.extend(current.values())
            elif isinstance(current, (list, tuple)):
                stack.extend(current)
            elif isinstance(current, str) and current:
                out.add(current)

    def _verify_harness_finding(
        self,
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        receipts_by_hash: dict[str, ProvenanceReceipt],
    ) -> None:
        """Invariant (EPIC D): a harness finding replays offline - it must
        cite a receipt that exists in the chain and report the decision the
        cited receipt actually recorded; a harness that misreports the gate
        cannot stay verifiable. Mutates *report* in place."""
        finding = decoded.get("x_finding") if isinstance(decoded, dict) else None
        if isinstance(finding, dict):
            cited = str(finding.get("cited_receipt", ""))
            cited_obj = receipts_by_hash.get(cited)
            if cited_obj is None:
                report.errors.append(
                    f"line {line_no}: finding {finding.get('finding_id', '')!r} "
                    f"cites receipt {cited!r} not in the chain"
                )
                report.valid = False
            else:
                claimed = str((finding.get("repro") or {}).get("actual_decision", ""))
                recorded = cited_obj.guardrail_verdict
                if claimed and recorded and claimed != recorded:
                    report.errors.append(
                        f"line {line_no}: finding {finding.get('finding_id', '')!r} "
                        f"misreports the cited receipt "
                        f"(claimed {claimed!r}, recorded {recorded!r})"
                    )
                    report.valid = False

    def _verify_time_anchor(
        self,
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        receipts_by_hash: dict[str, ProvenanceReceipt],
        raw_lines_by_hash: dict[str, str],
    ) -> None:
        """Invariant (EPIC G): the anchor binds a digest (sha256 over the
        exact cited ledger line) to an RFC 3161 TimeStampToken from a
        customer-chosen TSA. Offline re-check: the digest binds the
        receipt's own input_hash, the cited parent exists EARLIER in this
        chain, the head-line digest re-derives from the cited raw line,
        and the embedded token verifies (imprint, nonce, genTime, TSA
        signature). Fail-closed: a receipt claiming a TSA token in an
        install without the timestamp extra never verifies as attested.
        Mutates *report* in place."""
        x_ts = decoded.get("x_timestamp") if isinstance(decoded, dict) else None
        if isinstance(x_ts, dict):
            mode = x_ts.get("mode")
            digest = str(x_ts.get("digest", ""))
            self._verify_time_digest_binding(
                decoded, line_no, report, x_ts, digest, receipts_by_hash, raw_lines_by_hash
            )
            self._verify_time_source_mode(x_ts, line_no, report, mode, digest)

    def _verify_time_digest_binding(
        self,
        decoded: Any,
        line_no: int,
        report: VerificationReport,
        x_ts: dict[str, Any],
        digest: str,
        receipts_by_hash: dict[str, ProvenanceReceipt],
        raw_lines_by_hash: dict[str, str],
    ) -> None:
        """Invariant (EPIC G, digest leg): the anchor's digest binds the
        receipt's own input_hash, the cited parent exists EARLIER in this
        chain, and the head-line digest re-derives from the cited raw
        ledger line. Mutates *report* in place."""
        if digest != _SHA256_PREFIX + str(decoded.get("input_hash", "")):
            report.errors.append(
                f"line {line_no}: x_timestamp digest does not bind the receipt input_hash"
            )
            report.valid = False
        cited = str(x_ts.get("parent_receipt", ""))
        if cited not in receipts_by_hash:
            report.errors.append(
                f"line {line_no}: x_timestamp cites receipt {cited[:24]}... not in the chain"
            )
            report.valid = False
        else:
            raw_cited = raw_lines_by_hash.get(cited)
            import hashlib as _hl

            rederived = (
                _SHA256_PREFIX + _hl.sha256(raw_cited.encode("utf-8")).hexdigest()
                if raw_cited is not None
                else ""
            )
            if rederived != digest:
                report.errors.append(
                    f"line {line_no}: x_timestamp digest does not "
                    f"re-derive from the cited ledger line"
                )
                report.valid = False

    def _verify_time_source_mode(
        self,
        x_ts: dict[str, Any],
        line_no: int,
        report: VerificationReport,
        mode: Any,
        digest: str,
    ) -> None:
        """Invariant (EPIC G, mode leg): only tsa and opentimestamps modes
        may carry an x_timestamp anchor, and a tsa anchor must verify
        offline (imprint, nonce, genTime, TSA signature) with its recorded
        gen_time agreeing with the token. Fail-closed: internal mode and
        unknown modes never verify as attested. Mutates *report* in
        place."""
        if mode == "tsa":
            from raucle.timestamp import verify_token

            token_report = verify_token(
                base64.b64decode(x_ts.get("token", "")),
                expected_digest=bytes.fromhex(digest.removeprefix(_SHA256_PREFIX)),
                expected_nonce=int(x_ts.get("nonce", 0)),
            )
            if not token_report["valid"]:
                report.errors.extend(
                    f"line {line_no}: Time Stamp Token: {e}" for e in token_report["errors"]
                )
                report.valid = False
            elif str(x_ts.get("gen_time")) != str(token_report["gen_time"]):
                report.errors.append(
                    f"line {line_no}: recorded gen_time disagrees with the token's genTime"
                )
                report.valid = False
        elif mode == "opentimestamps":
            # Bounded claim: the receipt proves the anchoring EVENT
            # was recorded and binds digest + cite; the .ots proof
            # verifies against the Bitcoin chain externally. No
            # eIDAS Art 41 presumption attaches to it (spec).
            pass
        elif mode == "internal":
            report.errors.append(
                f"line {line_no}: internal time-source mode does not "
                f"carry an x_timestamp extension (spec time-source-v1)"
            )
            report.valid = False
        else:
            report.errors.append(f"line {line_no}: unsupported x_timestamp mode {mode!r}")
            report.valid = False

    def verify_chain(self, path: str | Path) -> VerificationReport:
        """Verify a JSONL chain file."""
        # pythonsecurity:S8707 CLI-input pattern (the engine-proven recipe
        # from raucle/policy_regression): canonicalise the chain path at
        # its first use, before any read, via the helper below (extracted
        # verbatim from the former inline block, python:S3776).
        chain_path = _canonicalise_chain_path(path)
        receipts_by_hash: dict[str, ProvenanceReceipt] = {}
        raw_lines_by_hash: dict[str, str] = {}
        report = VerificationReport(valid=True, receipt_count=0)
        revoked_ids: set[str] = set()
        revocation_lines: dict[str, int] = {}
        lease_grants: dict[str, dict[str, Any]] = {}
        # Receipts v1.2 (K3): the constraint values intent receipts disclose
        # across the whole chain, collected line by line so a later
        # revocation's reason can be refused for quoting them.
        intent_constraint_values: set[str] = set()
        # Receipts v1.2 (EPIC W lane W2): the LATEST tool_definition block
        # per tool, collected line by line; the pin discipline runs as a
        # chain-end pass (the newest block is the one the deployment's
        # registry state must answer for). The drift map records where
        # each tool's last receipted definition_changed finding sits in
        # the chain, so the pin pass can tell receipted drift from silent
        # drift.
        tool_definition_latest: dict[str, dict[str, Any]] = {}
        tool_definition_drift: dict[str, int] = {}
        # Receipts v1.2 (EPIC W lane W1): the x_state claim bound to
        # each write receipt, every gate receipt's tool, and the
        # ALLOWED receipts for pairing-covered write tools; the
        # coverage and linkage pass runs at chain end (the registry is
        # the deployment state answering for the chain's claims).
        state_evidence_by_write: dict[str, dict[str, Any]] = {}
        covered_writes: dict[str, dict[str, Any]] = {}
        gate_tools_by_hash: dict[str, str] = {}
        # Lane Q19: the bundle byte bound streams with the read, so an
        # oversize bundle refuses before its remaining lines are parsed.
        bounds = self._bounds
        bundle_bytes_seen = 0
        # python:S107: the chain-scoped collectors travel as one bundle
        # (the per-line helper now takes five parameters); the same
        # objects are shared, not copies, so every in-place mutation the
        # helpers make is visible to the chain-end pin passes below.
        collectors = _ChainCollectors(
            revoked_ids=revoked_ids,
            revocation_lines=revocation_lines,
            lease_grants=lease_grants,
            receipts_by_hash=receipts_by_hash,
            raw_lines_by_hash=raw_lines_by_hash,
            intent_constraint_values=intent_constraint_values,
            tool_definition_latest=tool_definition_latest,
            tool_definition_drift=tool_definition_drift,
            state_evidence_by_write=state_evidence_by_write,
            covered_writes=covered_writes,
            gate_tools_by_hash=gate_tools_by_hash,
        )

        with open(chain_path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                if bounds is not None:
                    bundle_bytes_seen += len(line.encode("utf-8")) + 1
                    if bundle_bytes_seen > bounds.max_bundle_bytes:
                        report.errors.append(
                            str(
                                ProvenanceVerifierBoundsExceeded(
                                    "bundle_bytes",
                                    bundle_bytes_seen,
                                    bounds.max_bundle_bytes,
                                    f"chain bundle exceeds the verify byte bound "
                                    f"at line {line_no}; the verifier stops "
                                    "reading and refuses the bundle",
                                )
                            )
                        )
                        report.valid = False
                        return report

                raw = self._parse_chain_line(line, line_no, report)
                if raw is None:
                    continue

                receipt = self._validate_chain_record(raw, line_no, report)
                if receipt is None:
                    continue

                # Capability conformance (verifier-side, when statements supplied)
                self._verify_capability_conformance(receipt, line_no, report)

                # G1: the exact ledger line, kept for the x_timestamp
                # head-digest re-derivation (anchors bind the raw bytes)
                raw_lines_by_hash[receipt.receipt_hash] = line

                self._verify_receipt_extensions(raw, line_no, receipt, report, collectors)

                receipts_by_hash[receipt.receipt_hash] = receipt
                report.receipt_count += 1

        # Q19: the node budget is a fail-fast refusal: an operator who raised
        # the byte bound for deep chains still gets a bounded walk. The
        # verifier refuses the bundle rather than grading past its budget.
        if bounds is not None and len(receipts_by_hash) > bounds.max_nodes:
            report.errors.append(
                str(
                    ProvenanceVerifierBoundsExceeded(
                        "node_count",
                        len(receipts_by_hash),
                        bounds.max_nodes,
                        "chain receipt count exceeds the verify node budget; "
                        "the verifier refuses the bundle and stops",
                    )
                )
            )
            report.valid = False
            return report

        # Second pass: DAG integrity + taint monotonicity
        self._verify_dag_and_taint(receipts_by_hash, report)
        # Q19: the bounded, memoised ancestry pass (depth bound, named cycle
        # refusal, work counters). Pure performance and bounds on honest
        # bundles: refusal names the limit, the observed value and the cap.
        try:
            self._verify_ancestry_bounds(receipts_by_hash, report)
        except ProvenanceVerifierBoundsExceeded as exc:
            report.errors.append(str(exc))
            report.valid = False
        # Receipts v1.2 (EPIC W lane W2): pin the LATEST definition block
        # per tool against the on-disk manifest (the registry state).
        self._verify_tool_definition_pins(tool_definition_latest, tool_definition_drift, report)
        # Receipts v1.2 (EPIC W lane W1): pairing coverage and linkage
        # (the registry state answers for the chain's write claims).
        self._verify_state_evidence_pins(
            state_evidence_by_write, covered_writes, gate_tools_by_hash, report
        )

        return report

    def trace(self, receipt_hash: str, path: str | Path) -> list[ProvenanceReceipt]:
        """Walk the DAG backwards from *receipt_hash* to all roots.

        Returns receipts in breadth-first order, deduplicated.
        """
        receipts = self._load_all(path)
        if receipt_hash not in receipts:
            raise KeyError(f"receipt {receipt_hash} not found in chain")

        visited: set[str] = set()
        order: list[ProvenanceReceipt] = []
        queue = [receipt_hash]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            r = receipts.get(current)
            if r is None:
                continue
            order.append(r)
            queue.extend(r.parents)
        return order

    def to_dot(self, receipt_hash: str, path: str | Path) -> str:
        """Render the ancestor DAG of *receipt_hash* as Graphviz DOT."""
        ancestors = self.trace(receipt_hash, path)
        lines = ["digraph provenance {", "  rankdir=LR;", "  node [shape=box, fontname=monospace];"]
        for r in ancestors:
            short = r.receipt_hash.split(":")[-1][:10]
            label_parts = [r.operation.value, r.agent_id]
            if r.model:
                label_parts.append(r.model)
            if r.tool:
                label_parts.append(r.tool)
            if r.taint:
                label_parts.append("taint=" + ",".join(r.taint))
            label = r"\n".join(label_parts) + r"\n[" + short + "]"
            lines.append(f'  "{r.receipt_hash}" [label="{label}"];')
        for r in ancestors:
            for parent in r.parents:
                lines.append(f'  "{parent}" -> "{r.receipt_hash}";')
        lines.append("}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _verify_signature(self, receipt: ProvenanceReceipt) -> bool:
        from cryptography.exceptions import InvalidSignature

        from raucle.pq import HybridVerificationError, PQUnavailable

        key = self._keys.get(receipt.agent_key_id)
        if key is None:
            return False
        try:
            parts = receipt.jws.split(".")
            if len(parts) == 4:
                return self._verify_signature_hybrid(parts, key)
            if len(parts) == 3:
                # v1 receipts and current pq1 receipts are BOTH
                # three-segment Compact JWSes; the JOSE header names the
                # profile. The pq1 header routes to hybrid verification
                # (single-segment signature slot over the raw
                # concatenation); everything else verifies classically.
                if _jws_declares_pq1(receipt.jws):
                    return self._verify_signature_hybrid(parts, key)
                return self._verify_signature_v1(parts, key)
            # 1, 2, 5+ segments never reach here (from_jws rejects them);
            # but keep the verifier total: any other shape fails closed.
            return False
        except PQUnavailable:
            raise
        except HybridVerificationError:
            return False
        except InvalidSignature:
            return False
        except (ValueError, TypeError, KeyError):
            # Decode errors (bad base64, malformed JWS structure, missing key)
            # — fail closed. Unexpected exceptions propagate as bugs rather
            # than silent verification failures.
            return False

    def _verify_signature_hybrid(self, parts: list[str], key: Any) -> bool:
        """pq1 hybrid receipt: fail-closed dual verification. No downgrade
        — both components must verify. Raises PQUnavailable when the
        runtime cannot do ML-DSA at all.

        Accepts both slot shapes during the deprecation window: the
        current three-segment Compact receipt (signature slot is ONE
        base64url segment over the raw component concatenation) and the
        legacy four-segment receipts whose slot itself carries the dot
        form; legacy acceptance logs the pq module's named deprecation
        marker."""
        from raucle.pq import (
            PQUnavailable,
            header_is_pq1,
            parse_hybrid_signature,
            verify_hybrid,
        )

        header = json.loads(_b64url_decode(parts[0]), object_pairs_hook=_reject_duplicate_keys)
        if not header_is_pq1(header):
            return False
        pqk = header.get("pqk")
        pq_key = self._pq_keys.get(pqk)
        if pq_key is None:
            # Unknown PQ key: fail closed. If ML-DSA is entirely
            # unavailable, say so distinctly.
            if not _has_mldsa():
                raise PQUnavailable(
                    "pq1 receipt requires ML-DSA-65 verification but "
                    "this runtime has no ML-DSA support"
                )
            return False
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        # Legacy emission (verify-only window): the slot itself is the
        # dot-separated two-segment form; current emission is one segment.
        signature_slot = parts[2] + "." + parts[3] if len(parts) == 4 else parts[2]
        # Shape-checked before crypto (segment sizes) for the same
        # reason as the v1 path: fail on structure before verifying.
        parse_hybrid_signature(signature_slot)
        verify_hybrid(signing_input, signature_slot, key, pq_key)
        return True

    def _verify_signature_v1(self, parts: list[str], key: Any) -> bool:
        """Classical v1 verification, with the pq1 downgrade closure: a
        receipt whose header declares the pq1 profile must never verify
        via the v1 path, even though its Ed25519 component is valid on
        its own. An attacker who strips the ML-DSA segment otherwise
        presents a fully "valid" v1 receipt - exactly the downgrade the
        hybrid profile exists to prevent."""
        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(_b64url_decode(header_b64), object_pairs_hook=_reject_duplicate_keys)
        if header.get(_PQ1_PROFILE) == _PQ1_ALG:
            return False
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        key.verify(_b64url_decode(sig_b64), signing_input)
        return True

    def _verify_statement(self, stmt: CapabilityStatement, agent_key_id: str) -> bool:
        """Authenticate a supplied capability statement before trusting it.

        A statement is only honoured if (a) its ``key_id`` matches the
        agent_key_id it is registered under AND is the SHA-256 prefix of its own
        ``public_key_pem`` (binding key_id to key), and (b) its signature
        verifies over ``body()`` under the key the verifier holds out-of-band for
        this agent. Verifying under the TRUSTED key — not the statement's
        embedded key — is what defeats forgery: an attacker can self-sign a
        widened statement with their own keypair, but it will not verify under
        the agent's real public key. (round-4 F2)
        """
        if stmt.key_id != agent_key_id:
            return False
        try:
            derived = _sha256_hex(stmt.public_key_pem.encode("ascii"))[:16]
        except Exception:
            return False
        if derived != stmt.key_id:
            return False
        key = self._keys.get(agent_key_id)
        if key is None:
            return False
        try:
            key.verify(base64.b64decode(stmt.signature), _canonical_json(stmt.body()))
            return True
        except Exception:
            return False

    def _check_sanitisation_taint(
        self,
        receipt: ProvenanceReceipt,
        inherited: set[str],
        my_taint: set[str],
        report: VerificationReport,
    ) -> None:
        """Check taint rules for a SANITISATION receipt."""
        # Sanitisation may remove specific tags listed in `corpus` field.
        removed: set[str] = set()
        if receipt.corpus.startswith(_REMOVED_PREFIX):
            removed = set(filter(None, receipt.corpus[len(_REMOVED_PREFIX) :].split(",")))

        # TAINT-LAUNDER: a SANITISATION receipt is only as trustworthy as
        # the authority granted to the signing key. When capability
        # statements are supplied, the issuing agent may only clear tags
        # named in its `sanitisation_authority`; anything else is an
        # unauthorised taint-laundering attempt. Without a capabilities
        # map we cannot check this (the `corpus="removed:..."` claim is
        # self-asserted and trusted — documented trust assumption).
        if self._caps:
            stmt = self._caps.get(receipt.agent_key_id)
            # A missing statement is already flagged as a capability
            # violation in the first pass; treat it as authorising nothing.
            unauthorised = {
                tag for tag in removed if stmt is None or not stmt.permits_sanitising(tag)
            }
            if unauthorised:
                report.unauthorised_sanitisations += 1
                report.errors.append(
                    f"receipt {receipt.receipt_hash}: agent {receipt.agent_key_id} "
                    f"cleared taint tag(s) {sorted(unauthorised)} without "
                    f"sanitisation_authority — unauthorised taint laundering"
                )
                report.valid = False

        expected = inherited - removed
        if my_taint != expected:
            report.taint_monotonicity_failures += 1
            report.errors.append(
                f"receipt {receipt.receipt_hash}: sanitisation taint mismatch "
                f"(expected {sorted(expected)}, got {sorted(my_taint)})"
            )
            report.valid = False

    @staticmethod
    def _check_monotonic_taint(
        receipt: ProvenanceReceipt,
        inherited: set[str],
        my_taint: set[str],
        report: VerificationReport,
    ) -> None:
        """Check taint monotonicity for a non-SANITISATION receipt."""
        missing = inherited - my_taint
        if missing:
            report.taint_monotonicity_failures += 1
            report.errors.append(
                f"receipt {receipt.receipt_hash}: taint not monotonic — "
                f"dropped {sorted(missing)} without a sanitisation step"
            )
            report.valid = False

    def _check_taint(
        self,
        receipt: ProvenanceReceipt,
        receipts: dict[str, ProvenanceReceipt],
        report: VerificationReport,
    ) -> None:
        if not receipt.parents:
            return  # roots have no inherited taint to check

        inherited: set[str] = set()
        for p_hash in receipt.parents:
            p = receipts.get(p_hash)
            if p is not None:
                inherited.update(p.taint)

        my_taint = set(receipt.taint)
        if receipt.operation == Operation.SANITISATION:
            self._check_sanitisation_taint(receipt, inherited, my_taint, report)
        else:
            self._check_monotonic_taint(receipt, inherited, my_taint, report)

    def _load_all(self, path: str | Path) -> dict[str, ProvenanceReceipt]:
        out: dict[str, ProvenanceReceipt] = {}
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    r = ProvenanceReceipt.from_jws(raw["jws"])
                except (ValueError, KeyError):
                    continue
                out[r.receipt_hash] = r
        return out


def _finish_ancestry_node(
    node: str,
    receipt: ProvenanceReceipt,
    depth_memo: dict[str, int],
    state: dict[str, int],
    bounds: ProvenanceVerifierBounds,
    report: VerificationReport,
) -> None:
    """Memoise one receipt's ancestry depth and police the depth bound.

    Verbatim extraction of the ``ready`` epilogue inside
    ``ProvenanceVerifier._verify_ancestry_bounds`` (cognitive-complexity
    decomposition, S3776): same body, same raise, no behaviour change.
    The caller keeps the loop ``continue``.
    """
    best = 0
    for parent in receipt.parents:
        best = max(best, depth_memo.get(parent, 0))
    depth_memo[node] = best + 1
    state[node] = _black
    report.traversal_receipts_expanded += 1
    if depth_memo[node] > bounds.max_depth:
        raise ProvenanceVerifierBoundsExceeded(
            "graph_depth",
            depth_memo[node],
            bounds.max_depth,
            f"receipt {node} ancestry depth exceeds the verify bound",
        )


def _expand_ancestry_node(
    node: str,
    receipt: ProvenanceReceipt,
    stack: list[tuple[str, bool]],
    state: dict[str, int],
    report: VerificationReport,
    receipts_by_hash: dict[str, ProvenanceReceipt],
) -> None:
    """Queue one receipt's white parents, counting examined edges.

    Verbatim extraction of the expansion pass inside
    ``ProvenanceVerifier._verify_ancestry_bounds`` (cognitive-complexity
    decomposition, S3776): same body, same cycle refusal, no behaviour
    change.
    """
    for parent in receipt.parents:
        report.traversal_edges_examined += 1
        pstate = state.get(parent, _white)
        if pstate == _grey:
            raise ProvenanceVerifierBoundsExceeded(
                "cycle",
                parent,
                "n/a",
                f"parent graph is not acyclic: receipt {node} cites in-flight ancestor {parent}",
            )
        if pstate == _white and parent in receipts_by_hash:
            stack.append((parent, False))


def _walk_ancestry_from(
    start: str,
    receipts_by_hash: dict[str, ProvenanceReceipt],
    state: dict[str, int],
    depth_memo: dict[str, int],
    bounds: ProvenanceVerifierBounds,
    report: VerificationReport,
) -> None:
    """Iterative ancestry DFS from one start receipt (Q19 walk).

    Verbatim extraction of the per-start walk inside
    ``ProvenanceVerifier._verify_ancestry_bounds`` (cognitive-complexity
    decomposition, S3776): same while-loop, same two refusals (graph
    depth, cycle), no behaviour change; the ``continue`` semantics ride
    on the loop being inside this helper now.
    """
    stack: list[tuple[str, bool]] = [(start, False)]
    while stack:
        node, ready = stack.pop()
        receipt = receipts_by_hash.get(node)
        if receipt is None:
            # cited-but-absent parents are per-line parent-link
            # failures already; nothing is walkable here.
            continue
        if ready:
            _finish_ancestry_node(node, receipt, depth_memo, state, bounds, report)
            continue
        if state.get(node, _white) != _white:
            # a duplicate pending entry: the node is already in
            # flight below, or already done (memo hit). Not a cycle.
            continue
        state[node] = _grey
        stack.append((node, True))
        _expand_ancestry_node(node, receipt, stack, state, report, receipts_by_hash)


def _tool_definition_closed_fields(
    block: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Closed field set for a tool_definition block.

    Verbatim extraction of the two field-set loops inside
    ``ProvenanceVerifier._verify_tool_definition``
    (cognitive-complexity decomposition, S3776): same loops, same error
    strings, no behaviour change.
    """
    # Closed field set: the block names a definition, never an
    # open-ended payload.
    for key in block:
        if key not in _TOOL_DEFINITION_FIELDS:
            report.errors.append(
                f"line {line_no}: tool_definition carries unknown field {key!r} "
                f"(closed set: {sorted(_TOOL_DEFINITION_FIELDS)})"
            )
            report.valid = False
    for required in _TOOL_DEFINITION_FIELDS:
        if block.get(required) is None:
            report.errors.append(f"line {line_no}: tool_definition missing field {required!r}")
            report.valid = False


def _tool_definition_known_values(
    block: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Version gate, vantage vocabulary and digest shape for a
    tool_definition block.

    Verbatim extraction of the three known-value checks inside
    ``ProvenanceVerifier._verify_tool_definition``
    (cognitive-complexity decomposition, S3776): same checks, same error
    strings, no behaviour change.
    """
    version = block.get("version")
    if version is not None and version != _TOOL_DEFINITION_VERSION:
        report.errors.append(
            f"line {line_no}: tool_definition version {version!r} is unknown "
            f"(supported: {_TOOL_DEFINITION_VERSION}); the block is refused, "
            "never skipped"
        )
        report.valid = False

    vantage = block.get("definition_vantage")
    if vantage is not None and vantage not in _TOOL_DEFINITION_VANTAGES:
        report.errors.append(
            f"line {line_no}: tool_definition vantage {vantage!r} outside the "
            f"closed vocabulary {sorted(_TOOL_DEFINITION_VANTAGES)}"
        )
        report.valid = False

    digest = block.get("definition_digest")
    if digest is not None and not _is_sha256_digest(digest):
        report.errors.append(
            f"line {line_no}: tool_definition definition_digest is not a sha256 "
            "digest of the form sha256:<64 hex characters>"
        )
        report.valid = False


def _record_tool_definition_latest(
    x_gate_payload: Any,
    block: dict[str, Any],
    digest: Any,
    line_no: int,
    tool_definition_latest: dict[str, dict[str, Any]],
) -> None:
    """Record the LATEST tool_definition block per tool for the chain-end
    pin pass (last write wins: lines verify in chain order).

    Verbatim extraction of the collector tail inside
    ``ProvenanceVerifier._verify_tool_definition``
    (cognitive-complexity decomposition, S3776): same body, no behaviour
    change. A structurally broken block still records what it claims, so
    the pin pass names the line where the registry state stops answering
    for the receipts.
    """
    manifest = str(block.get("definition_manifest") or "")
    tool = str(x_gate_payload.get("tool") or "") if isinstance(x_gate_payload, dict) else ""
    if tool:
        tool_definition_latest[tool] = {
            "line_no": line_no,
            "digest": digest,
            "manifest": manifest,
        }


def _x_dlp_vocabulary_errors(
    x_dlp: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Required fields and the closed action/direction vocabularies for
    an x_dlp block.

    Verbatim extraction of the structural and vocabulary sections
    inside ``ProvenanceVerifier._verify_x_dlp`` (cognitive-complexity
    decomposition, S3776): same loops, same error strings, no behaviour
    change.
    """
    # Structural validity first: every required field present.
    for required in _DLP_REQUIRED_FIELDS:
        if x_dlp.get(required) is None:
            report.errors.append(f"line {line_no}: x_dlp missing field {required!r}")
            report.valid = False

    action = x_dlp.get("action")
    if action not in _DLP_ACTIONS:
        report.errors.append(
            f"line {line_no}: x_dlp action {action!r} outside the closed "
            f"vocabulary {sorted(_DLP_ACTIONS)}"
        )
        report.valid = False

    direction = x_dlp.get("direction")
    if direction not in _DLP_DIRECTIONS:
        report.errors.append(
            f"line {line_no}: x_dlp direction {direction!r} outside the closed "
            f"vocabulary {sorted(_DLP_DIRECTIONS)}"
        )
        report.valid = False


def _x_dlp_digest_shapes(
    x_dlp: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Content-scanner digests stay in the sha256 digest shape.

    Verbatim extraction of the digest-shape loop inside
    ``ProvenanceVerifier._verify_x_dlp`` (cognitive-complexity
    decomposition, S3776): same loop, same error strings, no behaviour
    change.
    """
    # Digests are sha256-shaped: prefix plus 64 hex characters. The
    # verifier never sees content, only these digests.
    for digest_field in ("content_sha256", "redacted_content_sha256"):
        digest = x_dlp.get(digest_field)
        if digest is None:
            continue
        shape_ok = (
            isinstance(digest, str)
            and digest.startswith(_SHA256_PREFIX)
            and re.fullmatch(r"[0-9a-f]{64}", digest[len(_SHA256_PREFIX) :]) is not None
        )
        if not shape_ok:
            report.errors.append(
                f"line {line_no}: x_dlp {digest_field} is not a sha256 digest "
                f"of the form sha256:<64 hex characters>"
            )
            report.valid = False


def _x_dlp_redaction_consistency(
    x_dlp: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """The post-redaction digest is present iff the action is redacted.

    Verbatim extraction of the action/redaction consistency section
    inside ``ProvenanceVerifier._verify_x_dlp`` (cognitive-complexity
    decomposition, S3776): same checks, same error strings, no behaviour
    change.
    """
    # Action/redaction consistency: the post-redaction digest is
    # present if and only if the action is redacted.
    action = x_dlp.get("action")
    redacted_digest = x_dlp.get("redacted_content_sha256")
    if action == "redacted" and not redacted_digest:
        report.errors.append(
            f"line {line_no}: x_dlp action 'redacted' carries no redacted_content_sha256"
        )
        report.valid = False
    if action != "redacted" and redacted_digest is not None:
        report.errors.append(
            f"line {line_no}: x_dlp action {action!r} carries a "
            f"redacted_content_sha256 (present only when action='redacted')"
        )
        report.valid = False


def _x_dlp_matched_classes(
    x_dlp: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> set[str]:
    """The bounded matched-class vocabulary check; returns the accepted
    class set for the span-count cross-check.

    Verbatim extraction of the matched_classes section inside
    ``ProvenanceVerifier._verify_x_dlp`` (cognitive-complexity
    decomposition, S3776): same loop, same error strings, no behaviour
    change.
    """
    # Bounded class vocabulary, versioned: an unknown class fails
    # closed rather than widening disclosure.
    matched_classes = x_dlp.get("matched_classes")
    classes: set[str] = set()
    if not isinstance(matched_classes, list) or not matched_classes:
        report.errors.append(f"line {line_no}: x_dlp matched_classes must be a non-empty list")
        report.valid = False
    else:
        for mclass in matched_classes:
            if not isinstance(mclass, str) or mclass not in _DLP_MATCHED_CLASSES:
                report.errors.append(
                    f"line {line_no}: x_dlp unknown class {mclass!r} outside the "
                    f"bounded vocabulary {sorted(_DLP_MATCHED_CLASSES)}"
                )
                report.valid = False
            else:
                classes.add(mclass)
    return classes


def _x_dlp_span_counts(
    x_dlp: dict[str, Any],
    classes: set[str],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Span counts: non-negative integers, keys in the same bounded
    vocabulary, and every counted class listed in matched_classes.

    Verbatim extraction of the span_counts section inside
    ``ProvenanceVerifier._verify_x_dlp`` (cognitive-complexity
    decomposition, S3776): same loop, same error strings, no behaviour
    change; the per-row body rides on :func:`_x_dlp_span_count_row`.
    """
    span_counts = x_dlp.get("span_counts")
    if not isinstance(span_counts, dict):
        report.errors.append(f"line {line_no}: x_dlp span_counts must be an object")
        report.valid = False
        return
    for spclass, count in span_counts.items():
        _x_dlp_span_count_row(spclass, count, classes, line_no, report)


def _x_dlp_span_count_row(
    spclass: Any,
    count: Any,
    classes: set[str],
    line_no: int,
    report: VerificationReport,
) -> None:
    """One span_counts row: bounded key, non-negative count, and a class
    named by counts must be listed in matched_classes.

    Verbatim extraction of the per-row body inside
    ``ProvenanceVerifier._verify_x_dlp`` (cognitive-complexity
    decomposition, S3776): same checks and order, same error strings,
    no behaviour change; the loop ``continue`` rides on ``return``.
    """
    if not isinstance(spclass, str) or spclass not in _DLP_MATCHED_CLASSES:
        report.errors.append(
            f"line {line_no}: x_dlp span_counts unknown class {spclass!r} "
            f"outside the bounded vocabulary {sorted(_DLP_MATCHED_CLASSES)}"
        )
        report.valid = False
        return
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        report.errors.append(
            f"line {line_no}: x_dlp span_counts for {spclass!r} is not a non-negative integer"
        )
        report.valid = False
    # The row-shape guard above returned for a non-string key or an
    # unknown class, so the membership cross-check against
    # matched_classes needs none of those conjuncts repeated.
    if spclass not in classes:
        report.errors.append(
            f"line {line_no}: x_dlp span_counts names class {spclass!r} absent from matched_classes"
        )
        report.valid = False


def _x_dlp_bounded_disclosure(
    x_dlp: dict[str, Any],
    line_no: int,
    report: VerificationReport,
    receipts_by_hash: dict[str, ProvenanceReceipt],
) -> None:
    """No content-like field anywhere, and any cited receipt is in the
    chain (like every other extension citation).

    Verbatim extraction of the bounded-disclosure and citation sections
    inside ``ProvenanceVerifier._verify_x_dlp`` (cognitive-complexity
    decomposition, S3776): same checks, same error strings, no behaviour
    change.
    """
    # Bounded disclosure: no content-like field anywhere in the block.
    for leak_field in _DLP_FORBIDDEN_CONTENT_FIELDS:
        if leak_field in x_dlp:
            report.errors.append(
                f"line {line_no}: x_dlp carries content-like field "
                f"{leak_field!r} (bounded disclosure: counts, digests and "
                f"class names only, never content)"
            )
            report.valid = False

    # Chain membership of any cited receipt, like every other
    # extension citation.
    cited = str(x_dlp.get("cited_receipt", ""))
    if cited and cited not in receipts_by_hash:
        report.errors.append(f"line {line_no}: x_dlp cites receipt {cited!r} not in the chain")
        report.valid = False


def _x_state_closed_set(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Closed field set and version gate for an x_state block.

    Verbatim extraction of the field-set and version sections inside
    ``ProvenanceVerifier._verify_x_state`` (cognitive-complexity
    decomposition, S3776): same loops, same error strings, no behaviour
    change.
    """
    # Closed field set: the block names a state claim, never an
    # open-ended payload.
    for key in x_state:
        if key not in _X_STATE_FIELDS:
            report.errors.append(
                f"line {line_no}: x_state carries unknown field {key!r} "
                f"(closed set: {sorted(_X_STATE_FIELDS)})"
            )
            report.valid = False
    for required in ("version", "cited_receipt"):
        if x_state.get(required) is None:
            report.errors.append(f"line {line_no}: x_state missing field {required!r}")
            report.valid = False

    version = x_state.get("version")
    if version is not None and version != _STATE_EVIDENCE_VERSION:
        report.errors.append(
            f"line {line_no}: x_state version {version!r} is unknown "
            f"(supported: {_STATE_EVIDENCE_VERSION}); the block is refused, "
            "never skipped"
        )
        report.valid = False


def _x_state_cited_receipt(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
    receipts_by_hash: dict[str, ProvenanceReceipt],
) -> str:
    """The cited write receipt: sha256-shaped and present EARLIER in the
    chain, like every other extension citation.

    Verbatim extraction of the citation section inside
    ``ProvenanceVerifier._verify_x_state`` (cognitive-complexity
    decomposition, S3776): same checks, same error strings, no behaviour
    change; returns the cited hash the collector needs.
    """
    cited = str(x_state.get("cited_receipt") or "")
    if cited and not _is_sha256_digest(cited):
        report.errors.append(
            f"line {line_no}: x_state cited_receipt is not a sha256 receipt "
            "hash of the form sha256:<64 hex characters>"
        )
        report.valid = False
    if cited and cited not in receipts_by_hash:
        report.errors.append(f"line {line_no}: x_state cites receipt {cited!r} not in the chain")
        report.valid = False
    return cited


def _x_state_sentinel_semantics(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> str:
    """Sentinel semantics: absence is the literal sentinel, never a fake
    digest; a block carrying neither states nothing.

    Verbatim extraction of the sentinel section inside
    ``ProvenanceVerifier._verify_x_state`` (cognitive-complexity
    decomposition, S3776): same branch ladder and error strings, no
    behaviour change; per-branch field checks move to
    :func:`_x_state_absent_fields` and :func:`_x_state_evidence_fields`.
    """
    sentinel = x_state.get("state_evidence")
    has_digest = x_state.get("evidence_digest") is not None
    state = "invalid"
    if sentinel is not None and sentinel != _STATE_ABSENT_SENTINEL:
        report.errors.append(
            f"line {line_no}: x_state state_evidence {sentinel!r} is not the "
            f"literal sentinel {_STATE_ABSENT_SENTINEL!r}"
        )
        report.valid = False
    if sentinel == _STATE_ABSENT_SENTINEL:
        _x_state_absent_fields(x_state, line_no, report)
        state = "absent"
    elif has_digest:
        state = "evidence"
        _x_state_evidence_fields(x_state, line_no, report)
    else:
        report.errors.append(
            f"line {line_no}: x_state carries neither evidence nor the absent "
            "sentinel (a receipt for a pairing-covered tool must state one)"
        )
        report.valid = False
    return state


def _x_state_absent_fields(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """The absent sentinel never carries evidence fields.

    Verbatim extraction of the sentinel-branch check inside
    ``ProvenanceVerifier._verify_x_state`` (cognitive-complexity
    decomposition, S3776): same condition, same error string, no
    behaviour change.
    """
    has_digest = x_state.get("evidence_digest") is not None
    if has_digest or x_state.get("handle") is not None or x_state.get("field_classes") is not None:
        report.errors.append(
            f"line {line_no}: x_state state_evidence {_STATE_ABSENT_SENTINEL!r} "
            "never carries evidence fields (absence is stated, never a "
            "fake digest)"
        )
        report.valid = False


def _x_state_evidence_fields(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Evidence-carrying x_state blocks name the pairing fields.

    Verbatim extraction of the evidence-branch loop inside
    ``ProvenanceVerifier._verify_x_state`` (cognitive-complexity
    decomposition, S3776): same loop, same error strings, no behaviour
    change.
    """
    for required in ("pairing_id", "read_tool", "handle", "field_classes"):
        if x_state.get(required) is None:
            report.errors.append(f"line {line_no}: x_state missing field {required!r}")
            report.valid = False


def _x_state_digest_shape(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """The evidence digest stays in the sha256 digest shape.

    Verbatim extraction inside ``ProvenanceVerifier._verify_x_state``
    (cognitive-complexity decomposition, S3776): same check, same error
    string, no behaviour change.
    """
    digest = x_state.get("evidence_digest")
    if digest is not None and not _is_sha256_digest(digest):
        report.errors.append(
            f"line {line_no}: x_state evidence_digest is not a sha256 digest "
            "of the form sha256:<64 hex characters>"
        )
        report.valid = False


def _x_state_handle_shape(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """The handle is a non-empty string when present.

    Verbatim extraction inside ``ProvenanceVerifier._verify_x_state``
    (cognitive-complexity decomposition, S3776): same check, same error
    string, no behaviour change.
    """
    handle = x_state.get("handle")
    if handle is not None and (not isinstance(handle, str) or not handle):
        report.errors.append(
            f"line {line_no}: x_state handle must be a non-empty string "
            "(the object handle extracted per the pairing's id_pointer)"
        )
        report.valid = False


def _x_state_field_classes_shape(
    x_state: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """field_classes is a non-empty list of field-presence names.

    Verbatim extraction inside ``ProvenanceVerifier._verify_x_state``
    (cognitive-complexity decomposition, S3776): same check, same error
    string, no behaviour change.
    """
    field_classes = x_state.get("field_classes")
    if field_classes is not None and (
        not isinstance(field_classes, list)
        or not field_classes
        or any(not isinstance(c, str) or not c for c in field_classes)
    ):
        report.errors.append(
            f"line {line_no}: x_state field_classes must be a non-empty "
            "list of field-presence names (names only, never content)"
        )
        report.valid = False


def _x_state_collector(
    x_state: dict[str, Any],
    cited: str,
    state: str,
    line_no: int,
    state_evidence_by_write: dict[str, dict[str, Any]],
) -> None:
    """Chain-end collector: the state claim bound to this write receipt
    (last write wins, lines verify in chain order).

    Verbatim extraction of the collector tail inside
    ``ProvenanceVerifier._verify_x_state`` (cognitive-complexity
    decomposition, S3776): same body, no behaviour change.
    """
    field_classes = x_state.get("field_classes")
    if cited:
        state_evidence_by_write[cited] = {
            "line_no": line_no,
            "state": state,
            "pairing_id": str(x_state.get("pairing_id") or ""),
            "read_tool": str(x_state.get("read_tool") or ""),
            "field_classes": (
                [str(c) for c in field_classes] if isinstance(field_classes, list) else []
            ),
        }


def _counterfactual_required_fields(
    cf: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Closed field set for a counterfactual block.

    Verbatim extraction of the field-set loops inside
    ``ProvenanceVerifier._verify_counterfactual``
    (cognitive-complexity decomposition, S3776): same loops, same error
    strings, no behaviour change.
    """
    # Closed field set: the block names a hypothetical decision,
    # never an open-ended payload.
    for key in cf:
        if key not in _COUNTERFACTUAL_FIELDS:
            report.errors.append(
                f"line {line_no}: counterfactual carries unknown field {key!r} "
                f"(closed set: {sorted(_COUNTERFACTUAL_FIELDS)})"
            )
            report.valid = False

    for required in ("version", "ruleset_hash", "decision", "evaluated_at"):
        if cf.get(required) is None:
            report.errors.append(f"line {line_no}: counterfactual missing field {required!r}")
            report.valid = False


def _counterfactual_vocabularies(
    cf: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Version gate, closed decision vocabulary and ruleset digest shape.

    Verbatim extraction of the version/decision/ruleset_hash checks
    inside ``ProvenanceVerifier._verify_counterfactual``
    (cognitive-complexity decomposition, S3776): same checks, same error
    strings, no behaviour change.
    """
    version = cf.get("version")
    if version is not None and version != _COUNTERFACTUAL_VERSION:
        report.errors.append(
            f"line {line_no}: counterfactual version {version!r} is unknown "
            f"(supported: {_COUNTERFACTUAL_VERSION}); the block is refused, "
            f"never skipped"
        )
        report.valid = False

    decision = cf.get("decision")
    if decision is not None and decision not in _COUNTERFACTUAL_DECISIONS:
        report.errors.append(
            f"line {line_no}: counterfactual decision {decision!r} outside the "
            f"closed vocabulary {sorted(_COUNTERFACTUAL_DECISIONS)}"
        )
        report.valid = False

    if not _is_sha256_digest(cf.get("ruleset_hash")):
        report.errors.append(
            f"line {line_no}: counterfactual ruleset_hash is not a sha256 "
            f"digest of the form sha256:<64 hex characters>"
        )
        report.valid = False


def _counterfactual_evaluated_at(
    decoded: Any,
    cf: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """evaluated_at is an integer never later than the receipt's own
    iat: a post-dated block is editorial, not evidence.

    Verbatim extraction of the evaluated_at section inside
    ``ProvenanceVerifier._verify_counterfactual``
    (cognitive-complexity decomposition, S3776): same checks, same error
    strings, no behaviour change.
    """
    evaluated_at = cf.get("evaluated_at")
    iat = decoded.get("iat") if isinstance(decoded, dict) else None
    if not isinstance(evaluated_at, int) or isinstance(evaluated_at, bool):
        report.errors.append(f"line {line_no}: counterfactual evaluated_at is not an integer")
        report.valid = False
    elif isinstance(iat, int) and evaluated_at > iat:
        report.errors.append(
            f"line {line_no}: counterfactual evaluated_at {evaluated_at} is "
            f"later than the receipt's own iat {iat}"
        )
        report.valid = False


def _counterfactual_rule_fields(
    cf: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """rule_id is present if and only if the alternative rule fired
    (decision deny); an allow that carries rule fields claims a rule
    that did not fire.

    Verbatim extraction of the rule-fields section inside
    ``ProvenanceVerifier._verify_counterfactual``
    (cognitive-complexity decomposition, S3776): the section's
    ``decision`` local now re-reads the same field it always used, the
    rest of the body is unchanged, no behaviour change.
    """
    decision = cf.get("decision")
    if decision == "allow":
        for absent_field in ("rule_id", "rule_kind", "session"):
            if cf.get(absent_field) is not None:
                report.errors.append(
                    f"line {line_no}: counterfactual decision 'allow' carries "
                    f"{absent_field!r} (rule fields are present only when the "
                    f"alternative rule fired)"
                )
                report.valid = False
    elif decision == "deny":
        for required_field in ("rule_id", "rule_kind"):
            if cf.get(required_field) is None:
                report.errors.append(
                    f"line {line_no}: counterfactual decision 'deny' carries no "
                    f"{required_field!r} (the firing alternative rule is named)"
                )
                report.valid = False


def _counterfactual_rule_kind_vocab(
    cf: dict[str, Any],
    session_kinds: frozenset[str],
    line_no: int,
    report: VerificationReport,
) -> None:
    """The closed rule-kind vocabulary: a policy rule or a session rule
    may back a counterfactual; anything else (advisory detection,
    classifier verdicts) is detection, not this surface.

    Verbatim extraction of the rule-kind section inside
    ``ProvenanceVerifier._verify_counterfactual``
    (cognitive-complexity decomposition, S3776): the section's
    ``session_kinds`` local is now the parameter the caller computed in
    the same runtime position, the rest of the body is unchanged, no
    behaviour change.
    """
    rule_kind = cf.get("rule_kind")
    if rule_kind is not None:
        if rule_kind not in {"policy_rule"} | session_kinds:
            report.errors.append(
                f"line {line_no}: counterfactual rule_kind {rule_kind!r} "
                f"outside the closed vocabulary (policy_rule or a session "
                f"rule kind {sorted(session_kinds)})"
            )
            report.valid = False
        else:
            session = cf.get("session")
            if rule_kind in session_kinds and session is None:
                report.errors.append(
                    f"line {line_no}: counterfactual rule_kind {rule_kind!r} "
                    f"carries no session block (a session rule names the window "
                    f"it fired over)"
                )
                report.valid = False
            if rule_kind == "policy_rule" and session is not None:
                report.errors.append(
                    f"line {line_no}: counterfactual rule_kind 'policy_rule' "
                    f"carries a session block (a policy rule fires on the call, "
                    f"not over a session window)"
                )
                report.valid = False


def _counterfactual_session_field_sets(
    session: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Closed field set and required fields for a counterfactual session
    block.

    Verbatim extraction of the field-set loops inside
    ``ProvenanceVerifier._verify_counterfactual_session``
    (cognitive-complexity decomposition, S3776): same loops, same error
    strings, no behaviour change.
    """
    for key in session:
        if key not in _COUNTERFACTUAL_SESSION_FIELDS:
            report.errors.append(
                f"line {line_no}: counterfactual session carries unknown "
                f"field {key!r} (closed set: {sorted(_COUNTERFACTUAL_SESSION_FIELDS)})"
            )
            report.valid = False

    for required in ("session_id", "window_seconds", "participant", "window_evidence"):
        if session.get(required) is None:
            report.errors.append(
                f"line {line_no}: counterfactual session missing field {required!r}"
            )
            report.valid = False


def _counterfactual_session_window(
    session: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """window_seconds is a positive integer.

    Verbatim extraction inside
    ``ProvenanceVerifier._verify_counterfactual_session``
    (cognitive-complexity decomposition, S3776): same check, same error
    string, no behaviour change.
    """
    window_seconds = session.get("window_seconds")
    if (
        not isinstance(window_seconds, int)
        or isinstance(window_seconds, bool)
        or window_seconds < 1
    ):
        report.errors.append(
            f"line {line_no}: counterfactual session window_seconds is not a positive integer"
        )
        report.valid = False


def _counterfactual_session_participant(
    session: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """session participant stays inside the closed vocabulary.

    Verbatim extraction inside
    ``ProvenanceVerifier._verify_counterfactual_session``
    (cognitive-complexity decomposition, S3776): same check, same lazy
    import, same error string, no behaviour change.
    """
    participant = session.get("participant")
    if participant is not None:
        from raucle.policy import PARTICIPANTS

        if participant not in PARTICIPANTS:
            report.errors.append(
                f"line {line_no}: counterfactual session participant "
                f"{participant!r} outside the closed vocabulary "
                f"{list(PARTICIPANTS)}"
            )
            report.valid = False


def _counterfactual_window_evidence(
    session: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """window_evidence is exactly the closed two-key shape
    (non-negative integer counters, string tool names).

    Verbatim extraction of the window_evidence section inside
    ``ProvenanceVerifier._verify_counterfactual_session``
    (cognitive-complexity decomposition, S3776): same checks, same error
    strings, no behaviour change; the shape guard's ``return`` rides on
    it being the helper's tail.
    """
    evidence = session.get("window_evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"counters", "tools"}:
        report.errors.append(
            f"line {line_no}: counterfactual window_evidence must be exactly "
            f"the two-key shape {{'counters', 'tools'}}"
        )
        report.valid = False
        return
    counters = evidence.get("counters")
    if not isinstance(counters, dict) or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counters.values()
    ):
        report.errors.append(
            f"line {line_no}: counterfactual window_evidence counters must "
            f"map names to non-negative integers"
        )
        report.valid = False
    tools = evidence.get("tools")
    if not isinstance(tools, list) or any(not isinstance(tool, str) or not tool for tool in tools):
        report.errors.append(
            f"line {line_no}: counterfactual window_evidence tools must be a list of tool names"
        )
        report.valid = False


def _revocation_v12_fields(
    revocation: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> None:
    """Closed field set for a v1.2 revocation block.

    Verbatim extraction of the field-set loops inside
    ``ProvenanceVerifier._verify_v12_revocation_block``
    (cognitive-complexity decomposition, S3776): same loops, same error
    strings, no behaviour change.
    """
    # Closed field set: the block names a revocation event, never an
    # open-ended payload.
    for key in revocation:
        if key not in _REVOCATION_V12_FIELDS:
            report.errors.append(
                f"line {line_no}: x_revocation carries unknown field {key!r} "
                f"(closed set: {sorted(_REVOCATION_V12_FIELDS)})"
            )
            report.valid = False

    for required in (
        "version",
        "kind",
        "revoked_ids",
        "revoked_hashes",
        "actor",
        "reason_class",
        "revoked_at",
    ):
        if revocation.get(required) is None:
            report.errors.append(f"line {line_no}: x_revocation missing field {required!r}")
            report.valid = False


def _revocation_v12_vocabularies(
    revocation: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> Any:
    """Version gate and the closed kind/reason_class vocabularies.

    Verbatim extraction of the version/kind/reason_class checks inside
    ``ProvenanceVerifier._verify_v12_revocation_block``
    (cognitive-complexity decomposition, S3776): same checks, same error
    strings, no behaviour change; returns the block's ``kind`` the
    citation pass needs.
    """
    version = revocation.get("version")
    if version is not None and version != _REVOCATION_VERSION:
        report.errors.append(
            f"line {line_no}: x_revocation version {version!r} is unknown "
            f"(supported: {_REVOCATION_VERSION}); the block is refused, "
            f"never skipped"
        )
        report.valid = False

    kind = revocation.get("kind")
    if kind is not None and kind not in _REVOCATION_KINDS:
        report.errors.append(
            f"line {line_no}: x_revocation kind {kind!r} outside the closed "
            f"vocabulary {sorted(_REVOCATION_KINDS)}"
        )
        report.valid = False

    reason_class = revocation.get("reason_class")
    if reason_class is not None and reason_class not in _REVOCATION_REASON_CLASSES:
        report.errors.append(
            f"line {line_no}: x_revocation reason_class {reason_class!r} "
            f"outside the closed vocabulary {sorted(_REVOCATION_REASON_CLASSES)}"
        )
        report.valid = False
    return kind


def _revocation_ids_shape(
    revocation: dict[str, Any],
    line_no: int,
    report: VerificationReport,
) -> bool:
    """revoked_ids is a list of ids: the shape half of the chain linkage.

    Verbatim extraction of the ``ids_ok`` computation and its error
    path inside ``ProvenanceVerifier._verify_v12_revocation_block``
    (cognitive-complexity decomposition, S3776): same check, same error
    string, no behaviour change; returns ``ids_ok`` for the linkage and
    citation passes.
    """
    revoked_ids = revocation.get("revoked_ids")
    ids_ok = isinstance(revoked_ids, list) and all(isinstance(rid, str) for rid in revoked_ids)
    if not ids_ok:
        report.errors.append(f"line {line_no}: x_revocation revoked_ids must be a list of ids")
        report.valid = False
    return ids_ok


def _revocation_hashes_linkage(
    revocation: dict[str, Any],
    ids_ok: bool,
    line_no: int,
    report: VerificationReport,
) -> None:
    """Chain linkage: revoked_hashes keys exactly equal the revoked ids,
    every value a sha256 digest a third party holding the revoked
    material re-derives.

    Verbatim extraction of the hashes section inside
    ``ProvenanceVerifier._verify_v12_revocation_block``
    (cognitive-complexity decomposition, S3776): same checks and order,
    same error strings, no behaviour change.
    """
    revoked_ids = revocation.get("revoked_ids")
    revoked_hashes = revocation.get("revoked_hashes")
    if not isinstance(revoked_hashes, dict):
        report.errors.append(f"line {line_no}: x_revocation revoked_hashes must map ids to digests")
        report.valid = False
    elif ids_ok:
        if set(revoked_hashes) != set(revoked_ids):
            report.errors.append(
                f"line {line_no}: x_revocation revoked_hashes keys must equal "
                f"the revoked ids exactly (chain linkage)"
            )
            report.valid = False
        for rid, digest in revoked_hashes.items():
            if not _is_sha256_digest(digest):
                report.errors.append(
                    f"line {line_no}: x_revocation revoked_hashes for {rid!r} "
                    f"is not a sha256 digest of the form "
                    f"sha256:<64 hex characters>"
                )
                report.valid = False


def _revocation_v12_timestamp(
    revocation: dict[str, Any],
    decoded: Any,
    line_no: int,
    report: VerificationReport,
) -> None:
    """revoked_at is an integer never later than the receipt's own iat:
    a post-dated revocation timestamp is editorial, not evidence.

    Verbatim extraction of the timestamp section inside
    ``ProvenanceVerifier._verify_v12_revocation_block``
    (cognitive-complexity decomposition, S3776): same checks, same error
    strings, no behaviour change.
    """
    revoked_at = revocation.get("revoked_at")
    iat = decoded.get("iat") if isinstance(decoded, dict) else None
    if not isinstance(revoked_at, int) or isinstance(revoked_at, bool):
        report.errors.append(f"line {line_no}: x_revocation revoked_at is not an integer")
        report.valid = False
    elif isinstance(iat, int) and revoked_at > iat:
        report.errors.append(
            f"line {line_no}: x_revocation revoked_at {revoked_at} is later "
            f"than the receipt's own iat {iat}"
        )
        report.valid = False


def _revocation_v12_bounded_reason(
    revocation: dict[str, Any],
    line_no: int,
    report: VerificationReport,
    intent_constraint_values: set[str],
) -> None:
    """Bounded disclosure: the reason stays at class level. A revocation
    receipt is retained for the life of the archive, so it must never
    quote a constraint value the chain's intent receipts disclose.

    Verbatim extraction of the bounded-reason section inside
    ``ProvenanceVerifier._verify_v12_revocation_block``
    (cognitive-complexity decomposition, S3776): same loop and break,
    same error string, no behaviour change.
    """
    reason = revocation.get("reason")
    if isinstance(reason, str) and reason:
        for value in intent_constraint_values:
            if value and value in reason:
                report.errors.append(
                    f"line {line_no}: x_revocation reason quotes a constraint "
                    f"value the chain's receipts disclose (bounded disclosure: "
                    f"the reason stays at class level)"
                )
                report.valid = False
                break


def _revocation_v12_receipt_citations(
    revocation: dict[str, Any],
    kind: Any,
    ids_ok: bool,
    line_no: int,
    report: VerificationReport,
    receipts_by_hash: dict[str, ProvenanceReceipt],
) -> None:
    """kind = receipt: the same membership rule every extension citation
    obeys - every cited receipt must exist in this chain.

    Verbatim extraction of the citation section inside
    ``ProvenanceVerifier._verify_v12_revocation_block``
    (cognitive-complexity decomposition, S3776): the section's
    ``revoked_ids`` local now re-reads the same field it always used,
    the rest of the body is unchanged, no behaviour change.
    """
    if kind == "receipt" and ids_ok:
        revoked_ids = revocation.get("revoked_ids")
        for rid in revoked_ids:
            if rid not in receipts_by_hash:
                report.errors.append(
                    f"line {line_no}: x_revocation cites receipt {rid!r} not in the chain"
                )
                report.valid = False


# Ancestry walk node states (lane Q19): white = unvisited, grey = in
# flight, black = finished and memoised. Hoisted verbatim (same ints)
# from a _verify_ancestry_bounds local when its body was decomposed.
_white, _grey, _black = 0, 1, 2


def migrate_chain_envelope(
    in_path: str | Path,
    out_path: str | Path,
    public_keys: dict[str, bytes],
) -> int:
    """Offline one-off converter: rewrite a legacy rich-envelope chain to the
    v0.17 minimal ``{receipt_hash, jws}`` envelope.

    The v0.17 verifier intentionally accepts ONLY the minimal envelope (no
    dual-format tolerance — that would re-introduce the malleability the minimal
    envelope removes). This converter is the migration path. For each line it:

    1. parses the embedded JWS under the strict, structurally-complete contract;
    2. **verifies the Ed25519 signature** against *public_keys* (keyed by
       ``agent_key_id``) — a corrupted or unknown-key receipt is rejected, not
       silently rewritten; ``from_jws`` alone does NOT check signatures;
    3. recomputes the content-addressed ``receipt_hash`` from the JWS (never
       trusting the old envelope copy) and writes the minimal record.

    It is a separate, explicit, offline step — not part of any live verification
    path. Fails loudly (raising) on the first line whose JWS is missing, does not
    parse strictly, or fails signature verification, so a bad legacy chain is
    surfaced rather than migrated.

    Parameters
    ----------
    public_keys
        ``{agent_key_id: public_key_pem}`` — the keys that signed the chain.
        Required: migration verifies signatures, so the keys must be supplied.

    Returns the number of records converted.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)
    verifier = ProvenanceVerifier(public_keys=public_keys)
    count = 0
    with open(in_path, encoding="utf-8") as fin, open(out_path, "w", encoding="utf-8") as fout:
        for line_no, line in enumerate(fin, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            except ValueError as exc:
                raise ValueError(f"line {line_no}: malformed JSON: {exc}") from exc
            jws = raw.get("jws") if isinstance(raw, dict) else None
            if not jws:
                raise ValueError(f"line {line_no}: record has no 'jws' field; cannot migrate")
            # Strict, structurally-complete parse — a legacy line that cannot be
            # parsed is surfaced, not silently rewritten.
            receipt = ProvenanceReceipt.from_jws(jws, strict=True)
            # Signature verification (from_jws does not do this): only migrate a
            # receipt whose signature actually checks out under a trusted key.
            if not verifier._verify_signature(receipt):
                raise ValueError(
                    f"line {line_no}: signature verification failed for "
                    f"agent_key_id={receipt.agent_key_id} — refusing to migrate"
                )
            fout.write(
                json.dumps(
                    {"receipt_hash": receipt.receipt_hash, "jws": receipt.jws},
                    ensure_ascii=False,
                )
                + "\n"
            )
            count += 1
    return count
