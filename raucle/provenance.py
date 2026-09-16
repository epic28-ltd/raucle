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
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

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
#: Receipts declaring this in crit carry a two-signature slot (Ed25519 +
#: ML-DSA-65) and are verified fail-closed under both keys.
_PQ1_PROFILE = "raucle/pq1"
_PQ1_ALG = "ml-dsa-65"


def _has_mldsa() -> bool:
    """True when this runtime can verify ML-DSA-65 signatures."""
    try:
        from raucle.pq import pq_available

        return pq_available()
    except Exception:
        return False


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
    signature: str = ""  # base64 over the body

    def body(self) -> dict[str, Any]:
        """Return the canonical body that gets signed (excludes ``signature``).

        ``sanitisation_authority`` is included only when non-empty so that
        statements signed before this field existed continue to verify
        byte-for-byte (backward-compatible serialisation).
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
    taint: list[str] = field(default_factory=list)
    tenant: str | None = None
    issued_at: int = 0

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
        if self.tenant is not None:
            out["tenant"] = self.tenant
        return out

    def sign(self, identity: AgentIdentity, hybrid: Any = None) -> str:
        """Sign with *identity* and populate ``jws`` + ``receipt_hash``.

        With *hybrid* (a :class:`raucle.pq.HybridSigner`), the receipt is
        signed under the ``raucle/pq1`` profile instead: the header pins
        the PQ profile in ``crit``, and the signature slot carries the
        Ed25519 and ML-DSA-65 signatures joined by ``.``. Both must
        verify; there is no downgrade path (see docs/spec/provenance/
        v1/pq1-hybrid.md).

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
            taint=list(payload.get("taint", [])),
            tenant=payload.get("tenant"),
            issued_at=payload.get("iat", 0),
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
        """Record a tool / function invocation."""
        self._check_tool_permission(tool)
        receipt = self._build(
            operation=Operation.TOOL_CALL,
            parents=parents,
            tool=tool,
            input_hash=hash_obj(input_args),
            output_hash=hash_obj(output),
            taint=self._inherit_taint(parents, extra_taint),
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
# Verifier — walks the DAG and checks integrity
# ---------------------------------------------------------------------------


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

    def to_dict(self) -> dict[str, Any]:
        return {
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

    Parameters
    ----------
    public_keys : dict[str, bytes]
        Mapping ``key_id -> PEM-encoded public key bytes``.
    capabilities : dict[str, CapabilityStatement], optional
        Mapping ``agent_key_id -> CapabilityStatement``. When provided, the
        verifier independently confirms each receipt only invoked permitted
        models/tools. Omit to skip capability conformance (signature/DAG/taint
        still run).
    """

    def __init__(
        self,
        public_keys: dict[str, bytes],
        capabilities: dict[str, CapabilityStatement] | None = None,
        pq_public_keys: dict[str, bytes | str] | None = None,
    ) -> None:
        from cryptography.hazmat.primitives import serialization

        self._keys: dict[str, Any] = {
            kid: serialization.load_pem_public_key(pem) for kid, pem in public_keys.items()
        }
        self._caps: dict[str, CapabilityStatement] = dict(capabilities or {})
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

    def verify_chain(self, path: str | Path) -> VerificationReport:
        """Verify a JSONL chain file."""
        receipts_by_hash: dict[str, ProvenanceReceipt] = {}
        report = VerificationReport(valid=True, receipt_count=0)

        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue

                raw = self._parse_chain_line(line, line_no, report)
                if raw is None:
                    continue

                try:
                    # With validate_structure disabled: the chain verifier reports each
                    # structural error per-line below (via _structural_errors)
                    # rather than raising on the first, so callers see the full
                    # set of problems in one report.
                    receipt = ProvenanceReceipt.from_jws(
                        raw["jws"], strict=True, validate_structure=False
                    )
                except (ValueError, KeyError) as exc:
                    report.errors.append(f"line {line_no}: malformed record: {exc}")
                    report.valid = False
                    continue

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

                # Structural validity per operation (spec v1 §4.2/§6): required
                # fields, root rule, merge arity. A tool_call with no parents and
                # no output_hash, etc., is malformed and must be rejected.
                for serr in _structural_errors(receipt):
                    report.errors.append(f"line {line_no}: {serr}")
                    report.valid = False

                # Capability conformance (verifier-side, when statements supplied)
                self._verify_capability_conformance(receipt, line_no, report)

                receipts_by_hash[receipt.receipt_hash] = receipt
                report.receipt_count += 1

        # Second pass: DAG integrity + taint monotonicity
        self._verify_dag_and_taint(receipts_by_hash, report)

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

        from raucle.pq import (
            HybridVerificationError,
            PQUnavailable,
            header_is_pq1,
            parse_hybrid_signature,
            verify_hybrid,
        )

        key = self._keys.get(receipt.agent_key_id)
        if key is None:
            return False
        try:
            parts = receipt.jws.split(".")
            if len(parts) == 4:
                # pq1 hybrid receipt: fail-closed dual verification. No
                # downgrade — both components must verify.
                header = json.loads(
                    _b64url_decode(parts[0]), object_pairs_hook=_reject_duplicate_keys
                )
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
                if pq_key is None:
                    raise PQUnavailable(
                        "pq1 receipt's ML-DSA key could not be loaded in this runtime"
                    )
                signing_input = (parts[0] + "." + parts[1]).encode("ascii")
                signature_slot = parts[2] + "." + parts[3]
                # Shape-checked before crypto (segment sizes) for the same
                # reason as the v1 path: fail on structure before verifying.
                parse_hybrid_signature(signature_slot)
                verify_hybrid(signing_input, signature_slot, key, pq_key)
                return True
            if len(parts) == 3:
                header_b64, payload_b64, sig_b64 = parts
                # Downgrade closure (pq1 §Verification): a receipt whose header
                # declares the pq1 profile must never verify via the v1 path,
                # even though its Ed25519 component is valid on its own. An
                # attacker who strips the ML-DSA segment otherwise presents a
                # fully "valid" v1 receipt - exactly the downgrade the hybrid
                # profile exists to prevent.
                header = json.loads(
                    _b64url_decode(header_b64), object_pairs_hook=_reject_duplicate_keys
                )
                if header.get(_PQ1_PROFILE) == _PQ1_ALG:
                    return False
                signing_input = (header_b64 + "." + payload_b64).encode("ascii")
                key.verify(_b64url_decode(sig_b64), signing_input)
                return True
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
