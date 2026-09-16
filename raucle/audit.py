"""Tamper-evident audit chain for compliance evidence (EU AI Act Article 12).

Every detection event is appended to a hash-chained, append-only log.  Each
record's hash links to its predecessor, and the chain is periodically anchored
with an Ed25519-signed checkpoint.  Any modification to past records breaks
the chain and can be detected by ``AuditVerifier.verify_chain``.

This module ships only stdlib + ``cryptography`` (already pulled in by FastAPI)
so it does not expand the mandatory dependency surface.

Usage::

    from raucle.audit import HashChainSink, Ed25519Signer

    signer = Ed25519Signer.generate()
    sink = HashChainSink("audit.jsonl", signer=signer, checkpoint_every=100)
    scanner = Scanner(audit_sink=sink)

    # Later — verify
    from raucle.audit import AuditVerifier
    report = AuditVerifier(public_key=signer.public_key_pem).verify_chain("audit.jsonl")
    print(report.valid, report.first_invalid_index)

The format is plain JSON Lines so it streams to S3/GCS/Splunk without buffering.
Each line is one event::

    {
      "index": 42,
      "timestamp": "2026-05-13T18:23:04.123456Z",
      "prev_hash": "<hex sha256 of previous record's canonical bytes>",
      "event": {...},                       # caller-supplied payload
      "hash": "<hex sha256 of this record's canonical bytes>"
    }

Checkpoints (every ``checkpoint_every`` events, plus on close) are written as::

    {
      "checkpoint": true,
      "index": 100,
      "merkle_root": "<hex sha256 of all leaf hashes 0..99>",
      "signature": "<base64 ed25519 sig over canonical(index, merkle_root)>",
      "key_id": "<sha256(pubkey)[:16]>"
    }
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from raucle._canon import make_duplicate_key_rejecter as _make_duplicate_key_rejecter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ed25519 signing (optional — falls back to unsigned chain if unavailable)
# ---------------------------------------------------------------------------


class Ed25519Signer:
    """Wraps an Ed25519 keypair for signing audit checkpoints.

    Uses the ``cryptography`` library which is already a transitive dependency
    of FastAPI/Pydantic.  If not available, ``HashChainSink`` still produces a
    hash-chained log but skips signed checkpoints.
    """

    def __init__(self, private_key: Any) -> None:
        self._private_key = private_key
        try:
            from cryptography.hazmat.primitives import serialization

            self._public_key = private_key.public_key()
            self._public_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as exc:
            # Fail loud — a signer that cannot expose its public key
            # cannot produce checkpoint signatures that any downstream
            # verifier can attribute. Surface, don't swallow.
            from raucle.errors import ConfigurationError

            logger.exception("Ed25519Signer: failed to extract public key bytes: %s", exc)
            raise ConfigurationError(
                f"Ed25519Signer: failed to extract public key bytes: {exc}"
            ) from exc

    @classmethod
    def generate(cls) -> Ed25519Signer:
        """Generate a fresh Ed25519 keypair."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem_bytes: bytes, password: bytes | None = None) -> Ed25519Signer:
        """Load a signer from PEM-encoded private key bytes."""
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(pem_bytes, password=password)
        return cls(key)

    def sign(self, data: bytes) -> bytes:
        """Sign *data* and return the raw signature bytes."""
        return self._private_key.sign(data)

    def public_key_pem(self) -> bytes:
        return self._public_pem

    def key_id(self) -> str:
        """Stable short identifier derived from the public key (first 16 hex).

        ``_public_pem`` is always populated post-``__init__`` — a missing
        public key now raises ``ConfigurationError`` at construction.
        """
        return hashlib.sha256(self._public_pem).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Canonical JSON serialisation — required for deterministic hashing
# ---------------------------------------------------------------------------


#: Shared duplicate-key-rejecting ``object_pairs_hook`` (see ``_canon``).
_reject_duplicate_keys = _make_duplicate_key_rejecter("audit record (JSON ambiguity)")


def _loads_strict(line: str) -> Any:
    """json.loads with duplicate-key rejection — use everywhere a chain record is parsed."""
    return json.loads(line, object_pairs_hook=_reject_duplicate_keys)


def _canonical_json(obj: Any) -> bytes:
    """Serialise *obj* as canonical JSON for hashing (sorted keys, no spaces, UTF-8).

    ``allow_nan=False`` rejects non-finite floats (NaN/Infinity): they are not
    valid JSON (RFC 8259) and the Go/Rust/TS/C# verifiers reject them, so
    permitting them here would let caller-controlled event data produce signed
    bytes that the sibling implementations cannot verify (round-3 #13).
    """
    from ._canon import reorder_keys_utf16  # UTF-16 key ordering (shared)

    return json.dumps(
        reorder_keys_utf16(obj),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Hash-chain sink
# ---------------------------------------------------------------------------


class HashChainSink:
    """Append-only, hash-chained sink for audit events.

    Thread-safe.  Each call to :meth:`append` writes one JSON line containing
    the canonical hash of the event plus the previous record's hash.

    Parameters
    ----------
    path : str | Path
        File path or pre-opened file object.  When a path is given, the file
        is opened in append mode; existing chains are extended seamlessly.
    signer : Ed25519Signer | None
        Optional signer for periodic checkpoints.
    checkpoint_every : int
        Emit a signed checkpoint every N events.  Set to 0 to disable
        intermediate checkpoints (only emit on ``close``).
    """

    _GENESIS_HASH = "0" * 64
    _CHAIN_META_VERSION = 1

    def __init__(
        self,
        path: str | Path | IO[str],
        signer: Ed25519Signer | None = None,
        checkpoint_every: int = 1000,
    ) -> None:
        self._signer = signer
        self._checkpoint_every = checkpoint_every
        self._lock = threading.Lock()
        self._leaf_hashes: list[str] = []
        self._next_index = 0
        self._prev_hash = self._GENESIS_HASH
        self._is_new_chain = False

        if hasattr(path, "write"):
            self._file: IO[str] = path  # type: ignore[assignment]
            self._owns_file = False
            # In-memory IO is always treated as a freshly-created chain;
            # the caller is responsible for any prior content.
            self._is_new_chain = True
        else:
            path = Path(path)
            self._is_new_chain = not path.exists()
            if path.exists():
                # Resume an existing chain
                self._resume(path)
            self._file = open(path, "a", encoding="utf-8")  # noqa: SIM115 — held for sink lifetime
            self._owns_file = True

        # Loud warning when running without a signer: hash-chain is
        # still tamper-evident, but the chain has no cryptographic
        # attribution. Operators that want an attributable audit log
        # must supply a signer.
        if self._signer is None:
            logger.warning(
                "HashChainSink running UNSIGNED — hash chain is tamper-evident "
                "but unattributed. Supply a signer or set "
                "RAUCLE_AUDIT_PRIVATE_KEY_PEM for cryptographic provenance."
            )

        # Newly-created chains MUST have a chain_meta header. It is the
        # only record that self-describes the chain's signed-mode and
        # key_id. Verifiers refuse to attribute signed-mode otherwise.
        if self._is_new_chain:
            self._write_chain_header_unsafe()

    def _write_chain_header_unsafe(self) -> None:
        """Emit the genesis ``chain_meta`` header. Called from ``__init__``
        before any concurrent access is possible; does NOT acquire ``_lock``.

        The header is itself Ed25519-signed when a signer is supplied, so
        a downstream verifier can establish "this chain was created by
        ``key_id``" without relying on a later checkpoint.
        """
        body: dict[str, Any] = {
            "chain_meta": True,
            "version": self._CHAIN_META_VERSION,
            "signed": self._signer is not None,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        if self._signer is not None:
            body["key_id"] = self._signer.key_id()
            signing_bytes = _canonical_json(body)
            try:
                from raucle.pq import HybridRecordSigner

                if isinstance(self._signer, HybridRecordSigner):
                    body.update(self._signer.sign_record(signing_bytes))
                else:
                    sig = self._signer.sign(signing_bytes)
                    body["signature"] = base64.b64encode(sig).decode("ascii")
            except ImportError:
                sig = self._signer.sign(signing_bytes)
                body["signature"] = base64.b64encode(sig).decode("ascii")
        self._file.write(json.dumps(body, ensure_ascii=False) + "\n")
        self._file.flush()

    def _resume(self, path: Path) -> None:
        """Read an existing chain and recover the tail hash + index.

        Skips both ``checkpoint`` and ``chain_meta`` records — those are
        out-of-band metadata, not part of the event hash chain.
        """
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = _loads_strict(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("checkpoint") or rec.get("chain_meta"):
                    continue
                self._prev_hash = rec.get("hash", self._prev_hash)
                self._next_index = rec.get("index", -1) + 1
                self._leaf_hashes.append(rec.get("hash", ""))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append a single event to the chain.

        Returns the full record (with ``index``, ``prev_hash``, ``hash``,
        ``timestamp``) so callers can use it as a receipt.
        """
        with self._lock:
            record = {
                "index": self._next_index,
                "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                "prev_hash": self._prev_hash,
                "event": event,
            }
            record_hash = _sha256_hex(_canonical_json(record))
            record["hash"] = record_hash

            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()

            self._leaf_hashes.append(record_hash)
            self._prev_hash = record_hash
            self._next_index += 1

            if (
                self._signer
                and self._checkpoint_every > 0
                and self._next_index % self._checkpoint_every == 0
            ):
                self._emit_checkpoint_locked()

            return record

    def emit_checkpoint(self) -> dict[str, Any] | None:
        """Force-write a checkpoint now.  Returns the checkpoint record (or None
        if no signer configured)."""
        with self._lock:
            return self._emit_checkpoint_locked()

    def close(self) -> None:
        """Flush a final checkpoint and close the underlying file."""
        with self._lock:
            if self._signer:
                self._emit_checkpoint_locked()
            if self._owns_file:
                self._file.close()

    def __enter__(self) -> HashChainSink:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def event_count(self) -> int:
        return self._next_index

    @property
    def tail_hash(self) -> str:
        return self._prev_hash

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_checkpoint_locked(self) -> dict[str, Any] | None:
        if not self._signer or not self._leaf_hashes:
            return None

        merkle_root = _merkle_root(self._leaf_hashes)
        body = {
            "index": self._next_index,
            "merkle_root": merkle_root,
            "key_id": self._signer.key_id(),
        }
        signing_bytes = _canonical_json(body)
        checkpoint = {
            "checkpoint": True,
            **body,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        # Quantum-ready checkpoints: when the signer is a HybridRecordSigner
        # (Ed25519 + ML-DSA-65), the checkpoint carries both signatures over
        # the same canonical body. Verification enforces BOTH when pq_key_id
        # is present (see verify_chain); there is no classical-only path for
        # a hybrid checkpoint (downgrade closure, same rule as pq1 receipts).
        try:
            from raucle.pq import HybridRecordSigner

            if isinstance(self._signer, HybridRecordSigner):
                checkpoint.update(self._signer.sign_record(signing_bytes))
            else:
                sig = self._signer.sign(signing_bytes)
                checkpoint["signature"] = base64.b64encode(sig).decode("ascii")
        except ImportError:
            sig = self._signer.sign(signing_bytes)
            checkpoint["signature"] = base64.b64encode(sig).decode("ascii")
        self._file.write(json.dumps(checkpoint, ensure_ascii=False) + "\n")
        self._file.flush()
        return checkpoint


# ---------------------------------------------------------------------------
# Merkle helpers
# ---------------------------------------------------------------------------


def _merkle_root(leaf_hashes: list[str]) -> str:
    """Compute the Merkle root over a list of hex-encoded leaf hashes."""
    if not leaf_hashes:
        return _sha256_hex(b"")
    try:
        level = [bytes.fromhex(h) for h in leaf_hashes]
    except (ValueError, TypeError) as exc:
        # A tampered record can carry a non-hex 'hash'. A verifier must report
        # this as invalid, not crash out of verify_chain (round-3 #22).
        raise ValueError(f"non-hex leaf hash in chain: {exc}") from exc
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left  # duplicate last on odd count
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


@dataclass
class VerificationReport:
    """Outcome of verifying an audit chain file.

    ``signed_mode`` is derived from the chain's ``chain_meta`` header:

    * ``"signed"``    — header declares ``signed=true`` and the header
      signature verifies. Subsequent checkpoints must use the same
      ``key_id`` as the header.
    * ``"unsigned"``  — header declares ``signed=false``. Any signed
      checkpoint in the chain is treated as a forgery indicator and the
      chain is rejected.
    * ``"unknown"``   — legacy chain with no ``chain_meta`` header.
      Compliance teams should treat ``"unknown"`` as a soft failure;
      promote to signed by starting a new chain file.
    """

    valid: bool
    event_count: int
    checkpoint_count: int
    valid_signatures: int
    invalid_signatures: int
    first_invalid_index: int | None = None
    errors: list[str] = field(default_factory=list)
    signed_mode: str = "unknown"  # "signed" | "unsigned" | "unknown"
    chain_key_id: str | None = None  # populated from chain_meta when signed

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "event_count": self.event_count,
            "checkpoint_count": self.checkpoint_count,
            "valid_signatures": self.valid_signatures,
            "invalid_signatures": self.invalid_signatures,
            "first_invalid_index": self.first_invalid_index,
            "errors": self.errors,
            "signed_mode": self.signed_mode,
            "chain_key_id": self.chain_key_id,
        }


class AuditVerifier:
    """Verify the integrity of a hash-chained audit log.

    Parameters
    ----------
    public_key_pem : bytes | None
        Ed25519 public key in PEM format.  When provided, checkpoint
        signatures are also verified.  When None, only the hash chain itself
        is verified (still detects tampering with event content).
    """

    def __init__(
        self,
        public_key_pem: bytes | None = None,
        pq_public_keys: dict[str, bytes | str] | None = None,
        require_pq: bool = False,
    ) -> None:
        self._public_pem = public_key_pem
        # Quantum-strict mode: every signed record (chain_meta, checkpoint)
        # MUST carry a verifying ML-DSA-65 component. A chain with stripped
        # PQ fields then fails even though the classical halves verify -
        # the only complete answer to field-stripping, which leaves no
        # in-band trace. Deployments pin the operator PQ key id out of band.
        self._require_pq = require_pq
        self._public_key: Any = None
        # ML-DSA-65 keys for quantum-ready hybrid checkpoints:
        # pq_key_id -> PEM (or raw PEM string). A checkpoint that declares
        # pq_key_id fails closed when it cannot be verified here.
        self._pq_public_keys: dict[str, Any] = {}
        for kid, pem in (pq_public_keys or {}).items():
            try:
                from raucle.pq import pq_public_key_from_pem

                self._pq_public_keys[kid] = pq_public_key_from_pem(pem)
            except Exception:
                self._pq_public_keys[kid] = None
        if public_key_pem:
            from cryptography.hazmat.primitives import serialization

            self._public_key = serialization.load_pem_public_key(public_key_pem)

    def _verify_event_record(
        self,
        rec: dict[str, Any],
        line_no: int,
        expected_index: int,
        prev_hash: str,
        report: VerificationReport,
    ) -> str:
        """Verify one event record. Returns the stored hash to chain forward."""
        if rec.get("index") != expected_index:
            report.errors.append(
                f"line {line_no}: index mismatch (expected {expected_index}, "
                f"got {rec.get('index')})"
            )
            if report.first_invalid_index is None:
                report.first_invalid_index = rec.get("index", expected_index)
            report.valid = False

        if rec.get("prev_hash") != prev_hash:
            report.errors.append(
                f"line {line_no}: prev_hash mismatch — chain broken at index {expected_index}"
            )
            if report.first_invalid_index is None:
                report.first_invalid_index = expected_index
            report.valid = False

        # Recompute hash without the hash field
        stored_hash = rec.pop("hash", None)
        recomputed = _sha256_hex(_canonical_json(rec))
        rec["hash"] = stored_hash  # restore for any downstream readers
        if stored_hash != recomputed:
            report.errors.append(
                f"line {line_no}: hash mismatch at index {expected_index} "
                f"(stored != recomputed) — record tampered"
            )
            if report.first_invalid_index is None:
                report.first_invalid_index = expected_index
            report.valid = False

        return stored_hash or ""

    def _verify_downgrade_and_truncation(
        self,
        report: VerificationReport,
        last_event_index: int,
        last_signed_checkpoint_index: int,
    ) -> None:
        """Post-loop checks: AUDIT-DOWNGRADE and AUDIT-TRUNC (a)."""
        # ---- AUDIT-DOWNGRADE: a verifier holding a key must not accept a
        # signature-stripped chain. Anything not provably "signed" is invalid.
        if self._public_key is not None and report.signed_mode != "signed":
            report.errors.append(
                "public key supplied but chain is not signed "
                f"(signed_mode={report.signed_mode!r}) — refusing to accept a "
                "signature-stripped / unattributed chain (AUDIT-DOWNGRADE)"
            )
            report.valid = False

        # ---- AUDIT-TRUNC (a): with a key, require a signed checkpoint that
        # covers the final event index. Any event past the last signed
        # checkpoint is an unverifiable tail (could be a truncation point —
        # or, symmetrically, the dropped records are simply gone). A cleanly
        # closed chain has a head checkpoint at the final index.
        if (
            self._public_key is not None
            and report.signed_mode == "signed"
            and last_event_index >= 0
            and last_signed_checkpoint_index < last_event_index + 1
        ):
            report.errors.append(
                f"unverifiable tail beyond last signed checkpoint: last signed "
                f"checkpoint covers index {last_signed_checkpoint_index}, but chain "
                f"has events through index {last_event_index} (AUDIT-TRUNC)"
            )
            report.valid = False

    def verify_chain(
        self,
        path: str | Path,
        expected_head: dict[str, Any] | None = None,
    ) -> VerificationReport:
        """Verify the chain at *path*.  Returns a :class:`VerificationReport`.

        Parameters
        ----------
        expected_head : dict | None
            Optional externally-anchored high-water mark used to detect
            trailing-record truncation. Recognised keys:

            * ``"index"`` — the expected final event index. The chain's last
              event index must equal this (so dropping the final N events is
              detected as ``index`` falling short).
            * ``"hash"`` — the expected hash (``sha256`` hex) of the final
              event record.
            * ``"merkle_root"`` — the expected Merkle root over all leaf
              hashes 0..N.

            When supplied, verification fails if the actual head does not
            match. This is the **only** way to detect truncation that drops
            records past the last signed checkpoint: a hash chain or a signed
            checkpoint can only attest to records it has seen, so a verifier
            with no external anchor cannot distinguish a truncated-but-valid
            prefix from a complete chain. Anchor this value out-of-band
            (e.g. emit it from the writer, store it in a separate trust store).

        Downgrade / truncation protection
        ----------------------------------
        When this verifier was constructed *with* a ``public_key_pem``:

        * a chain that is not ``signed_mode == "signed"`` (unsigned or a
          legacy header-less chain) is rejected — a verifier holding a key
          must not silently accept a signature-stripped chain
          (``AUDIT-DOWNGRADE``); and
        * the chain MUST carry a valid signed checkpoint covering the FINAL
          event index. Any event records appearing after the last signed
          checkpoint are an unverifiable tail and the chain is rejected
          (``AUDIT-TRUNC``). A cleanly-closed chain always has such a head
          checkpoint because :meth:`HashChainSink.close` emits one.

        When NO key is supplied, behaviour is unchanged: a best-effort
        hash-chain integrity check (still detects in-place tampering, but
        cannot detect trailing truncation without ``expected_head``).
        """
        report = VerificationReport(
            valid=True,
            event_count=0,
            checkpoint_count=0,
            valid_signatures=0,
            invalid_signatures=0,
        )

        prev_hash = HashChainSink._GENESIS_HASH
        expected_index = 0
        leaf_hashes: list[str] = []
        # Highest event index covered by a valid signed checkpoint, plus
        # the index of the last event record seen. Used for AUDIT-TRUNC.
        last_signed_checkpoint_index = -1
        last_event_index = -1
        last_event_hash: str | None = None

        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = _loads_strict(line)
                except json.JSONDecodeError as exc:
                    report.errors.append(f"line {line_no}: invalid JSON: {exc}")
                    report.valid = False
                    continue

                if rec.get("chain_meta"):
                    self._verify_chain_header(rec, line_no, report)
                    continue

                if rec.get("checkpoint"):
                    sigs_before = report.valid_signatures
                    self._verify_checkpoint(rec, leaf_hashes, expected_index, report)
                    # A checkpoint that produced a verified signature (only
                    # possible when a public key is supplied) advances the
                    # high-water mark of cryptographically-attested records.
                    if report.valid_signatures > sigs_before:
                        last_signed_checkpoint_index = rec.get("index", -1)
                    continue

                # Verify event record
                stored_hash = self._verify_event_record(
                    rec, line_no, expected_index, prev_hash, report
                )
                leaf_hashes.append(stored_hash)
                prev_hash = stored_hash or prev_hash
                last_event_index = expected_index
                last_event_hash = stored_hash
                expected_index += 1
                report.event_count += 1

        # ---- AUDIT-DOWNGRADE / AUDIT-TRUNC (a)
        self._verify_downgrade_and_truncation(
            report, last_event_index, last_signed_checkpoint_index
        )

        # ---- AUDIT-TRUNC (b): externally-anchored high-water mark. The only
        # way to detect truncation that drops records past the last checkpoint.
        if expected_head is not None:
            self._verify_expected_head(
                expected_head, last_event_index, last_event_hash, leaf_hashes, report
            )

        return report

    @staticmethod
    def _verify_expected_head(
        expected_head: dict[str, Any],
        last_event_index: int,
        last_event_hash: str | None,
        leaf_hashes: list[str],
        report: VerificationReport,
    ) -> None:
        """Compare the actual chain head against an externally-supplied anchor."""
        exp_index = expected_head.get("index")
        if exp_index is not None and exp_index != last_event_index:
            report.errors.append(
                f"head index mismatch: expected final index {exp_index}, "
                f"actual {last_event_index} — chain truncated or extended "
                f"(AUDIT-TRUNC)"
            )
            report.valid = False

        exp_hash = expected_head.get("hash")
        if exp_hash is not None and exp_hash != last_event_hash:
            report.errors.append(
                f"head hash mismatch: expected final record hash {exp_hash!r}, "
                f"actual {last_event_hash!r} — chain truncated or tampered "
                f"(AUDIT-TRUNC)"
            )
            report.valid = False

        exp_root = expected_head.get("merkle_root")
        if exp_root is not None:
            try:
                actual_root = _merkle_root(leaf_hashes)
            except ValueError as exc:
                report.errors.append(f"head merkle_root: {exc} — chain tampered")
                report.valid = False
                actual_root = None
            if actual_root is not None and exp_root != actual_root:
                report.errors.append(
                    f"head merkle_root mismatch: expected {exp_root!r}, actual "
                    f"{actual_root!r} — chain truncated or tampered (AUDIT-TRUNC)"
                )
                report.valid = False

    def _verify_chain_header(
        self,
        rec: dict[str, Any],
        line_no: int,
        report: VerificationReport,
    ) -> None:
        """Validate a ``chain_meta`` header and set ``signed_mode``."""
        if report.signed_mode != "unknown":
            # Multiple headers in one file = forgery indicator.
            report.errors.append(f"line {line_no}: duplicate chain_meta header")
            report.valid = False
            return

        is_signed = bool(rec.get("signed"))
        report.signed_mode = "signed" if is_signed else "unsigned"

        if is_signed:
            kid = rec.get("key_id") or ""
            report.chain_key_id = kid
            sig_b64 = rec.get("signature")
            if not sig_b64:
                report.errors.append(
                    f"line {line_no}: chain_meta declares signed=true but has no signature"
                )
                report.valid = False
                return
            if not self._public_key:
                # We cannot verify a signed chain without a public key, so we
                # must not report it as valid: a consumer trusting
                # (valid=True, signed_mode="signed") would be deceived by a
                # fully forged chain (round-3 #9). Fail closed and stop
                # claiming the chain is "signed" — it is unverifiable here.
                report.signed_mode = "unverifiable"
                report.errors.append(
                    f"line {line_no}: chain_meta declares signed=true but no public key "
                    f"was supplied — cannot verify; chain is not trusted"
                )
                report.valid = False
                return
            body = {
                k: v for k, v in rec.items() if k not in ("signature", "pq_key_id", "pq_signature")
            }
            try:
                self._public_key.verify(base64.b64decode(sig_b64), _canonical_json(body))
            except Exception as exc:
                report.invalid_signatures += 1
                report.errors.append(
                    f"line {line_no}: chain_meta signature verification failed: {exc}"
                )
                report.valid = False
                return
            # Quantum-ready chain headers: pq_key_id declared -> the ML-DSA-65
            # component must verify too (same fail-closed rule as checkpoints).
            pq_key_id = rec.get("pq_key_id")
            if self._require_pq and not pq_key_id:
                report.errors.append(
                    f"line {line_no}: require_pq: chain_meta carries no ML-DSA-65 "
                    "component (field-stripped hybrid chain, or a classical chain "
                    "presented to a quantum-strict verifier)"
                )
                report.valid = False
                return
            if pq_key_id:
                from raucle.pq import verify_record_hybrid

                if not verify_record_hybrid(
                    {
                        "signature": sig_b64,
                        "pq_key_id": pq_key_id,
                        "pq_signature": rec.get("pq_signature", ""),
                    },
                    _canonical_json(body),
                    lambda r: True,
                    pq_public_keys=self._pq_public_keys,
                ):
                    report.errors.append(
                        f"line {line_no}: chain_meta hybrid ML-DSA-65 component failed verification"
                    )
                    report.valid = False

    def _verify_checkpoint(
        self,
        rec: dict[str, Any],
        leaf_hashes: list[str],
        expected_index: int,
        report: VerificationReport,
    ) -> None:
        report.checkpoint_count += 1

        # If the header declared an unsigned chain, a checkpoint (which
        # carries a signature) is a forgery indicator.
        if report.signed_mode == "unsigned":
            report.errors.append(
                f"checkpoint at index {rec.get('index', '?')}: signed checkpoint "
                f"appearing in chain whose chain_meta declares signed=false"
            )
            report.valid = False
            return

        ckpt_index = rec.get("index", -1)
        if ckpt_index != expected_index:
            report.errors.append(
                f"checkpoint at index {ckpt_index} does not match chain head ({expected_index})"
            )
            report.valid = False
            return

        try:
            expected_root = _merkle_root(leaf_hashes)
        except ValueError as exc:
            report.errors.append(f"checkpoint at index {ckpt_index}: {exc} — chain tampered")
            report.valid = False
            return
        if rec.get("merkle_root") != expected_root:
            report.errors.append(
                f"checkpoint at index {ckpt_index}: merkle_root mismatch — chain tampered"
            )
            report.valid = False
            return

        # If the chain_meta header pinned a key_id, the checkpoint must
        # use it. Defends against splicing a checkpoint from another
        # chain into this one.
        if report.chain_key_id and rec.get("key_id", "") != report.chain_key_id:
            report.errors.append(
                f"checkpoint at index {ckpt_index}: key_id {rec.get('key_id', '')!r} "
                f"does not match chain_meta key_id {report.chain_key_id!r}"
            )
            report.valid = False
            return

        if not self._public_key:
            # Hash matches but we can't verify signature without a key
            return

        try:
            sig = base64.b64decode(rec["signature"])
            body = {
                "index": ckpt_index,
                "merkle_root": rec["merkle_root"],
                "key_id": rec.get("key_id", ""),
            }
            self._public_key.verify(sig, _canonical_json(body))

            # Quantum-ready checkpoints: when the record declares pq_key_id,
            # the ML-DSA-65 component MUST verify too (fail-closed; no
            # classical-only acceptance of a hybrid checkpoint - the same
            # downgrade-closure rule as pq1 receipts).
            pq_key_id = rec.get("pq_key_id")
            if self._require_pq and not pq_key_id:
                report.invalid_signatures += 1
                report.errors.append(
                    f"checkpoint at index {ckpt_index}: require_pq: no ML-DSA-65 "
                    "component on this checkpoint"
                )
                report.valid = False
                return
            if pq_key_id:
                from raucle.pq import verify_record_hybrid

                body_fields = {
                    "signature": rec["signature"],
                    "pq_key_id": pq_key_id,
                    "pq_signature": rec.get("pq_signature", ""),
                }
                if not verify_record_hybrid(
                    body_fields,
                    _canonical_json(body),
                    lambda r: True,  # classical half already verified above
                    pq_public_keys=self._pq_public_keys,
                ):
                    report.invalid_signatures += 1
                    report.errors.append(
                        f"checkpoint at index {ckpt_index}: hybrid ML-DSA-65 "
                        "component failed verification (missing key, unknown "
                        "pq_key_id, or tampered pq_signature)"
                    )
                    report.valid = False
                    return
            report.valid_signatures += 1
        except Exception as exc:
            report.invalid_signatures += 1
            report.errors.append(
                f"checkpoint at index {ckpt_index}: signature verification failed: {exc}"
            )
            report.valid = False


# ---------------------------------------------------------------------------
# Convenience: a no-op sink used when audit logging is disabled
# ---------------------------------------------------------------------------


class NullSink:
    """A no-op sink.  Use this as the default when audit logging is disabled."""

    def append(self, event: dict[str, Any]) -> dict[str, Any]:  # noqa: D401
        return {}

    def close(self) -> None:
        # No-op: a NullSink holds no file handle or buffer, so there is nothing
        # to flush or release.
        return

    @property
    def event_count(self) -> int:
        return 0

    @property
    def tail_hash(self) -> str:
        return ""


# Export the env-var name so the CLI and server can both reference it.
ENV_AUDIT_PATH = "RAUCLE_AUDIT_PATH"
ENV_AUDIT_KEY = "RAUCLE_AUDIT_PRIVATE_KEY_PEM"


def sink_from_env() -> HashChainSink | None:
    """Build a HashChainSink from environment variables, or None if not configured.

    - ``RAUCLE_AUDIT_PATH`` — file path for the chain log
    - ``RAUCLE_AUDIT_PRIVATE_KEY_PEM`` — PEM private key (optional)

    Legacy ``RAUCLE_DETECT_*`` names (pre-rename) remain supported.
    """
    from raucle._env import env as _env

    path = _env("AUDIT_PATH")
    if not path:
        return None
    signer: Ed25519Signer | None = None
    key_pem = _env("AUDIT_PRIVATE_KEY_PEM")
    if key_pem:
        try:
            signer = Ed25519Signer.from_pem(key_pem.encode())
        except Exception as exc:
            # Explicitly configured + failed = refuse to continue. An
            # operator who sets the env var expects a signed chain; a
            # silent fallback to unsigned violates that expectation.
            from raucle.errors import ConfigurationError

            logger.critical("Failed to load audit signer from %s: %s", ENV_AUDIT_KEY, exc)
            raise ConfigurationError(
                f"audit signer (env {ENV_AUDIT_KEY}) failed to load: {exc}"
            ) from exc
    return HashChainSink(path, signer=signer)
