"""Segmented receipt store: size-based segments with seal sidecars.

PR-B Task B2. The receipt store stops being one immortal file. Writes go to
an active segment; when it exceeds ``max_segment_bytes`` the store appends a
seal sidecar (.meta), seals the segment (read-only), and starts the next.

A sealed segment IS a valid receipt chain: plain JSONL of
``{"receipt_hash", "jws"}`` minimal envelopes, nothing else, so it is
directly consumable by ``raucle audit-pack build`` and
``ProvenanceVerifier`` byte-for-byte. Seal metadata (receipt count, last
hash, sealed_at) lives in a ``.meta`` sidecar, never inside the segment -
the chain stays pure for every existing verifier and all five reference
ports.

Query surface (``recent``, ``find_by_hash``, ``total_receipt_count``) reads
newest-first across segments without loading everything into memory: the
active segment is tailed, sealed segments are read backwards.

The trust story stays where it belongs: segments are the chain of record,
tamper-evident through the receipt signatures inside them and
the sealed read-only mode. Query helpers are conveniences, never a trust decision.

Restart resume: a store that lands on an existing writable tail segment
resumes writing INTO it on the first append instead of starting a new
numbered segment, so no writable segment is ever orphaned as unsealed
and never reopened. Resume and seal both fail closed by name (``ReceiptStoreSealRefused``)
when a segment holds an unparsable non-blank line: nothing silently seals
a torn record or chains past it.

The seal meta records its trust state honestly: with a configured seal
signer (an optional house ``Signer``, e.g. an Ed25519 ``raucle.audit.Ed25519Signer``)
each ``.meta`` carries ``key_id`` plus a base64 Ed25519 ``signature`` over
the canonical meta bytes, checked offline by ``verify_seal_meta``; with no
seal identity configured the meta records ``unsigned: true`` instead -
anonymous sealing is never presented as signed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raucle.errors import ReceiptStoreSealRefused

_DEFAULT_SEGMENT_BYTES = 64 * 1024 * 1024  # 64 MiB

#: Meta keys recording the seal's trust state (signed seal).
_SIGNATURE_KEY = "signature"
_KEY_ID_KEY = "key_id"
#: Meta key recording an anonymous seal (no seal identity configured).
_UNSIGNED_KEY = "unsigned"
#: The one field the seal signature must never cover: itself.
_SIGNATURE_SELF_FIELD = "signature"


class SegmentedReceiptStore:
    """Append-only receipt storage with size-based segmentation.

    Parameters
    ----------
    base_dir
        Directory holding ``seg-NNNNNN.jsonl`` files.
    max_segment_bytes
        Rollover threshold. Sealing happens after a write pushes the active
        segment over the limit (never mid-record).
    seal_signer
        Optional house seal identity: an object with ``sign(data: bytes)``,
        ``public_key_pem()`` and a ``key_id`` (:class:`raucle.audit.Ed25519Signer`
        or the KMS signers satisfy this). When configured, every seal meta
        carries ``key_id`` plus an Ed25519 ``signature`` over the canonical
        meta bytes; when not configured, the meta records ``unsigned: true``.
    """

    def __init__(
        self,
        base_dir: str | Path,
        max_segment_bytes: int = _DEFAULT_SEGMENT_BYTES,
        seal_signer: Any | None = None,
    ) -> None:
        self._base = Path(base_dir)
        self._seal_signer = seal_signer
        # Write/seal mutual exclusion: a concurrent operator seal (or segment
        # rollover) closes the active file; without this lock a racing append
        # writes into the closed handle (ValueError: I/O operation on closed
        # file) and the receipt is silently dropped.
        self._lock = threading.Lock()
        # Floor at one minimal record so a misconfiguration cannot create
        # an infinite rollover loop.
        self._max_bytes = max(64, int(max_segment_bytes))
        self._active_name: str | None = None
        self._active_file: Any = None
        self._active_size = 0
        # Active segment is opened lazily on first write, so an unused store
        # touches nothing.
        self._base.mkdir(parents=True, exist_ok=True)
        existing = self.segments()
        if existing and _is_writable(existing[-1]):
            last = existing[-1]
            self._active_name = last.name
            self._active_size = last.stat().st_size

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def append_line(self, line: str) -> None:
        """Append one record line (no newline; caller's line must be JSON).

        Flushes per write. Seals the segment when the write crossed the
        threshold.
        """
        if not line.endswith("\n"):
            line += "\n"
        with self._lock:
            if self._active_file is None:
                self._resume_or_start_segment()
            assert self._active_file is not None
            self._active_file.write(line)
            self._active_file.flush()
            os.fsync(self._active_file.fileno())
            self._active_size += len(line.encode("utf-8"))
            if self._active_size >= self._max_bytes:
                self._seal_active()

    def seal_now(self) -> str | None:
        """Operator action: seal the active segment immediately."""
        with self._lock:
            return self._seal_active()

    def set_seal_signer(self, signer: Any | None) -> None:
        """Bind (or replace) the seal identity after construction.

        Boot order in the gateway constructs the store before its signing
        identity exists: the gateway calls this right after the identity
        bootstrap. A store sealing before any signer is bound records
        ``unsigned: true`` for that seal - honest by construction.
        """
        with self._lock:
            self._seal_signer = signer

    # ------------------------------------------------------------------
    # Read path (bounded memory)
    # ------------------------------------------------------------------

    @property
    def active_segment(self) -> str | None:
        return self._active_name

    def segments(self) -> list[Path]:
        """All segment files, oldest first."""
        return sorted(self._base.glob("seg-*.jsonl"))

    def total_receipt_count(self) -> int:
        count = 0
        for seg in self.segments():
            count += self._count_lines(seg)
        return count

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Newest-first records across all segments, at most *limit*.

        Reads the active segment's tail first, then walks sealed segments
        backwards. Only holds *limit* records in memory.
        """
        out: list[dict[str, Any]] = []
        for seg in reversed(self.segments()):
            if len(out) >= limit:
                break
            for rec in self._iter_records_reverse(seg):
                out.append(rec)
                if len(out) >= limit:
                    break
        return out

    def find_by_hash(self, receipt_hash: str) -> dict[str, Any] | None:
        """Locate one record by receipt hash across segments."""
        for seg in reversed(self.segments()):
            for rec in self._iter_records_reverse(seg):
                if rec.get("receipt_hash") == receipt_hash:
                    return rec
        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _start_segment(self, index: int) -> None:
        name = f"seg-{index:06d}.jsonl"
        path = self._base / name
        self._active_file = open(path, "a", encoding="utf-8")  # noqa: SIM115
        self._active_name = name
        self._active_size = path.stat().st_size

    def _resume_or_start_segment(self) -> None:
        """Lazy open for the write path: resume the recorded writable tail
        segment when one exists, else start the next numbered segment.

        Resume semantics (external review of v0.23.7): a constructor that
        lands on an existing writable last segment records its name; the
        first write REOPENS that segment instead of orphaning it as an
        unsealed, never-reopened, forever-writable file.
        """
        if self._active_name is not None:
            path = self._base / self._active_name
            if path.exists() and _is_writable(path):
                self._open_existing_segment(self._active_name)
                return
        self._start_segment(len(self.segments()))

    def _open_existing_segment(self, name: str) -> None:
        """Re-open an existing writable segment in append mode.

        Sets ``_active_name``/``_active_size`` from disk. Fails closed by
        name (:class:`ReceiptStoreSealRefused`) when the tail (the last
        non-blank line) is unparsable: chaining a new record after a torn
        write would build a second record stream inside one segment file.
        """
        path = self._base / name
        tail = ""
        tail_line_no = 0
        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if line:
                    tail = line
                    tail_line_no = line_no
        if tail:
            try:
                json.loads(tail)
            except json.JSONDecodeError:
                raise ReceiptStoreSealRefused(
                    f"refusing to resume segment {name}: the tail (physical "
                    f"line {tail_line_no}) is not parseable JSON (torn or "
                    "corrupt record); appending would chain past it and the "
                    "segment stays as it is - resolve the line, then restart"
                ) from None
        self._active_file = open(path, "a", encoding="utf-8")  # noqa: SIM115
        self._active_name = name
        self._active_size = path.stat().st_size

    def _seal_active(self) -> str | None:
        """Close and seal the active segment with a sidecar meta file.

        Fails closed by name (:class:`ReceiptStoreSealRefused`) when the
        segment contains a non-blank unparsable line: the refusal leaves
        the active file open and writable and writes no meta, so the
        operator gets the refusal and decides. The meta is written only on
        a successful seal and records the seal's trust state honestly:
        ``key_id`` plus an Ed25519 ``signature`` over the canonical meta
        bytes with a configured seal signer, ``unsigned: true`` without.

        A store that never appended still seals its recorded writable tail
        segment by name (the zero-receipt seal), because the resume opens
        it first.
        """
        if self._active_file is None:
            name = self._active_name
            if name is None:
                return None
            path = self._base / name
            if not (path.exists() and _is_writable(path)):
                return None
            # Resume-then-seal: an operator sealing a restarted store gets
            # the same named refusal a first append would get.
            self._open_existing_segment(name)
            assert self._active_file is not None
        name = self._active_name
        assert name is not None
        # Count receipts for the seal metadata. A non-blank line that is
        # not parseable JSON fails the seal by name; it never counts as a
        # receipt and never seals silently.
        receipt_count = 0
        last_hash = ""
        with open(self._base / name, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    raise ReceiptStoreSealRefused(
                        f"refusing to seal segment {name}: physical line "
                        f"{line_no} is not parseable JSON (torn or corrupt "
                        "record); the segment stays open and writable - "
                        "resolve the line, then seal again"
                    ) from None
                receipt_count += 1
                if isinstance(rec, dict) and "receipt_hash" in rec:
                    last_hash = rec["receipt_hash"]
        import time as _time

        meta = {
            "segment": name,
            "receipt_count": receipt_count,
            "last_receipt_hash": last_hash,
            "sealed_at": _time.time(),
        }
        if self._seal_signer is not None:
            meta[_KEY_ID_KEY] = _seal_signer_key_id(self._seal_signer)
            meta[_SIGNATURE_KEY] = base64.b64encode(
                self._seal_signer.sign(_seal_meta_canonical_bytes(meta))
            ).decode("ascii")
        else:
            meta[_UNSIGNED_KEY] = True
        # Seal metadata lives in a SIDECAR (.meta), never inside the segment:
        # the segment must be a pure receipt chain so ProvenanceVerifier and
        # the audit pack consume it byte-for-byte with no special casing.
        meta_path = self._base / (name + ".meta")
        self._active_file.flush()
        os.fsync(self._active_file.fileno())
        self._active_file.close()
        meta_path.write_text(json.dumps(meta, ensure_ascii=False) + "\n", encoding="utf-8")
        # read-only from here on
        path = self._base / name
        mode = path.stat().st_mode
        os.chmod(path, mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
        self._active_file = None
        self._active_name = None
        # open the next
        self._start_segment(len(self.segments()))
        return name

    def _count_lines(self, seg: Path) -> int:
        count = 0
        with open(seg, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count

    def _iter_records_reverse(self, seg: Path) -> Iterator[dict[str, Any]]:
        """Yield parsed records from *seg* newest-first (bounded chunks)."""
        with open(seg, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            chunk_size = 64 * 1024
            rem = b""
            while pos > 0:
                read = min(chunk_size, pos)
                pos -= read
                fh.seek(pos)
                block = fh.read(read)
                lines = (rem + block).split(b"\n")
                rem = lines[0]
                for raw in reversed(lines[1:]):
                    rec = self._parse(raw)
                    if rec is not None:
                        yield rec
            rec = self._parse(rem)
            if rec is not None:
                yield rec

    @staticmethod
    def _parse(raw: bytes) -> dict[str, Any] | None:
        """Parse a receipt envelope; None for blanks and checkpoints.

        Checkpoint records are sealing metadata, not receipts: the query
        surface must never return them (only the seal writes and reads
        them, and chain verification consumes them separately).
        """
        line = raw.decode("utf-8", "replace").strip()
        if not line:
            return None
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(rec, dict):
            return None
        if "receipt_hash" not in rec or "jws" not in rec:
            return None
        return rec


def _is_writable(path: Path) -> bool:
    import os as _os

    return bool(_os.access(path, _os.W_OK))


def _seal_meta_canonical_bytes(meta: dict[str, Any]) -> bytes:
    """Canonical bytes the seal signature covers: the meta WITHOUT the
    ``signature`` field itself (the key id IS covered), JSON with sorted
    keys and compact separators, UTF-8 encoded. Sign and verify feed the
    same helper, so the covered material is byte-identical by construction.
    """
    core = {k: v for k, v in meta.items() if k != _SIGNATURE_SELF_FIELD}
    return json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _seal_signer_key_id(signer: Any) -> str:
    """The house key id for a seal signer.

    Uses the signer's own ``key_id`` when it exposes one as a property or
    method (both :class:`raucle.audit.Ed25519Signer` and the identity and
    KMS signers do), else falls back to the house derivation: sha256 over
    the public PEM, first 16 hex. No key-id scheme of its own.
    """
    key_id = getattr(signer, "key_id", None)
    if callable(key_id):
        return str(key_id())
    if key_id:
        return str(key_id)
    return hashlib.sha256(signer.public_key_pem()).hexdigest()[:16]


@dataclass(frozen=True)
class SealMetaVerdict:
    """The named outcome of :func:`verify_seal_meta`.

    ``verified`` is True only when the signature validates over the
    canonical meta bytes. ``unsigned`` is True when the meta records (or
    implies, as a pre-signature seal does) an unsigned seal. A refusal
    carries ``reason``; verification never raises for a tampered meta.
    """

    verified: bool
    unsigned: bool
    reason: str | None = None


def verify_seal_meta(meta: dict[str, Any], public_key: bytes | None = None) -> SealMetaVerdict:
    """Verify a seal meta's signature over its canonical meta bytes.

    Reports the seal's state by name, never silently:

    * an ``unsigned: true`` meta (no seal identity at seal time) does not
      verify and reports ``unsigned``,
    * a meta with no signature fields at all (a seal written by an earlier
      store version, or an anonymous seal) reports ``unsigned`` the same
      way,
    * a signed meta needs the sealing signer's Ed25519 public key as PEM
      bytes; without the key the verdict is named, not silent,
    * a signature that does not verify (tampered counts, hash or key id,
      or a wrong key) fails with a named reason.

    Consumers must treat a ``verified`` False as untrusted seal metadata;
    nothing here upgrades evidence.
    """
    if meta.get(_UNSIGNED_KEY):
        return SealMetaVerdict(
            verified=False,
            unsigned=True,
            reason="seal meta is unsigned (no seal identity was configured at seal time)",
        )
    signature = meta.get(_SIGNATURE_KEY)
    if not signature or not meta.get(_KEY_ID_KEY):
        return SealMetaVerdict(
            verified=False,
            unsigned=True,
            reason="seal meta carries no seal signature fields (unsigned seal)",
        )
    if public_key is None:
        return SealMetaVerdict(
            verified=False,
            unsigned=False,
            reason="seal meta is signed but no public key was supplied to verify against",
        )
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = serialization.load_pem_public_key(public_key)
    if not isinstance(key, Ed25519PublicKey):
        return SealMetaVerdict(
            verified=False,
            unsigned=False,
            reason="verify_seal_meta expects an Ed25519 public key (PEM)",
        )
    try:
        key.verify(base64.b64decode(signature), _seal_meta_canonical_bytes(meta))
    except (InvalidSignature, ValueError):
        return SealMetaVerdict(
            verified=False,
            unsigned=False,
            reason="seal meta signature does not verify over the canonical meta "
            "bytes (tampered meta or wrong key)",
        )
    return SealMetaVerdict(verified=True, unsigned=False, reason=None)
