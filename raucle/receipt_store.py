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
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_DEFAULT_SEGMENT_BYTES = 64 * 1024 * 1024  # 64 MiB


class SegmentedReceiptStore:
    """Append-only receipt storage with size-based segmentation.

    Parameters
    ----------
    base_dir
        Directory holding ``seg-NNNNNN.jsonl`` files.
    max_segment_bytes
        Rollover threshold. Sealing happens after a write pushes the active
        segment over the limit (never mid-record).
    """

    def __init__(
        self,
        base_dir: str | Path,
        max_segment_bytes: int = _DEFAULT_SEGMENT_BYTES,
    ) -> None:
        self._base = Path(base_dir)
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
        if self._active_file is None:
            self._start_segment(len(self.segments()))
        assert self._active_file is not None
        self._active_file.write(line)
        self._active_file.flush()
        os.fsync(self._active_file.fileno())
        self._active_size += len(line.encode("utf-8"))
        if self._active_size >= self._max_bytes:
            self._seal_active()

    def seal_now(self) -> str | None:
        """Operator action: seal the active segment immediately."""
        return self._seal_active()

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

    def _seal_active(self) -> str | None:
        """Close and seal the active segment with a sidecar meta file."""
        if self._active_file is None:
            return None
        name = self._active_name
        assert name is not None
        # Count receipts for the seal metadata
        receipt_count = 0
        last_hash = ""
        with open(self._base / name, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                receipt_count += 1
                try:
                    rec = json.loads(line)
                    if "receipt_hash" in rec:
                        last_hash = rec["receipt_hash"]
                except json.JSONDecodeError:
                    pass
        import time as _time

        meta = {
            "segment": name,
            "receipt_count": receipt_count,
            "last_receipt_hash": last_hash,
            "sealed_at": _time.time(),
        }
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
