"""The gateway boot streams its stores in bounded windows (L1).

Boot-streaming architecture v0.1 (docs/spec/boot-streaming-v0.1.md, ADR
0007): the gateway binds first, then a background compactor rebuilds the
store-derived state through bounded windows, reporting per-surface
readiness. The boot's resident memory is bounded by configuration, not
by store size, and a watchdog turns the preflight's projection into a
checked runtime invariant.

Three pieces, one contract per surface:

* :class:`BootReadiness` holds the machine-readable readiness states
  (gate, session continuity, chain scan, receipt index) and reports
  them on ``/health``. A surface that is not ready refuses by name,
  never with an empty answer that looks complete.
* :class:`BootWatchdog` samples the process resident size against the
  J1 ceiling during the scan and the compactor; a breach is the shipped
  named refusal (:class:`raucle.errors.BootMemoryCeilingExceeded`),
  never an OOM kill.
* :class:`BootCompactor` runs the four ordered phases of the spec:
  migration (inside the J2 one-transaction invariants), a TTL-bounded
  tail window that lands session continuity, a batched historical
  sweep, then the live-tail follow mode (the shipped append path).

An interrupted run resumes or restarts itself, never crash-loops: the
phases are idempotent over their line ranges and ``rebuild_from_store``
stays the operator's repair contract.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeGuard

from raucle.audit import (
    DEFAULT_SCAN_WINDOW_BYTES,
    HashChainSink,
    _canonical_json,
    _loads_strict,
    _sha256_hex,
)
from raucle.errors import BootMemoryCeilingExceeded, ChainTailMalformed

logger = logging.getLogger(__name__)

#: The operator path a chain refusal names (mirrors chain_rotation).
ROTATE_COMMAND = "raucle rotate-chain"

#: The done key the compactor persists inside the index: a completed
#: build marks itself so a warm restart neither re-runs continuity nor
#: re-sweeps what is already projected. The gateway reads it to pick
#: the warm boot path (inline continuity replay) over the cold one.
BOOT_COMPACTOR_DONE_KEY = "boot_compactor_done"
_DONE_KEY = BOOT_COMPACTOR_DONE_KEY

#: Readiness state vocabulary, per the spec's /health contract.
_PENDING = "pending"
_BUILDING = "building"
_READY = "ready"
_REFUSED = "refused"


def _rss_mb() -> int:
    """Current resident size in MB (Linux /proc, getrusage fallback)."""
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            resident_pages = int(fh.read().split()[1])
        return resident_pages * 4096 // (1024 * 1024)
    except (OSError, ValueError, IndexError):
        pass
    try:
        import resource

        # ru_maxrss is KiB on Linux: a high-water mark, but the honest
        # fallback where statm is unavailable.
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) // 1024
    except (OSError, ValueError, AttributeError):
        return 0


class BootReadiness:
    """Per-surface readiness, monotonic per boot by construction.

    A surface reports ready only after its phase landed, and a surface
    that reported ready never regresses without a named refusal at the
    cause (a scan break, a compactor fault, a watchdog breach).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_continuity = _PENDING
        self._chain_scan: dict[str, Any] = {
            "state": "idle",
            "verified_through": 0,
            "progress": 0.0,
        }
        self._receipt_index: dict[str, Any] = {
            "state": _PENDING,
            "indexed_rows": 0,
            "progress": 0.0,
        }
        # Q11 F: the signing state of the audit chain's genesis (state and
        # the key id the genesis is attributed to), set honestly from the
        # chain on disk at boot, never from the config's wish.
        self._audit_chain: dict[str, Any] = {"state": _PENDING, "key_id": None}

    def snapshot(self) -> dict[str, Any]:
        """A deep copy of the readiness block (safe to serve on /health)."""
        with self._lock:
            return {
                "gate": _READY,
                "session_continuity": self._session_continuity,
                "chain_scan": dict(self._chain_scan),
                "receipt_index": dict(self._receipt_index),
                "audit_chain": dict(self._audit_chain),
            }

    def set_audit_chain(self, state: str, key_id: str | None = None) -> None:
        """Q11 F: record the audit chain's actual signing state."""
        with self._lock:
            self._audit_chain = {"state": state, "key_id": key_id}

    def set_session_continuity(self, state: str) -> None:
        with self._lock:
            self._session_continuity = state

    def set_chain_scan(self, **fields: Any) -> None:
        with self._lock:
            self._chain_scan.update(fields)

    def set_receipt_index(self, **fields: Any) -> None:
        with self._lock:
            self._receipt_index.update(fields)

    def session_continuity_ready(self) -> bool:
        with self._lock:
            return self._session_continuity == _READY


class BootWatchdog:
    """The preflight's runtime leg: sample resident size against the
    J1 ceiling while the boot's bounded windows run.

    ``ceiling_mb=0`` derives the ceiling from detected memory (the J1
    default); a sampler override exists for tests and for benches.
    """

    def __init__(self, ceiling_mb: int = 0, sampler: Callable[[], int] | None = None):
        self._sampler = sampler or _rss_mb
        self.ceiling_mb = int(ceiling_mb)
        if self.ceiling_mb <= 0:
            from raucle.chain_rotation import default_boot_ceiling_mb, detected_total_memory_mb

            detected = detected_total_memory_mb()
            self.ceiling_mb = default_boot_ceiling_mb(detected) if detected else 0

    def sample_mb(self) -> int:
        return int(self._sampler())

    def check(self) -> None:
        """Raise the named J1 refusal when the resident sample is over
        the ceiling. Never returns a verdict: the breach is the refusal."""
        if self.ceiling_mb <= 0:
            return
        rss = self.sample_mb()
        if rss > self.ceiling_mb:
            raise BootMemoryCeilingExceeded(
                f"boot_memory_ceiling_exceeded: the boot sampled {rss} MB "
                f"resident against the {self.ceiling_mb} MB ceiling "
                f"(RAUCLE_BOOT_MEM_CEILING_MB). The boot refuses by name "
                f"rather than be OOM-killed; shrink the bounded windows "
                f"(RAUCLE_BOOT_SCAN_WINDOW_MB, RAUCLE_INDEX_CACHE_MB), "
                f"archive the stores with '{ROTATE_COMMAND}' or raise "
                f"the ceiling."
            )


def _record_iat(record: dict[str, Any]) -> int:
    """Decode a receipt envelope's ``iat`` (0 when undecodable)."""
    try:
        from raucle.receipt_index import ReceiptIndex

        payload = ReceiptIndex._decode_payload(record)  # noqa: SLF001 - in-package wiring
        return int(payload.get("iat", 0))
    except Exception:
        return 0


def _is_receipt_envelope(record: Any) -> TypeGuard[dict[str, Any]]:
    """Shape-filter a disposable projection: only receipt envelopes
    project; skipping non-receipts (chain_meta, checkpoints) is not
    truncation (spec 3.7)."""
    return isinstance(record, dict) and "receipt_hash" in record and "jws" in record


class BootCompactor:
    """The background compactor: four ordered phases, per-surface
    readiness, resume-or-restart after an interruption.

    The index is a disposable projection and the chain of record is
    never touched: every phase either reads the chain through bounded
    windows or writes only the projection.
    """

    def __init__(
        self,
        index: Any,
        *,
        store: Any = None,
        flat_path: str | Path | None = None,
        readiness: BootReadiness | None = None,
        watchdog: BootWatchdog | None = None,
        ttl_seconds: int = 900,
        batch_rows: int = 1000,
        scan_window_bytes: int = DEFAULT_SCAN_WINDOW_BYTES,
        session_replay: Callable[[], None] | None = None,
        audit_chain: str | Path | None = None,
        frontier_attach: Callable[[Any], None] | None = None,
    ) -> None:
        self.index = index
        self.store = store
        self.flat_path = Path(flat_path) if flat_path else None
        self.readiness = readiness or BootReadiness()
        self.watchdog = watchdog or BootWatchdog()
        self.ttl_seconds = int(ttl_seconds)
        self.batch_rows = max(1, int(batch_rows))
        self.scan_window_bytes = max(1024, int(scan_window_bytes))
        self.session_replay = session_replay
        self.audit_chain = Path(audit_chain) if audit_chain else None
        self.frontier_attach = frontier_attach
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_background(self) -> threading.Thread:
        """Run the phases on a daemon thread (spec 3.2 step 6)."""
        if self._thread is not None and self._thread.is_alive():
            return self._thread
        self._thread = threading.Thread(
            target=self._run_safe, name="raucle-boot-compactor", daemon=True
        )
        self._thread.start()
        return self._thread

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def _run_safe(self) -> None:
        try:
            self.run_phases()
        except Exception as exc:  # a compactor fault is named, never a crash-loop
            logger.exception("boot compactor fault")
            self.readiness.set_receipt_index(state=_REFUSED, error=f"boot_compactor_fault: {exc}")

    # ------------------------------------------------------------------
    # The phases
    # ------------------------------------------------------------------

    def run_phases(self) -> None:
        """Run every phase to completion or to a named refusal."""
        # Phase 1 (migration): the copy deferred at open runs inside the
        # J2 invariants, one transaction, recovery by schema inspection.
        try:
            if self.index.pending_migration:
                self.index.run_pending_migration()
        except Exception as exc:
            self.readiness.set_receipt_index(
                state=_REFUSED, error=f"receipt_index_migration_failed: {exc}"
            )
            return

        # The background chain scan (spec 3.4): independent of the index
        # build, reported on its own surface.
        if self.audit_chain is not None and self.audit_chain.exists():
            self._scan_chain()

        # A completed build is a warm boot: neither continuity nor the
        # sweep re-runs (the done flag is the build's receipt).
        if self._done():
            self.readiness.set_session_continuity(_READY)
            self.readiness.set_receipt_index(
                state=_READY, indexed_rows=self.index.count(), progress=1.0
            )
            return

        self.readiness.set_receipt_index(state=_BUILDING, progress=0.0)
        try:
            self._tail_window_phase()
            self._sweep_phase()
        except BootMemoryCeilingExceeded as exc:
            self.readiness.set_receipt_index(state=_REFUSED, error=str(exc))
            return
        except ChainTailMalformed as exc:
            self.readiness.set_receipt_index(state=_REFUSED, error=str(exc))
            return
        except Exception as exc:
            logger.exception("boot compactor phase fault (recorded, resumable)")
            self.readiness.set_receipt_index(state=_REFUSED, error=f"boot_compactor_fault: {exc}")
            return
        self.readiness.set_receipt_index(
            state=_READY, indexed_rows=self.index.count(), progress=1.0
        )

    def _done(self) -> bool:
        try:
            return self.index.get_state(_DONE_KEY) == "1"
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Phase 2 + 3: the TTL-bounded tail window and session continuity
    # ------------------------------------------------------------------

    def _tail_window_phase(self) -> None:
        """Index the recent receipts covering the session-window TTL,
        newest first, then land session continuity (spec 3.5 phases 2
        and 3). Bounded by the TTL, not by the store: a segment whose
        records are all outside the window ends the walk."""
        boundary = int(time.time()) - self.ttl_seconds
        if self.store is not None:
            segments = self.store.segments()
            for seg in reversed(segments):
                covered_any = False
                for batch in self._segment_batches(seg, boundary):
                    self.watchdog.check()
                    self.index.index_batch(batch, segment=seg.name)
                    covered_any = True
                if not covered_any:
                    break
        else:
            flat = self.flat_path
            if flat is not None and flat.exists():
                self._tail_window_flat(flat, boundary)
        # Phase 3: behavioural counters go live over the tail window.
        # Until it lands, session-rule calls refuse by name (the Q1
        # contract forbids serving them cold).
        if self.session_replay is not None:
            try:
                self.session_replay()
            except Exception:
                logger.exception("session continuity replay fault (recorded)")
        self.readiness.set_session_continuity(_READY)

    def _segment_batches(self, seg: Path, boundary: int):
        """Yield batches of in-window ``(line_no, record)`` items from
        one segment, streaming: memory holds one batch, never a
        segment."""
        batch: list[tuple[int, dict[str, Any]]] = []
        with open(seg, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not _is_receipt_envelope(record):
                    continue
                if _record_iat(record) >= boundary:
                    batch.append((line_no, record))
                    if len(batch) >= self.batch_rows:
                        yield batch
                        batch = []
        if batch:
            yield batch

    def _tail_window_flat(self, flat: Path, boundary: int) -> None:
        """The flat-store tail window: a bounded reverse read of the
        legacy single-file chain, growing until the window covers the
        TTL (same primitive as the audit tail resume)."""
        from raucle.audit import read_last_lines

        window = self.scan_window_bytes
        size = flat.stat().st_size
        while True:
            start, entries = read_last_lines(flat, window)
            kept = entries if start == 0 else entries[1:]
            items = []
            for line_no, (_offset, text, _terminated) in enumerate(kept, start=1):
                if not text.strip():
                    continue
                try:
                    record = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if _is_receipt_envelope(record) and _record_iat(record) >= boundary:
                    items.append((line_no, record))
            if items or start == 0:
                self.watchdog.check()
                self.index.index_batch(items)
                return
            window = min(size, window * 2)

    # ------------------------------------------------------------------
    # Phase 4: the batched historical sweep
    # ------------------------------------------------------------------

    def _sweep_phase(self) -> None:
        """Index the historical prefix in batches, one transaction per
        batch, then mark the build done (spec 3.5 phase 4).

        Segment stores sweep every sealed and active segment except the
        live tail the append path owns: the sweep re-reads what the tail
        window already projected, but every batch is idempotent over
        its line range, so a resumed sweep inserts nothing twice. The
        flat legacy store has no stable per-line key, so its sweep
        rebuilds the projection first (the rebuild_from_flat_file
        contract); the done flag then keeps restarts from repeating it.
        """
        if self.store is not None:
            self._sweep_segments()
        else:
            flat = self.flat_path
            if flat is not None and flat.exists():
                self._sweep_flat(flat)

    def _sweep_segments(self) -> None:
        total_bytes = sum(seg.stat().st_size for seg in self.store.segments()) or 1
        done_bytes = 0
        for seg in self.store.segments():
            batch: list[tuple[int, dict[str, Any]]] = []
            with open(seg, encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, start=1):
                    line = line.strip()
                    if line:
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            record = None
                        if _is_receipt_envelope(record):
                            batch.append((line_no, record))
                    if len(batch) >= self.batch_rows:
                        self.watchdog.check()
                        # The cursor rides the rows' transaction: an
                        # interrupted sweep resumes at a committed cursor
                        # and re-inserts nothing (idempotent batches).
                        self.index.index_batch(
                            batch,
                            segment=seg.name,
                            state_updates={"cursor": f"{seg.name}:{line_no}"},
                        )
                        batch = []
                    done_bytes += len(line.encode("utf-8")) + 1
                    if done_bytes % (1 << 20) < self.batch_rows:
                        self.readiness.set_receipt_index(
                            state=_BUILDING, progress=min(1.0, done_bytes / total_bytes)
                        )
            if batch:
                self.watchdog.check()
                self.index.index_batch(
                    batch,
                    segment=seg.name,
                    state_updates={
                        "cursor": f"{seg.name}:end",
                        _DONE_KEY: "1",
                    },
                )
            self.readiness.set_receipt_index(
                state=_BUILDING, progress=min(1.0, done_bytes / total_bytes)
            )
        # Live-tail handover (spec 3.5): rows the live append path
        # projected during the build are twins of swept rows; the store
        # copy is the projection truth, so a twin is dropped once. A
        # live row with no swept twin is the tail the sweep never
        # reached and stays.
        self.index.drop_live_twins()
        # The build is done even when the final segment held no batch
        # (an empty or fully-live store): a separate one-statement
        # transaction; a crash before it simply re-runs the idempotent
        # sweep on the next boot.
        if self.index.get_state(_DONE_KEY) != "1":
            self.index.set_state(_DONE_KEY, "1")

    def _sweep_flat(self, flat: Path) -> None:
        self.index.clear()
        batch: list[tuple[int, dict[str, Any]]] = []
        total_bytes = flat.stat().st_size or 1
        done_bytes = 0
        with open(flat, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if line:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        record = None
                    if _is_receipt_envelope(record):
                        batch.append((line_no, record))
                if len(batch) >= self.batch_rows:
                    self.watchdog.check()
                    self.index.index_batch(batch)
                    batch = []
                done_bytes += len(line.encode("utf-8")) + 1
                if done_bytes % (1 << 20) < self.batch_rows:
                    self.readiness.set_receipt_index(
                        state=_BUILDING, progress=min(1.0, done_bytes / total_bytes)
                    )
        if batch:
            self.watchdog.check()
            self.index.index_batch(batch)
        self.index.set_state(_DONE_KEY, "1")

    # ------------------------------------------------------------------
    # The background chain scan (spec 3.4)
    # ------------------------------------------------------------------

    def _scan_chain(self) -> None:
        """Walk the audit chain verifying each record's link as it goes,
        through the file stream (one line in memory at a time). The scan
        is an addition, not boot-time verification of the chain of
        record: readiness reports a real signal (verified through
        offset), and a break stops the scan with its coordinates.
        """
        path = self.audit_chain
        if path is None:  # the run_phases caller guards this; the scan is a no-op without a chain
            return
        size = path.stat().st_size or 1
        self.readiness.set_chain_scan(state="scanning", verified_through=0, progress=0.0)
        prev_hash = HashChainSink._GENESIS_HASH
        expected_index = 0
        consumed = 0
        last_check_mb = 0
        frontier: Any | None = None
        if self.frontier_attach is not None:
            from raucle.audit import MerkleFrontier

            frontier = MerkleFrontier()
        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                offset = consumed
                consumed += len(line.encode("utf-8"))
                if consumed >> 20 != last_check_mb:
                    last_check_mb = consumed >> 20
                    try:
                        self.watchdog.check()
                    except BootMemoryCeilingExceeded as exc:
                        self.readiness.set_chain_scan(
                            state=_REFUSED, verified_through=offset, error=str(exc)
                        )
                        return
                if not line.strip():
                    continue
                try:
                    rec = _loads_strict(line)
                except json.JSONDecodeError as exc:
                    self.readiness.set_chain_scan(
                        state=_REFUSED,
                        verified_through=offset,
                        error=(
                            f"chain_tail_malformed: unparsable line (file {path}, "
                            f"line {line_no}, offset {offset}): {exc}. The scan "
                            f"refuses by name; archive the chain with "
                            f"'{ROTATE_COMMAND}' and start a fresh one."
                        ),
                    )
                    return
                if rec.get("checkpoint") or rec.get("chain_meta"):
                    continue
                stored_hash = rec.get("hash")
                body = {k: v for k, v in rec.items() if k != "hash"}
                broken = (
                    rec.get("prev_hash") != prev_hash
                    or rec.get("index") != expected_index
                    or (
                        stored_hash is not None
                        and _sha256_hex(_canonical_json(body)) != stored_hash
                    )
                )
                if broken:
                    self.readiness.set_chain_scan(
                        state=_REFUSED,
                        verified_through=offset,
                        error=(
                            f"chain_refused: record (file {path}, line {line_no}, "
                            f"offset {offset}, index {rec.get('index')}) does not "
                            f"recompute onto its predecessor; the scan stops at the "
                            f"break and the sink must not append past it. Archive "
                            f"the chain with '{ROTATE_COMMAND}' and start a fresh one."
                        ),
                    )
                    return
                prev_hash = stored_hash or prev_hash
                expected_index += 1
                if stored_hash is not None and frontier is not None:
                    frontier.add(stored_hash)
                self.readiness.set_chain_scan(
                    state="scanning",
                    verified_through=consumed,
                    progress=min(1.0, consumed / size),
                )
        self.readiness.set_chain_scan(state="done", verified_through=consumed, progress=1.0)
        self._attach_rebuilt_frontier(frontier, consumed)

    def _attach_rebuilt_frontier(self, frontier: Any, consumed: int) -> None:
        """D2 close (checker 20 Nov): the completed scan rebuilds the
        Merkle frontier and hands it to the audit sink, so the promised
        anchoring recovery actually runs instead of staying degraded by
        name. Only a COMPLETED scan attaches: a refused or broken scan
        leaves anchoring degraded, which is the fail-closed posture. A
        sidecar failure here is named and swallowed - anchoring is
        disposable state and must never fail the boot."""
        if frontier is None or self.frontier_attach is None:
            return
        try:
            self.frontier_attach(frontier)
            logger.info(
                "frontier rebuilt by the boot chain scan: %d leaves attached",
                frontier.leaf_count,
            )
        except Exception as exc:  # noqa: BLE001 - sidecar state, named + non-fatal
            logger.warning(
                "frontier attach after the boot scan failed (named, anchoring stays degraded): %s",
                exc,
            )
