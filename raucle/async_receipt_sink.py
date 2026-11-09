"""X5: async receipt sink — a bounded single-consumer queue in front of a
receipt writer (``SegmentedReceiptStore.append_line`` or any envelope sink).

Why this exists (NFR-S-M): the receipt emit path (Ed25519 sign + fsync'd
JSONL append) is the slowest leg of the hot path. Decoupling it from the
gate lets the gate keep deciding at its own ceiling while receipts drain in
a background thread — but only with a named overflow contract:

**Overflow contract (named, never silent).** ``submit`` is *non-blocking*:
when the bounded queue is full the receipt cannot be enqueued, which is a
receipt-loss event. That loss MUST be a named failure event, never a
silent drop:

* ``ReceiptSinkOverflow`` is raised to the caller (fail-loud),
* the sink records a ``receipt_sink_overflow`` event in its in-memory
  ``overflow_events`` list (bounded) and logs it at ERROR level with the
  event name, the queue depth and the envelope's ``receipt_hash``.

Operators alert on the named event; a counter that disappears silently is
the failure mode this module exists to prevent. ``close()`` drains the
queue and reports (drained, lost) counts so shutdown never guesses.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable
from typing import Any

__all__ = ["AsyncReceiptSink", "ReceiptSinkOverflow"]

logger = logging.getLogger(__name__)

_MAX_OVERFLOW_EVENTS = 256


class ReceiptSinkOverflow(RuntimeError):
    """A receipt could not be enqueued because the bounded queue was full.

    This is a receipt-LOSS event: the caller (or the gate wrapper around
    it) must decide fail-loudly. It is never swallowed by the sink itself.
    """


class AsyncReceiptSink:
    """Bounded-queue async producer/consumer in front of a receipt writer.

    Parameters
    ----------
    writer
        Callable receiving each receipt envelope (a ``dict`` such as
        ``{"receipt_hash": ..., "jws": ...}``). Typically
        ``SegmentedReceiptStore.append_receipt``-style append.
    max_queue
        Hard bound on queued-but-not-yet-written receipts. ``0`` or less
        is rejected — an unbounded queue is unbounded memory.
    name
        Label for logs and overflow events.
    """

    def __init__(
        self,
        writer: Callable[[dict[str, Any]], None],
        *,
        max_queue: int = 1024,
        name: str = "receipt-sink",
    ) -> None:
        if not callable(writer):
            raise TypeError("writer must be callable")
        if max_queue <= 0:
            raise ValueError("max_queue must be a positive integer (bounded queue is mandatory)")
        self._writer = writer
        self._name = name
        self._q: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=max_queue)
        self._overflow_events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._submitted = 0
        self._written = 0
        self._write_errors = 0
        self._thread: threading.Thread
        self._thread = threading.Thread(
            target=self._run, name=f"async-receipt-sink[{name}]", daemon=True
        )
        self._thread.start()

    # -- producer side -------------------------------------------------------

    def submit(self, envelope: dict[str, Any]) -> None:
        """Enqueue a receipt envelope. Non-blocking.

        Raises
        ------
        ReceiptSinkOverflow
            The queue was full: the receipt is LOST. The loss is recorded
            as a named ``receipt_sink_overflow`` event and logged before
            the exception propagates.
        """
        try:
            self._q.put_nowait(envelope)
        except queue.Full:
            self._record_overflow(envelope)
            raise ReceiptSinkOverflow(
                f"receipt_sink_overflow: sink={self._name!r} queue full "
                f"(max_queue={self._q.maxsize}); receipt "
                f"{envelope.get('receipt_hash') if isinstance(envelope, dict) else None!r} lost"
            ) from None
        with self._lock:
            self._submitted += 1

    def _record_overflow(self, envelope: dict[str, Any]) -> None:
        event = {
            "event": "receipt_sink_overflow",
            "sink": self._name,
            "queue_max": self._q.maxsize,
            "receipt_hash": envelope.get("receipt_hash") if isinstance(envelope, dict) else None,
        }
        with self._lock:
            if len(self._overflow_events) < _MAX_OVERFLOW_EVENTS:
                self._overflow_events.append(event)
        # The named failure event: searchable, countable, never silent.
        logger.error("receipt_sink_overflow: sink=%s detail=%s", self._name, event)

    @property
    def overflow_events(self) -> list[dict[str, Any]]:
        """Bounded list of named overflow events (for tests/diagnostics)."""
        with self._lock:
            return list(self._overflow_events)

    @property
    def depth(self) -> int:
        return self._q.qsize()

    @property
    def submitted(self) -> int:
        with self._lock:
            return self._submitted

    # -- consumer side -------------------------------------------------------

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                return
            try:
                self._writer(item)
            except Exception:  # noqa: BLE001 - the sink must never die silently
                with self._lock:
                    self._write_errors += 1
                logger.exception(
                    "receipt_sink_write_error: sink=%s receipt_hash=%s",
                    self._name,
                    item.get("receipt_hash") if isinstance(item, dict) else None,
                )
            finally:
                self._q.task_done()
                with self._lock:
                    self._written += 1

    def close(self, drain_timeout: float = 10.0) -> dict[str, int]:
        """Stop accepting, drain the queue, join the writer thread.

        Returns counters so shutdown reports what actually happened:
        ``{"submitted", "written", "write_errors", "lost"}``.
        ``lost`` counts receipts enqueued-but-never-written when the drain
        times out — another named accounting, never a silent guess.
        """
        self._q.put(None)
        self._thread.join(timeout=max(drain_timeout, 0.0))
        with self._lock:
            written, errs, submitted = self._written, self._write_errors, self._submitted
        lost = submitted - written - self._q.qsize()
        if lost > 0:
            logger.error(
                "receipt_sink_drain_loss: sink=%s lost=%d (drain timeout)", self._name, lost
            )
        return {
            "submitted": submitted,
            "written": written,
            "write_errors": errs,
            "lost": max(lost, 0),
        }
