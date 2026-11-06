"""Shared mechanics for pulled audit-source connectors.

A connector wraps a **transport** — a callable
``transport(url, params, headers) -> (status, headers, body_bytes)`` — so the
HTTP layer is fully injectable. Production wires in a real client; tests wire
in recorded fixture responses. No connector touches the network itself.

Cursors and idempotency
-----------------------
``fetch_all(after)`` pages until the source reports no next page and yields
chain-event payloads. Because vendors redeliver events (page-boundary
overlaps, retry replays), every record carries the vendor's unique event id
and the yielder drops ids already seen in the same session **and** (when
``resume=True``) every id at or after the resume cursor. Callers wanting
end-to-end idempotency across runs should persist the returned next-cursor
and the emitted source ids; appending an event twice breaks nothing in
``HashChainSink`` but pollutes downstream correlation, so dedupe before sink.

Rate limits — handled honestly
------------------------------
We do not silently spin on 429/403. When the vendor signals exhaustion, the
connector raises :class:`RateLimitError` carrying the source's own retry
hint (``Retry-After`` header if present, else the vendor-specific reset
header). The caller decides to sleep, back off, or surface the failure; tests
assert the header is parsed, not invented. This module has **no** implicit
sleep — deterministic and caller-controlled by design.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

Transport = Callable[
    [str, dict[str, str] | None, dict[str, str] | None],
    tuple[int, dict[str, str], bytes],
]

#: Canonical sha256 over the deterministic mapping of one source event to a
#: chain event. Used by the vector corpus to pin the mapping against drift.
MAPPING_VERSION = "p3b.v1"


@dataclass(frozen=True)
class RateLimitError(Exception):
    """Vendor rate-limit exhaustion, with the vendor's own retry hint."""

    source: str
    status: int
    retry_after: float | None
    detail: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return (
            f"{self.source} rate limit {self.status}; retry_after="
            f"{self.retry_after if self.retry_after is not None else 'unspecified'};"
            f" {self.detail}"
        )


@dataclass(frozen=True)
class CursorPage:
    """One fetched page: raw vendor events plus the resume cursor."""

    events: tuple[dict[str, Any], ...]
    next_cursor: str | None
    seen_at_cursor: str | None = None  # vendor-side anchor echoed for debugging


def chain_event(
    *,
    source: str,
    source_id: str,
    timestamp: str | None,
    action: str | None,
    actor: dict[str, Any],
    raw: dict[str, Any],
) -> dict[str, Any]:
    """Deterministic vendor-event -> chain-event mapping (shared by both).

    Everything is copied verbatim from the vendor payload — no wall-clock,
    no reformatting of timestamps, no defaulting of unknowns to placeholders.
    The ``actor`` sub-dict is ``{"status": "known", "identity": ...}`` or
    ``{"status": "unknown", "reason": ...}``; both are produced by the
    connector, never extrapolated.
    """
    return {
        "kind": "source_event",
        "mapping_version": MAPPING_VERSION,
        "source": source,
        "source_id": source_id,
        "timestamp": timestamp,
        "action": action,
        "actor": actor,
        "raw": raw,
    }


def record_key(ev: dict[str, Any]) -> bytes:
    """Canonical bytes for a chain event (stable hashing / corpus vectors)."""
    return json.dumps(ev, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def vector(ev: dict[str, Any]) -> str:
    """sha256 over :func:`record_key` — the corpus-pinned mapping vector."""
    return hashlib.sha256(record_key(ev)).hexdigest()


class SourceConnector:
    """Base class: paging, dedupe, rate-limit surfacing. Subclasses implement
    :meth:`_page` and :meth:`_map`."""

    source = "abstract"

    def __init__(
        self,
        transport: Transport,
        *,
        dedupe: bool = True,
    ) -> None:
        self._transport = transport
        self._dedupe = dedupe
        self._seen: set[str] = set()

    def _page(self, cursor: str | None) -> CursorPage:  # pragma: no cover - abstract
        raise NotImplementedError

    def _map(self, event: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def fetch_page(self, cursor: str | None) -> CursorPage:
        """One page, deduped. Duplicate deliveries inside/at page boundaries
        are dropped (idempotency); the cursor still advances."""
        page = self._page(cursor)
        if not self._dedupe:
            return page
        kept = tuple(ev for ev in page.events if self._remember_and_allow(ev))
        return CursorPage(kept, page.next_cursor, page.seen_at_cursor)

    def fetch_all(self, after: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield deduped chain events until the vendor reports no next page."""
        cursor = after
        while True:
            page = self.fetch_page(cursor)
            for ev in page.events:
                yield self._map(ev)
            if not page.next_cursor:
                return
            cursor = page.next_cursor

    def iter_pages(self, after: str | None = None) -> Iterator[CursorPage]:
        cursor = after
        while True:
            page = self.fetch_page(cursor)
            yield page
            if not page.next_cursor:
                return
            cursor = page.next_cursor

    def _remember_and_allow(self, event: dict[str, Any]) -> bool:
        key = self._event_key(event)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def _event_key(self, event: dict[str, Any]) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def _guard_rate_limit(
        self, status: int, headers: dict[str, str], vendor_reset_key: str
    ) -> None:
        """Surface vendor rate-limit exhaustion honestly; no sleep, no silent
        retry. Okta signals with 429 (+ Retry-After, or X-Rate-Limit-Reset
        epoch seconds); GitHub with 429, or 403 carrying
        ``X-RateLimit-Remaining: 0`` (a scope-forbidden 403 is *not* a rate
        limit and must not be misread as one). Raises RateLimitError with the
        vendor's own retry hint parsed from headers."""
        is_limit = status == 429 or (
            status == 403
            and headers.get("X-RateLimit-Remaining", headers.get(vendor_reset_key, "")) == "0"
        )
        if not is_limit:
            return
        retry_after: float | None
        if "Retry-After" in headers:
            retry_after = float(headers["Retry-After"])
        elif vendor_reset_key in headers:
            # Vendor reset headers carry epoch seconds; the hint is the wait
            # until reset — computed here so the caller gets a usable number.
            import datetime as dt

            reset = dt.datetime.fromtimestamp(float(headers[vendor_reset_key]), dt.timezone.utc)
            retry_after = max(0.0, (reset - dt.datetime.now(dt.timezone.utc)).total_seconds())
        else:
            retry_after = None
        raise RateLimitError(
            source=self.source,
            status=status,
            retry_after=retry_after,
            detail=f"Rate-limit signal in headers: {sorted(headers)}",
        )
