"""X3 slice 4: the single-writer receipt sidecar.

The decided scale answer (docs/spec/x3-sidecar-v0.1.md): several gateway
replicas can serve traffic while ONE process owns the append path, so the
SQLite WAL file never has two writers. The MINT stays in the gateway; the
APPEND (chain segment write) and the INDEX projection go through this
service.

Shape:

- ``ReceiptSidecar`` owns the ``SegmentedReceiptStore`` and the
  ``ReceiptIndex``. Submissions enter a bounded FIFO queue (the X5
  ``AsyncReceiptSink``) and one writer thread drains it: chain order is
  arrival order, and only that thread ever writes the chain or the index.
- ``POST /submit`` carries the minted envelope plus a shared-secret
  handshake (HMAC over nonce, sent-at timestamp and body, constant-time
  compare). A missing or wrong authenticator is a named 401 refusal and
  nothing is appended. The nonce is submit anti-replay (issue #340, on
  the ADR 0008 section 5 contract): the first submit of a nonce and
  body is consumed atomically before enqueue (202 queued); an identical
  resubmission gets the named duplicate answer (200 ``status:
  duplicate``) and is never appended again; the same nonce with a
  different body is refused as ``nonce_reuse_mismatch`` (409); a
  captured submit whose signed sent-at lies outside the clock-skew
  window is refused as ``stale_timestamp`` (400). The nonce store is
  SQLite-backed and single-host only (see
  ``raucle.sidecar_nonce_store``); its unavailability refuses the
  submit fail-closed (``nonce_store_unavailable``, 503, nothing
  enqueued).
- Overflow is a named ``receipt_sink_overflow`` refusal (HTTP 503). The
  gateway receipts the loss as an advisory ``x_sidecar`` receipt: the
  enforcement decision completed before submission and stands; this is
  fail-open for receipt persistence only, never for enforcement.
- Restart resumes on the same store directory: the store reopens the last
  unsealed segment, the ``ReceiptIndex`` constructor runs the unchanged
  J2 interrupted-migration recovery, and a projection left behind by a
  crash between append and index write is rebuilt from the chain of
  record (``rebuild_from_store`` is the repair contract, unchanged).

Stdlib only: no new mandatory dependency enters the receipt path.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlunsplit
from urllib.request import Request, urlopen

from raucle.async_receipt_sink import AsyncReceiptSink, ReceiptSinkOverflow
from raucle.receipt_index import ReceiptIndex
from raucle.receipt_store import SegmentedReceiptStore
from raucle.sidecar_nonce_store import SidecarSubmitNonceStore

__all__ = [
    "ReceiptSidecar",
    "SidecarClient",
    "SidecarError",
    "SidecarRefused",
    "SidecarUnreachable",
    "SIDECAR_SECRET_ENV",
    "SIDECAR_URL_ENV",
    "SIDECAR_TIMEOUT_ENV",
    "SIDECAR_MAX_QUEUE_ENV",
]

logger = logging.getLogger(__name__)

SIDECAR_SECRET_ENV = "RAUCLE_RECEIPT_SIDECAR_SECRET"
SIDECAR_URL_ENV = "RAUCLE_RECEIPT_SIDECAR_URL"
SIDECAR_TIMEOUT_ENV = "RAUCLE_RECEIPT_SIDECAR_TIMEOUT"
SIDECAR_MAX_QUEUE_ENV = "RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE"

_DEFAULT_MAX_QUEUE = 4096
_DEFAULT_TIMEOUT = 2.0
#: The accepted clock-skew window for the signed sent-at timestamp: a
#: submit is acceptable only while |now - sent_at| <= this many seconds.
#: Combined with retention >= 2 * skew (enforced on the nonce store), a
#: replayed captured request is refused either as a duplicate (nonce
#: retained) or as stale (sent-at outside the window), never accepted a
#: second time. A wider operational window is a constructor opt-in.
_DEFAULT_SKEW_SECONDS = 300
#: The envelope shape is closed: exactly these two keys, nothing else.
_ENVELOPE_KEYS = {"receipt_hash", "jws"}
_RECEIPT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
#: The submit nonce shape, shared with the nonce store (defence in depth).
_SUBMIT_NONCE_RE = re.compile(r"^[0-9a-f]{16,128}$")


class SidecarError(RuntimeError):
    """Named transport or protocol failure talking to the sidecar.

    The reason string is the searchable name (``receipt_sink_overflow``,
    ``unauthorized``, ``sidecar_unreachable``...): receipt loss is never
    silent and never an exception into the gate path. ``body`` carries
    the sidecar's parsed JSON answer when there was one (refused hash,
    queue depth).
    """

    def __init__(self, reason: str, detail: str = "", body: dict[str, Any] | None = None) -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
        self.body: dict[str, Any] = body or {}


class SidecarRefused(SidecarError):
    """The sidecar answered with a named refusal (4xx/5xx)."""


class SidecarUnreachable(SidecarError):
    """Transport failure: connection refused, DNS, timeout."""


def _mac(secret: str, nonce: str, sent_at: int, body: bytes) -> str:
    """The handshake authenticator: HMAC-SHA256 over nonce, sent-at and body.

    Both sides compute it over the canonical nonce + newline + sent-at
    (the integer's decimal string) + newline + exact request bytes, so
    the authenticator is tamper-evident per request and the freshness
    claim cannot be altered without the secret.
    """
    return hmac.new(
        secret.encode("utf-8"),
        nonce.encode("ascii") + b"\n" + str(sent_at).encode("ascii") + b"\n" + body,
        hashlib.sha256,
    ).hexdigest()


def _sidecar_max_queue_from_env() -> int:
    """The submit queue bound, from RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE."""
    raw = os.environ.get(SIDECAR_MAX_QUEUE_ENV, "").strip()
    if not raw:
        return _DEFAULT_MAX_QUEUE
    try:
        value = int(raw)
    except ValueError:
        logger.error(
            "%s=%r is not an integer; using the default %d",
            SIDECAR_MAX_QUEUE_ENV,
            raw,
            _DEFAULT_MAX_QUEUE,
        )
        return _DEFAULT_MAX_QUEUE
    if value < 1:
        logger.error(
            "%s=%d is not a positive bound; using the default %d",
            SIDECAR_MAX_QUEUE_ENV,
            value,
            _DEFAULT_MAX_QUEUE,
        )
        return _DEFAULT_MAX_QUEUE
    return value


class SidecarClient:
    """Gateway-side submit client: mint, sign, then POST the envelope.

    One HTTP round trip per receipt; the sidecar enqueues and answers
    immediately (the fsync lives in its writer thread, off the gate
    path). Each request carries a fresh random nonce, its signed
    sent-at timestamp and the HMAC over all three (nonce, sent-at,
    body), so the sidecar can refuse a replayed request by name instead
    of appending it twice. Named failures raise ``SidecarError``
    subclasses; nothing here ever changes an enforcement decision.
    """

    def __init__(self, url: str, secret: str, timeout: float = _DEFAULT_TIMEOUT) -> None:
        if not url:
            raise ValueError("sidecar url is empty")
        self._url = url.rstrip("/")
        self._secret = secret
        self._timeout = timeout

    def submit(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Submit one minted envelope; returns the sidecar's JSON body.

        A first submission answers 202 (``status: queued``); a replay of
        an identical submission answers 200 (``status: duplicate``) with
        the first accepted receipt hash, never a second acceptance.
        Raises ``SidecarRefused`` for named refusals (overflow,
        unauthorized, invalid envelope, stale timestamp, nonce reuse
        mismatch, nonce store unavailable) and ``SidecarUnreachable``
        for transport failures. Both are receipt-loss events the caller
        records by name.
        """
        body = json.dumps(
            {
                "receipt_hash": envelope.get("receipt_hash", ""),
                "jws": envelope.get("jws", ""),
            },
            ensure_ascii=False,
        ).encode("utf-8")
        nonce = secrets.token_hex(16)
        sent_at = int(time.time())
        request = Request(
            self._url + "/submit",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Raucle-Nonce": nonce,
                "X-Raucle-Sidecar-Sent-At": str(sent_at),
                "X-Raucle-Sidecar-Auth": _mac(self._secret, nonce, sent_at, body),
            },
        )
        try:
            with urlopen(request, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            detail = ""
            with contextlib.suppress(Exception):  # diagnostic read only
                detail = err.read().decode("utf-8", "replace")
            parsed: Any = None
            try:
                parsed = json.loads(detail)
            except (json.JSONDecodeError, AttributeError):
                parsed = None
            reason = (
                str(parsed.get("error") or f"http_{err.code}")
                if isinstance(parsed, dict)
                else f"http_{err.code}"
            )
            raise SidecarRefused(
                reason, detail, parsed if isinstance(parsed, dict) else None
            ) from None
        except OSError as err:
            # URLError rides OSError (its base class) and so does the
            # socket-timeout family: this catch owns transport failures.
            raise SidecarUnreachable("sidecar_unreachable", str(err)) from None


class ReceiptSidecar:
    """The single owner of the receipt chain and index append path."""

    def __init__(
        self,
        store_dir: str | Path,
        *,
        secret: str = "",
        index_path: str | Path | None = None,
        host: str = "127.0.0.1",
        port: int = 8092,
        max_queue: int = _DEFAULT_MAX_QUEUE,
        max_segment_bytes: int = 64 * 1024 * 1024,
        index_cache_mb: int = 64,
        skew_seconds: int = _DEFAULT_SKEW_SECONDS,
        retention_seconds: int | None = None,
    ) -> None:
        if not secret:
            raise ValueError(
                f"{SIDECAR_SECRET_ENV} is empty: the receipt sidecar refuses "
                "to own the chain without its shared secret (fail closed)"
            )
        self._secret = secret
        self._host = host
        self._port = int(port)
        self._store_dir = Path(store_dir)
        self._skew_seconds = int(skew_seconds)
        self._store = SegmentedReceiptStore(
            base_dir=self._store_dir, max_segment_bytes=max_segment_bytes
        )
        idx = Path(index_path) if index_path else self._store_dir / "index.sqlite"
        # defer_migration stays False: the J2 interrupted-migration
        # recovery runs in the constructor, unchanged from the gateway
        # path (the sidecar is the store owner, and boot is not the hot
        # path). A pending migration resumes here, never crash-loops.
        self._index = ReceiptIndex(sqlite_path=idx, cache_mb=index_cache_mb)
        if self._index.count() < self._store.total_receipt_count():
            logger.info(
                "receipt sidecar: index is behind the chain (%d < %d); "
                "rebuilding the projection from the store",
                self._index.count(),
                self._store.total_receipt_count(),
            )
            self._index.rebuild_from_store(self._store)
        # Submit anti-replay (issue #340, ADR 0008 section 5): the
        # HMAC nonce of every accepted submit is consumed into a
        # persistent, atomic, single-host store next to the index, in
        # its own namespace (own file, own table), separate from any
        # handshake replay keys. A corrupt nonce store fails the boot
        # (the constructor raises), never an unprotected sidecar.
        self._nonces = SidecarSubmitNonceStore(
            self._store_dir / "submit_nonces.sqlite",
            skew_seconds=self._skew_seconds,
            retention_seconds=retention_seconds,
        )
        # The single writer: one bounded queue, one drain thread. Chain
        # order is arrival order and only this thread ever appends or
        # indexes, so the chain and the SQLite WAL each have exactly one
        # writer process.
        self._sink = AsyncReceiptSink(
            writer=self._append_and_index, max_queue=max_queue, name="receipt-sidecar"
        )
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Bind the HTTP server and serve in a daemon thread."""
        if self._server is not None:
            return
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer((self._host, self._port), handler)
        self._port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="receipt-sidecar-http", daemon=True
        )
        self._thread.start()
        logger.info(
            "receipt sidecar: single writer serving %s (store=%s, queue max=%d)",
            self.url,
            self._store_dir,
            self._sink_max,
        )

    def stop(self) -> dict[str, int]:
        """Drain and close. Idempotent; returns the sink's counters."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        counts = self._sink.close()
        self._index.close()
        self._nonces.close()
        return counts

    # ------------------------------------------------------------------
    # Introspection (tests, health)
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        # Deliberate: the submit surface is plaintext HTTP on a trusted
        # local or in-cluster segment, per the spec; mTLS is a named
        # follow-up, not an assumption (docs/spec/x3-sidecar-v0.1.md).
        return urlunsplit(("http", f"{self._host}:{self._port}", "", "", ""))

    @property
    def port(self) -> int:
        return self._port

    @property
    def store(self) -> SegmentedReceiptStore:
        return self._store

    @property
    def store_dir(self) -> Path:
        return self._store_dir

    @property
    def index(self) -> ReceiptIndex:
        return self._index

    @property
    def sink(self) -> AsyncReceiptSink:
        return self._sink

    @property
    def nonces(self) -> SidecarSubmitNonceStore:
        return self._nonces

    @property
    def skew_seconds(self) -> int:
        return self._skew_seconds

    @property
    def _sink_max(self) -> int:
        return self._sink._q.maxsize  # noqa: SLF001 - diagnostic line only

    def health(self) -> dict[str, Any]:
        """Counts only: no secret material, no receipt content."""
        return {
            "status": "ok",
            "chain_receipts": self._store.total_receipt_count(),
            "index_receipts": self._index.count(),
            "queue_depth": self._sink.depth,
            "tracked_submit_nonces": self._nonces.count(),
        }

    # ------------------------------------------------------------------
    # The single write path
    # ------------------------------------------------------------------

    def _append_and_index(self, envelope: dict[str, Any]) -> None:
        """Append one envelope to the chain, then project it.

        The serialisation is the production one
        (``json.dumps(..., ensure_ascii=False)`` over the two-key
        envelope), so a chain written through the sidecar is
        byte-identical to a single-writer one and every existing
        verifier consumes segments unchanged.
        """
        line = json.dumps(
            {"receipt_hash": envelope["receipt_hash"], "jws": envelope["jws"]},
            ensure_ascii=False,
        )
        self._store.append_line(line)
        try:
            self._index.index_receipt(envelope)
        except sqlite3.Error:
            # Index failure degrades queries, never the chain. Anything
            # outside sqlite's failure class propagates to the sink's
            # own named write-error boundary (receipt_sink_write_error),
            # which is the honest accounting for it.
            logger.exception("receipt sidecar: index insert failed (query degraded)")


def _make_handler(sidecar: ReceiptSidecar) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        """Tiny HTTP surface: POST /submit, GET /health. Nothing else."""

        def _respond(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path != "/submit":
                # No reflection of the request path: a 404 is a named
                # error, not an echo of caller-controlled bytes.
                self._respond(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                self._respond(400, {"error": "invalid_request", "detail": "bad length"})
                return
            body = self.rfile.read(length)
            nonce = self.headers.get("X-Raucle-Nonce") or ""
            sent_at_raw = self.headers.get("X-Raucle-Sidecar-Sent-At") or ""
            authenticator = self.headers.get("X-Raucle-Sidecar-Auth") or ""
            if not nonce or not sent_at_raw or not authenticator:
                self._respond(401, {"error": "unauthorized", "detail": "handshake headers missing"})
                return
            if not _SUBMIT_NONCE_RE.fullmatch(nonce):
                self._respond(
                    400,
                    {
                        "error": "invalid_nonce",
                        "detail": "nonce must be 16 to 128 lowercase hex characters",
                    },
                )
                return
            try:
                sent_at = int(sent_at_raw)
            except ValueError:
                self._respond(
                    401,
                    {"error": "unauthorized", "detail": "sent-at is not an integer unix timestamp"},
                )
                return
            if abs(int(time.time()) - sent_at) > sidecar._skew_seconds:
                # Fail closed BEFORE any nonce consumption: a stale or
                # far-future submit burns no nonce record and appends
                # nothing. The timestamp is under the HMAC, so a
                # capturer cannot refresh it to dodge this window.
                self._respond(
                    400,
                    {
                        "error": "stale_timestamp",
                        "detail": (
                            "sent-at outside the accepted clock-skew window "
                            f"({sidecar._skew_seconds} s)"
                        ),
                    },
                )
                return
            if not hmac.compare_digest(_mac(sidecar._secret, nonce, sent_at, body), authenticator):
                self._respond(401, {"error": "unauthorized", "detail": "handshake mismatch"})
                return
            try:
                envelope = json.loads(body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._respond(400, {"error": "invalid_envelope", "detail": "body is not JSON"})
                return
            if (
                not isinstance(envelope, dict)
                or set(envelope) != _ENVELOPE_KEYS
                or not _RECEIPT_HASH_RE.match(str(envelope.get("receipt_hash") or ""))
                or not isinstance(envelope.get("jws"), str)
                or not envelope["jws"]
            ):
                self._respond(
                    400,
                    {
                        "error": "invalid_envelope",
                        "detail": "expected exactly {receipt_hash, jws} with a sha256 receipt hash",
                    },
                )
                return
            # Submit anti-replay: the nonce is consumed atomically
            # BEFORE the envelope is enqueued (ADR 0008 section 5). The
            # claim-before-enqueue ordering is at-most-once ingest: an
            # enqueue refusal after the claim (overflow) is named to
            # the caller and never retried under the same nonce.
            body_digest = hashlib.sha256(body).hexdigest()
            try:
                decision = sidecar._nonces.consume(nonce, body_digest, envelope["receipt_hash"])
            except ValueError:
                self._respond(
                    400,
                    {"error": "invalid_request", "detail": "nonce or digest shape refused"},
                )
                return
            except sqlite3.Error:
                # Fail closed: without a decided nonce the submit is not
                # ingested. Nothing is enqueued, nothing is appended,
                # the transaction is rolled back in the store, and the
                # refusal is named for the receipted-loss path.
                logger.exception("receipt sidecar: nonce store unavailable (submit refused)")
                self._respond(
                    503,
                    {
                        "error": "nonce_store_unavailable",
                        "detail": "submit refused fail-closed; no nonce record, nothing enqueued",
                        "refused_receipt": envelope["receipt_hash"],
                    },
                )
                return
            if decision.outcome == "mismatch":
                self._respond(
                    409,
                    {
                        "error": "nonce_reuse_mismatch",
                        "detail": "this nonce was already accepted with a different request body",
                        "first_receipt_hash": decision.first_receipt_hash,
                    },
                )
                return
            if decision.outcome == "duplicate":
                # The named duplicate answer: this exact request
                # identity (nonce and body bytes) was already accepted;
                # the envelope is not appended again and the reply
                # carries the first accepted receipt hash.
                self._respond(
                    200,
                    {
                        "status": "duplicate",
                        "detail": "this nonce and body were already accepted; not appended again",
                        "first_receipt_hash": decision.first_receipt_hash,
                        "queue_depth": sidecar._sink.depth,
                    },
                )
                return
            try:
                sidecar._sink.submit(envelope)
            except ReceiptSinkOverflow:
                self._respond(
                    503,
                    {
                        "error": "receipt_sink_overflow",
                        "detail": "bounded submit queue full",
                        "refused_receipt": envelope.get("receipt_hash"),
                        "queue_depth": sidecar._sink.depth,
                    },
                )
                return
            except Exception:  # noqa: BLE001 - never a 500 without a name
                logger.exception("receipt sidecar: submit failed unexpectedly")
                self._respond(500, {"error": "sidecar_error", "detail": "internal failure"})
                return
            self._respond(202, {"status": "queued", "queue_depth": sidecar._sink.depth})

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if self.path == "/health":
                self._respond(200, sidecar.health())
                return
            self._respond(404, {"error": "not_found"})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib API
            logger.debug("receipt sidecar http: " + format, *args)

    return _Handler
