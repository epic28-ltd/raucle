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
  handshake (HMAC over nonce and body, constant-time compare). A missing
  or wrong authenticator is a named 401 refusal and nothing is appended.
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from raucle.async_receipt_sink import AsyncReceiptSink, ReceiptSinkOverflow
from raucle.receipt_index import ReceiptIndex
from raucle.receipt_store import SegmentedReceiptStore

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
#: The envelope shape is closed: exactly these two keys, nothing else.
_ENVELOPE_KEYS = {"receipt_hash", "jws"}
_RECEIPT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def _mac(secret: str, nonce: str, body: bytes) -> str:
    """The handshake authenticator: HMAC-SHA256 over nonce and body.

    Both sides compute it over the exact request bytes, so the
    authenticator is tamper-evident per request.
    """
    return hmac.new(
        secret.encode("utf-8"), nonce.encode("ascii") + b"\n" + body, hashlib.sha256
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
    path). Named failures raise ``SidecarError`` subclasses; nothing
    here ever changes an enforcement decision.
    """

    def __init__(self, url: str, secret: str, timeout: float = _DEFAULT_TIMEOUT) -> None:
        if not url:
            raise ValueError("sidecar url is empty")
        self._url = url.rstrip("/")
        self._secret = secret
        self._timeout = timeout

    def submit(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Submit one minted envelope; returns the sidecar's 202 body.

        Raises ``SidecarRefused`` for named refusals (overflow,
        unauthorized, invalid envelope) and ``SidecarUnreachable`` for
        transport failures. Both are receipt-loss events the caller
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
        request = Request(
            self._url + "/submit",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Raucle-Nonce": nonce,
                "X-Raucle-Sidecar-Auth": _mac(self._secret, nonce, body),
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
        except (URLError, OSError) as err:
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
        return counts

    # ------------------------------------------------------------------
    # Introspection (tests, health)
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        # Deliberate: the submit surface is plaintext HTTP on a trusted
        # local or in-cluster segment, per the spec; mTLS is a named
        # follow-up, not an assumption (docs/spec/x3-sidecar-v0.1.md).
        return f"http://{self._host}:{self._port}"  # NOSONAR

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
    def _sink_max(self) -> int:
        return self._sink._q.maxsize  # noqa: SLF001 - diagnostic line only

    def health(self) -> dict[str, Any]:
        """Counts only: no secret material, no receipt content."""
        return {
            "status": "ok",
            "chain_receipts": self._store.total_receipt_count(),
            "index_receipts": self._index.count(),
            "queue_depth": self._sink.depth,
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
            authenticator = self.headers.get("X-Raucle-Sidecar-Auth") or ""
            if not nonce or not authenticator:
                self._respond(401, {"error": "unauthorized", "detail": "handshake headers missing"})
                return
            if not hmac.compare_digest(_mac(sidecar._secret, nonce, body), authenticator):
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
