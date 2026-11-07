"""Tests for SCITT transparency-service anchoring of receipt-chain heads (N2).

Every test runs against a loopback HTTP double — no external network
calls. The double implements the well-known SCITT registration flow:
submit entry, poll operation status, fetch signed_statement.
"""

from __future__ import annotations

import email.utils
import hashlib
import json
import socket
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from raucle.audit import HashChainSink
from raucle.transparency import (
    STATUS_ANCHORED,
    STATUS_DIGEST_MISMATCH,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SELF_SIGNED_ONLY,
    SCITTAnchorClient,
    compute_chain_head,
    verify_transparency_anchor,
)

# ---------------------------------------------------------------------------
# Loopback Transparency Service double (no external calls)
# ---------------------------------------------------------------------------


class _FakeTSHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _send_raw(self, code: int, body: bytes) -> None:
        self.server.record.setdefault("requests", []).append(
            {"method": self.command, "path": self.path}
        )
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header(
            "Date",
            self.server.record.get("date_header") or email.utils.formatdate(usegmt=True),
        )
        if self.server.record.get("raw_retry_after") is not None:
            self.send_header("Retry-After", self.server.record["raw_retry_after"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, body: dict, extra_headers: dict | None = None) -> None:
        self.server.record.setdefault("requests", []).append(
            {"method": self.command, "path": self.path}
        )
        raw = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header(
            "Date",
            self.server.record.get("date_header") or email.utils.formatdate(usegmt=True),
        )
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        submitted = json.loads(self.rfile.read(length).decode("utf-8"))
        self.server.record["submitted_entry"] = submitted
        self.server.record["entries"] += 1
        # 201 Created, Location points at the operation status URL (relative,
        # as the real flow permits — the client must resolve it RFC 3986-style).
        self._send_json(
            201,
            {"operation_id": self.server.record["op_id"]},
            extra_headers={"Location": f"/entries/{self.server.record['op_id']}/operations"},
        )

    def do_GET(self) -> None:  # noqa: N802
        record = self.server.record
        if self.path.endswith("/operations"):
            record["polls"] += 1
            # Optional fault-injection knobs for the poll-edge tests.
            if record.get("always_pending"):
                self._send_json(
                    200,
                    {"operation_id": record["op_id"], "status": "pending"},
                    extra_headers={"Retry-After": "1"},
                )
                return
            if record.get("raw_poll_body") is not None:
                self._send_raw(record.get("raw_poll_code", 200), record["raw_poll_body"])
                return
            sequence: list = record["status_sequence"]
            status = sequence.pop(0) if sequence else "complete"
            if status == "pending":
                self._send_json(
                    200,
                    {"operation_id": record["op_id"], "status": "pending"},
                    extra_headers={"Retry-After": "1"},
                )
                return
            if status == "failed":
                self._send_json(
                    200, {"operation_id": record["op_id"], "status": "failed", "reason": "test"}
                )
                return
            self._send_json(
                200,
                {
                    "operation_id": record["op_id"],
                    "status": "complete",
                    "signed_statement_url": f"/entries/{record['op_id']}/signed-statement",
                },
            )
            return
        if self.path.endswith("/signed-statement"):
            statement_head = record["statement_head"] or dict(
                record["submitted_entry"]["chain_head"]
            )
            statement = {
                "entry_profile": record["submitted_entry"]["entry_profile"],
                "chain_id": record["submitted_entry"]["chain_id"],
                "chain_head": statement_head,
            }
            self._send_json(200, {"statement": statement, "signature": "c2lnLXRlc3Q="})
            return
        self._send_json(404, {"error": "no such path"})


@pytest.fixture
def ts_double():
    record: dict = {
        "requests": [],
        "entries": 0,
        "polls": 0,
        "op_id": "op-1",
        "status_sequence": [],
        "statement_head": None,  # override to force an echo mismatch
        "submitted_entry": None,
        # Fault-injection knobs for the poll-edge tests (default: clean).
        "always_pending": False,  # poll answers pending forever
        "raw_poll_body": None,  # raw bytes for GET /operations
        "raw_poll_code": 200,  # status code used with raw_poll_body
        "date_header": None,  # override the Date header (garbage date tests)
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeTSHandler)
    server.record = record
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# Chain fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def chain_path(tmp_path):
    """A small three-event hash chain written by the real HashChainSink."""
    path = tmp_path / "chain.jsonl"
    sink = HashChainSink(path)
    try:
        for i in range(3):
            sink.append({"tool": f"tool-{i}", "verdict": "ALLOWED"})
    finally:
        sink.close()
    return path


def _client(ts_double, **kwargs):
    return SCITTAnchorClient(
        f"http://127.0.0.1:{ts_double.server_address[1]}/transparency",
        token="test-token",
        poll_interval=0.01,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_registration_happy_path(ts_double, chain_path):
    head = compute_chain_head(chain_path)
    client = _client(ts_double)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_ANCHORED
    assert result.chain_head == head
    # The double saw exactly the entry we intended, token sent as header.
    submitted = ts_double.record["submitted_entry"]
    assert submitted["entry_profile"] == "urn:raucle:scitt:receipt-chain-head:v1"
    assert submitted["chain_head"]["hash"] == head.hash
    assert ts_double.record["entries"] == 1
    assert ts_double.record["polls"] == 1


def test_pending_then_done_polling(ts_double, chain_path):
    ts_double.record["status_sequence"] = ["pending", "pending"]
    client = _client(ts_double)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_ANCHORED
    assert ts_double.record["polls"] == 3  # two pending, then complete
    assert not ts_double.record["status_sequence"]  # drained the queue


def test_digest_mismatch_named_status(ts_double, chain_path):
    # Service anchored different material than we submitted.
    ts_double.record["statement_head"] = {
        "index": 99,
        "hash": "f" * 64,
    }
    client = _client(ts_double)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_DIGEST_MISMATCH
    assert any("DIGEST-MISMATCH" in obs for obs in result.observation)

    # Same named status offline, given a cached (fetched) statement.
    cached = {
        "statement": {"chain_head": {"index": 99, "hash": "f" * 64}},
        "signature": "c2lnLXRlc3Q=",
    }
    check = verify_transparency_anchor(chain_path, cached)
    assert check.status == STATUS_DIGEST_MISMATCH
    assert check.reasons  # honest reasons, never silent


def test_absent_transparency_self_signed_only(chain_path):
    check = verify_transparency_anchor(chain_path, None)
    assert check.status == STATUS_SELF_SIGNED_ONLY
    assert any("SELF-SIGNED-ONLY" in reason for reason in check.reasons)
    assert check.chain_head == compute_chain_head(chain_path)


def test_canonical_bytes_never_mutated_by_anchoring(ts_double, chain_path):
    before = hashlib.sha256(chain_path.read_bytes()).hexdigest()
    head = compute_chain_head(chain_path)
    result = assert_anchor_ok(ts_double, chain_path)
    check = verify_transparency_anchor(
        chain_path,
        {
            "statement": {
                "chain_id": "chain-a",
                "chain_head": {"index": head.index, "hash": head.hash},
            },
            "signature": "c2lnLXRlc3Q=",
        },
    )
    after = hashlib.sha256(chain_path.read_bytes()).hexdigest()
    assert before == after, "anchoring must be read-only over the chain file"
    assert result.status == STATUS_ANCHORED
    assert check.status == STATUS_ANCHORED


def assert_anchor_ok(ts_double, chain_path):
    return _client(ts_double).register(chain_path, chain_id="chain-a")


def test_tampered_chain_refuses_to_anchor(chain_path):
    lines = chain_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    rec["event"]["verdict"] = "DENIED"  # flip a signed field
    lines[-1] = json.dumps(rec, ensure_ascii=False)
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to anchor a tampered chain"):
        compute_chain_head(chain_path)


# ---------------------------------------------------------------------------
# Poll/HTTP edge cases against a fake host (named failures, never silent)
# ---------------------------------------------------------------------------


def test_pending_forever_returns_named_pending_with_location(ts_double, chain_path):
    """The operation never completes: status is PENDING and the caller is
    told it may resume, with the operation location recorded."""
    ts_double.record["always_pending"] = True
    client = _client(ts_double, max_polls=3)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_PENDING
    assert ts_double.record["polls"] == 3
    assert any("operation location:" in o for o in result.observation)
    assert any("still pending after 3 polls" in o and "may resume" in o for o in result.observation)
    assert result.chain_head == compute_chain_head(chain_path)


def test_operation_failed_after_poll_is_named_status(ts_double, chain_path):
    """The service reports the operation failed: named TRANSPARENCY-FAILED
    with the service's reason carried into the observations."""
    ts_double.record["status_sequence"] = ["failed"]
    client = _client(ts_double)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_FAILED
    assert ts_double.record["polls"] == 1
    assert any("operation failed:" in o for o in result.observation)
    assert any("test" in o for o in result.observation)


def test_garbage_poll_status_fails_closed(ts_double, chain_path):
    """A poll body carrying a status the protocol does not define — even a
    200 response with parseable JSON — fails closed with TRANSPARENCY-FAILED."""
    ts_double.record["raw_poll_body"] = json.dumps({"status": "garbled-bytes"}).encode("utf-8")
    client = _client(ts_double)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_FAILED
    assert any(
        "unknown operation status 'garbled-bytes'" in o and "failing closed" in o
        for o in result.observation
    )


def test_malformed_poll_body_never_silent(ts_double, chain_path):
    """A poll body that is not JSON at all surfaces the decode failure —
    the client must not mistake garbage for a completed operation."""
    ts_double.record["raw_poll_body"] = b"<html>not json</html>"
    client = _client(ts_double)
    with pytest.raises(json.JSONDecodeError):
        client.register(chain_path, chain_id="chain-a")


def test_unparseable_date_header_is_named_rejection(ts_double, chain_path):
    """A Date header that is not an HTTP-date anywhere in the flow is a
    named hard failure, not an ignored header."""
    ts_double.record["date_header"] = "yesterday-ish"
    client = _client(ts_double)
    with pytest.raises(ValueError, match="unparseable Date header"):
        client.register(chain_path, chain_id="chain-a")


def test_garbage_retry_after_is_ignored_not_fatal(ts_double, chain_path):
    """A Retry-After that is neither delta-seconds nor an HTTP-date is
    treated as zero: the flow proceeds instead of erroring."""
    ts_double.record["status_sequence"] = ["pending"]
    client = _client(ts_double)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_ANCHORED


def test_http_date_retry_after_is_honoured_and_clamped(ts_double, chain_path):
    """An HTTP-date Retry-After parses, is honoured (capped at 30s), and
    the flow keeps polling instead of erroring."""
    import time as _time

    ts_double.record["raw_poll_body"] = json.dumps(
        {"operation_id": ts_double.record["op_id"], "status": "pending"}
    ).encode("utf-8")
    ts_double.record["raw_retry_after"] = email.utils.formatdate(_time.time() + 60, usegmt=True)
    client = _client(ts_double, max_polls=2)
    result = client.register(chain_path, chain_id="chain-a")
    assert result.status == STATUS_PENDING
    assert any("honouring Retry-After" in o for o in result.observation)


def test_connection_refused_surfaces_immediately(chain_path, tmp_path):
    """A dead service (connection refused) surfaces as a network error the
    caller plans for — it must not be swallowed or retried into silence."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing is listening on this port now
    client = SCITTAnchorClient(
        f"http://127.0.0.1:{port}/transparency", token="t", poll_interval=0.01
    )
    with pytest.raises((urllib.error.URLError, ConnectionError, OSError, RuntimeError)):
        client.register(chain_path, chain_id="chain-a")
