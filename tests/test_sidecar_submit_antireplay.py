"""Sidecar submit anti-replay (issue #340 items 1 and 2) and sidecar
persistence-failure regression coverage (issue #344 item 3, sidecar part).

Pinned contract (docs/adr/0008-replay-state-and-execution-idempotency.md
section 5, implemented on the raucle/replay_store.py machinery):

- a first submit of a nonce and body is accepted once, atomically, and
  enqueued;
- an identical resubmission of the same nonce and body gets the named
  duplicate answer (200, ``status: duplicate``, first accepted receipt
  hash) and is never appended again, in serial use and under
  concurrency (exactly one winner);
- the same nonce over a different body is refused by name
  (``nonce_reuse_mismatch``, 409) and the nonce record keeps the first
  digest;
- the submit timestamp is HMAC-bound; a captured submit outside the
  clock-skew window is refused by name (``stale_timestamp``, 400) and
  burns no nonce record, so a replay is refused either as a duplicate
  (nonce retained) or as stale (nonce expired), never accepted twice;
- consumed nonces persist across a sidecar restart (single-host SQLite
  store); retention is an explicit operator choice and a bounded
  retention must cover at least twice the skew window;
- a sidecar nonce-store write failure fails the submit closed with a
  named refusal (503, ``nonce_store_unavailable``, nothing enqueued) and
  corrupts neither the receipt ledger nor enforcement; a failing chain
  append is contained by the sink and leaves the ledger byte-identical;
- a corrupt nonce store fails the sidecar boot instead of serving
  unprotected;
- no response body ever reflects request-supplied bytes (S5131): the
  responder speaks only fixed named status strings, computed counters
  and store-held values, pinned by marker-payload grep tests.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.sidecar import ReceiptSidecar, SidecarClient, _mac
from raucle.sidecar_nonce_store import SidecarSubmitNonceStore

SECRET = "test-sidecar-secret"
POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
# Hostile bytes no honest sidecar response can ever carry (S5131 pin).
XSS_MARKER = "<script>alert('rw3-xss-marker')</script>"


def _wait_until(predicate, timeout=10.0, interval=0.05):
    """Poll an async sidecar write until *predicate* holds or time is up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError("sidecar did not settle within the timeout")


def _sidecar(tmp_path, **kwargs):
    """A started sidecar on an ephemeral port; caller stops it."""
    sc = ReceiptSidecar(
        store_dir=tmp_path / "segments",
        secret=SECRET,
        host="127.0.0.1",
        port=0,
        **kwargs,
    )
    sc.start()
    return sc


def _jws_for(payload):
    """A synthetic but decodable JWS: the index projects its payload."""
    raw = base64.urlsafe_b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode(
        "ascii"
    )
    return "synthetic." + raw.rstrip("=") + ".sig"


def _envelope_body(receipt_hash=HASH_A, i=0):
    """The exact request bytes the gateway client serialises, for a
    receipt whose JWS payload the receipt index can project."""
    payload = {
        "iat": 1764000000,
        "x_gate": {
            "tool": "lookup_balance",
            "agent_id": "agent:svc",
            "decision": "allow",
            "trace_id": f"t{i}",
        },
    }
    return json.dumps(
        {"receipt_hash": receipt_hash, "jws": _jws_for(payload)}, ensure_ascii=False
    ).encode("utf-8")


def _post_with(sc, headers, body):
    """POST /submit with explicit header control; returns (status, parsed body)."""
    request = urllib.request.Request(
        sc.url + "/submit",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(detail)
        except json.JSONDecodeError:
            parsed = {"raw": detail}
        return err.code, parsed


def _post_raw(sc, headers, body):
    """POST /submit without parsing; returns (status, raw body text,
    content type) for grep-the-output assertions on hostile payloads."""
    request = urllib.request.Request(
        sc.url + "/submit",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as resp:
            return (
                resp.status,
                resp.read().decode("utf-8", "replace"),
                resp.headers.get("Content-Type", ""),
            )
    except urllib.error.HTTPError as err:
        return (
            err.code,
            err.read().decode("utf-8", "replace"),
            err.headers.get("Content-Type", ""),
        )


def _authenticated_headers(nonce, sent_at, body, secret=SECRET):
    """The full signed handshake headers for one request identity."""
    return {
        "X-Raucle-Nonce": nonce,
        "X-Raucle-Sidecar-Sent-At": str(sent_at),
        "X-Raucle-Sidecar-Auth": _mac(secret, nonce, sent_at, body),
    }


def _post(sc, nonce, sent_at, body):
    """A freshly signed submit."""
    return _post_with(sc, _authenticated_headers(nonce, sent_at, body), body)


def _chain_bytes(store_dir):
    """Every chain byte in one string, for byte-identity assertions."""
    chunks = []
    for seg in sorted(Path(store_dir).glob("seg-*.jsonl")):
        chunks.append(seg.read_bytes())
    return b"".join(chunks)


def _chain_hashes(store_dir):
    hashes = []
    for raw in _chain_bytes(store_dir).split(b"\n"):
        if raw.strip():
            hashes.append(json.loads(raw)["receipt_hash"])
    return hashes


def _install_nonce_fault(sc):
    """Fail every nonce-store INSERT with a trigger (a real storage fault)."""
    conn = sqlite3.connect(str(sc.store_dir / "submit_nonces.sqlite"))
    conn.execute(
        "CREATE TRIGGER submit_nonce_fault BEFORE INSERT ON submit_nonces "
        "BEGIN SELECT RAISE(ABORT, 'injected storage fault'); END"
    )
    conn.commit()
    return conn


class TestSubmitNonceStore:
    def test_consume_outcomes_first_duplicate_mismatch(self, tmp_path):
        store = SidecarSubmitNonceStore(tmp_path / "submit_nonces.sqlite")
        first = store.consume("f" * 32, hashlib.sha256(b"one").hexdigest(), HASH_A)
        assert first.outcome == "first"
        same_body = store.consume("f" * 32, hashlib.sha256(b"one").hexdigest(), HASH_A)
        assert same_body == ("duplicate", HASH_A)
        other_body = store.consume("f" * 32, hashlib.sha256(b"two").hexdigest(), HASH_B)
        assert other_body == ("mismatch", HASH_A)
        # a mismatch never overwrites the first digest: the original body
        # still answers as the duplicate
        assert store.consume("f" * 32, hashlib.sha256(b"one").hexdigest(), HASH_A) == (
            "duplicate",
            HASH_A,
        )

    def test_nonce_and_digest_shapes_are_enforced(self, tmp_path):
        store = SidecarSubmitNonceStore(tmp_path / "submit_nonces.sqlite")
        for bad in ("", "short", "F" * 32, "f" * 15, "f" * 129, "g" * 32, "f" * 32 + "\n"):
            with pytest.raises(ValueError):
                store.consume(bad, hashlib.sha256(b"x").hexdigest(), HASH_A)
        with pytest.raises(ValueError):
            store.consume("f" * 32, "tooshort", HASH_A)
        with pytest.raises(ValueError):
            store.consume("f" * 32, hashlib.sha256(b"x").hexdigest(), "nope")

    def test_retention_must_cover_twice_the_skew_window(self, tmp_path):
        # 9 s of retention against a 5 s skew forgets before the HMAC-bound
        # sent-at window stops the replay: refuse the configuration.
        with pytest.raises(ValueError, match="at least twice the clock-skew window"):
            SidecarSubmitNonceStore(
                tmp_path / "submit_nonces.sqlite", skew_seconds=5, retention_seconds=9
            )
        ok = SidecarSubmitNonceStore(
            tmp_path / "submit_nonces.sqlite", skew_seconds=5, retention_seconds=10
        )
        ok.close()

    def test_purge_expired_never_forgets_silently(self, tmp_path):
        store = SidecarSubmitNonceStore(tmp_path / "submit_nonces.sqlite")
        store.consume("f" * 32, hashlib.sha256(b"one").hexdigest(), HASH_A)
        with pytest.raises(ValueError, match="must not be forgotten silently"):
            store.purge_expired()
        assert store.purge_expired(older_than_seconds=0) == 1
        store.close()


class TestFirstAndDuplicate:
    def test_first_submit_accepted_once_and_identical_resubmit_is_named_duplicate(self, tmp_path):
        sc = _sidecar(tmp_path)
        try:
            body = _envelope_body()
            status, first = _post(sc, "e" * 32, int(time.time()), body)
            assert status == 202
            assert first["status"] == "queued"
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)

            # byte-identical resubmission: the named duplicate answer,
            # never a second acceptance
            status, duplicate = _post(sc, "e" * 32, int(time.time()), body)
            assert status == 200
            assert duplicate["status"] == "duplicate"
            assert duplicate["first_receipt_hash"] == HASH_A
            # a settled instant: the duplicate must not have enqueued
            # anything new
            time.sleep(0.3)
            assert sc.store.total_receipt_count() == 1
            assert sc.index.count() == 1
            assert sc.nonces.count() == 1
            assert _chain_hashes(sc.store_dir) == [HASH_A]
        finally:
            sc.stop()

    def test_captured_verbatim_replay_gets_the_duplicate_answer(self, tmp_path):
        # a captured request (headers and bytes exactly as captured, no
        # re-signing) replayed within the skew window: the named
        # duplicate answer, nothing appended again
        sc = _sidecar(tmp_path)
        try:
            body = _envelope_body()
            captured = _authenticated_headers("a" * 32, int(time.time()), body)
            assert _post_with(sc, captured, body)[0] == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)

            status, duplicate = _post_with(sc, captured, body)
            assert status == 200
            assert duplicate["status"] == "duplicate"
            assert duplicate["first_receipt_hash"] == HASH_A
            time.sleep(0.3)
            assert sc.store.total_receipt_count() == 1
            assert sc.index.count() == 1
            assert _chain_hashes(sc.store_dir) == [HASH_A]
        finally:
            sc.stop()

    def test_fresh_nonce_same_envelope_is_still_a_legitimate_mint(self, tmp_path):
        # anti-replay scope is the REQUEST (nonce and body), not the
        # envelope: a new submit identity for a new mint event is
        # accepted and the sidecar keeps every attempt by design.
        sc = _sidecar(tmp_path)
        try:
            body = _envelope_body()
            assert _post(sc, "1" * 32, int(time.time()), body)[0] == 202
            assert _post(sc, "2" * 32, int(time.time()), body)[0] == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 2)
            assert sc.nonces.count() == 2
        finally:
            sc.stop()


class TestMismatchAndHandshake:
    def test_same_nonce_different_body_refused_as_nonce_reuse_mismatch(self, tmp_path):
        sc = _sidecar(tmp_path)
        try:
            body_a = _envelope_body(HASH_A)
            body_b = _envelope_body(HASH_B)
            now = int(time.time())
            assert _post(sc, "d" * 32, now, body_a)[0] == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)

            status, refused = _post(sc, "d" * 32, now + 1, body_b)
            assert status == 409
            assert refused["error"] == "nonce_reuse_mismatch"
            assert refused["first_receipt_hash"] == HASH_A
            assert _chain_hashes(sc.store_dir) == [HASH_A]

            # the record is intact: the original body still answers as
            # the duplicate and body B was never appended
            status, duplicate = _post(sc, "d" * 32, now + 2, body_a)
            assert status == 200
            assert duplicate["status"] == "duplicate"
            assert duplicate["first_receipt_hash"] == HASH_A
            assert sc.store.total_receipt_count() == 1
        finally:
            sc.stop()

    def test_missing_or_garbage_handshake_elements_refused(self, tmp_path):
        sc = _sidecar(tmp_path)
        try:

            def post_raw(headers):
                return _post_with(sc, headers, _envelope_body())

            status, missing = post_raw({"Content-Type": "application/json"})
            assert status == 401
            assert missing["error"] == "unauthorized"
            assert "handshake headers missing" in missing["detail"]

            nonce = "c" * 32
            now = int(time.time())
            body = _envelope_body()
            status, garbage_ts = post_raw(
                {
                    "Content-Type": "application/json",
                    "X-Raucle-Nonce": nonce,
                    "X-Raucle-Sidecar-Sent-At": "not-a-timestamp",
                    "X-Raucle-Sidecar-Auth": _mac(SECRET, nonce, 0, body),
                }
            )
            assert status == 401
            assert "sent-at is not an integer" in garbage_ts["detail"]

            status, bad_nonce = post_raw(
                {
                    "Content-Type": "application/json",
                    "X-Raucle-Nonce": "NONSENSE",
                    "X-Raucle-Sidecar-Sent-At": str(now),
                    "X-Raucle-Sidecar-Auth": _mac(SECRET, "NONSENSE", now, body),
                }
            )
            assert status == 400
            assert bad_nonce["error"] == "invalid_nonce"
            assert sc.store.total_receipt_count() == 0
            assert sc.nonces.count() == 0
        finally:
            sc.stop()


class TestSkewWindow:
    def test_captured_submit_outside_the_skew_window_is_refused_and_burns_no_nonce(self, tmp_path):
        sc = _sidecar(tmp_path, skew_seconds=120)
        try:
            body = _envelope_body()
            nonce = "a" * 32
            now = int(time.time())
            # margins against the sidecar's later clock read: 120 s
            # window, probes at 97 s past and 123 s future both refuse
            for sent_at in (now - 120 - 3, now + 120 + 3):
                status, refused = _post(sc, nonce, sent_at, body)
                assert status == 400
                assert refused["error"] == "stale_timestamp"
            assert sc.store.total_receipt_count() == 0
            assert sc.nonces.count() == 0

            # the stale attempts burned nothing: the same nonce is still
            # fresh inside the window (100 s past, under the 120 s skew)
            status, accepted = _post(sc, nonce, now - 100, body)
            assert status == 202
            assert accepted["status"] == "queued"
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)
            assert sc.nonces.count() == 1
        finally:
            sc.stop()


class TestConcurrency:
    def test_concurrent_identical_submits_win_exactly_once(self, tmp_path):
        sc = _sidecar(tmp_path)
        try:
            body = _envelope_body()
            now = int(time.time())
            results: list[tuple[int, dict]] = []
            results_lock = threading.Lock()

            def submit():
                outcome = _post(sc, "9" * 32, now, body)
                with results_lock:
                    results.append(outcome)

            threads = [threading.Thread(target=submit) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert sum(1 for status, _ in results if status == 202) == 1
            duplicates = [parsed for status, parsed in results if status == 200]
            assert len(duplicates) == 7
            assert all(d["status"] == "duplicate" for d in duplicates)
            assert all(d["first_receipt_hash"] == HASH_A for d in duplicates)
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)
            assert _chain_hashes(sc.store_dir) == [HASH_A]
        finally:
            sc.stop()

    def test_concurrent_store_consumes_are_atomic(self, tmp_path):
        store = SidecarSubmitNonceStore(tmp_path / "submit_nonces.sqlite")
        digest = hashlib.sha256(b"one").hexdigest()
        outcomes: list[str] = []
        outcomes_lock = threading.Lock()

        def consume():
            decision = store.consume("f" * 32, digest, HASH_A)
            with outcomes_lock:
                outcomes.append(decision.outcome)

        threads = [threading.Thread(target=consume) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes.count("first") == 1
        assert outcomes.count("duplicate") == 7
        store.close()


class TestRestartPersistence:
    def test_consumed_nonces_persist_across_a_sidecar_restart(self, tmp_path):
        sc1 = _sidecar(tmp_path)
        body = _envelope_body()
        try:
            assert _post(sc1, "7" * 32, int(time.time()), body)[0] == 202
            _wait_until(lambda: sc1.store.total_receipt_count() == 1 and sc1.index.count() == 1)
        finally:
            sc1.stop()

        # same store directory: the consumed nonce survives the restart
        sc2 = _sidecar(tmp_path)
        try:
            assert sc2.nonces.count() == 1
            status, duplicate = _post(sc2, "7" * 32, int(time.time()), body)
            assert status == 200
            assert duplicate["status"] == "duplicate"
            assert duplicate["first_receipt_hash"] == HASH_A
            # a settled instant: the duplicate must not have enqueued
            # anything new
            time.sleep(0.3)
            assert sc2.store.total_receipt_count() == 1
            assert _chain_hashes(sc2.store_dir) == [HASH_A]
        finally:
            sc2.stop()


class TestRetention:
    def test_retention_expires_the_record_and_the_skew_window_still_blocks_replay(self, tmp_path):
        # retention 2 s must cover twice the 1 s skew: the record is the
        # duplicate answer's lifetime, while the HMAC-bound sent-at
        # window keeps blocking the replay itself either way.
        sc = _sidecar(tmp_path, skew_seconds=1, retention_seconds=2)
        try:
            body = _envelope_body()
            captured = _authenticated_headers("5" * 32, int(time.time()), body)
            assert _post_with(sc, captured, body)[0] == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)

            # inside both windows: the named duplicate answer
            status, duplicate = _post_with(sc, captured, body)
            assert status == 200
            assert duplicate["status"] == "duplicate"

            # past retention (and any skew window): the verbatim
            # captured bytes are refused as stale, never accepted as a
            # second first acceptance, because the sent-at timestamp is
            # HMAC-bound and cannot be refreshed by a capturer
            time.sleep(3.5)
            status, stale = _post_with(sc, captured, body)
            assert status == 400
            assert stale["error"] == "stale_timestamp"
            assert sc.store.total_receipt_count() == 1

            # a fresh legitimate submit sweeps the expired record: the
            # nonce identity expires with its record, and this submit
            # documents the honest expiry behaviour
            body_two = _envelope_body(HASH_B)
            assert _post(sc, "6" * 32, int(time.time()), body_two)[0] == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 2)
            assert sc.nonces.count() == 1  # the expired "5"*32 record is gone

            # now the expired nonce identity may be consumed again (in
            # window, new body): named expiry, not silent protection
            assert _post(sc, "5" * 32, int(time.time()), body_two)[0] == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 3)
            assert sc.nonces.count() == 2
        finally:
            sc.stop()


def _hostile_envelope_body():
    """A shape-valid envelope whose only loosely validated field (``jws``,
    any non-empty string) carries hostile bytes that must never appear in
    any response."""
    return json.dumps(
        {"receipt_hash": HASH_A, "jws": f"evil.{XSS_MARKER}.sig"},
        ensure_ascii=False,
    ).encode("utf-8")


class TestHostileRequestBodies:
    """pythonsecurity:S5131: no request-supplied bytes or paths are ever
    reflected into a sidecar response body. Each reachable answer is
    asserted raw, by grep, against a marker payload."""

    def test_no_hostile_body_or_header_bytes_appear_in_any_response(self, tmp_path):
        sc = _sidecar(tmp_path)
        fault = None
        try:
            now = int(time.time())
            # (1) 202: a marker-carrying but shape-valid envelope is
            # accepted; the answer names the queue state only
            hostile_body = _hostile_envelope_body()
            nonce_a = "1" * 32
            status, raw, ctype = _post_raw(
                sc, _authenticated_headers(nonce_a, now, hostile_body), hostile_body
            )
            assert status == 202
            assert "application/json" in ctype
            assert XSS_MARKER not in raw
            assert '"status": "queued"' in raw

            # the identical resubmission answers the named duplicate from
            # the store-held hash; still no echo of the marker field
            _wait_until(lambda: sc.store.total_receipt_count() == 1)
            status, raw, ctype = _post_raw(
                sc, _authenticated_headers(nonce_a, now, hostile_body), hostile_body
            )
            assert status == 200
            assert '"error"' not in raw
            assert XSS_MARKER not in raw

            # (2) 400 invalid_envelope: raw non-JSON marker bytes signed
            # with a valid handshake are named, never echoed
            garbage_body = b"<svg onload=alert(1)>%s</svg>" % XSS_MARKER.encode("utf-8")
            nonce_b = "2" * 32
            status, raw, ctype = _post_raw(
                sc, _authenticated_headers(nonce_b, now, garbage_body), garbage_body
            )
            assert status == 400
            assert "application/json" in ctype
            assert b'"error": "invalid_envelope"' in raw.encode("utf-8", "replace")
            assert XSS_MARKER not in raw

            # (3) 409: a re-used nonce over a hostile second body is
            # refused by name with the first accepted hash only
            body_a = _envelope_body(HASH_A)
            assert _post(sc, "3" * 32, now, body_a)[0] == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 2)
            mixed = json.dumps(
                {"receipt_hash": HASH_B, "jws": XSS_MARKER}, ensure_ascii=False
            ).encode("utf-8")
            status, raw, ctype = _post_raw(
                sc, _authenticated_headers("3" * 32, now + 1, mixed), mixed
            )
            assert status == 409
            assert '"nonce_reuse_mismatch"' in raw
            assert XSS_MARKER not in raw

            # (4) 400 invalid_nonce: a hostile nonce header is named, not
            # reflected (headers are compared, never re-served)
            hostile_nonce = "N" * 8 + XSS_MARKER
            status, raw, ctype = _post_raw(
                sc,
                _authenticated_headers(hostile_nonce, now, body_a),
                body_a,
            )
            assert status == 400
            assert '"invalid_nonce"' in raw
            assert XSS_MARKER not in raw

            # (5) 503: a failing nonce store answers the named refusal;
            # the body carries no request-supplied value at all
            fault = _install_nonce_fault(sc)
            status, raw, ctype = _post_raw(
                sc, _authenticated_headers("4" * 32, now, hostile_body), hostile_body
            )
            assert status == 503
            assert '"nonce_store_unavailable"' in raw
            assert XSS_MARKER not in raw
            assert '"receipt_hash"' not in raw and "jws" not in raw
        finally:
            if fault is not None:
                fault.execute("DROP TRIGGER IF EXISTS submit_nonce_fault")
                fault.close()
            sc.stop()


class TestSubmitPersistenceFailure:
    """Issue #344 item 3 (sidecar part): persistence failures fail closed
    and corrupt neither the receipt ledger nor enforcement."""

    def test_nonce_store_write_failure_fails_the_submit_closed(self, tmp_path):
        sc = _sidecar(tmp_path)
        fault = None
        try:
            fault = _install_nonce_fault(sc)
            before = _chain_bytes(sc.store_dir)
            status, refused = _post(sc, "3" * 32, int(time.time()), _envelope_body())
            assert status == 503
            assert refused["error"] == "nonce_store_unavailable"
            # S5131: the refusal never echoes the request-supplied
            # envelope back; the body is the named error and detail only
            assert set(refused) == {"error", "detail"}
            time.sleep(0.2)
            # fail closed: nothing enqueued, nothing appended, no index row
            assert sc.sink._write_errors == 0
            assert sc.sink.depth == 0
            assert sc.sink.submitted == 0
            assert _chain_bytes(sc.store_dir) == before
            assert sc.index.count() == 0

            # a replay of the same nonce is refused the same way, so no
            # second identity confusion arises either
            status, refused_again = _post(sc, "3" * 32, int(time.time()), _envelope_body())
            assert status == 503
            assert refused_again["error"] == "nonce_store_unavailable"
            assert _chain_bytes(sc.store_dir) == before
        finally:
            if fault is not None:
                fault.execute("DROP TRIGGER submit_nonce_fault")
                fault.close()
            sc.stop()

    def test_recovery_after_nonce_store_failure_is_clean(self, tmp_path):
        sc = _sidecar(tmp_path)
        fault = None
        try:
            fault = _install_nonce_fault(sc)
            status, _ = _post(sc, "b" * 32, int(time.time()), _envelope_body())
            assert status == 503

            fault.execute("DROP TRIGGER submit_nonce_fault")
            fault.commit()
            # recovery: the next genuine submit is accepted exactly once
            status, accepted = _post(sc, "b" * 32, int(time.time()), _envelope_body())
            assert status == 202
            assert accepted["status"] == "queued"
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)
            assert sc.nonces.count() == 1
            assert _chain_hashes(sc.store_dir) == [HASH_A]
            # and the nonce that was refused during the fault is not
            # phantom-retained: consuming it now is a clean first accept
            status, accepted_now = _post(sc, "3" * 32, int(time.time()), _envelope_body(HASH_B))
            assert status == 202
            _wait_until(lambda: sc.store.total_receipt_count() == 2)
            assert _chain_hashes(sc.store_dir) == [HASH_A, HASH_B]
        finally:
            if fault is not None:
                fault.execute("DROP TRIGGER IF EXISTS submit_nonce_fault")
                fault.close()
            sc.stop()

    def test_corrupt_nonce_store_fails_the_sidecar_boot(self, tmp_path):
        store_dir = tmp_path / "segments"
        store_dir.mkdir(parents=True, exist_ok=True)
        (store_dir / "submit_nonces.sqlite").write_bytes(b"not a database at all")
        with pytest.raises(sqlite3.DatabaseError):
            sc = ReceiptSidecar(store_dir=store_dir, secret=SECRET, host="127.0.0.1", port=0)
            sc.start()
            sc.stop()  # pragma: no cover - only reached if the boot wrongly succeeds
        chunks = [seg.read_bytes() for seg in sorted(store_dir.glob("seg-*.jsonl"))]
        assert chunks == []  # no chain was ever opened by a failed boot

    def test_chain_append_failure_is_contained_and_the_ledger_stays_intact(
        self, tmp_path, monkeypatch
    ):
        sc = _sidecar(tmp_path)
        try:
            original_append = sc.store.append_line

            def failing_append(line):
                raise OSError("injected segment disk fault")

            monkeypatch.setattr(sc.store, "append_line", failing_append)
            client = SidecarClient(url=sc.url, secret=SECRET, timeout=5.0)
            # the submit is accepted (queued) before the writer faults
            client.submit({"receipt_hash": HASH_A, "jws": _jws_for({"x_gate": {}})})
            _wait_until(lambda: sc.sink._write_errors == 1)
            assert sc.sink.depth == 0

            # the ledger is untouched: no partial line, no index row
            assert _chain_bytes(sc.store_dir) == b""
            assert sc.index.count() == 0

            monkeypatch.undo()
            monkeypatch.setattr(sc.store, "append_line", original_append)
            client.submit({"receipt_hash": HASH_B, "jws": _jws_for({"x_gate": {"tool": "two"}})})
            _wait_until(lambda: sc.store.total_receipt_count() == 1 and sc.index.count() == 1)
            assert _chain_hashes(sc.store_dir) == [HASH_B]
        finally:
            sc.stop()

    def test_gateway_enforcement_stands_when_the_sidecar_fails_closed(self, tmp_path, caplog):
        sc = _sidecar(tmp_path)
        fault = None
        try:
            fault = _install_nonce_fault(sc)
            cfg = GatewayConfig(
                host="127.0.0.1",
                admin_api_key="k",
                signer_backend="local",
                policy_file="",
                receipt_store=str(tmp_path / "gw-legacy.jsonl"),
                audit_chain=str(tmp_path / "gw-audit.jsonl"),
                registry_path=str(tmp_path / "gw-registry.jsonl"),
                emit_receipts=True,
                receipt_sidecar_url=sc.url,
                receipt_sidecar_secret=SECRET,
                receipt_sidecar_timeout=5.0,
            )
            policy = tmp_path / "policies.yaml"
            policy.write_text(POLICY, encoding="utf-8")
            cfg.policy_file = str(policy)
            gw = RaucleGateway(cfg)
            from raucle.gateway_app import create_gateway_app

            client = TestClient(create_gateway_app(gw))
            resp = client.post(
                "/gate",
                json={
                    "tool": "lookup_balance",
                    "args": {"account": "ACC-001"},
                    "agent_id": "agent:svc",
                },
                headers={"X-Trace-Id": "t0"},
            )
            # enforcement already completed and returned to the caller:
            # the sidecar's fail-closed refusal never changes it
            assert resp.status_code == 200, resp.text
            decision = resp.json()
            assert decision.get("decision") == "allow"
            time.sleep(0.3)
            assert sc.store.total_receipt_count() == 0
            assert sc.index.count() == 0
            # the refusal is named on the gateway's receipt-loss path
            assert "nonce_store_unavailable" in caplog.text
            # no second acceptance by any route: the chain has no line
            assert _chain_hashes(sc.store_dir) == []
        finally:
            if fault is not None:
                fault.execute("DROP TRIGGER submit_nonce_fault")
                fault.close()
            sc.stop()
