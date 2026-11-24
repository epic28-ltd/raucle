"""RAU-05: ``_FileCache`` staleness - content-hash invalidation.

The cache keyed entries on ``(mtime_ns, size)``, and a same-size write
with a preserved mtime (restore-from-backup, or a careful attacker
rewriting a registry in place) served the stale set. Entries are now
stamped ``(sha256(content), len(content))`` over the bytes the cache
read, so the parse always corresponds to the stamp. These tests drive
the gateway's real revocation surface (`_load_revoked_ids`, the shared
``_FileCache`` consumer); the seal layer these bytes now feed lives in
tests/test_policy_seal.py.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from raucle.gateway import GatewayConfig, RaucleGateway


def _policy(tmp_path: Path) -> Path:
    path = tmp_path / "policies.yaml"
    path.write_text(
        """version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:bot
    ttl_seconds: 300
    constraints:
      allow:
        account: ["ACC-001"]
""",
        encoding="utf-8",
    )
    return path


def _config(tmp_path: Path, **kw) -> GatewayConfig:
    values: dict = dict(
        policy_file=str(_policy(tmp_path)),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_key_path=str(tmp_path / "signer.pem"),
        gate_auth="off",
        signer_backend="local",
    )
    values.update(kw)
    return GatewayConfig(**values)


def _rev_line(token_id: str, reason: str = "test") -> str:
    """One revocation record; same byte length for any equal-length id."""
    line = json.dumps({"token_id": token_id, "reason": reason})
    assert "\n" not in line
    return line + "\n"


def _write_atomic(path: Path, content: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _freeze_mtime(path: Path, stamp: tuple[int, int]) -> None:
    """Restore (atime, mtime) ns so the write leaves no stat trace."""
    os.utime(path, ns=stamp)


def _stat_ns(path: Path) -> tuple[int, int]:
    st = path.stat()
    return (st.st_atime_ns, st.st_mtime_ns)


class TestContentHashInvalidation:
    def test_same_size_same_mtime_altered_rewrites_reach_the_gate(self, tmp_path: Path):
        """The residual: content rewritten in place without touching size or
        mtime must still be served fresh."""
        revocations = tmp_path / "revocations.jsonl"
        old = _rev_line("cap:aaaaaaaaaaaa")
        new = _rev_line("cap:bbbbbbbbbbbb")
        assert len(old) == len(new), "test precondition: same-size contents"
        revocations.write_text(old, encoding="utf-8")
        gateway = RaucleGateway(_config(tmp_path, revocations_file=str(revocations)))
        assert gateway._load_revoked_ids() == {"cap:aaaaaaaaaaaa"}

        stamp = _stat_ns(revocations)
        _write_atomic(revocations, new)
        _freeze_mtime(revocations, stamp)

        assert gateway._load_revoked_ids() == {"cap:bbbbbbbbbbbb"}
        # and back again: the invalidation is content-driven both ways
        stamp = _stat_ns(revocations)
        _write_atomic(revocations, old)
        _freeze_mtime(revocations, stamp)
        assert gateway._load_revoked_ids() == {"cap:aaaaaaaaaaaa"}

    def test_identical_content_write_keeps_the_cached_parse(self, tmp_path: Path, monkeypatch):
        """A same-content rewrite refreshes correctly and cheaply: identical
        content is served from the cache without a second parse (the parse
        count pin, driven through the loader seam)."""
        revocations = tmp_path / "revocations.jsonl"
        revocations.write_text(_rev_line("cap:aaaaaaaaaaaa"), encoding="utf-8")
        gateway = RaucleGateway(_config(tmp_path, revocations_file=str(revocations)))
        assert gateway._load_revoked_ids() == {"cap:aaaaaaaaaaaa"}

        parses = {"n": 0}
        original = gateway._revoked_ids_from_bytes

        def counting(data: bytes) -> set[str]:
            parses["n"] += 1
            return original(data)

        monkeypatch.setattr(gateway, "_revoked_ids_from_bytes", counting)

        revocations.write_text(_rev_line("cap:aaaaaaaaaaaa"), encoding="utf-8")
        # same bytes again: the stamp matches, so no reparse - the value
        # served is the previously parsed set
        assert gateway._load_revoked_ids() == {"cap:aaaaaaaaaaaa"}
        assert gateway._load_revoked_ids() == {"cap:aaaaaaaaaaaa"}
        assert parses["n"] == 0

    def test_read_failure_raises_into_the_deny_path(self, tmp_path: Path):
        """The stat-failure rule, preserved: a file that cannot be READ
        (here: a directory) raises out of the cache instead of serving
        any stale or empty set."""
        revocations = tmp_path / "revocations.jsonl"
        revocations.mkdir(exist_ok=True)
        gateway = RaucleGateway(_config(tmp_path, revocations_file=str(revocations)))
        with pytest.raises(OSError):
            gateway._load_revoked_ids()

    def test_concurrent_swaps_never_serve_a_torn_mix(self, tmp_path: Path):
        """Concurrent reload discipline: appends/swaps racing readers never
        produce a value parsed across two different reads. Writers swap
        atomically between two same-size contents with frozen mtimes, so
        every read sees one full snapshot; the cache must serve a value
        that corresponds to exactly one of them."""
        revocations = tmp_path / "revocations.jsonl"
        content_a = _rev_line("cap:aaaaaaaaaaaa")
        content_b = _rev_line("cap:bbbbbbbbbbbb")
        revocations.write_text(content_a, encoding="utf-8")
        gateway = RaucleGateway(_config(tmp_path, revocations_file=str(revocations)))
        assert gateway._load_revoked_ids() == {"cap:aaaaaaaaaaaa"}

        stop = threading.Event()
        start = threading.Barrier(3)
        observed: list[set[str]] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def writer() -> None:
            start.wait()
            try:
                for i in range(200):
                    content = content_b if i % 2 == 0 else content_a
                    stamp = _stat_ns(revocations)
                    _write_atomic(revocations, content)
                    _freeze_mtime(revocations, stamp)
            except Exception as exc:  # pragma: no cover - reported below
                with lock:
                    errors.append(exc)
            finally:
                stop.set()

        def reader() -> None:
            start.wait()
            try:
                while not stop.is_set():
                    value = gateway._load_revoked_ids()
                    with lock:
                        observed.append(value)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert errors == []
        assert observed, "the readers must have served at least one value"
        for value in observed:
            assert value in (
                {"cap:aaaaaaaaaaaa"},
                {"cap:bbbbbbbbbbbb"},
            ), f"a torn mix reached the gate: {value!r}"
        # the swap actually raced: both snapshots were observed
        assert {"cap:bbbbbbbbbbbb"} in observed and {"cap:aaaaaaaaaaaa"} in observed
