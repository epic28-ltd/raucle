"""Segmented receipt store crash-rollback and recovery (issue 344, item 2).

Regression slice proving the crash-consistency behaviour the earlier
receipt-store tests do not cover (``tests/test_receipt_store.py`` owns the
clean seal/resume contract; PR #361 owns the legacy flat-writer failure
propagation). The windows proven here:

- crash between an append and its rollover (kill after a write crossed the
  rollover threshold, before the seal ran),
- crash inside the seal, between the ``.meta`` sidecar write and the
  read-only flip (the half-sealed segment: recovery must never silently
  append into a segment whose seal sidecar already exists),
- crash after the read-only flip but before the next segment opens,
- a failed append (write/flush/fsync) followed by the next append on the
  SAME store object: an intact tail resumes cleanly, a torn tail is
  refused by name instead of silently chained past,
- sealed-segment receipts verify (or refuse by name) after recovery:
  record tamper and record truncation are caught on verify.

Fail-closed fixes these tests pin (all in ``raucle.receipt_store``):

1. ``_open_existing_segment`` refuses to resume any segment that already
   carries a ``.meta`` seal sidecar while it is still writable,
2. ``append_line`` drops the open handle after a failed write/flush/fsync
   so the next append re-validates the tail,
3. ``_seal_active`` fsyncs the meta before the read-only flip.
"""

import json
import os

import pytest

from raucle.errors import ReceiptStoreSealRefused
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.provenance import ProvenanceVerifier
from raucle.receipt_store import SegmentedReceiptStore, verify_seal_meta

POLICY = """
version: 1
issuer: crashrecovery.test
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""


def _line(i: int) -> str:
    return json.dumps({"receipt_hash": f"sha256:{i:064x}", "jws": f"h{i}.p{i}.s{i}"})


def _store(tmp_path, max_bytes: int = 1 << 20) -> SegmentedReceiptStore:
    return SegmentedReceiptStore(base_dir=tmp_path / "receipts", max_segment_bytes=max_bytes)


def _segment_paths(tmp_path):
    base = tmp_path / "receipts"
    return sorted(p.name for p in base.glob("seg-*.jsonl"))


class TestCrashBeforeRollover:
    """Kill after a write crossed the rollover threshold, before the seal."""

    def test_crossed_threshold_segment_seals_through_itself_on_restart(self, tmp_path, monkeypatch):
        store = _store(tmp_path, 300)
        store.append_line(_line(1))
        store.append_line(_line(2))

        # The crash: the seal that the threshold-crossing append would have
        # run never happens (the process dies first).
        def _kill():
            raise OSError("simulated crash before rollover")

        monkeypatch.setattr(store, "_seal_active", _kill)
        with pytest.raises(OSError, match="simulated crash before rollover"):
            store.append_line(_line(3))

        # After the kill: one writable segment, over its threshold, no meta.
        seg = tmp_path / "receipts" / "seg-000000.jsonl"
        assert os.access(seg, os.W_OK)
        assert not seg.with_name(seg.name + ".meta").exists()

        # Recovery: the restart resumes the over-threshold segment; the
        # NEXT append seals through it (never a new segment, never an
        # orphan) and carries rollover numbering on contiguously.
        restart = SegmentedReceiptStore(base_dir=tmp_path / "receipts", max_segment_bytes=300)
        restart.append_line(_line(4))
        assert _segment_paths(tmp_path) == ["seg-000000.jsonl", "seg-000001.jsonl"]
        meta = json.loads((tmp_path / "receipts" / "seg-000000.jsonl.meta").read_text())
        on_disk = [line for line in seg.read_text().splitlines() if line.strip()]
        # The resumed append seals THROUGH the over-threshold segment (the
        # killed append's line is in it, and the restart's append lands
        # there too before the seal runs), then numbering continues.
        assert meta["receipt_count"] == len(on_disk) == 4
        assert meta["last_receipt_hash"] == f"sha256:{4:064x}"
        import stat as _stat

        mode = seg.stat().st_mode
        assert not (mode & (_stat.S_IWUSR | _stat.S_IWGRP | _stat.S_IWOTH))
        assert restart.active_segment == "seg-000001.jsonl"
        assert _line(4) in (tmp_path / "receipts" / "seg-000000.jsonl").read_text()
        assert restart.total_receipt_count() == 4


class TestCrashInsideSeal:
    """Kill between the .meta sidecar write and the read-only flip.

    The crashed state is a half-sealed segment: a seal sidecar exists but
    the segment is still writable. Recovery must fail closed by name, not
    silently grow the sealed segment past its recorded seal.
    """

    def test_half_sealed_segment_refuses_append_after_restart(self, tmp_path, monkeypatch):
        store = _store(tmp_path)
        store.append_line(_line(1))
        store.append_line(_line(2))
        meta_path = tmp_path / "receipts" / "seg-000000.jsonl.meta"
        seg_path = tmp_path / "receipts" / "seg-000000.jsonl"

        real_chmod = os.chmod

        def _bomb_chmod(*args, **kwargs):
            raise OSError("simulated kill between meta write and chmod")

        monkeypatch.setattr(os, "chmod", _bomb_chmod)
        with pytest.raises(OSError, match="simulated kill"):
            store.seal_now()
        monkeypatch.setattr(os, "chmod", real_chmod)

        assert meta_path.exists()
        assert os.access(seg_path, os.W_OK)
        frozen = seg_path.read_text()
        frozen_meta = meta_path.read_text()

        restart = SegmentedReceiptStore(base_dir=tmp_path / "receipts")
        with pytest.raises(ReceiptStoreSealRefused) as excinfo:
            restart.append_line(_line(3))
        message = str(excinfo.value)
        assert "seg-000000.jsonl" in message
        assert "sidecar" in message
        # The refusal is fail-closed AND un-poisoned: the segment keeps its
        # crashed bytes exactly, the sidecar is untouched, and the refusal
        # repeats on the next attempt.
        assert seg_path.read_text() == frozen
        assert meta_path.read_text() == frozen_meta
        assert json.loads(frozen_meta)["receipt_count"] == 2
        with pytest.raises(ReceiptStoreSealRefused):
            restart.append_line(_line(4))
        # No new segment was silently started for the refused receipt.
        assert len(_segment_paths(tmp_path)) == 1

    def test_half_sealed_segment_refuses_seal_now_after_restart(self, tmp_path, monkeypatch):
        store = _store(tmp_path)
        store.append_line(_line(1))
        store.append_line(_line(2))
        meta_path = tmp_path / "receipts" / "seg-000000.jsonl.meta"

        def _bomb_chmod(*args, **kwargs):
            raise OSError("simulated kill between meta write and chmod")

        monkeypatch.setattr(os, "chmod", _bomb_chmod)
        with pytest.raises(OSError):
            store.seal_now()

        frozen_meta = meta_path.read_text()
        restart = SegmentedReceiptStore(base_dir=tmp_path / "receipts")
        # An operator re-running the seal on the crashed state gets the same
        # named refusal; the stale sidecar of the incomplete seal is never
        # silently overwritten with fresh seal metadata.
        with pytest.raises(ReceiptStoreSealRefused):
            restart.seal_now()
        assert meta_path.read_text() == frozen_meta

    def test_operator_resolve_sidecar_then_restart_appends_normally(self, tmp_path, monkeypatch):
        """The resolution the refusal names: discarding the sidecar of the
        incomplete seal returns the segment to plain writable resume."""
        store = _store(tmp_path)
        store.append_line(_line(1))
        store.append_line(_line(2))

        def _bomb_chmod(*args, **kwargs):
            raise OSError("simulated kill between meta write and chmod")

        monkeypatch.setattr(os, "chmod", _bomb_chmod)
        with pytest.raises(OSError):
            store.seal_now()

        # Operator decision: the seal sidecar belongs to a seal that never
        # completed, so it is discarded (never rewritten by the store).
        (tmp_path / "receipts" / "seg-000000.jsonl.meta").unlink()
        restart = SegmentedReceiptStore(base_dir=tmp_path / "receipts")
        restart.append_line(_line(3))
        assert restart.active_segment == "seg-000000.jsonl"
        seg = (tmp_path / "receipts" / "seg-000000.jsonl").read_text()
        assert _line(1) in seg and _line(3) in seg


class TestCrashAfterSealFlip:
    """Kill after the read-only flip but before the next segment opens."""

    def test_restart_after_completed_flip_starts_the_next_segment(self, tmp_path, monkeypatch):
        from raucle.audit import Ed25519Signer

        signer = Ed25519Signer.generate()
        store = SegmentedReceiptStore(
            base_dir=tmp_path / "receipts", max_segment_bytes=1 << 20, seal_signer=signer
        )
        store.append_line(_line(1))
        store.append_line(_line(2))

        def _kill_next_open(_index):
            raise OSError("simulated crash after the read-only flip")

        monkeypatch.setattr(store, "_start_segment", _kill_next_open)
        with pytest.raises(OSError, match="simulated crash"):
            store.seal_now()
        seg_path = tmp_path / "receipts" / "seg-000000.jsonl"
        assert not os.access(seg_path, os.W_OK)

        # Recovery: the sealed segment is left exactly as it was; the first
        # append opens the NEXT numbered segment (contiguous, no rewrite of
        # the sealed one), and the sidecar signature still verifies.
        restart = SegmentedReceiptStore(base_dir=tmp_path / "receipts")
        restart.append_line(_line(3))
        assert _segment_paths(tmp_path) == ["seg-000000.jsonl", "seg-000001.jsonl"]
        seg_path = tmp_path / "receipts" / "seg-000000.jsonl"
        meta = json.loads(seg_path.with_suffix(".jsonl.meta").read_text())
        on_disk = [line for line in seg_path.read_text().splitlines() if line.strip()]
        assert meta["receipt_count"] == len(on_disk) == 2
        verdict = verify_seal_meta(meta, signer.public_key_pem())
        assert verdict.verified is True
        assert _line(1) in seg_path.read_text()
        assert _line(3) in (tmp_path / "receipts" / "seg-000001.jsonl").read_text()


class TestFailedAppendRevalidatesTail:
    """A failed append drops the open handle so the next append re-validates
    the tail on the SAME store object (crash semantics without a restart)."""

    def test_failed_fsync_then_next_append_resumes_intact_tail(self, tmp_path, monkeypatch):
        store = _store(tmp_path)
        seg_path = tmp_path / "receipts" / "seg-000000.jsonl"

        real_fsync = os.fsync
        calls = {"n": 0}

        def _one_shot_enospc(fd, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("simulated ENOSPC")
            return real_fsync(fd, *args, **kwargs)

        monkeypatch.setattr(os, "fsync", _one_shot_enospc)
        # The FIRST append fails at fsync: the write itself landed (intact
        # line), the caller saw the failure.
        with pytest.raises(OSError, match="simulated ENOSPC"):
            store.append_line(_line(1))
        # The NEXT append re-opens the segment through the tail validation
        # instead of silently writing past whatever the failed write left.
        store.append_line(_line(2))
        assert store.active_segment == "seg-000000.jsonl"
        content = seg_path.read_text()
        assert _line(1) in content
        assert _line(2) in content
        assert store.total_receipt_count() == 2

    def test_partial_write_then_next_append_refuses_torn_tail_by_name(self, tmp_path):
        store = _store(tmp_path)
        seg_path = tmp_path / "receipts" / "seg-000000.jsonl"
        store.append_line(_line(1))

        class _MidRecordFailHandle:
            """Delegating wrapper: the FIRST write lands partial bytes then
            raises - the shape a real mid-record ENOSPC leaves behind."""

            def __init__(self, inner) -> None:
                self._inner = inner
                self._failed = False

            def write(self, data):
                if not self._failed:
                    self._inner.write(data[:8])
                    self._failed = True
                    raise OSError("simulated mid-record write failure")
                return self._inner.write(data)

            def flush(self):
                return self._inner.flush()

            def fileno(self):
                return self._inner.fileno()

        store._active_file = _MidRecordFailHandle(store._active_file)
        with pytest.raises(OSError, match="simulated mid-record write failure"):
            store.append_line(_line(2))

        # The crashed write left a torn record; the next append must refuse
        # by name (never chain a third record past the torn second one).
        with pytest.raises(ReceiptStoreSealRefused) as excinfo:
            store.append_line(_line(3))
        assert "physical line 2" in str(excinfo.value)
        assert _line(3) not in seg_path.read_text()
        content = seg_path.read_text()
        # line 1 fully intact; line 2 torn partial with NO trailing newline
        assert content.count("\n") == 1
        # And the refusal survives re-opening: the segment is sealed-ready
        # only after the operator resolves the torn line.
        with pytest.raises(ReceiptStoreSealRefused):
            store.append_line(_line(4))


def _seg_gateway(tmp_path):
    """A local-signature gateway writing receipts through the segmented
    store (receipt_store_dir), no auth, emit_receipts on."""
    (tmp_path / "policies.yaml").write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(tmp_path / "policies.yaml"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
        gate_auth="off",
        receipt_store_dir=str(tmp_path / "segments"),
    )
    gw = RaucleGateway(config)
    # Small threshold so a handful of gate calls produce sealed segments.
    gw._receipt_store._max_bytes = 400
    return gw


def _verifier(gw):
    return ProvenanceVerifier(
        public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
    )


class TestSealedSegmentVerifyAfterRecovery:
    """Gateway receipts sealed into segments still verify after recovery;
    record tamper and record truncation are caught on verify."""

    def _store_with_sealed_segments(self, tmp_path, calls: int = 3):
        gw = _seg_gateway(tmp_path)
        decisions = [
            gw.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
            for _ in range(calls)
        ]
        assert all(d["decision"] == "allow" for d in decisions)
        segdir = tmp_path / "segments"
        segs = sorted(p for p in segdir.glob("seg-*.jsonl"))
        sealed = segs[:-1] if os.access(segs[-1], os.W_OK) else segs
        assert sealed, "no seal ran in the gateway store"
        return gw, segdir, sealed

    def test_sealed_segment_meta_and_receipts_verify_after_recovery(self, tmp_path):
        gw, segdir, sealed = self._store_with_sealed_segments(tmp_path)
        # Recovery: a fresh store over the same directory resumes the
        # writable tail; the sealed segments and their sidecars stay exact.
        restart = SegmentedReceiptStore(base_dir=segdir)
        assert restart.active_segment is not None
        for seg_path in sealed:
            meta = json.loads((segdir / (seg_path.name + ".meta")).read_text())
            report = _verifier(gw).verify_chain(seg_path)
            assert report.valid, report.errors
            on_disk = [line for line in seg_path.read_text().splitlines() if line.strip()]
            assert meta["receipt_count"] == len(on_disk) == report.receipt_count
            # The gateway's own seal signature survives recovery.
            gate_meta = json.loads((segdir / (seg_path.name + ".meta")).read_text())
            verdict = verify_seal_meta(gate_meta, gw.gate_identity.public_key_pem())
            assert verdict.verified is True, verdict.reason

    def test_tampered_record_in_sealed_segment_caught_on_verify(self, tmp_path):
        gw, segdir, sealed = self._store_with_sealed_segments(tmp_path)
        seg_path = sealed[0]
        tampered_copy = tmp_path / "tampered.jsonl"
        with (
            open(seg_path, encoding="utf-8") as src,
            open(tampered_copy, "w", encoding="utf-8") as dst,
        ):
            for line in src:
                rec = json.loads(line)
                rec["jws"] = rec["jws"][:-1] + ("A" if rec["jws"][-1] != "A" else "B")
                dst.write(json.dumps(rec) + "\n")
        report = _verifier(gw).verify_chain(tampered_copy)
        assert report.valid is False
        assert report.errors
        # The seal sidecar still matches the UNtouched original: the meta
        # records the seal-time truth, and the tampered copy is caught by
        # record-level verification, not silently re-sealed.
        meta = json.loads((segdir / (seg_path.name + ".meta")).read_text())
        assert verify_seal_meta(meta, gw.gate_identity.public_key_pem()).verified is True

    def test_truncated_record_in_sealed_segment_caught_on_verify(self, tmp_path):
        gw, segdir, sealed = self._store_with_sealed_segments(tmp_path)
        seg_path = sealed[0]
        data = seg_path.read_text()
        truncated_copy = tmp_path / "truncated.jsonl"
        truncated_copy.write_text(data[: len(data) - 40], encoding="utf-8")
        report = _verifier(gw).verify_chain(truncated_copy)
        assert report.valid is False
        assert report.errors


class TestTelemetryFailureVsReceiptPersistence:
    """The two failure classes stay separate on the segmented path:

    telemetry (SIEM) export failure never blocks a decision nor voids the
    receipt it accompanied; an authoritative segmented-store write failure
    downgrades the decision visibly, exactly as PR #361 pinned for the
    legacy flat writer.
    """

    def test_siem_outage_keeps_allow_and_receipts_verifiable(self, tmp_path, monkeypatch):
        gw = _seg_gateway(tmp_path)
        gw.siem.enabled = True
        gw.siem.backend = "splunk"
        gw.siem.url = ""  # empty target keeps the destination tripwire out
        from raucle.gateway import SIEMForwarder

        def _outage(self, event):
            raise ConnectionError("simulated SIEM outage")

        monkeypatch.setattr(SIEMForwarder, "_forward_splunk", _outage)

        decision = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc"
        )
        # enforcement is untouched ...
        assert decision["decision"] == "allow"
        assert decision["receipt_id"]
        # ... the outage is buffered by name for retry ...
        buffered = gw.siem.buffered_events()
        assert len(buffered) == 1
        assert buffered[0]["event"] == "gate_decision"
        # ... and the receipt the decision produced is valid evidence: it
        # verifies offline, it is not voided and not withheld.
        segdir = tmp_path / "segments"
        seg = sorted(segdir.glob("seg-*.jsonl"))[0]
        report = _verifier(gw).verify_chain(seg)
        assert report.valid, report.errors
        assert report.receipt_count >= 1

    def test_segmented_write_failure_downgrades_allow_to_deny_visibly(self, tmp_path):
        gw = _seg_gateway(tmp_path)

        class _BrokenStore:
            def append_line(self, line):
                raise OSError("simulated receipt disk failure")

        gw._receipt_store = _BrokenStore()
        decision = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc"
        )
        # Fail-closed: a policy-allowed call whose receipt cannot be written
        # returns the visible downgrade, never a clean allow.
        assert decision["decision"] == "deny"
        assert decision["reason"] == "receipt emission failed"
        # No receipt id is handed out for a receipt that was never written.
        assert decision["receipt_id"] is None

    def test_segmented_write_failure_propagates_from_sign_and_store(self, tmp_path):
        gw = _seg_gateway(tmp_path)

        class _BrokenStore:
            def append_line(self, line):
                raise OSError("simulated receipt disk failure")

        gw._receipt_store = _BrokenStore()
        payload = {
            "iss": "raucle-gateway",
            "typ": "provenance-receipt/v1",
            "iat": 1,
            "agent_id": "agent:gate",
            "agent_key_id": gw.gate_identity.key_id,
            "operation": "guardrail_scan",
            "parents": [],
            "taint": ["gate:observed"],
            "input_hash": "a" * 64,
            "ruleset_hash": "b" * 64,
            "guardrail_verdict": "deny",
        }
        with pytest.raises(OSError, match="simulated receipt disk failure"):
            gw._sign_and_store_receipt(payload)
