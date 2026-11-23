"""X3 slice 4: the single-writer receipt sidecar.

The decided scale answer (docs/spec/x3-sidecar-v0.1.md): several gateway
replicas can serve traffic while ONE process owns the append path, so the
SQLite WAL file never has two writers. The mint stays in the gateway; the
append plus index write go through the sidecar over local HTTP with a
shared-secret handshake.

Pinned red-first:

- two gateway processes submitting concurrently produce a strictly
  ordered, intact chain (no interleaving corruption),
- overflow is a named refusal and the loss is receipted advisory
  (x_sidecar), never a silent drop, and never an enforcement change,
- a sidecar restart resumes (J2 recovery path unchanged, index rebuilt
  from the chain when it is behind),
- chains verify through the standard offline verifier exactly as
  single-writer ones do, byte-identically.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.provenance import ProvenanceVerifier
from raucle.sidecar import ReceiptSidecar, SidecarClient, SidecarRefused

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


def _gateway(tmp_path, url, *, secret=SECRET, name="gw"):
    """A real gateway in sidecar mode (no local write projection)."""
    cfg = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / f"{name}-legacy.jsonl"),
        audit_chain=str(tmp_path / f"{name}-audit.jsonl"),
        registry_path=str(tmp_path / f"{name}-registry.jsonl"),
        emit_receipts=True,
        receipt_sidecar_url=url,
        receipt_sidecar_secret=secret,
        receipt_sidecar_timeout=5.0,
    )
    policy = tmp_path / f"{name}-policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    cfg.policy_file = str(policy)
    return RaucleGateway(cfg)


def _gate(client, i=0):
    resp = client.post(
        "/gate",
        json={
            "tool": "lookup_balance",
            "args": {"account": "ACC-001"},
            "agent_id": "agent:svc",
        },
        headers={"X-Trace-Id": f"t{i}"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _chain_lines(store_dir):
    lines = []
    for seg in sorted(Path(store_dir).glob("seg-*.jsonl")):
        with open(seg, encoding="utf-8") as fh:
            for raw in fh:
                if raw.strip():
                    lines.append(raw.rstrip("\n"))
    return lines


def _verify(gateways, store_dir):
    """Every segment verifies with the standard offline verifier."""
    for gw in gateways:
        verifier = ProvenanceVerifier(
            public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
        )
        for seg in sorted(Path(store_dir).glob("seg-*.jsonl")):
            report = verifier.verify_chain(seg)
            assert report.valid, (seg, report.errors)


class TestHandshakeAndValidation:
    def test_wrong_secret_is_a_named_refusal_and_appends_nothing(self, tmp_path):
        sc = _sidecar(tmp_path)
        try:
            client = SidecarClient(url=sc.url, secret="not-the-secret", timeout=5.0)
            envelope = {"receipt_hash": "sha256:" + "a" * 64, "jws": "x.y.z"}
            with pytest.raises(SidecarRefused) as exc:
                client.submit(envelope)
            assert "unauthorized" in exc.value.reason
            assert sc.store.total_receipt_count() == 0
        finally:
            sc.stop()

    def test_malformed_envelope_is_a_named_refusal(self, tmp_path):
        sc = _sidecar(tmp_path)
        try:
            client = SidecarClient(url=sc.url, secret=SECRET, timeout=5.0)
            for bad in (
                {"receipt_hash": "nope", "jws": "x.y.z"},
                {"receipt_hash": "sha256:" + "a" * 64},
                {"receipt_hash": "sha256:" + "a" * 64, "jws": "", "extra": 1},
            ):
                with pytest.raises(SidecarRefused) as exc:
                    client.submit(bad)
                assert "invalid_envelope" in exc.value.reason
            assert sc.store.total_receipt_count() == 0
        finally:
            sc.stop()

    def test_empty_secret_refuses_to_start(self, tmp_path):
        with pytest.raises(ValueError, match="RAUCLE_RECEIPT_SIDECAR_SECRET"):
            ReceiptSidecar(store_dir=tmp_path / "segments", secret="")

    def test_health_reports_counts(self, tmp_path):
        import urllib.request

        sc = _sidecar(tmp_path)
        try:
            gw_local = _gateway(tmp_path, "", name="gw-local")
            c_local = TestClient(_app(gw_local))
            _gate(c_local)
            envelope = json.loads(
                Path(gw_local.config.receipt_store).read_text(encoding="utf-8").splitlines()[-1]
            )
            client = SidecarClient(url=sc.url, secret=SECRET, timeout=5.0)
            client.submit(envelope)
            _wait_until(lambda: sc.index.count() == 1)
            with urllib.request.urlopen(f"{sc.url}/health", timeout=5.0) as resp:
                body = json.loads(resp.read())
            assert body["status"] == "ok"
            assert body["chain_receipts"] == 1
            assert body["index_receipts"] == 1
        finally:
            sc.stop()


class TestSingleWriterOrdering:
    def test_two_gateways_concurrently_strict_order_no_corruption(self, tmp_path):
        sc = _sidecar(tmp_path)
        try:
            gw1 = _gateway(tmp_path, sc.url, name="gw1")
            gw2 = _gateway(tmp_path, sc.url, name="gw2")
            c1 = TestClient(_app(gw1))
            c2 = TestClient(_app(gw2))
            per_gateway = 25

            def run(client):
                for i in range(per_gateway):
                    _gate(client, i)

            t1 = threading.Thread(target=run, args=(c1,))
            t2 = threading.Thread(target=run, args=(c2,))
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            _wait_until(lambda: sc.store.total_receipt_count() == 2 * per_gateway)
            _wait_until(lambda: sc.index.count() == 2 * per_gateway)

            # strictly ordered, intact chain: every line parses, every
            # receipt appears exactly once at one position, no torn lines
            lines = _chain_lines(sc.store_dir)
            assert len(lines) == 2 * per_gateway
            hashes = []
            for line in lines:
                rec = json.loads(line)
                assert set(rec) == {"receipt_hash", "jws"}
                hashes.append(rec["receipt_hash"])
            assert len(set(hashes)) == len(hashes), "duplicate or torn line"
            assert sc.index.count() == 2 * per_gateway
            _verify((gw1, gw2), sc.store_dir)
        finally:
            sc.stop()

    def test_byte_compatibility_with_the_single_writer_path(self, tmp_path):
        """The same envelope through the sidecar and through the
        gateway's local path lands as identical bytes on disk."""
        sc = _sidecar(tmp_path)
        try:
            gw_local = _gateway(tmp_path, "", name="gw-local")
            assert gw_local._sidecar_client is None
            c_local = TestClient(_app(gw_local))
            _gate(c_local)
            local_lines = (
                Path(gw_local.config.receipt_store).read_text(encoding="utf-8").splitlines()
            )
            assert local_lines
            envelope = json.loads(local_lines[-1])

            client = SidecarClient(url=sc.url, secret=SECRET, timeout=5.0)
            client.submit(envelope)
            _wait_until(lambda: sc.store.total_receipt_count() == 1)
            assert _chain_lines(sc.store_dir)[-1] == local_lines[-1]
        finally:
            sc.stop()


class TestOverflowContract:
    def test_named_refusal_and_receipted_advisory(self, tmp_path, monkeypatch):
        sc = _sidecar(tmp_path, max_queue=2)
        try:
            # a real envelope to fill the queue with
            gw_local = _gateway(tmp_path, "", name="gw-local")
            c_local = TestClient(_app(gw_local))
            _gate(c_local)
            fill = json.loads(
                Path(gw_local.config.receipt_store).read_text(encoding="utf-8").splitlines()[-1]
            )

            blocker = threading.Event()
            original_append = sc.store.append_line

            def blocked_append(line):
                blocker.wait(30.0)
                original_append(line)

            monkeypatch.setattr(sc.store, "append_line", blocked_append)

            client = SidecarClient(url=sc.url, secret=SECRET, timeout=5.0)
            # fill the bounded queue (the writer holds one more in
            # flight, so loop until the named refusal arrives)
            filled = 0
            for _ in range(10):
                try:
                    client.submit(fill)
                    filled += 1
                except SidecarRefused:
                    break
            else:
                raise AssertionError("the bounded queue never overflowed")
            with pytest.raises(SidecarRefused) as exc:
                client.submit(fill)
            assert exc.value.reason == "receipt_sink_overflow"
            assert any(
                event.get("event") == "receipt_sink_overflow" for event in sc.sink.overflow_events
            )

            # the gateway's receipt is refused by name; the advisory is
            # minted, also refused while the queue is full, and rides the
            # next successful submit from the pending list
            gw = _gateway(tmp_path, sc.url, name="gw")
            client_gw = TestClient(_app(gw))
            refused = _gate(client_gw)
            blocker.set()
            # let the writer drain the blocked fills before the next
            # submit, so the second gate call is deterministic
            _wait_until(lambda: sc.store.total_receipt_count() == filled)
            second = _gate(client_gw)
            expected = filled + 2  # fills + advisory + second gate receipt
            _wait_until(lambda: sc.store.total_receipt_count() == expected)

            lines = _chain_lines(sc.store_dir)
            chain_hashes = [json.loads(line)["receipt_hash"] for line in lines]
            assert refused["receipt_id"] not in chain_hashes, "refused receipt must be absent"
            assert second["receipt_id"] in chain_hashes

            advisories = []
            for line in lines:
                payload = json.loads(_b64url_json(json.loads(line)["jws"]))
                if "x_sidecar" in payload:
                    advisories.append(payload["x_sidecar"])
            assert len(advisories) == 1
            advisory = advisories[0]
            assert advisory["action"] == "refused"
            assert advisory["refused_receipt"] == refused["receipt_id"]
            assert advisory["reason"] == "receipt_sink_overflow"
            assert gw._pending_sidecar_advisories.maxlen == 128
            assert len(gw._pending_sidecar_advisories) == 0

            # the chain (fills + advisory + second gate receipt) verifies
            _verify((gw_local, gw), sc.store_dir)
        finally:
            sc.stop()


class TestRestartResume:
    def test_restart_resumes_and_rebuilds_behind_index(self, tmp_path):
        store_dir = tmp_path / "segments"
        sc = _sidecar(tmp_path)
        gw = _gateway(tmp_path, sc.url, name="gw")
        try:
            c = TestClient(_app(gw))
            for i in range(4):
                _gate(c, i)
            _wait_until(lambda: sc.store.total_receipt_count() == 4)
            _wait_until(lambda: sc.index.count() == 4)
        finally:
            sc.stop()

        # a crash gap: a real receipt reaches the chain but not the index
        gw_local = _gateway(tmp_path, "", name="gw-local")
        c_local = TestClient(_app(gw_local))
        _gate(c_local)
        gap_line = Path(gw_local.config.receipt_store).read_text(encoding="utf-8").splitlines()[-1]
        active = sorted(store_dir.glob("seg-*.jsonl"))[-1]
        with open(active, "a", encoding="utf-8") as fh:
            fh.write(gap_line + "\n")

        sc2 = ReceiptSidecar(store_dir=store_dir, secret=SECRET, host="127.0.0.1", port=0)
        sc2.start()
        try:
            # J2 recovery ran in the index constructor; the behind index was
            # rebuilt from the chain of record on boot
            assert sc2.index.count() == 5
            assert sc2.store.total_receipt_count() == 5

            gw2 = _gateway(tmp_path, sc2.url, name="gw2")
            c2 = TestClient(_app(gw2))
            for i in range(4):
                _gate(c2, i)
            _wait_until(lambda: sc2.store.total_receipt_count() == 9)
            _wait_until(lambda: sc2.index.count() == 9)

            lines = _chain_lines(store_dir)
            assert len(lines) == 9
            hashes = [json.loads(line)["receipt_hash"] for line in lines]
            assert len(set(hashes)) == 9
            _verify((gw, gw_local, gw2), store_dir)
        finally:
            sc2.stop()


class TestMisconfigurationGuard:
    def test_two_writer_boot_is_refused_by_name(self, tmp_path):
        cfg = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "flat.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
            receipt_store_dir=str(tmp_path / "segments"),
            receipt_sidecar_url="http://127.0.0.1:1/",
            receipt_sidecar_secret=SECRET,
        )
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY, encoding="utf-8")
        cfg.policy_file = str(policy)
        with pytest.raises(ValueError, match="single-writer guard"):
            RaucleGateway(cfg)

    def test_env_round_trip(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_RECEIPT_SIDECAR_URL", "http://sidecar:8092")
        monkeypatch.setenv("RAUCLE_RECEIPT_SIDECAR_SECRET", "s3cret")
        monkeypatch.setenv("RAUCLE_RECEIPT_SIDECAR_TIMEOUT", "3.5")
        cfg = GatewayConfig.from_env()
        assert cfg.receipt_sidecar_url == "http://sidecar:8092"
        assert cfg.receipt_sidecar_secret == "s3cret"
        assert cfg.receipt_sidecar_timeout == 3.5

    def test_sidecar_queue_env_round_trip(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE", "17")
        from raucle.sidecar import _sidecar_max_queue_from_env

        assert _sidecar_max_queue_from_env() == 17


def _b64url_json(jws):
    import base64

    payload = jws.split(".")[1]
    return base64.urlsafe_b64decode(payload + "=" * ((4 - len(payload) % 4) % 4))


def _app(gateway):
    from raucle.gateway_app import create_gateway_app

    return create_gateway_app(gateway)


class TestCoverageCompletions:
    """The gate counts these branches: fail-closed CLI boot, the serve
    loop shutdown, transport names, env guards, HTTP 404s, lifecycle
    idempotency, and the advisory pending-list edges."""

    def test_cli_refuses_without_secret(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RAUCLE_RECEIPT_SIDECAR_SECRET", raising=False)
        from raucle.cli import main

        assert main(["sidecar", "--store-dir", str(tmp_path / "s")]) == 1

    def test_cli_serves_until_interrupted_then_drains(self, tmp_path, monkeypatch):
        import time as time_mod

        import raucle.sidecar as sidecar_mod

        monkeypatch.setenv("RAUCLE_RECEIPT_SIDECAR_SECRET", SECRET)
        seen: dict[str, bool] = {}

        class FakeSidecar:
            def __init__(self, **_kwargs) -> None:
                seen["initialised"] = True

            def start(self) -> None:
                seen["serving"] = True

            def stop(self) -> dict[str, int]:
                seen["stopped"] = True
                return {"written": 3, "lost": 0}

            url = "http://127.0.0.1:1"

        monkeypatch.setattr(sidecar_mod, "ReceiptSidecar", FakeSidecar)

        def _interrupt(_seconds: float) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(time_mod, "sleep", _interrupt)
        from raucle.cli import main

        assert main(["sidecar", "--store-dir", str(tmp_path / "s")]) == 0
        assert seen == {"initialised": True, "serving": True, "stopped": True}

    def test_unreachable_sidecar_is_a_named_transport_error(self):
        from raucle.sidecar import SidecarUnreachable

        client = SidecarClient(url="http://127.0.0.1:1", secret=SECRET, timeout=0.5)
        with pytest.raises(SidecarUnreachable) as exc:
            client.submit({"receipt_hash": "sha256:" + "c" * 64, "jws": "x.y.z"})
        assert exc.value.reason == "sidecar_unreachable"

    def test_max_queue_env_guards_garbage(self, monkeypatch):
        from raucle.sidecar import _sidecar_max_queue_from_env

        monkeypatch.setenv("RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE", "not-a-number")
        assert _sidecar_max_queue_from_env() == 4096
        monkeypatch.setenv("RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE", "-3")
        assert _sidecar_max_queue_from_env() == 4096

    def test_unknown_paths_answer_404_and_lifecycle_is_idempotent(self, tmp_path):
        import urllib.error
        import urllib.request

        sc = _sidecar(tmp_path)
        try:
            sc.start()  # idempotent
            with pytest.raises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(f"{sc.url}/nope", timeout=5.0)
            assert caught.value.code == 404
            with pytest.raises(urllib.error.HTTPError) as caught:
                request = urllib.request.Request(sc.url + "/nope", data=b"{}", method="POST")
                urllib.request.urlopen(request, timeout=5.0)
            assert caught.value.code == 404
        finally:
            sc.stop()
            sc.stop()  # idempotent

    def test_pend_spillover_drops_oldest(self, tmp_path):
        gw_local = _gateway(tmp_path, "", name="gw-spill")
        for i in range(130):
            gw_local._pend_sidecar_advisory({"receipt_hash": f"sha256:{i:064x}", "jws": "x"})
        pending = gw_local._pending_sidecar_advisories
        assert len(pending) == 128
        # the two oldest were dropped with a named log, never silently
        assert pending[0]["receipt_hash"] == "sha256:" + f"{2:064x}"

    def test_drain_clears_when_the_gateway_owns_no_client(self, tmp_path):
        gw_local = _gateway(tmp_path, "", name="gw-drain")
        gw_local._pending_sidecar_advisories.append({"receipt_hash": "sha256:" + "d" * 64})
        gw_local._drain_pending_sidecar_advisories()
        assert len(gw_local._pending_sidecar_advisories) == 0
        # the no-client submit guard returns without touching anything
        gw_local._submit_receipt_to_sidecar({"receipt_hash": "sha256:" + "e" * 64})

    def test_advisory_suppressed_when_receipts_are_off(self, tmp_path):
        cfg = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "off-legacy.jsonl"),
            audit_chain=str(tmp_path / "off-audit.jsonl"),
            registry_path=str(tmp_path / "off-registry.jsonl"),
            emit_receipts=False,
            receipt_sidecar_url="http://127.0.0.1:1/",
            receipt_sidecar_secret=SECRET,
        )
        policy = tmp_path / "off-policies.yaml"
        policy.write_text(POLICY, encoding="utf-8")
        cfg.policy_file = str(policy)
        gw = RaucleGateway(cfg)
        assert (
            gw._emit_sidecar_advisory(
                {"receipt_hash": "sha256:" + "f" * 64},
                type("R", (), {"reason": "receipt_sink_overflow"})(),
            )
            is None
        )
