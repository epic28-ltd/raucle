"""NFR reliability chaos additions (P5.NFR / reliability-v1).

Two families beyond the existing durability tests (segment flush
durability, corrupt-key/corrupt-users fail-closed, connector
malformed-page fail-loud), which already live in ``test_receipt_store.py``,
``test_gateway_persistence.py`` and ``test_connectors_*.py``:

1. Corrupt-CURSOR chaos (request side). The existing connector suites
   cover corrupt RESPONSES (malformed pages, nextLink without skiptoken).
   No suite covers a corrupt cursor coming back OUT of a persisted resume
   file and being fed back INTO a connector. The failure mode that would
   silently corrupt an ingest is the connector laundering the garbage
   cursor — normalising, trimming or defaulting it to ``None`` so the fetch
   silently restarts from page 1 and re-delivers the whole window as if
   nothing happened. These tests pin fail-closed: the corrupt cursor goes
   to the vendor VERBATIM, the vendor's error surfaces, and ingest ABORTS
   instead of restarting.

2. Gate-under-concurrent-STOP chaos. Decisions keep being made and
   receipted by several writer threads while an operator thread
   concurrently seals the active segment (the honest model of "stopping"
   the durable ingest — ``seal_now``, after which no further writes are
   counted as delivered). Invariants: every accepted write is on disk
   exactly once, no torn JSONL lines, and every emitted receipt re-parses
   from disk as a structurally valid JWS envelope.
"""

from __future__ import annotations

import itertools
import json
import threading
import time

import pytest

from raucle.audit import Ed25519Signer
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.connectors import EntraSignInConnector, GitHubAuditConnector, OktaConnector
from raucle.passport import issue_passport, verify_passport
from raucle.provenance import AgentIdentity, Operation, ProvenanceReceipt
from raucle.receipt_store import SegmentedReceiptStore
from raucle.trust_registry import TrustRegistry

CORRUPT_CURSORS = ["   ", "\n\t", "\x00CUR", '{"cursor":1}', "skiptoken=%27", "CUR_B\x0b\x0c"]

# ---------------------------------------------------------------------------
# Family 1: corrupt inbound cursor fails closed
# ---------------------------------------------------------------------------


class _BadRequestTransport:
    """Mimics real vendors: an unrecognised opaque cursor is a 400, not a
    rewind to page one. Records the cursor VERBATIM so tests can assert the
    connector did not normalise it before sending."""

    record_key: str = "after"

    def __init__(self) -> None:
        self.last_cursor: str | None = None
        self.calls = 0

    def __call__(self, _url, params, _headers):
        self.calls += 1
        cursor = (params or {}).get(self.record_key)
        self.last_cursor = cursor
        if cursor in CORRUPT_CURSORS:
            return 400, {}, b'{"error": "invalid cursor"}'
        return 200, {}, json.dumps([{"id": "evt-ok-1"}])


class _EntraBadRequestTransport(_BadRequestTransport):
    record_key = "$skiptoken"


@pytest.fixture
def entra_env(monkeypatch):
    monkeypatch.setenv("ENTRA_TOKEN", "test-token-fixture")


@pytest.fixture
def github_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-fixture")


@pytest.fixture
def okta_env(monkeypatch):
    monkeypatch.setenv("OKTA_TOKEN", "test-token-fixture")


@pytest.mark.parametrize("cursor", CORRUPT_CURSORS)
def test_entra_corrupt_cursor_fails_closed_verbatim(entra_env, cursor):
    tr = _EntraBadRequestTransport()
    connector = EntraSignInConnector(tr, filter="createdDateTime ge 2026-01-01T00:00:00Z", top=3)
    with pytest.raises(RuntimeError):
        connector.fetch_page(cursor)
    assert tr.calls == 1
    assert tr.last_cursor == cursor  # verbatim — no laundering


def test_entra_fetch_all_with_corrupt_start_cursor_aborts_not_restarts(entra_env):
    """A corrupt persisted cursor must abort ingest — NOT silently restart
    from the first page and re-deliver the whole window."""
    tr = _EntraBadRequestTransport()
    connector = EntraSignInConnector(tr, filter="f", top=3)
    with pytest.raises(RuntimeError):
        assert not list(connector.fetch_all("CUR_B\x0b\x0c"))
    assert tr.calls == 1, "a corrupt cursor must terminate the pull, never loop pages"


@pytest.mark.parametrize("cursor", CORRUPT_CURSORS)
def test_github_corrupt_cursor_fails_closed_verbatim(github_env, cursor):
    tr = _BadRequestTransport()
    connector = GitHubAuditConnector(tr, org="epic28-ltd", created_phrase="2026-11-01..2026-11-07")
    with pytest.raises(RuntimeError):
        connector.fetch_page(cursor)
    assert tr.last_cursor == cursor


def test_github_fetch_all_with_corrupt_start_cursor_aborts_not_restarts(github_env):
    tr = _BadRequestTransport()
    connector = GitHubAuditConnector(tr, org="epic28-ltd", created_phrase="2026-11-01..2026-11-07")
    with pytest.raises(RuntimeError):
        assert not list(connector.fetch_all(' link="after=CUR_B&per_page=100" '))
    assert tr.calls == 1


@pytest.mark.parametrize("cursor", CORRUPT_CURSORS)
def test_okta_corrupt_cursor_fails_closed_verbatim(okta_env, cursor):
    tr = _BadRequestTransport()
    connector = OktaConnector(
        tr,
        base_url="https://chaos-okta.example.com",
        since="2026-01-01T00:00:00Z",
    )
    with pytest.raises(RuntimeError):
        connector.fetch_page(cursor)
    assert tr.last_cursor == cursor


# ---------------------------------------------------------------------------
# Family 2: gate under concurrent stop
# ---------------------------------------------------------------------------


def test_gate_decisions_under_concurrent_stop_reaccount_exactly_once(tmp_path):
    """Writers decide a gate call and append its receipt while a stopper
    thread repeatedly seals the store. After the storm:

    - every accepted append is on disk exactly once (no lost receipt),
    - every physical line parses (no torn records from mid-write seals),
    - every receipt re-parses as a structurally valid JWS from JWS alone,
    - a sealed-before-write segment never drops the un-sealed tail.
    """
    issuer = CapabilityIssuer.generate(issuer="chaos.platform.example")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    cap = issuer.mint(agent_id="agent:chaos", tool="transfer_funds", constraints={})
    agent = AgentIdentity.generate(agent_id="agent:chaos")
    store = SegmentedReceiptStore(base_dir=tmp_path / "receipts")

    WRITES = 120
    errors: list[Exception] = []
    counter = itertools.count()
    lock = threading.Lock()
    written = []

    def writer() -> None:
        while True:
            with lock:
                i = next(counter)
            if i >= WRITES:
                return
            try:
                gate.check(cap, tool="transfer_funds", args={"amount": i})
                rec = ProvenanceReceipt(
                    agent_id="agent:chaos",
                    agent_key_id=agent.key_id,
                    operation=Operation.TOOL_CALL,
                    tool="transfer_funds",
                    input_hash=f"sha256:chaos-{i}",
                    issued_at=1700000000,
                )
                jws = rec.sign(agent)
                store.append_line(json.dumps({"receipt_hash": rec.receipt_hash, "jws": jws}))
                # append_line fsyncs before returning — the write is "accepted".
                with lock:
                    written.append(rec.receipt_hash)
            except Exception as exc:  # pragma: no cover - any error fails the test
                errors.append(exc)
                return

    def stopper() -> None:
        deadline = time.time() + 5.0
        while time.time() < deadline and len(written) < WRITES:
            store.seal_now()
            time.sleep(0.0005)

    threads = [threading.Thread(target=writer) for _ in range(4)]
    threads.append(threading.Thread(target=stopper))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
        assert not t.is_alive(), "chaos thread hung"

    assert not errors, f"writer hit a concurrent-stop error: {errors!r}"
    assert len(written) == WRITES

    envelopes = []
    for seg in (tmp_path / "receipts").glob("seg-*.jsonl"):
        for line in seg.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                envelopes.append(json.loads(line))  # torn line => ValueError => fail
    assert len(envelopes) == WRITES, "no accepted write may be lost or duplicated"
    assert len({e["receipt_hash"] for e in envelopes}) == WRITES, "exactly once"
    for e in envelopes:
        parsed = ProvenanceReceipt.from_jws(e["jws"])
        assert parsed.tool == "transfer_funds"

    assert store.total_receipt_count() == WRITES


def test_passport_verify_valid_while_receipt_store_stops_mid_stream(tmp_path):
    """Stopping/rotating the durable store must not perturb offline
    verification — the stop-then-verify invariant."""
    org_signer = Ed25519Signer.generate()
    reg = TrustRegistry(tmp_path / "reg.jsonl")
    reg.publish(org_signer.public_key_pem().decode(), issuer="Chaos Org")
    agent = AgentIdentity.generate(agent_id="agent:chaos")
    passport = issue_passport(agent.statement, issuer_signer=org_signer, issuer="Chaos Org")

    # A churned store: many segments, sealed repeatedly, mid-stream.
    churn = SegmentedReceiptStore(base_dir=tmp_path / "churn", max_segment_bytes=128)
    for i in range(64):
        churn.append_line(json.dumps({"receipt_hash": f"sha256:{i}", "jws": "x.y.z"}))
    churn.seal_now()
    for i in range(64, 128):
        churn.append_line(json.dumps({"receipt_hash": f"sha256:{i}", "jws": "x.y.z"}))
    churn.seal_now()

    assert churn.total_receipt_count() == 128
    v = verify_passport(passport, registry=reg)
    assert v.valid
    assert v.agent_id == "agent:chaos"
