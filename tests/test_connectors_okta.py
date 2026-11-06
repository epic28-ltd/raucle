"""Offline tests for the Okta System Log connector (no network).

All requests are served from recorded fixture JSON files under
``tests/fixtures/okta_system_log/`` via an injectable transport, exactly the
shape the real HTTPS layer must produce.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from raucle.connectors import OktaConnector
from raucle.connectors.base import RateLimitError, vector

FIXTURES = Path(__file__).parent / "fixtures" / "okta_system_log"


class RecordedOktaTransport:
    """Serves recorded pages; asserts auth header presence like real calls."""

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def __call__(self, _url, params, headers):
        self.calls.append(dict(params or {}))
        after = (params or {}).get("after")
        name = "page1.json" if not after else {"CUR_2": "page2.json", "CUR_4": "page3.json"}[after]
        body = (FIXTURES / name).read_bytes()
        return 200, {"X-Rate-Limit-Limit": "600", "Content-Type": "application/json"}, body


@pytest.fixture
def connector(monkeypatch):
    monkeypatch.setenv("OKTA_TOKEN", "test-token-fixture")
    return OktaConnector(
        RecordedOktaTransport(),
        base_url="https://example.okta.com",
        since="2026-11-06T00:00:00Z",
        limit=2,
    )


def test_okta_pages_deterministically_and_dedupes_overlap(connector):
    events = list(connector.fetch_all())
    ids = [ev["source_id"] for ev in events]
    # okta-evt-0002 straddles the page boundary (fixture overlap): once only.
    assert ids == [
        "okta-evt-0001",
        "okta-evt-0002",
        "okta-evt-0003",
        "okta-evt-0004",
        "okta-evt-0005",
        "okta-evt-0006",
    ]


def test_okta_mapping_is_verbatim_and_deterministic(connector):
    events = list(connector.fetch_all())
    first = events[0]
    assert first["kind"] == "source_event"
    assert first["source"] == "okta"
    assert first["timestamp"] == "2026-11-06T09:15:00.000Z"  # verbatim, no rewrite
    assert first["action"] == "user.session.start"
    assert first["actor"] == {
        "status": "known",
        "identity": "ada@example.com",
        "id": "00uabc001",
        "type": "User",
    }
    assert first["raw"]["uuid"] == "okta-evt-0001"  # raw carried for evidence


def test_okta_unknown_actors_are_named_not_invented(connector):
    by_id = {ev["source_id"]: ev for ev in connector.fetch_all()}
    # System actor without id: evidenced displayName -> known, type System.
    assert by_id["okta-evt-0003"]["actor"] == {
        "status": "known",
        "identity": "Okta System",
        "type": "System",
    }
    # Display name only, no id, not System: unknown, reason recorded.
    assert by_id["okta-evt-0004"]["actor"] == {"status": "unknown", "reason": "actor_without_id"}
    # actor absent entirely: unknown, not a guessed principal.
    assert by_id["okta-evt-0006"]["actor"] == {"status": "unknown", "reason": "missing_actor"}
    # No placeholder text ever leaks into identity.
    for ev in by_id.values():
        if ev["actor"]["status"] == "unknown":
            assert "identity" not in ev["actor"]


def test_okta_resumed_pull_does_not_redeliver_boundary_overlap(monkeypatch):
    # A fresh connector resuming from an earlier cursor: the page-boundary
    # event (okta-evt-0002, served on both pages) stays single-delivery.
    monkeypatch.setenv("OKTA_TOKEN", "test-token-fixture")
    fresh = OktaConnector(
        RecordedOktaTransport(),
        base_url="https://example.okta.com",
        since="2026-11-06T00:00:00Z",
        limit=2,
    )
    assert [ev["source_id"] for ev in fresh.fetch_all(after="CUR_2")] == [
        "okta-evt-0002",
        "okta-evt-0003",
        "okta-evt-0004",
        "okta-evt-0005",
        "okta-evt-0006",
    ]


def test_okta_in_session_redelivery_is_suppressed(connector):
    # Same connector instance: after consuming the full stream, re-pulling
    # from an earlier cursor redelivers pages 2 and 3 wholesale; in-session
    # dedupe suppresses *all* of them rather than duplicating records.
    assert list(connector.fetch_all())  # full stream, six events
    assert list(connector.fetch_all(after="CUR_2")) == []


def test_okta_rate_limit_surfaced_with_vendor_hint_not_slept(monkeypatch, connector):
    monkeypatch.setenv("OKTA_TOKEN", "test-token-fixture")

    def throttled(_url, _params, _headers):
        return 429, {"X-Rate-Limit-Reset": "9999999999", "Retry-After": "42"}, b"[]"

    connector._transport = throttled
    with pytest.raises(RateLimitError) as exc:
        next(connector.fetch_all())
    assert exc.value.source == "okta"
    assert exc.value.status == 429
    assert exc.value.retry_after == 42.0  # parsed from the vendor header, not invented


def test_okta_malformed_page_fails_loud(monkeypatch):
    monkeypatch.setenv("OKTA_TOKEN", "test-token-fixture")
    connector = OktaConnector(
        lambda *_a, **_k: (200, {}, b'[{"published": "2026-11-06"}]'),
        base_url="https://example.okta.com",
        since="2026-11-06T00:00:00Z",
    )
    with pytest.raises(RuntimeError, match="uuid"):
        list(connector.fetch_all())


def test_okta_corpus_vector_pins_the_mapping(connector):
    """Corpus vector: canonical mapping of fixture event 1 is pinned by hash.

    If a future change intentionally remaps fields, this vector must be
    deliberately advanced — accidental drift fails here.
    """
    first = next(connector.fetch_all())
    assert vector(first) == ("68a71e385dbea324b136ece87a11d2dcf0d99f97e646c2c06add7c79d2d57826")
