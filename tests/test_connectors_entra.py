"""Offline tests for the Entra ID (Azure AD) sign-in connector (no network).

All requests are served from recorded fixture JSON files under
``tests/fixtures/entra_sign_ins/`` via an injectable transport, exactly the
Graph odata-envelope shape the real HTTPS layer must produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from raucle.connectors import EntraSignInConnector
from raucle.connectors.base import RateLimitError, vector

FIXTURES = Path(__file__).parent / "fixtures" / "entra_sign_ins"
CORPUS = (
    Path(__file__).parent.parent / "docs" / "spec" / "connectors" / "v1" / "entra-test-vectors.json"
)


class RecordedEntraTransport:
    """Serves recorded Graph envelope pages; records the query params."""

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def __call__(self, _url, params, headers):
        self.calls.append(dict(params or {}))
        assert headers.get("Authorization") == "Bearer test-token-fixture"
        skiptoken = (params or {}).get("$skiptoken")
        name = {
            None: "page1.json",
            "TOKEN_2": "page2.json",
            "TOKEN_4": "page3.json",
        }[skiptoken]
        body = (FIXTURES / name).read_bytes()
        return 200, {"Retry-After": "120", "Content-Type": "application/json"}, body


@pytest.fixture
def connector(monkeypatch):
    monkeypatch.setenv("ENTRA_TOKEN", "test-token-fixture")
    return EntraSignInConnector(
        RecordedEntraTransport(),
        filter="createdDateTime ge 2026-11-06T00:00:00Z",
        top=3,
    )


def test_entra_pages_deterministically_and_dedupes_boundary_overlap(connector):
    events = list(connector.fetch_all())
    ids = [ev["source_id"] for ev in events]
    # entra-sin-0003 straddles the page 1/2 boundary (fixture overlap): once only.
    assert ids == [f"entra-sin-{n:04d}" for n in (1, 2, 3, 4, 5, 6, 7)]


def test_entra_skips_are_passed_back_verbatim(connector):
    list(connector.fetch_all())
    skips = [params.get("$skiptoken") for params in connector._transport.calls]
    assert skips == [None, "TOKEN_2", "TOKEN_4"]
    # and the window filter rides on every page
    assert all(
        params["$filter"].startswith("createdDateTime ge") for params in connector._transport.calls
    )


def test_entra_mapping_is_deterministic_and_verbatim(connector):
    events = list(connector.fetch_all())
    first = events[0]
    assert first["kind"] == "source_event"
    assert first["source"] == "entra_id"
    assert first["timestamp"] == "2026-11-06T09:15:07.000Z"  # verbatim, no rewrite
    assert first["action"] == "signin.success"  # derived from status.errorCode == 0
    assert first["actor"] == {
        "status": "known",
        "identity": "ada@contoso.com",
        "id": "uid-1001",
        "type": "user",
    }
    assert first["raw"]["id"] == "entra-sin-0001"  # raw carried for evidence


def test_entra_unknown_actors_are_named_not_invented(connector):
    by_id = {ev["source_id"]: ev for ev in connector.fetch_all()}
    # Service principal with name + id: known, type servicePrincipal.
    assert by_id["entra-sin-0002"]["actor"] == {
        "status": "known",
        "identity": "backup-runner",
        "id": "sp-7",
        "type": "servicePrincipal",
    }
    # UPN without userId (guest/automated flow): known; no id is *invented*.
    assert by_id["entra-sin-0003"]["actor"] == {
        "status": "known",
        "identity": "svc-archiver@contoso.com",
        "type": "user",
    }
    # userId with no name field anywhere: id alone does not a principal make.
    assert by_id["entra-sin-0004"]["actor"] == {
        "status": "unknown",
        "reason": "id_without_identifier",
    }
    # No principal evidence at all: unknown, not a guessed account.
    assert by_id["entra-sin-0005"]["actor"] == {
        "status": "unknown",
        "reason": "missing_actor_identity",
    }
    for ev in by_id.values():
        if ev["actor"]["status"] == "unknown":
            assert "identity" not in ev["actor"]  # no placeholder text leaks


def test_entra_error_codes_carry_deterministic_actions(connector):
    by_id = {ev["source_id"]: ev for ev in connector.fetch_all()}
    assert by_id["entra-sin-0006"]["action"] == "signin.error.50074"  # MFA requirement
    assert by_id["entra-sin-0007"]["action"] == "signin.success"


def test_entra_resumed_pull_from_cursor_does_not_redeliver(connector):
    # A fresh connector resuming from the second page cursor: the page-boundary
    # event (entra-sin-0003, served on both pages) stays single-delivery.
    assert [ev["source_id"] for ev in connector.fetch_all(after="TOKEN_2")] == [
        "entra-sin-0003",
        "entra-sin-0004",
        "entra-sin-0005",
        "entra-sin-0006",
        "entra-sin-0007",
    ]


def test_entra_in_session_redelivery_is_suppressed(connector):
    assert list(connector.fetch_all())  # full stream, seven events
    assert list(connector.fetch_all(after="TOKEN_2")) == []


def test_entra_rate_limit_surfaced_with_vendor_hint_not_slept(monkeypatch, connector):
    monkeypatch.setenv("ENTRA_TOKEN", "test-token-fixture")

    def throttled(_url, _params, _headers):
        return 429, {"Retry-After": "37"}, json.dumps({"error": {"code": "throttled"}}).encode()

    connector._transport = throttled
    with pytest.raises(RateLimitError) as exc:
        next(connector.fetch_all())
    assert exc.value.source == "entra_id"
    assert exc.value.status == 429
    assert exc.value.retry_after == 37.0  # parsed from the vendor header, not invented


def test_entra_malformed_page_fails_loud(monkeypatch):
    monkeypatch.setenv("ENTRA_TOKEN", "test-token-fixture")
    connector = EntraSignInConnector(
        lambda *_a, **_k: (
            200,
            {},
            json.dumps(
                {"@odata.context": "x", "value": [{"createdDateTime": "2026-11-06"}]}
            ).encode(),
        ),
        filter="createdDateTime ge 2026-11-06T00:00:00Z",
    )
    with pytest.raises(RuntimeError, match="id"):
        list(connector.fetch_all())


def test_entra_next_link_without_skiptoken_fails_loud():
    from raucle.connectors.entra import skiptoken_from_next_link

    with pytest.raises(ValueError, match="skiptoken"):
        skiptoken_from_next_link(
            "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=3&$filter=x"
        )


def test_entra_corpus_vector_pins_the_mapping(connector):
    """Corpus vector: the canonical mapping of fixture record 1 is pinned by hash.

    If a future change intentionally remaps fields, this vector must be
    deliberately advanced -- accidental drift fails here.
    """
    first = next(connector.fetch_all())
    assert vector(first) == ("874cb303962aff205e487daeb2bd2b3c33785c06e2b66b0d4d0fb3212026d202")


def test_entra_n10_corpus_integrity():
    """The published N10 corpus reproduces from the mapping, vector by vector.

    Each vector carries the raw Graph record, the expected chain event, and
    the expected canonical sha256; a mapping change must advance the JSON
    deliberately, and this test refuses any silent divergence.
    """
    corpus = json.loads(CORPUS.read_text())
    assert corpus["meta"]["module"] == "raucle.connectors.entra"
    assert corpus["meta"]["mapping_version"] == "p3b.v1"
    from raucle.connectors.base import chain_event, record_key
    from raucle.connectors.entra import map_entra_action, map_entra_actor

    for vec in corpus["vectors"]:
        rec = vec["input_sign_in"]
        mapped = chain_event(
            source="entra_id",
            source_id=rec["id"],
            timestamp=rec.get("createdDateTime"),
            action=map_entra_action(rec),
            actor=map_entra_actor(rec),
            raw=rec,
        )
        assert mapped == vec["expected_chain_event"], vec["id"]
        assert record_key(mapped).decode() == vec["expected_canonical_utf8"], vec["id"]
        assert vector(mapped) == vec["expected_vector_sha256"], vec["id"]
