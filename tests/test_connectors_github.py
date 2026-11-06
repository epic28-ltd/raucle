"""Offline tests for the GitHub audit-log connector (no network).

All requests are served from recorded fixture JSON files; the transport also
replays the ``Link`` header GitHub actually sends, including the overlapping
page at the boundary that exercises duplicate-delivery idempotency.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from raucle.connectors import GitHubAuditConnector
from raucle.connectors.base import RateLimitError, vector
from raucle.connectors.github_audit import github_after_from_link_header

FIXTURES = Path(__file__).parent / "fixtures" / "github_audit"

_NEXT = {"": "CUR_B", "CUR_B": "CUR_C"}


class RecordedGitHubTransport:
    """Replays pages with a Link header whose cursor the connector must track.

    Deliberately re-serves the page-boundary event (gh-evt-0002 twice across
    pages, plus a duplicated line inside one page) to regress the
    duplicate-delivery idempotency requirement.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def __call__(self, _url, params, _headers):
        self.calls.append(dict(params or {}))
        after = (params or {}).get("after", "")
        source = {
            "": ("page1.json", "after=CUR_B&per_page=100"),
            "CUR_B": ("page2_overlap.json", "after=CUR_C&per_page=100"),
            "CUR_C": ("page3_final.json", None),
        }[after]
        name, next_query = source
        headers = {}
        if next_query:
            headers["Link"] = f'<https://api.github.com/orgs/x/audit-log?{next_query}>; rel="next"'
        return 200, headers, (FIXTURES / name).read_bytes()


@pytest.fixture
def connector(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-fixture")
    return GitHubAuditConnector(
        RecordedGitHubTransport(),
        org="epic28-ltd",
        created_phrase="2026-11-01..2026-11-07",
    )


def test_github_pages_and_dedupes_duplicate_delivery(connector):
    events = list(connector.fetch_all())
    ids = [ev["source_id"] for ev in events]
    # gh-evt-0002 appears at the page boundary AND twice inside page 2:
    # duplicate deliveries collapse to exactly one mapped chain event.
    assert ids == ["gh-evt-0001", "gh-evt-0002", "gh-evt-0003", "gh-evt-0004", "gh-evt-0005"]
    assert ids.count("gh-evt-0002") == 1


def test_github_cursor_is_tracked_from_link_header(connector):
    pages = list(connector.iter_pages())
    assert [p.next_cursor for p in pages] == ["CUR_B", "CUR_C", None]


def test_github_mapping_uses_document_id_and_verbatim_timestamp(connector):
    events = list(connector.fetch_all())
    first = events[0]
    assert first["source"] == "github"
    assert first["source_id"] == "gh-evt-0001"
    assert first["timestamp"] == "2026-11-06T10:00:00.123Z"
    assert first["action"] == "repo.create"
    assert first["actor"] == {"status": "known", "identity": "octodev"}


def test_github_unknown_actor_named_not_invented(connector):
    by_id = {ev["source_id"]: ev for ev in connector.fetch_all()}
    # Legacy export shape: actor inside data.
    assert by_id["gh-evt-0003"]["actor"] == {"status": "known", "identity": "legacy-admin"}
    # Bot actors are their own login, carried verbatim (no de-botting).
    assert by_id["gh-evt-0005"]["actor"] == {"status": "known", "identity": "dependabot[bot]"}
    # Integration event with no actor field anywhere: unknown, named reason.
    assert by_id["gh-evt-0004"]["actor"] == {"status": "unknown", "reason": "no_actor_field"}


def test_github_rate_limit_403_with_zero_remaining_is_rate_limit(monkeypatch, connector):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-fixture")

    def throttled(_url, _params, _headers):
        return (
            403,
            {
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1790000000",
            },
            b"{}",
        )

    connector._transport = throttled
    with pytest.raises(RateLimitError) as exc:
        next(connector.fetch_all())
    assert exc.value.status == 403
    assert exc.value.retry_after is not None and exc.value.retry_after >= 0


def test_github_forbidden_403_is_not_a_rate_limit(monkeypatch, connector):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-fixture")

    def forbidden(_url, _params, _headers):
        return 403, {"X-RateLimit-Remaining": "4996"}, b'{"message": "Not Found"}'

    connector._transport = forbidden
    with pytest.raises(RuntimeError, match="returned 403") as exc:
        next(connector.fetch_all())
    assert not isinstance(exc.value, RateLimitError)


def test_github_after_from_link_header_edge_cases():
    assert (
        github_after_from_link_header(
            {
                "Link": '<https://api.github.com/orgs/x/audit-log?after=cur1&z=2>; rel="next", '
                '<https://api.github.com/orgs/x/audit-log?after=cur1&z=2>; rel="last"'
            }
        )
        == "cur1"
    )
    assert github_after_from_link_header({}) is None
    with pytest.raises(ValueError, match="after"):
        github_after_from_link_header(
            {"Link": '<https://api.github.com/orgs/x/audit-log>; rel="next"'}
        )


def test_github_corpus_vector_pins_the_mapping(connector):
    """Corpus vector: canonical mapping of fixture entry gh-evt-0001 is pinned."""
    first = next(connector.fetch_all())
    assert vector(first) == ("602ad3a2997413af9d87992e5eabccbddb81a469d2f4f86656c2fdc95aa002c8")
