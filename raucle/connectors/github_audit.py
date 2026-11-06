"""GitHub audit-log connector — pulled, cursor-paged, duplicate-idempotent.

API: ``GET https://api.github.com/orgs/{org}/audit-log?q={phrase}&after={cursor}
&include=all&order=asc`` (needs an org admin token with ``audit_log:read``).
Cursor pagination: the opaque ``after`` token comes from the ``rel="next"``
entry of the ``Link`` response header.

Duplicate-delivery idempotency (the subtle one): GitHub's audit-log search
endpoint can redeliver the same entry across pages — page-boundary overlap
while events stream in, and cursor-token reuse after a caller retries. Every
entry carries a unique ``_document_id``; the connector dedupes on
``source:_document_id`` in :meth:`SourceConnector.fetch_page`, so a redelivered
event is never mapped twice even when the raw stream contains it repeatedly.
The regression corpus includes an explicit overlapping-page fixture pair.

Rate limits: GitHub responds ``403`` with ``X-RateLimit-Remaining: 0`` (
plus ``X-RateLimit-Reset`` epoch seconds) or ``429``. A scope-forbidden 403
carries a nonzero ``X-RateLimit-Remaining`` and is surfaced as a plain
runtime error, never as a rate limit. As with Okta there is no silent sleep
or retry — the caller receives :class:`RateLimitError` with the vendor's own
``Retry-After`` / reset hint.

Actor attribution: GitHub audit entries carry ``actor`` (the login text) in
several shapes — ``actor``, ``actor_login``, ``data.actor`` (older export
format). The connector normalises only what the entry actually evidences:
absent actor fields stay ``{"status": "unknown", "reason": "..."}`` and are
never defaulted to an org name or the token owner.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from raucle.connectors.base import CursorPage, SourceConnector, chain_event

Transport = Callable[
    [str, dict[str, str] | None, dict[str, str] | None],
    tuple[int, dict[str, str], bytes],
]

_LINK_NEXT = re.compile(r'<([^>]*)>;\s*rel="next"')


def github_after_from_link_header(headers: dict[str, str]) -> str | None:
    """Extract ``after=...`` from the Link header's rel="next" URL.

    Returns ``None`` when there is no next page (last page). Raises ``ValueError``
    on a next link with no ``after`` token so callers fail loud rather than
    silently refetching from page one.
    """
    for value in (headers.get("Link") or "", headers.get("link") or ""):
        match = _LINK_NEXT.search(value)
        if match:
            query = match.group(1).partition("?")[2]
            for part in query.split("&"):
                if part.startswith("after="):
                    return part[len("after=") :] or None
            raise ValueError(f"GitHub rel=next Link without after token: {match.group(1)!r}")
    return None


def map_github_actor(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalise the several GitHub audit actor shapes; unknowns are named.

    Never invents a principal: an entry without an evidenced ``actor``/
    ``actor_login``/``data.actor`` stays unknown with the reason recorded.
    """
    for key in ("actor", "actor_login"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return {"status": "known", "identity": value}
        if isinstance(value, dict):
            login = value.get("login")
            if isinstance(login, str) and login.strip():
                return {"status": "known", "identity": login}
    data = entry.get("data")
    if isinstance(data, dict):
        login = data.get("actor")
        if isinstance(login, str) and login.strip():
            return {"status": "known", "identity": login}
    return {"status": "unknown", "reason": "no_actor_field"}


class GitHubAuditPageMalformed(RuntimeError):
    """Vendor payload broke the documented contract (missing _document_id)."""


class GitHubAuditConnector(SourceConnector):
    """Pull org audit-log entries and yield raucle chain events.

    ``transport`` injectable; tests use recorded fixture responses — no
    network. ``@timestamp`` is copied verbatim (deterministic mapping).
    """

    source = "github"

    def __init__(
        self,
        transport: Transport,
        *,
        org: str,
        created_phrase: str,
        include: str = "all",
        order: str = "asc",
        per_page: int = 100,
        **kwargs: Any,
    ) -> None:
        super().__init__(transport, **kwargs)
        self._org = org
        self._created = created_phrase
        self._include = include
        self._order = order
        self._per_page = per_page

    def url(self, after: str | None) -> str:
        return f"https://api.github.com/orgs/{self._org}/audit-log"

    def page_params(self, after: str | None) -> dict[str, str]:
        params = {
            "q": f"created:{self._created}",
            "include": self._include,
            "order": self._order,
            "per_page": str(self._per_page),
        }
        if after:
            params["after"] = after
        return params

    def _headers(self) -> dict[str, str]:
        import os

        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if not token:
            raise RuntimeError("GITHUB_TOKEN not set; refusing an anonymous GitHub audit-log pull")
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _page(self, cursor: str | None) -> CursorPage:
        after = cursor
        status, headers, body = self._transport(
            self.url(after), self.page_params(after), self._headers()
        )
        self._guard_rate_limit(status, headers, "X-RateLimit-Remaining")
        if status != 200:
            raise RuntimeError(f"GitHub audit-log API returned {status}: {body[:200]!r}")
        entries = json.loads(body)
        if not isinstance(entries, list):
            raise GitHubAuditPageMalformed("GitHub audit-log response is not a JSON array")
        for ev in entries:
            if not isinstance(ev, dict) or not ev.get("_document_id"):
                raise GitHubAuditPageMalformed(f"GitHub audit entry missing '_document_id': {ev!r}")
        return CursorPage(tuple(entries), github_after_from_link_header(headers))

    def _event_key(self, event: dict[str, Any]) -> str:
        return f"github:{event['_document_id']}"

    def _map(self, event: dict[str, Any]) -> dict[str, Any]:
        return chain_event(
            source="github",
            source_id=event["_document_id"],
            timestamp=event.get("@timestamp"),
            action=event.get("action"),
            actor=map_github_actor(event),
            raw=event,
        )


__all__ = [
    "GitHubAuditConnector",
    "GitHubAuditPageMalformed",
    "github_after_from_link_header",
    "map_github_actor",
]
