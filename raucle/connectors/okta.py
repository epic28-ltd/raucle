"""Okta System Log connector — pulled, cursor-paged, deterministic mapping.

API: ``GET https://{org}.okta.com/api/v1/logs?since=...&after={cursor}&limit={n}``
(Okta System Log, read-only ``SSWS`` token). Pagination is the opaque
``after`` cursor taken from the final event's ``_links.next`` ``href`` query
parameter; a page whose last event has no ``after`` in ``_links.next`` is the
last page. ``since`` bounds the window so a caller controls scope.

Rate limits (documented honestly): Okta returns ``429`` with either an
``X-Rate-Limit-Reset`` epoch-seconds header or, over HTTPS, ``Retry-After``.
The connector does **not** sleep or silently retry — it raises
:class:`raucle.connectors.base.RateLimitError` carrying the vendor's own hint
parsed from the response headers, and the caller (scheduler/CLI) decides
whether to sleep and re-pull. Cursor-based paging makes that safe: re-pulling
with the same ``after`` cursor redelivers overlap that dedupe catches.

Actor attribution (no invented identities): Okta's per-event ``actor`` object
maps to::

    {"status": "known",   "identity": ..., "id": ..., "type": ...}   # attributable
    {"status": "unknown", "reason": "..."}                           # evidence missing

Unknown is a *named status* (e.g. ``missing_actor``,
``actor_without_id``), never a placeholder identity like "anonymous". If Okta
did not evidence a principal, the record says so.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from raucle.connectors.base import CursorPage, SourceConnector, chain_event

Transport = Callable[
    [str, dict[str, str] | None, dict[str, str] | None],
    tuple[int, dict[str, str], bytes],
]


def map_okta_actor(event: dict[str, Any]) -> dict[str, Any]:
    """Okta ``actor`` object -> attributed actor dict; unknowns are named.

    Attribution requires Okta's own evidence: a present ``id`` for the
    principal, or a ``type == "System"`` system actor with a ``displayName``.
    Anything else stays ``unknown`` with the reason recorded.
    """
    actor = event.get("actor")
    if not isinstance(actor, dict) or not actor:
        return {"status": "unknown", "reason": "missing_actor"}
    actor_id = actor.get("id")
    identity = actor.get("login") or actor.get("displayName")
    actor_type = actor.get("type")
    if actor_id is None:
        if actor_type == "System" and identity:
            return {"status": "known", "identity": identity, "type": "System"}
        return {"status": "unknown", "reason": "actor_without_id"}
    if not identity:
        return {"status": "unknown", "reason": "actor_without_identity"}
    return {"status": "known", "identity": identity, "id": actor_id, "type": actor_type}


def _next_after(events: list[dict[str, Any]]) -> str | None:
    """The opaque ``after`` cursor from the final event's ``_links.next``.

    Okta puts the next-page cursor in the query string of the last event's
    ``_links.next`` href on every non-final page; the final page omits it.
    Returns ``None`` only when there is genuinely no next page (empty page or
    final page), and raises on an unparsable link rather than silently
    dropping events to fetch.
    """
    if not events:
        return None
    nxt = (events[-1].get("_links") or {}).get("next")
    if not isinstance(nxt, dict):
        return None
    query = nxt.get("href", "").partition("?")[2]
    for part in query.split("&"):
        if part.startswith("after="):
            return part[len("after=") :] or None
    raise OktaPageMalformed(f"Okta _links.next missing 'after' cursor: {nxt!r}")


class OktaPageMalformed(RuntimeError):
    """Vendor payload broke the documented contract (e.g. missing uuid)."""


class OktaConnector(SourceConnector):
    """Pull Okta System Log entries and yield raucle chain events.

    ``transport`` is injectable for offline fixture tests; the default
    transport would perform the live HTTPS call (implement in the deploy
    harness; this module stays network-free).
    """

    source = "okta"

    def __init__(
        self,
        transport: Transport,
        *,
        base_url: str,
        since: str,
        limit: int = 100,
        **kwargs: Any,
    ) -> None:
        super().__init__(transport, **kwargs)
        self._base_url = base_url.rstrip("/")
        self._since = since
        self._limit = limit

    def url(self, _after: str | None) -> str:
        return f"{self._base_url}/api/v1/logs"

    def page_params(self, after: str | None) -> dict[str, str]:
        params = {"since": self._since, "limit": str(self._limit)}
        if after:
            params["after"] = after
        return params

    def _headers(self) -> dict[str, str]:
        import os

        token = os.environ.get("OKTA_TOKEN", "").strip()
        if not token:
            raise RuntimeError(
                "OKTA_TOKEN not set; refusing to send an anonymous Okta System Log pull"
            )
        return {"Authorization": f"SSWS {token}", "Accept": "application/json"}

    def _page(self, cursor: str | None) -> CursorPage:
        after = cursor
        status, headers, body = self._transport(
            self.url(after), self.page_params(after), self._headers()
        )
        self._guard_rate_limit(status, headers, "X-Rate-Limit-Reset")
        if status != 200:
            raise RuntimeError(f"Okta System Log API returned {status}: {body[:200]!r}")
        events = json.loads(body)
        if not isinstance(events, list):
            raise OktaPageMalformed("Okta System Log response is not a JSON array")
        for ev in events:
            if not isinstance(ev, dict) or not ev.get("uuid"):
                raise OktaPageMalformed(f"Okta event missing required 'uuid': {ev!r}")
        return CursorPage(tuple(events), _next_after(events))

    def _event_key(self, event: dict[str, Any]) -> str:
        return f"okta:{event['uuid']}"

    def _map(self, event: dict[str, Any]) -> dict[str, Any]:
        return chain_event(
            source="okta",
            source_id=event["uuid"],
            timestamp=event.get("published"),
            action=event.get("eventType"),
            actor=map_okta_actor(event),
            raw=event,
        )


__all__ = ["OktaConnector", "OktaPageMalformed", "map_okta_actor"]
