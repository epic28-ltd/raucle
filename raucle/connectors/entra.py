"""Entra ID (Azure AD) sign-in connector — pulled, cursor-paged, deterministic.

API: ``GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$top={n}
&$filter={filter}&$skiptoken={cursor}`` (Microsoft Graph audit log, an app with
the read-only ``AuditLog.Read.All`` scope). Pagination is Microsoft Graph's
odata envelope: a non-final response carries a ``@odata.nextLink`` whose query
string contains ``$skiptoken``; the final page omits ``nextLink`` entirely.
The ``$filter`` (e.g. ``createdDateTime ge ...``) bounds the window so a
caller controls scope. The skiptoken is an opaque Microsoft value — passed
back verbatim, never parsed or reconstructed.

Rate limits (documented honestly): Graph signals throttling with ``429`` plus
a ``Retry-After`` header (seconds). The connector does **not** sleep or
silently retry — it raises :class:`raucle.connectors.base.RateLimitError`
carrying the vendor's own hint parsed from the response headers; cursor
paging makes caller-controlled re-pulls safe because overlap is deduped.

Actor attribution (no invented identities): a sign-in record attributes its
principal from Graph's own fields — ``userPrincipalName``/``userId`` for user
flows, ``servicePrincipalName``/``servicePrincipalId`` for application
flows. The mapping produces::

    {"status": "known",   "identity": ..., "id": ..., "type": ...}   # attributable
    {"status": "unknown", "reason": "..."}                           # evidence missing

Known requires Graph to have evidenced a principal *name* (userPrincipalName
or servicePrincipalName); ``id`` is included only when the record also
carries ``userId``/``servicePrincipalId`` — absence of an id is normal for
some guest/automated flows and is never filled in. A record with an id but no
name stays ``unknown`` (reason ``id_without_identifier``); one with no
principal evidence at all is ``missing_actor_identity``. No placeholder
identity string is ever synthesised.

Action mapping: Graph sign-in records have no single ``action`` field as such
(the ``status.errorCode`` is what distinguishes outcomes). The connector
derives a deterministic action — ``signin.success`` when ``errorCode == 0``,
``signin.error.<code>`` otherwise — purely from the record's own ``status``
object; this derivation and its inputs are published in
``docs/spec/connectors/v1/entra-id-mapping.md``. Nothing else in the record
is reformatted: ``createdDateTime`` is copied verbatim.

Mapping corpus: ``docs/spec/connectors/v1/entra-test-vectors.json`` pins the
deterministic mapping (one vector per fixture shape) against drift.
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


def skiptoken_from_next_link(next_url: Any) -> str | None:
    """Extract the opaque ``$skiptoken`` from a Graph ``@odata.nextLink``.

    The value is returned **raw** (not percent-decoded) so it can be passed
    back as a query value verbatim — a reconstructed skiptoken is a cursor
    the vendor did not issue. Returns ``None`` when there is no next page
    (last page), and raises ``ValueError`` on a next link with no skiptoken
    so callers fail loud rather than silently refetching from page one.
    """
    if not isinstance(next_url, str) or not next_url:
        return None
    query = next_url.partition("?")[2]
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if name == "$skiptoken":
            return value or None
    raise ValueError(f"Entra @odata.nextLink without $skiptoken: {next_url!r}")


def map_entra_actor(record: dict[str, Any]) -> dict[str, Any]:
    """Graph sign-in record -> attributed actor dict; unknowns are named.

    Attribution requires an evidenced principal *name*:
    ``userPrincipalName`` (type ``user``) or ``servicePrincipalName`` (type
    ``servicePrincipal``). The id rides along only when Graph carried
    ``userId``/``servicePrincipalId`` — never synthesised.
    """
    upn = record.get("userPrincipalName")
    spn = record.get("servicePrincipalName")
    if isinstance(upn, str) and upn.strip():
        actor: dict[str, Any] = {"status": "known", "identity": upn, "type": "user"}
        user_id = record.get("userId")
        if isinstance(user_id, str) and user_id.strip():
            actor["id"] = user_id
        return actor
    if isinstance(spn, str) and spn.strip():
        actor = {"status": "known", "identity": spn, "type": "servicePrincipal"}
        sp_id = record.get("servicePrincipalId")
        if isinstance(sp_id, str) and sp_id.strip():
            actor["id"] = sp_id
        return actor
    user_id = record.get("userId")
    sp_id = record.get("servicePrincipalId")
    if (isinstance(user_id, str) and user_id.strip()) or (isinstance(sp_id, str) and sp_id.strip()):
        return {"status": "unknown", "reason": "id_without_identifier"}
    return {"status": "unknown", "reason": "missing_actor_identity"}


def map_entra_action(record: dict[str, Any]) -> str | None:
    """Derive the deterministic action from the record's own ``status`` object.

    ``status.errorCode == 0`` (or an empty status object) maps to
    ``signin.success``; any other errorCode maps to ``signin.error.<code>``
    verbatim. Records without a ``status`` object at all keep ``None`` — the
    mapping never invents an outcome.
    """
    status = record.get("status")
    if not isinstance(status, dict):
        return None
    code = status.get("errorCode", 0)
    if code == 0:
        return "signin.success"
    return f"signin.error.{code}"


class EntraSignInPageMalformed(RuntimeError):
    """Vendor payload broke the documented contract (e.g. missing sign-in id)."""


class EntraSignInConnector(SourceConnector):
    """Pull Entra ID / Azure AD sign-in records and yield raucle chain events.

    ``transport`` is injectable for offline fixture tests; the default
    transport would perform the live HTTPS call (implement in the deploy
    harness; this module stays network-free).
    """

    source = "entra_id"

    def __init__(
        self,
        transport: Transport,
        *,
        filter: str,
        top: int = 100,
        base_url: str = "https://graph.microsoft.com/v1.0",
        **kwargs: Any,
    ) -> None:
        super().__init__(transport, **kwargs)
        self._base_url = base_url.rstrip("/")
        self._filter = filter
        self._top = top

    def url(self, after: str | None) -> str:
        return f"{self._base_url}/auditLogs/signIns"

    def page_params(self, after: str | None) -> dict[str, str]:
        params = {"$top": str(self._top), "$filter": self._filter}
        if after:
            params["$skiptoken"] = after
        return params

    def _headers(self) -> dict[str, str]:
        import os

        token = os.environ.get("ENTRA_TOKEN", "").strip()
        if not token:
            raise RuntimeError("ENTRA_TOKEN not set; refusing an anonymous Entra audit-log pull")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _page(self, cursor: str | None) -> CursorPage:
        after = cursor
        status, headers, body = self._transport(
            self.url(after), self.page_params(after), self._headers()
        )
        self._guard_rate_limit(status, headers, "Retry-After")
        if status != 200:
            raise RuntimeError(f"Entra auditLogs/signIns API returned {status}: {body[:200]!r}")
        envelope = json.loads(body)
        if not isinstance(envelope, dict) or not isinstance(envelope.get("value"), list):
            raise EntraSignInPageMalformed(
                "Entra auditLogs/signIns response is not a Graph odata envelope"
            )
        records = envelope["value"]
        for rec in records:
            if not isinstance(rec, dict) or not rec.get("id"):
                raise EntraSignInPageMalformed(
                    f"Entra sign-in record missing required 'id': {rec!r}"
                )
        return CursorPage(tuple(records), skiptoken_from_next_link(envelope.get("@odata.nextLink")))

    def _event_key(self, event: dict[str, Any]) -> str:
        return f"entra_id:{event['id']}"

    def _map(self, event: dict[str, Any]) -> dict[str, Any]:
        return chain_event(
            source="entra_id",
            source_id=event["id"],
            timestamp=event.get("createdDateTime"),
            action=map_entra_action(event),
            actor=map_entra_actor(event),
            raw=event,
        )


__all__ = [
    "EntraSignInConnector",
    "EntraSignInPageMalformed",
    "map_entra_action",
    "map_entra_actor",
    "skiptoken_from_next_link",
]
