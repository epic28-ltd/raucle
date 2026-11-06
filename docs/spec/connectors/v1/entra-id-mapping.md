# Entra ID (Azure AD) sign-in records → raucle chain events (field mapping)

Companion to `raucle.connectors.entra` (module docstring carries the same
rules) and the machine-readable corpus
[`entra-test-vectors.json`](entra-test-vectors.json). Nothing here makes
compliance claims; it documents a deterministic mapping and its honesty
rules.

## Source

`GET https://graph.microsoft.com/v1.0/auditLogs/signIns` (Microsoft Graph
audit log; read-only `AuditLog.Read.All` scope). Paging is the Graph odata
envelope: a non-final response carries `@odata.nextLink`, whose query string
holds the opaque `$skiptoken`; the last page omits `nextLink`. The skiptoken
is passed back **verbatim** — never percent-reconstructed, never parsed as
structured data.

## Field mapping

| Chain-event field | Graph source | Rule |
| --- | --- | --- |
| `kind` | — | constant `source_event` |
| `mapping_version` | — | constant `p3b.v1` |
| `source` | — | constant `entra_id` |
| `source_id` | `id` | required; a record without one raises `EntraSignInPageMalformed` |
| `timestamp` | `createdDateTime` | copied **verbatim** — no reformatting, no timezone normalisation |
| `action` | `status.errorCode` | **derived** (Graph sign-ins have no single action field): `signin.success` when `errorCode == 0`; `signin.error.<code>` otherwise; a record with no `status` object keeps `action: null` — the outcome is never invented |
| `actor` | principal fields | see below |
| `raw` | whole record | carried intact for evidence |

## Actor attribution (no invented identities)

Attribution uses only what the record itself evidences:

* `userPrincipalName` present → known, `type: "user"`; `id` added **only**
  when the record also carries `userId` (absence is normal for some
  guest/automated flows and is never filled in).
* else `servicePrincipalName` present → known, `type: "servicePrincipal"`;
  `id` added only with `servicePrincipalId`.
* else any id present (`userId`/`servicePrincipalId`) but no name anywhere →
  `{"status": "unknown", "reason": "id_without_identifier"}` — an id without
  an evidenced name is not a usable principal.
* else → `{"status": "unknown", "reason": "missing_actor_identity"}`.

Unknown is a named status with a machine-readable reason; no placeholder
identity string (no `"anonymous"`, no service-name default, no tenant-name
fallback) is ever synthesised. Where the reason matters, downstream consumers
decide policy; the connector only records the evidence.

## Idempotency and rate limits

Dedupe is by `entra_id:<id>` inside the paging machinery
(`SourceConnector.fetch_page`), with a resumable cursor, so Graph's
page-boundary redispatches and caller retries stay single-delivery. Throttling
surfaces as `RateLimitError` carrying Graph's own `Retry-After` header value —
no sleep, no silent retry; re-pulls after a back-off are safe because of the
cursor + dedupe.
