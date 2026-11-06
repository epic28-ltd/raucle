"""Audit-source connectors: pull external audit streams into raucle events.

Cloud/SaaS control planes keep their own audit logs (Okta System Log, GitHub
audit-log, ...). These connectors *pull* those streams through pluggable
transports (so tests run fully offline against recorded fixtures) and map each
vendor event deterministically to a raucle chain-event payload — the same
``event`` dict shape a :class:`raucle.audit.HashChainSink` accepts.

Two rules are hard, project-wide:

* **No invented identities.** If a vendor event does not carry an attributable
  actor, the mapped record says so (``actor.status == "unknown"`` plus a
  machine-readable ``reason``); the connector never guesses a principal.
* **Idempotency by source id.** Pagination quirks mean vendors redeliver
  events. Every connector dedupes on the vendor's unique event id and exposes
  a resumable cursor.
"""

from raucle.connectors.base import (
    RateLimitError,
    SourceConnector,
    chain_event,
    vector,
)
from raucle.connectors.github_audit import GitHubAuditConnector
from raucle.connectors.okta import OktaConnector

__all__ = [
    "GitHubAuditConnector",
    "OktaConnector",
    "RateLimitError",
    "SourceConnector",
    "chain_event",
    "vector",
]
