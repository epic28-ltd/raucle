"""T-S4 - Shared SSRF guard for outbound ``urllib`` call sites.

Single guard used by every outbound HTTP caller in the package
(``raucle.timestamp.submit_timestamp_request``,
``raucle.transparency.SCITTAnchorClient``). A helper duplicated in
``gateway.py``/``feed.py`` predates this module; new outbound call sites
MUST use this one.

Contract
--------
* scheme MUST be exactly ``http`` or ``https`` (``urllib`` handles
  ``file:``, ``ftp:``, and data URLs elsewhere - so scheme is checked
  before ``urlopen`` ever sees the URL);
* the host MUST NOT be loopback, link-local (includes the cloud metadata
  address), RFC1918 private, reserved, multicast, or unspecified; hosts
  named ``localhost`` or under ``.local``/``.internal``/``.localdomain``
  are rejected too;
* set ``RAUCLE_ALLOW_PRIVATE_URLS`` to a truthy value to opt in
  explicitly (loopback test doubles, on-prem TSAs).

Resolution-time trust is out of scope for this guard: a public DNS name
that later resolves to a private address is not caught here (the same
documented limit as the SIEM forwarder check in ``gateway.py``).
``feed.py`` does full resolution-time pinning for its own fetcher; if a
call site needs DNS-resolution defence, follow that pattern instead of
downgrading this one.
"""

from __future__ import annotations

import ipaddress
import os
import urllib.parse

_TRUTHY = frozenset({"1", "true", "yes", "on"})

_PRIVATE_SUFFIXES = (".local", ".internal", ".localdomain", ".lan")
_PRIVATE_NAMES = frozenset({"localhost", "localhost.localdomain", "metadata"})


def allow_private_urls() -> bool:
    """True when the operator has opted in via RAUCLE_ALLOW_PRIVATE_URLS."""
    return os.environ.get("RAUCLE_ALLOW_PRIVATE_URLS", "").strip().lower() in _TRUTHY


def is_private_target(host: str) -> bool:
    """True when ``host`` names loopback/link-local/RFC1918/reserved space."""
    host = host.lower().rstrip(".")
    if host in _PRIVATE_NAMES or host.endswith(_PRIVATE_SUFFIXES):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # A DNS name we cannot classify syntactically; resolution-time
        # trust is out of scope (documented above).
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def validate_url(url: str, *, purpose: str = "request") -> None:
    """Validate ``url`` for an outbound HTTP call; raise ``ValueError`` if unsafe.

    Call this immediately before ``urllib.request.urlopen``. Raises
    ``ValueError`` naming the rejected class of address so the operator
    can tell an SSRF attempt from a misconfiguration.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(
            f"refusing {purpose}: only http:// and https:// URLs are allowed, "
            f"got scheme {parts.scheme!r}"
        )
    host = parts.hostname
    if not host:
        raise ValueError(f"refusing {purpose}: URL has no host")
    if parts.username is not None or parts.password is not None:
        raise ValueError(
            f"refusing {purpose}: userinfo (user:pass@) in URLs is not accepted"
        )
    if allow_private_urls():
        return
    if is_private_target(host):
        raise ValueError(
            f"refusing {purpose}: {host!r} targets loopback/link-local/private "
            "address space; set RAUCLE_ALLOW_PRIVATE_URLS to override explicitly"
        )

