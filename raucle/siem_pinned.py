"""DNS-gated, IP-pinned egress transport for the SIEM forwarder (RAU-04).

``siem_target_allowed`` validates the outbound target, but a hostname
that resolves to a private address passed a literal-IP-only check, and
the forwarder posted wherever DNS pointed (RED-036). This module gives
the forwarder's requests session a transport that closes the two sides
of that hole:

- **Every address is judged**: the resolver hook returns the full
  getaddrinfo record list and the gate refuses when ANY record lands in
  private/loopback/link-local/reserved/multicast space (first-record
  preference is not trust).
- **The connection is pinned by name-shaped address**: the pinned
  connection resolves, re-checks, and dials the validated address in ONE
  step immediately before the socket is created. SNI, the ``Host``
  header and certificate verification still bind to the operator's
  original hostname (the connection's host is never rewritten), and no
  DNS lookup happens between the connect-time check and the dial - so a
  rebinding race between validation and request is closed, not narrowed.
- **Fail-closed resolution**: a target that cannot resolve refuses
  (the request is not attempted on a maybe).

Residuals, stated honestly:

- An operator who sets ``RAUCLE_SIEM_ALLOW_PRIVATE=1`` opts out
  everywhere (validation and the connect-time gate); internal
  collectors remain the deliberate use case.
- IPv6: addresses dial as parsed literals; the connect gate judges the
  address class itself, so scoped link-local forms are refused rather
  than dialed.
- The connect gate is not a proxy-escape hatch: the forwarder never
  configures proxies, so the dial address and the validated address are
  the same choice.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any

import requests
import urllib3
import urllib3.connection
import urllib3.util.connection
from requests.adapters import HTTPAdapter

#: The house SSRF predicate shared with ``siem_target_allowed``: one
#: definition of "an address the gateway may not reach uninvited".
_DENIED_FLAGS = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_reserved",
    "is_multicast",
    "is_unspecified",
)


def address_is_denied(ip: str) -> bool:
    """True when *ip* is loopback, link-local, private, reserved,
    multicast or unspecified - the SIEM ranges the gate refuses."""
    address = ipaddress.ip_address(ip)
    return any(getattr(address, flag) for flag in _DENIED_FLAGS)


def resolve_siem_host(host: str) -> list[tuple[int, str]]:
    """Resolve *host* to its full record list, in getaddrinfo order.

    Returns ``[(family, address_string), ...]`` with duplicates dropped.
    Raises (``socket.gaierror``/``OSError``) when the name cannot
    resolve: callers refuse unresolvable targets fail-closed.
    """
    infos = socket.getaddrinfo(host, None)
    out: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        address = str(sockaddr[0])
        if (family, address) not in seen:
            seen.add((family, address))
            out.append((family, address))
    return out


class SIEMTargetRefused(ValueError):
    """The outbound SIEM target is not permitted (RAU-04).

    Raised at validation (via the ``False`` gate value) and at connect
    time by the pinned transport's re-check. Connect-time refusals name
    the offending resolved address; the forwarder buffers the event and
    never dials past one.
    """


def allow_private_opted_in() -> bool:
    """The deliberate opt-in for internal collectors (same contract as
    the validation-side check; one env var, one meaning)."""
    import os

    return os.environ.get("RAUCLE_SIEM_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes")


def make_connect_gate(
    resolver: Callable[[str], list[tuple[int, str]]] | None = None,
) -> Callable[[str, int], list[tuple[int, str]]]:
    """Build the connect-time check: resolve now and judge every record.

    Returned hook: ``(host, port) -> validated address list``; raises
    :class:`SIEMTargetRefused` when any resolved address is denied (or
    when the opt-in is NOT set and the name cannot resolve). This is the
    single seam the pinned connection calls immediately before dialing.
    """
    resolve = resolver or resolve_siem_host

    def check(host: str, port: int) -> list[tuple[int, str]]:
        if allow_private_opted_in():
            # the operator named internal collectors deliberately; the
            # validation side made the same decision for the same URL
            return resolve(host)
        try:
            addrs = resolve(host)
        except OSError:
            raise SIEMTargetRefused(
                f"SIEM target '{host}' does not resolve; refusing fail-closed at connect time"
            ) from None
        denied = [ip for _family, ip in addrs if address_is_denied(ip)]
        if denied:
            raise SIEMTargetRefused(
                f"SIEM target '{host}' resolves to a refused address at connect "
                f"time ({', '.join(sorted(set(denied)))}); no request is dialed "
                "(RAUCLE_SIEM_ALLOW_PRIVATE=1 is the explicit opt-in)"
            )
        return addrs

    return check


# ---------------------------------------------------------------------------
# The pinned connection classes
# ---------------------------------------------------------------------------


def _pinned_new_conn(self: Any) -> socket.socket:
    """The socket factory for pinned connections (overrides the base
    ``HTTPConnection._new_conn``).

    Resolves the ORIGINAL host right now, judges every record, and dials
    the validated address literal. Nothing re-resolves afterwards: the
    address dialed IS the address checked. ``self.host`` stays the
    operator's name, so the Host header, SNI and certificate binding
    never see the pinned address.
    """
    host = self._dns_host or self.host
    addrs = self._connect_gate(host, self.port)
    pinned = addrs[0][1]
    self._siem_pinned_address = pinned
    return urllib3.util.connection.create_connection(
        (pinned, self.port),
        self.timeout,
        source_address=self.source_address,
        socket_options=self.socket_options,
    )


def _pinned_pool_classes(
    connect_gate_hook: Callable[[str, int], list[tuple[int, str]]],
) -> dict[str, type]:
    """Pool classes whose connections pin dial addresses (per session).

    The dial override lives on the CONNECTION class (where the socket is
    created); the pool classes only swap it in, so retry/pool semantics
    stay urllib3's own.
    """

    def _make_conn_cls(base: type) -> type:
        attrs: dict[str, Any] = {
            "_connect_gate": staticmethod(connect_gate_hook),
            "_new_conn": _pinned_new_conn,
        }
        return type(f"Pinned{base.__name__}", (base,), attrs)

    return {
        "http": type(
            "PinnedHTTPConnectionPool",
            (urllib3.HTTPConnectionPool,),
            {"ConnectionCls": _make_conn_cls(urllib3.connection.HTTPConnection)},
        ),
        "https": type(
            "PinnedHTTPSConnectionPool",
            (urllib3.HTTPSConnectionPool,),
            {"ConnectionCls": _make_conn_cls(urllib3.connection.HTTPSConnection)},
        ),
    }


class PinnedHTTPAdapter(HTTPAdapter):
    """A requests adapter whose pools connect by validated address.

    Resolution and the connect-time gate run inside the connection's
    socket factory, immediately before the dial - there is no DNS step
    between the check and the socket. Host, SNI and certificate
    verification keep the original hostname.
    """

    def __init__(self, connect_gate: Callable[[str, int], list[tuple[int, str]]], **kw) -> None:
        # set BEFORE super().__init__: HTTPAdapter.__init__ itself calls
        # init_poolmanager, and the override reads this attribute
        self._pool_classes = _pinned_pool_classes(connect_gate)
        super().__init__(**kw)

    def init_poolmanager(self, *args: Any, **pool_kwargs: Any) -> None:
        super().init_poolmanager(*args, **pool_kwargs)
        # pools are created lazily per host, so re-pointing the class map
        # right after construction applies to every connection made through
        # this adapter
        self.poolmanager.pool_classes_by_scheme = self._pool_classes


def build_pinned_session() -> requests.Session:
    """A session whose HTTP(S) mounts are the pinned, DNS-gated adapter."""
    session = requests.Session()
    adapter = PinnedHTTPAdapter(connect_gate=make_connect_gate())
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


__all__ = [
    "PinnedHTTPAdapter",
    "SIEMTargetRefused",
    "address_is_denied",
    "allow_private_opted_in",
    "build_pinned_session",
    "make_connect_gate",
    "resolve_siem_host",
]
