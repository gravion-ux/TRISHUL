"""Validation for the URLs TRISHUL contacts on its own initiative.

Two kinds of outbound request exist in TRISHUL:

* requests to a *scan target*, which are gated by the scope policy
  (:class:`backend.app.core.scope.ScopePolicy`), and
* requests to an *operator-configured endpoint* -- an AI provider or an
  enrichment integration -- which are gated by :class:`UrlGuard` here.

Both gates expose ``check_url(url)`` so that
:func:`request_with_safe_redirects` can re-validate every redirect hop
before the request is made.

The HTTP client must never follow a redirect on its own. A remote server
could otherwise bounce TRISHUL into the private network -- or into the
cloud metadata service -- with the configured credentials still
attached, and no gate would ever be consulted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

import httpx

from backend.app.core.utils import is_ip

#: Hosts that must never be contacted, whatever the operator configured.
#: They are the well-known cloud metadata endpoints.
DEFAULT_BLOCKED_HOSTNAMES: tuple[str, ...] = (
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
)

#: Status codes that carry a ``Location`` header.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

#: Headers that carry a credential and must not cross an origin boundary.
SENSITIVE_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "x-api-key"}
)


class UrlGuardError(ValueError):
    """Raised when an outbound URL must not be contacted."""


class UrlGate(Protocol):
    """The contract every URL gate implements."""

    async def check_url(self, url: str) -> str:
        """Validate ``url`` and return the host it points at."""
        ...


@dataclass(frozen=True)
class UrlGuard:
    """Validates the endpoints the operator configures.

    Local and internal inference servers are a supported deployment, so
    private and loopback addresses are allowed by default. The cloud
    metadata endpoints are always refused, and so is every address that
    cannot be reached safely (link-local, unspecified, multicast,
    reserved).
    """

    allow_private: bool = True
    blocked_hostnames: tuple[str, ...] = DEFAULT_BLOCKED_HOSTNAMES
    _resolved: dict[str, list[str]] = field(
        default_factory=dict, compare=False, repr=False
    )

    # -- structure ---------------------------------------------------------

    def check(self, url: str) -> str:
        """Validate the *shape* of ``url`` without any I/O.

        Returns the host the URL points at.
        """
        parsed = urlparse(url or "")
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise UrlGuardError(
                f"Unsupported URL scheme {scheme or '(missing)'!r}: only http and https "
                "may be contacted."
            )
        if parsed.username or parsed.password:
            raise UrlGuardError(
                "A URL must not carry credentials; send them in a header instead."
            )
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            raise UrlGuardError(f"Could not determine a host from {url!r}.")
        if self._is_blocked(host):
            raise UrlGuardError(
                f"Refusing to contact {host!r}: it is on the blocked-hostname list."
            )
        return host

    def _is_blocked(self, host: str) -> bool:
        for blocked in self.blocked_hostnames:
            entry = str(blocked).lower().rstrip(".")
            if not entry:
                continue
            if host == entry or host.endswith("." + entry):
                return True
        return False

    # -- addresses ---------------------------------------------------------

    def _address_problem(self, address: str) -> str | None:
        """Return a reason string when ``address`` must not be contacted."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        # The order matters. Python classifies the IPv6 loopback (``::1``) as
        # *reserved* as well, so loopback has to be settled before the
        # reserved check -- otherwise a local inference server on ``::1``
        # would be refused even though loopback is explicitly allowed.
        if ip.is_unspecified:
            return "unspecified address"
        if ip.is_multicast:
            return "multicast address"
        if ip.is_link_local:
            return "link-local address"
        if ip.is_loopback:
            return None if self.allow_private else "private address"
        if ip.is_reserved:
            return "reserved address"
        if ip.is_private:
            return None if self.allow_private else "private address"
        return None

    async def _resolve(self, host: str) -> list[str]:
        """Resolve ``host`` to the addresses it maps to (best effort)."""
        if is_ip(host):
            return [host]
        cached = self._resolved.get(host)
        if cached is not None:
            return cached
        try:
            infos = await asyncio.to_thread(
                socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP
            )
        except socket.gaierror:
            # The name does not resolve. The request itself would fail, so
            # there is nothing left to protect against on this hop.
            return []
        addresses: list[str] = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        self._resolved[host] = addresses
        return addresses

    async def check_url(self, url: str) -> str:
        """Validate ``url`` and return the host it points at."""
        host = self.check(url)
        for address in await self._resolve(host):
            problem = self._address_problem(address)
            if problem:
                raise UrlGuardError(
                    f"Refusing to contact {host!r}: it resolves to {address} ({problem})."
                )
        return host


# ---------------------------------------------------------------------------
# Redirect-safe requests
# ---------------------------------------------------------------------------


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port)


def _drop_sensitive_headers(headers: dict[str, str]) -> None:
    for name in list(headers):
        if name.lower() in SENSITIVE_HEADERS:
            headers.pop(name, None)


async def request_with_safe_redirects(
    client: httpx.AsyncClient,
    url: str,
    *,
    guard: UrlGate,
    method: str = "GET",
    max_hops: int = 5,
    **kwargs: Any,
) -> httpx.Response:
    """Send a request, re-validating every redirect hop.

    ``httpx`` would otherwise follow the whole chain on its own. Every
    hop is validated by ``guard`` *before* the request is made, and a
    credential is dropped as soon as the chain crosses an origin
    boundary.
    """
    current = url
    headers = {str(key): str(value) for key, value in (kwargs.pop("headers", None) or {}).items()}
    for _hop in range(max_hops + 1):
        await guard.check_url(current)
        request = client.build_request(method, current, headers=headers, **kwargs)
        response = await client.send(request, follow_redirects=False)
        if response.status_code not in REDIRECT_STATUSES:
            return response

        location = response.headers.get("location")
        if not location:
            return response

        await response.aclose()
        next_url = urljoin(current, location)
        if _origin(next_url) != _origin(current):
            _drop_sensitive_headers(headers)
        if response.status_code == 303 and method.upper() != "HEAD":
            method = "GET"
            kwargs.pop("json", None)
            kwargs.pop("content", None)
            kwargs.pop("data", None)
        current = next_url

    raise UrlGuardError(f"Refusing to follow more than {max_hops} redirects.")
