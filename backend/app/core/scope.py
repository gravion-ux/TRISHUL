"""Target scope enforcement and SSRF protection.

Every active operation is gated here. The rules are deliberately strict:
a target must resolve to a public address, and (when an allowlist is
configured) must additionally match one of the approved scopes.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlparse

from backend.app.core.utils import is_ip


class ScopeError(ValueError):
    """Raised when a target is outside the permitted testing scope."""


class ScopePolicy:
    """Evaluates targets against the configured scope rules.

    Parameters
    ----------
    allow_private:
        Permit RFC1918 / loopback / link-local addresses. Required for
        internal engagements, off by default so that a stray target cannot
        reach cloud metadata services or internal admin panels.
    authorized_targets:
        Optional allowlist of hostnames or suffixes. When non-empty, only
        matching hosts may be scanned.
    blocked_hostnames:
        Hostnames that are always refused (cloud metadata endpoints).
    """

    def __init__(
        self,
        *,
        allow_private: bool = False,
        authorized_targets: Iterable[str] | None = None,
        blocked_hostnames: Iterable[str] | None = None,
    ) -> None:
        self.allow_private = allow_private
        self.authorized_targets = [item.strip().lower() for item in (authorized_targets or []) if item.strip()]
        self.blocked_hostnames = [item.strip().lower() for item in (blocked_hostnames or []) if item.strip()]

    # -- allowlist ---------------------------------------------------------

    def _matches_allowlist(self, host: str) -> bool:
        if not self.authorized_targets:
            return True
        candidate = host.lower()
        for entry in self.authorized_targets:
            if candidate == entry:
                return True
            if entry.startswith("*.") and candidate.endswith(entry[1:]):
                return True
            if candidate.endswith("." + entry.lstrip("*.")):
                return True
        return False

    def _is_blocked_hostname(self, host: str) -> bool:
        candidate = host.lower().rstrip(".")
        return any(
            candidate == blocked or candidate.endswith("." + blocked)
            for blocked in self.blocked_hostnames
        )

    # -- address checks ----------------------------------------------------

    @staticmethod
    def address_problem(address: str, allow_private: bool) -> str | None:
        """Return a reason string when ``address`` must not be contacted."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if ip.is_loopback:
            return "loopback address"
        if ip.is_link_local:
            return "link-local address"
        if ip.is_multicast:
            return "multicast address"
        if ip.is_unspecified:
            return "unspecified address"
        if ip.is_reserved:
            return "reserved address"
        if ip.is_private and not allow_private:
            return "private address"
        return None

    async def resolve_addresses(self, host: str) -> list[str]:
        """Resolve ``host`` to every address it maps to.

        The name is resolved on every check rather than cached, so a host
        that starts resolving to a blocked address is caught at the next
        request instead of being trusted for the rest of the scan.
        """
        if is_ip(host):
            return [host]
        try:
            infos = await asyncio.to_thread(
                socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP
            )
        except socket.gaierror as exc:
            raise ScopeError(f"Could not resolve target host {host!r}: {exc}") from exc
        addresses: list[str] = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ScopeError(f"Target host {host!r} did not resolve to any address.")
        return addresses

    # -- entry point -------------------------------------------------------

    async def check(self, host: str) -> list[str]:
        """Validate ``host`` and return the addresses it resolved to.

        Raises
        ------
        ScopeError
            When the host is blocked, outside the allowlist, or resolves to
            a non-public address while private targets are not permitted.
        """
        if not host:
            raise ScopeError("Target host must not be empty.")

        if self._is_blocked_hostname(host):
            raise ScopeError(f"Target {host!r} is on the blocked-hostname list.")

        if not self._matches_allowlist(host):
            raise ScopeError(
                f"Target {host!r} is not in the authorized target list "
                f"({', '.join(self.authorized_targets)})."
            )

        addresses = await self.resolve_addresses(host)
        for address in addresses:
            problem = self.address_problem(address, self.allow_private)
            if problem:
                raise ScopeError(
                    f"Refusing to scan {host!r}: it resolves to {address} ({problem}). "
                    "Set TRISHUL_ALLOW_PRIVATE_TARGETS=1 if this is an authorized internal test."
                )
        return addresses

    async def check_url(self, url: str) -> str:
        """Validate the host of ``url`` and return it.

        This is the URL-shaped entry point used by the verification
        agent: every request it makes -- and every redirect hop it
        follows -- is checked here before a socket is opened.
        """
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").strip()
        if not host:
            raise ScopeError(f"Could not determine a host from {url!r}.")
        await self.check(host)
        return host
