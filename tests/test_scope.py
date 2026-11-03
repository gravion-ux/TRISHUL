"""Tests for scope enforcement and SSRF protection."""

from __future__ import annotations

import pytest

from backend.app.core.scope import ScopeError, ScopePolicy


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "192.168.1.10", "169.254.169.254", "::1", "0.0.0.0"],
)
def test_private_and_special_addresses_are_refused(address):
    policy = ScopePolicy(allow_private=False)
    problem = policy.address_problem(address, allow_private=False)
    assert problem is not None


def test_public_address_is_allowed():
    policy = ScopePolicy()
    assert policy.address_problem("93.184.216.34", allow_private=False) is None


def test_private_address_allowed_when_opted_in():
    policy = ScopePolicy(allow_private=True)
    assert policy.address_problem("192.168.1.10", allow_private=True) is None


@pytest.mark.asyncio
async def test_blocked_hostname_is_refused():
    policy = ScopePolicy(blocked_hostnames=["metadata.google.internal"])
    with pytest.raises(ScopeError):
        await policy.check("metadata.google.internal")


@pytest.mark.asyncio
async def test_allowlist_blocks_other_hosts():
    policy = ScopePolicy(authorized_targets=["example.com"])
    with pytest.raises(ScopeError):
        await policy.check("evil.test")


@pytest.mark.asyncio
async def test_allowlist_permits_matching_host():
    policy = ScopePolicy(authorized_targets=["example.com"])
    # The allowlist check happens before DNS resolution, so this must not
    # raise an allowlist error even though the name may not resolve here.
    try:
        await policy.check("example.com")
    except ScopeError as exc:
        assert "not in the authorized target list" not in str(exc)


@pytest.mark.asyncio
async def test_ip_literal_is_checked_directly():
    policy = ScopePolicy()
    with pytest.raises(ScopeError):
        await policy.check("127.0.0.1")
