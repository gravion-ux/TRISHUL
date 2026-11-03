"""Tests for authentication, tokens and rate limiting."""

from __future__ import annotations

import time

from backend.app.core.security import (
    RateLimiter,
    TokenManager,
    api_key_hint,
    hash_password,
    verify_password,
)


def test_password_hash_roundtrip():
    encoded = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong password", encoded)


def test_password_hash_is_salted():
    first = hash_password("same-password")
    second = hash_password("same-password")
    assert first != second


def test_verify_password_rejects_garbage():
    assert not verify_password("anything", "not-a-hash")


def test_token_issue_and_verify(tmp_path):
    manager = TokenManager(tmp_path / ".secret")
    token, ttl = manager.issue("admin")
    assert ttl > 0
    payload = manager.verify(token)
    assert payload is not None
    assert payload["sub"] == "admin"


def test_token_rejects_tampering(tmp_path):
    manager = TokenManager(tmp_path / ".secret")
    token, _ = manager.issue("admin")
    header, _, signature = token.rpartition(".")
    forged = f"{header}.{'x' * len(signature)}"
    assert manager.verify(forged) is None


def test_token_rejects_garbage(tmp_path):
    manager = TokenManager(tmp_path / ".secret")
    assert manager.verify("nonsense") is None
    assert manager.verify("") is None


def test_expired_token_is_rejected(tmp_path):
    manager = TokenManager(tmp_path / ".secret", ttl_seconds=-1)
    token, _ = manager.issue("admin")
    assert manager.verify(token) is None


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(limit=3, window_seconds=60)
    for _ in range(3):
        allowed, _, _ = limiter.allow("client")
        assert allowed
    allowed, remaining, retry_after = limiter.allow("client")
    assert not allowed
    assert remaining == 0
    assert retry_after > 0


def test_rate_limiter_is_per_key():
    limiter = RateLimiter(limit=1, window_seconds=60)
    assert limiter.allow("a")[0]
    assert limiter.allow("b")[0]
    assert not limiter.allow("a")[0]


def test_rate_limiter_window_expires():
    limiter = RateLimiter(limit=1, window_seconds=1)
    assert limiter.allow("client")[0]
    time.sleep(1.1)
    assert limiter.allow("client")[0]


def test_api_key_hint_never_reveals_the_secret():
    hint = api_key_hint("sk-abcdefghijklmnopqrstuvwxyz")
    assert "abcdefghijklmnopqrstuvwxyz" not in hint
    assert hint.startswith("sk-a")
