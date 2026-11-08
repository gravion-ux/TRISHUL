"""The token endpoint must be rate limited by source address.

``POST /api/auth/token`` accepted an unlimited number of password
guesses. Every other authenticated route was rate limited, so the login
endpoint was the cheapest way to grind the administrator password.
"""

from __future__ import annotations

from backend.app import main as main_module
from backend.app.core.security import RateLimiter
from conftest import TEST_PASSWORD


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, host: str) -> None:
        self.client = _FakeClient(host)


def _fresh_limiter(settings, monkeypatch) -> RateLimiter:
    limiter = RateLimiter(
        limit=settings.security.login_rate_limit_attempts,
        window_seconds=settings.security.login_rate_limit_window_seconds,
    )
    monkeypatch.setattr(main_module, "login_limiter", limiter)
    return limiter


def test_the_client_key_is_the_source_address():
    assert main_module._client_key(_FakeRequest("203.0.113.9")) == "203.0.113.9"


def test_the_login_limiter_uses_the_configured_budget(settings):
    assert main_module.login_limiter.limit == settings.security.login_rate_limit_attempts
    assert (
        main_module.login_limiter.window_seconds
        == settings.security.login_rate_limit_window_seconds
    )


def test_repeated_login_attempts_are_refused(client, settings, monkeypatch):
    _fresh_limiter(settings, monkeypatch)

    for _ in range(settings.security.login_rate_limit_attempts):
        response = client.post(
            "/api/auth/token", json={"username": "admin", "password": "wrong-password"}
        )
        assert response.status_code == 401, response.text

    blocked = client.post(
        "/api/auth/token", json={"username": "admin", "password": TEST_PASSWORD}
    )

    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After")


def test_a_correct_login_still_works_before_the_budget_is_spent(client, settings, monkeypatch):
    _fresh_limiter(settings, monkeypatch)

    response = client.post(
        "/api/auth/token", json={"username": "admin", "password": TEST_PASSWORD}
    )

    assert response.status_code == 200, response.text
    assert response.json()["access_token"]


def test_the_budget_is_tracked_per_source_address(client, settings, monkeypatch):
    limiter = _fresh_limiter(settings, monkeypatch)

    for _ in range(settings.security.login_rate_limit_attempts):
        assert limiter.allow("login:203.0.113.9")[0] is True

    assert limiter.allow("login:203.0.113.9")[0] is False
    assert limiter.allow("login:198.51.100.4")[0] is True
