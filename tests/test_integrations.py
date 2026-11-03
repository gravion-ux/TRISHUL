"""Tests for the external API integration system."""

from __future__ import annotations

import httpx
import pytest

from backend.app.models import IntegrationAuthType, IntegrationConfigRequest
from backend.app.services.integrations import IntegrationError, IntegrationManager


def install_transport(monkeypatch, handler) -> None:
    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _request(name: str = "demo") -> IntegrationConfigRequest:
    return IntegrationConfigRequest(
        name=name,
        base_url="https://api.example.test",
        path="/lookup",
        method="GET",
        auth_type=IntegrationAuthType.BEARER,
        api_key="secret-token",
        params={"host": "example.com"},
        response_json_path="data.result",
        rate_limit_per_minute=5,
        cache_ttl_seconds=60,
    )


def test_save_and_list(integration_manager):
    config = integration_manager.save(_request())
    assert config.name == "demo"
    assert config.has_api_key is True
    assert "secret-token" not in config.model_dump_json()
    assert len(integration_manager.list()) == 1


def test_api_key_is_stored_encrypted(integration_manager, storage, credentials):
    integration_manager.save(_request())
    stored = storage.get_integration("demo")
    assert "secret-token" not in str(stored)
    assert credentials.get("integration:demo") == "secret-token"


@pytest.mark.asyncio
async def test_invoke_extracts_the_configured_path(integration_manager, monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": {"result": {"score": 7}}})

    install_transport(monkeypatch, handler)
    integration_manager.save(_request())
    result = await integration_manager.invoke("demo")

    assert result.ok is True
    assert result.data == {"score": 7}
    assert captured["auth"] == "Bearer secret-token"
    assert "host=example.com" in captured["url"]


@pytest.mark.asyncio
async def test_invoke_fails_when_the_path_is_missing(integration_manager, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": True})

    install_transport(monkeypatch, handler)
    integration_manager.save(_request())
    with pytest.raises(IntegrationError):
        await integration_manager.invoke("demo")


@pytest.mark.asyncio
async def test_invoke_caches_the_response(integration_manager, monkeypatch):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json={"data": {"result": 1}})

    install_transport(monkeypatch, handler)
    integration_manager.save(_request())
    await integration_manager.invoke("demo")
    second = await integration_manager.invoke("demo")

    assert calls["count"] == 1
    assert second.cached is True


@pytest.mark.asyncio
async def test_rate_limit_is_enforced(integration_manager, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"result": 1}})

    install_transport(monkeypatch, handler)
    request = _request()
    request.rate_limit_per_minute = 1
    integration_manager.save(request)

    await integration_manager.invoke("demo")
    with pytest.raises(IntegrationError):
        await integration_manager.invoke("demo")


@pytest.mark.asyncio
async def test_http_errors_are_reported(integration_manager, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    install_transport(monkeypatch, handler)
    integration_manager.save(_request())
    with pytest.raises(IntegrationError):
        await integration_manager.invoke("demo")


@pytest.mark.asyncio
async def test_disabled_integration_is_refused(integration_manager, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    install_transport(monkeypatch, handler)
    request = _request()
    request.enabled = False
    integration_manager.save(request)
    with pytest.raises(IntegrationError):
        await integration_manager.invoke("demo")


def test_delete_removes_the_definition_and_the_secret(integration_manager, credentials):
    integration_manager.save(_request())
    assert integration_manager.delete("demo") is True
    assert integration_manager.get("demo") is None
    assert credentials.get("integration:demo") is None


@pytest.mark.asyncio
async def test_enrich_with_no_integrations_returns_empty(integration_manager):
    assert await integration_manager.enrich({"host": "example.com"}) == []
