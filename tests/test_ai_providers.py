"""Tests for the AI provider implementations.

Every provider is exercised against a mocked HTTP transport so the tests
prove the request shape and the response parsing without touching a network.
"""

from __future__ import annotations

import json

import httpx
import pytest

from backend.app.ai.base import AIRequest, ProviderError
from backend.app.ai.providers.anthropic import AnthropicProvider
from backend.app.ai.providers.gemini import GeminiProvider
from backend.app.ai.providers.ollama import OllamaProvider
from backend.app.ai.providers.openai_compatible import OpenAICompatibleProvider
from backend.app.models import ProviderKind


def install_transport(monkeypatch, handler) -> None:
    """Route every httpx.AsyncClient through a mock transport."""
    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_ollama_returns_completion(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {"role": "assistant", "content": '{"severity":"High"}'},
                "done": True,
            },
        )

    install_transport(monkeypatch, handler)
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1:8b")
    response = await provider.complete(
        AIRequest(prompt="p", system="s", json_mode=True)
    )

    assert response.text == '{"severity":"High"}'
    assert response.provider == "ollama"
    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["body"]["model"] == "llama3.1:8b"
    assert captured["body"]["format"] == "json"
    assert captured["body"]["messages"][0]["role"] == "system"


@pytest.mark.asyncio
async def test_ollama_lists_models(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": [{"name": "llama3.1:8b"}, {"name": "qwen2.5:7b"}]})

    install_transport(monkeypatch, handler)
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1:8b")
    models = await provider.list_models()
    assert models == ["llama3.1:8b", "qwen2.5:7b"]


@pytest.mark.asyncio
async def test_ollama_reports_http_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    install_transport(monkeypatch, handler)
    provider = OllamaProvider(base_url="http://localhost:11434", model="m")
    with pytest.raises(ProviderError):
        await provider.complete(AIRequest(prompt="p"))


@pytest.mark.asyncio
async def test_openai_compatible_sends_bearer_token(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"role": "assistant", "content": "hello"}}],
                "usage": {"total_tokens": 12},
            },
        )

    install_transport(monkeypatch, handler)
    provider = OpenAICompatibleProvider(
        base_url="https://api.openai.com/v1", model="gpt-4o-mini", api_key="sk-test-key"
    )
    response = await provider.complete(AIRequest(prompt="p", system="s", json_mode=True))

    assert response.text == "hello"
    assert captured["auth"] == "Bearer sk-test-key"
    assert captured["body"]["response_format"] == {"type": "json_object"}
    # OpenAI-compatible servers reject json_object unless "json" is mentioned.
    assert "json" in captured["body"]["messages"][0]["content"].lower()


@pytest.mark.asyncio
async def test_openai_compatible_omits_response_format_without_json_mode(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"role": "assistant", "content": "hello"}}],
            },
        )

    install_transport(monkeypatch, handler)
    provider = OpenAICompatibleProvider(
        base_url="https://api.openai.com/v1", model="gpt-4o-mini", api_key="sk-test-key"
    )
    await provider.complete(AIRequest(prompt="p", system="s"))

    assert "response_format" not in captured["body"]


@pytest.mark.asyncio
async def test_openai_compatible_lists_models(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}]})

    install_transport(monkeypatch, handler)
    provider = OpenAICompatibleProvider(base_url="https://api.openai.com/v1", model="x")
    assert await provider.list_models() == ["gpt-4o-mini", "gpt-4o"]


@pytest.mark.asyncio
async def test_openai_compatible_handles_empty_choices(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    install_transport(monkeypatch, handler)
    provider = OpenAICompatibleProvider(base_url="https://api.openai.com/v1", model="x")
    with pytest.raises(ProviderError):
        await provider.complete(AIRequest(prompt="p"))


@pytest.mark.asyncio
async def test_anthropic_uses_x_api_key(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["key"] = request.headers.get("x-api-key")
        captured["version"] = request.headers.get("anthropic-version")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"model": "claude-3-5-sonnet-latest", "content": [{"type": "text", "text": "hi"}]},
        )

    install_transport(monkeypatch, handler)
    provider = AnthropicProvider(
        base_url="https://api.anthropic.com", model="claude-3-5-sonnet-latest", api_key="sk-ant-test"
    )
    response = await provider.complete(AIRequest(prompt="p", system="s"))

    assert response.text == "hi"
    assert captured["key"] == "sk-ant-test"
    assert captured["version"] == "2023-06-01"
    assert captured["body"]["system"] == "s"


@pytest.mark.asyncio
async def test_gemini_uses_key_query_parameter(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {"content": {"parts": [{"text": "gemini says hi"}]}, "finishReason": "STOP"}
                ]
            },
        )

    install_transport(monkeypatch, handler)
    provider = GeminiProvider(
        base_url="https://generativelanguage.googleapis.com",
        model="gemini-2.0-flash",
        api_key="AIza-test-key",
    )
    response = await provider.complete(AIRequest(prompt="p", system="s"))

    assert response.text == "gemini says hi"
    assert "key=AIza-test-key" in captured["url"]
    assert captured["body"]["systemInstruction"]["parts"][0]["text"] == "s"


@pytest.mark.asyncio
async def test_provider_health_reports_unreachable(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    install_transport(monkeypatch, handler)
    provider = OllamaProvider(base_url="http://localhost:11434", model="m")
    reachable, message = await provider.health()
    assert reachable is False
    assert "503" in message


def test_provider_kinds_are_distinct():
    assert OllamaProvider.kind == ProviderKind.OLLAMA
    assert AnthropicProvider.kind == ProviderKind.ANTHROPIC
    assert GeminiProvider.kind == ProviderKind.GEMINI
    assert OpenAICompatibleProvider.kind == ProviderKind.OPENAI_COMPATIBLE
