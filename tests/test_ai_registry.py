"""Tests for the AI manager: configuration, secrets and provider selection."""

from __future__ import annotations

import httpx
import pytest

from backend.app.ai.registry import AIManager
from backend.app.models import ProviderConfigRequest, ProviderEdition, ProviderKind


def test_catalog_covers_both_editions(ai_manager):
    kinds = {descriptor.kind for descriptor in ai_manager.catalog()}
    assert ProviderKind.OLLAMA in kinds
    assert ProviderKind.LMSTUDIO in kinds
    assert ProviderKind.LLAMACPP in kinds
    assert ProviderKind.OPENAI in kinds
    assert ProviderKind.ANTHROPIC in kinds
    assert ProviderKind.GEMINI in kinds
    assert ProviderKind.OPENAI_COMPATIBLE in kinds
    assert ProviderKind.CUSTOM in kinds

    editions = {descriptor.edition for descriptor in ai_manager.catalog()}
    assert editions == {ProviderEdition.LOCAL, ProviderEdition.PROVIDER}


def test_local_edition_defaults_to_ollama(ai_manager):
    config = ai_manager.current_config()
    assert config.provider == ProviderKind.OLLAMA
    assert config.base_url == "http://localhost:11434"


def test_save_config_persists_provider(ai_manager):
    config = ai_manager.save_config(
        ProviderConfigRequest(
            provider=ProviderKind.OPENAI,
            model="gpt-4o",
            base_url="https://api.openai.com/v1",
            api_key="sk-secret-value-123456",
            edition=ProviderEdition.PROVIDER,
        )
    )
    assert config.provider == ProviderKind.OPENAI
    assert config.model == "gpt-4o"
    assert config.has_api_key is True
    assert "secret-value" not in config.api_key_hint
    assert config.api_key_hint.startswith("sk-s")


def test_api_key_is_stored_encrypted(ai_manager, storage, credentials):
    ai_manager.save_config(
        ProviderConfigRequest(
            provider=ProviderKind.OPENAI, api_key="sk-secret-value-123456"
        )
    )
    # The configuration itself must never contain the secret.
    stored = storage.get_provider_config()
    assert "sk-secret-value-123456" not in str(stored)
    # The encrypted store holds the real value.
    assert credentials.get("provider:openai") == "sk-secret-value-123456"


def test_keeping_the_existing_key_when_not_resupplied(ai_manager):
    ai_manager.save_config(
        ProviderConfigRequest(provider=ProviderKind.OPENAI, api_key="sk-secret-value-123456")
    )
    config = ai_manager.save_config(ProviderConfigRequest(provider=ProviderKind.OPENAI, model="gpt-4o"))
    assert config.has_api_key is True


def test_reset_config_restores_defaults(ai_manager):
    ai_manager.save_config(ProviderConfigRequest(provider=ProviderKind.OPENAI, model="gpt-4o"))
    config = ai_manager.reset_config()
    assert config.provider == ProviderKind.OLLAMA


def test_build_provider_selects_the_right_class(ai_manager):
    from backend.app.ai.providers.anthropic import AnthropicProvider
    from backend.app.ai.providers.ollama import OllamaProvider
    from backend.app.ai.providers.openai_compatible import OpenAICompatibleProvider

    assert isinstance(ai_manager.build_provider(kind=ProviderKind.OLLAMA), OllamaProvider)
    assert isinstance(ai_manager.build_provider(kind=ProviderKind.ANTHROPIC), AnthropicProvider)
    assert isinstance(
        ai_manager.build_provider(kind=ProviderKind.OPENAI_COMPATIBLE),
        OpenAICompatibleProvider,
    )
    assert isinstance(ai_manager.build_provider(kind=ProviderKind.LMSTUDIO), OpenAICompatibleProvider)


@pytest.mark.asyncio
async def test_test_reports_a_failing_connection(ai_manager, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="nope")

    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    result = await ai_manager.test(kind=ProviderKind.OLLAMA)
    assert result.ok is False
    assert result.message


@pytest.mark.asyncio
async def test_health_requires_a_key_for_cloud_providers(ai_manager):
    ai_manager.save_config(
        ProviderConfigRequest(provider=ProviderKind.OPENAI, api_key=None, base_url="https://x.test/v1")
    )
    ai_manager.credentials.delete("provider:openai")
    health = await ai_manager.health()
    assert health.configured is False
    assert "API key" in health.message
