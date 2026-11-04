"""Tests for the AI manager: configuration, secrets and provider selection.

These tests are edition-agnostic on purpose.  Every release archive ships the
same test suite, but the LOCAL archive defaults to Ollama while the PROVIDER
archive defaults to OpenAI, so the expectations are derived from the shipped
configuration instead of hard-coding one provider.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
import yaml

from backend.app.ai.registry import AIManager
from backend.app.core.config import Settings, reload_settings
from backend.app.core.provider_catalog import descriptor_for
from backend.app.models import ProviderConfigRequest, ProviderEdition, ProviderKind

ROOT_DIR = Path(__file__).resolve().parents[1]


def _expected_defaults(settings) -> tuple[str, str]:
    """The endpoint and model the manager resolves for the shipped provider."""
    descriptor = descriptor_for(settings.ai.provider)
    assert descriptor is not None, f"unknown provider: {settings.ai.provider}"
    return (
        settings.ai.base_url or descriptor.default_base_url,
        settings.ai.model or descriptor.default_model,
    )


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


def test_defaults_follow_the_shipped_configuration(ai_manager):
    """The manager starts from whatever the shipped configuration selects."""
    config = ai_manager.current_config()
    expected = ProviderKind(ai_manager.settings.ai.provider)
    base_url, model = _expected_defaults(ai_manager.settings)
    assert config.provider == expected
    assert config.base_url == base_url
    assert config.model == model
    assert config.edition.value == ai_manager.settings.ai.edition


def test_local_edition_configuration_selects_ollama():
    """The LOCAL edition file really does select Ollama on the loopback port."""
    raw = yaml.safe_load((ROOT_DIR / "config" / "default.local.yaml").read_text(encoding="utf-8"))
    settings = Settings(**raw)
    assert settings.ai.edition == "local"
    assert settings.ai.provider == "ollama"
    assert settings.ai.base_url == "http://localhost:11434"
    assert settings.ai.model == "llama3.1:8b"


def test_provider_edition_configuration_selects_openai():
    """The PROVIDER edition file really does select a hosted provider."""
    raw = yaml.safe_load(
        (ROOT_DIR / "config" / "default.provider.yaml").read_text(encoding="utf-8")
    )
    settings = Settings(**raw)
    assert settings.ai.edition == "provider"
    assert settings.ai.provider == "openai"
    assert settings.ai.base_url == "https://api.openai.com/v1"
    assert settings.ai.model == "gpt-4o-mini"


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
    """A reset returns to the shipped default of this edition, not to a fixed one."""
    ai_manager.save_config(ProviderConfigRequest(provider=ProviderKind.OPENAI, model="gpt-4o"))
    config = ai_manager.reset_config()
    base_url, model = _expected_defaults(ai_manager.settings)
    assert config.provider == ProviderKind(ai_manager.settings.ai.provider)
    assert config.base_url == base_url
    assert config.model == model


def test_an_explicit_provider_survives_the_edition_default():
    """Environment variables are the highest-precedence layer.

    An operator who explicitly selects a provider must not have it silently
    rewritten by the edition's default.
    """
    original = os.environ.get("TRISHUL_AI_PROVIDER")
    os.environ["TRISHUL_AI_PROVIDER"] = "lmstudio"
    try:
        settings = reload_settings()
        assert settings.ai.provider == "lmstudio"
    finally:
        if original is None:
            os.environ.pop("TRISHUL_AI_PROVIDER", None)
        else:
            os.environ["TRISHUL_AI_PROVIDER"] = original
        reload_settings()


def test_switching_provider_moves_the_endpoint_and_the_model():
    """A provider switch must not keep the previous provider's URL."""
    original_provider = os.environ.get("TRISHUL_AI_PROVIDER")
    original_base_url = os.environ.get("TRISHUL_AI_BASE_URL")
    original_model = os.environ.get("TRISHUL_AI_MODEL")
    os.environ["TRISHUL_AI_PROVIDER"] = "anthropic"
    os.environ.pop("TRISHUL_AI_BASE_URL", None)
    os.environ.pop("TRISHUL_AI_MODEL", None)
    try:
        settings = reload_settings()
        assert settings.ai.provider == "anthropic"
        assert settings.ai.base_url == "https://api.anthropic.com"
        assert settings.ai.model == "claude-3-5-sonnet-latest"
    finally:
        for name, value in (
            ("TRISHUL_AI_PROVIDER", original_provider),
            ("TRISHUL_AI_BASE_URL", original_base_url),
            ("TRISHUL_AI_MODEL", original_model),
        ):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        reload_settings()


def test_an_explicit_endpoint_survives_a_provider_switch():
    """A pinned endpoint and model are never overwritten."""
    original_provider = os.environ.get("TRISHUL_AI_PROVIDER")
    original_base_url = os.environ.get("TRISHUL_AI_BASE_URL")
    original_model = os.environ.get("TRISHUL_AI_MODEL")
    os.environ["TRISHUL_AI_PROVIDER"] = "openai-compatible"
    os.environ["TRISHUL_AI_BASE_URL"] = "http://vllm.internal:8000/v1"
    os.environ["TRISHUL_AI_MODEL"] = "qwen2.5-7b-instruct"
    try:
        settings = reload_settings()
        assert settings.ai.provider == "openai-compatible"
        assert settings.ai.base_url == "http://vllm.internal:8000/v1"
        assert settings.ai.model == "qwen2.5-7b-instruct"
    finally:
        for name, value in (
            ("TRISHUL_AI_PROVIDER", original_provider),
            ("TRISHUL_AI_BASE_URL", original_base_url),
            ("TRISHUL_AI_MODEL", original_model),
        ):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        reload_settings()


def test_the_provider_edition_promotes_a_local_provider():
    """Without an explicit choice the PROVIDER edition prefers a hosted provider."""
    original_edition = os.environ.get("TRISHUL_EDITION")
    original_provider = os.environ.get("TRISHUL_AI_PROVIDER")
    os.environ["TRISHUL_EDITION"] = "provider"
    os.environ.pop("TRISHUL_AI_PROVIDER", None)
    try:
        settings = reload_settings()
        assert settings.ai.edition == "provider"
        assert settings.ai.provider == "openai"
        assert settings.ai.base_url == "https://api.openai.com/v1"
        assert settings.ai.model == "gpt-4o-mini"
    finally:
        for name, value in (
            ("TRISHUL_EDITION", original_edition),
            ("TRISHUL_AI_PROVIDER", original_provider),
        ):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        reload_settings()


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
