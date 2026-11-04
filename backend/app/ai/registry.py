"""AI provider registry and manager.

The manager owns the *active* provider configuration and hands out ready to
use provider instances. Resolution order for the active configuration is:

1. A configuration saved by the operator (persisted in the database).
2. The YAML defaults, overlaid with environment variables.

API keys are never stored in the configuration: they live encrypted in the
credential store and are looked up on demand.
"""

from __future__ import annotations

import os
from typing import Any

from backend.app.ai.base import AIProvider, AIRequest, AIResponse, ProviderError
from backend.app.ai.providers.anthropic import AnthropicProvider
from backend.app.ai.providers.gemini import GeminiProvider
from backend.app.ai.providers.ollama import OllamaProvider
from backend.app.ai.providers.openai_compatible import OpenAICompatibleProvider
from backend.app.core.config import Settings
from backend.app.core.provider_catalog import DESCRIPTORS as DESCRIPTORS
from backend.app.core.provider_catalog import PROVIDER_CATALOG as PROVIDER_CATALOG
from backend.app.core.secrets import CredentialStore, provider_secret_name
from backend.app.core.security import api_key_hint
from backend.app.core.storage import Storage
from backend.app.core.utils import utcnow
from backend.app.models import (
    AiHealth,
    ProviderConfig,
    ProviderConfigRequest,
    ProviderDescriptor,
    ProviderEdition,
    ProviderKind,
    ProviderTestResult,
)

# Environment variables that can supply a key when the operator has not
# stored one in the dashboard. This keeps CI and headless usage possible.
ENV_KEYS: dict[ProviderKind, tuple[str, ...]] = {
    ProviderKind.OPENAI: ("OPENAI_API_KEY",),
    ProviderKind.OPENAI_COMPATIBLE: ("OPENAI_API_KEY", "TRISHUL_AI_API_KEY"),
    ProviderKind.CUSTOM: ("TRISHUL_AI_API_KEY",),
    ProviderKind.ANTHROPIC: ("ANTHROPIC_API_KEY",),
    ProviderKind.GEMINI: ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    ProviderKind.OLLAMA: ("OLLAMA_API_KEY",),
    ProviderKind.LMSTUDIO: ("LMSTUDIO_API_KEY",),
    ProviderKind.LLAMACPP: ("LLAMACPP_API_KEY",),
}

# The catalogue itself lives in the core layer so that the configuration layer
# can resolve a provider's documented endpoint and model without importing the
# AI layer. It is re-exported here because this module is its historical home
# and ``backend.app.ai`` publishes it as part of the public surface.


class AIManager:
    """Creates providers and runs completions against the active configuration."""

    def __init__(
        self,
        storage: Storage,
        credentials: CredentialStore,
        settings: Settings,
    ) -> None:
        self.storage = storage
        self.credentials = credentials
        self.settings = settings

    # -- configuration -----------------------------------------------------

    def catalog(self) -> list[ProviderDescriptor]:
        return list(PROVIDER_CATALOG)

    def _defaults_for(self, kind: ProviderKind, edition: ProviderEdition) -> ProviderDescriptor:
        descriptor = DESCRIPTORS.get(kind)
        if descriptor is None:
            raise ValueError(f"Unknown provider: {kind}")
        return descriptor

    def current_config(self) -> ProviderConfig:
        """Return the active configuration without exposing any secret."""
        saved = self.storage.get_provider_config() or {}
        kind_value = saved.get("provider") or self.settings.ai.provider
        try:
            kind = ProviderKind(kind_value)
        except ValueError:
            kind = ProviderKind.OLLAMA
        edition_value = saved.get("edition") or self.settings.ai.edition
        try:
            edition = ProviderEdition(edition_value)
        except ValueError:
            edition = ProviderEdition.LOCAL

        descriptor = self._defaults_for(kind, edition)
        # A saved configuration wins. Then the resolved settings (the YAML
        # defaults plus any environment override). Only then the catalogue
        # default for the provider.
        base_url = saved.get("base_url") or self.settings.ai.base_url or descriptor.default_base_url
        model = saved.get("model") or self.settings.ai.model or descriptor.default_model
        timeout = int(saved.get("timeout_seconds") or self.settings.ai.timeout_seconds)

        key = self.api_key_for(kind)
        return ProviderConfig(
            edition=edition,
            provider=kind,
            model=model,
            base_url=base_url,
            timeout_seconds=timeout,
            has_api_key=bool(key),
            api_key_hint=api_key_hint(key),
            updated_at=self._parse_timestamp(saved.get("updated_at")),
        )

    @staticmethod
    def _parse_timestamp(value: Any):
        if not value:
            return None
        from datetime import datetime

        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None

    def api_key_for(self, kind: ProviderKind) -> str | None:
        """Return the API key for ``kind`` from the store, then the environment."""
        stored = self.credentials.get(provider_secret_name(kind.value))
        if stored:
            return stored
        for env_name in ENV_KEYS.get(kind, ()):
            value = os.environ.get(env_name)
            if value:
                return value
        return None

    def save_config(self, request: ProviderConfigRequest) -> ProviderConfig:
        """Persist a new provider configuration and optionally a new key."""
        current = self.current_config()
        kind = request.provider
        descriptor = self._defaults_for(kind, request.edition or current.edition)

        edition = request.edition or current.edition
        base_url = (request.base_url or descriptor.default_base_url).rstrip("/")
        model = request.model or descriptor.default_model
        timeout = request.timeout_seconds or current.timeout_seconds

        if request.api_key is not None:
            self.credentials.set(provider_secret_name(kind.value), request.api_key or None)

        payload = {
            "edition": edition.value,
            "provider": kind.value,
            "model": model,
            "base_url": base_url,
            "timeout_seconds": timeout,
            "updated_at": utcnow().isoformat(),
        }
        self.storage.set_provider_config(payload)
        return self.current_config()

    def reset_config(self) -> ProviderConfig:
        """Drop the saved configuration and fall back to the edition defaults."""
        self.storage.set_provider_config({})
        return self.current_config()

    # -- provider construction --------------------------------------------

    def build_provider(
        self,
        *,
        kind: ProviderKind | None = None,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: int | None = None,
    ) -> AIProvider:
        """Instantiate a provider client."""
        config = self.current_config()
        kind = kind or config.provider
        model = model or config.model
        base_url = (base_url or config.base_url).rstrip("/")
        timeout = timeout or config.timeout_seconds
        key = api_key if api_key is not None else self.api_key_for(kind)

        if kind == ProviderKind.OLLAMA:
            return OllamaProvider(base_url=base_url, model=model, api_key=key, timeout=timeout)
        if kind == ProviderKind.ANTHROPIC:
            return AnthropicProvider(base_url=base_url, model=model, api_key=key, timeout=timeout)
        if kind == ProviderKind.GEMINI:
            return GeminiProvider(base_url=base_url, model=model, api_key=key, timeout=timeout)
        # openai, lmstudio, llamacpp, openai-compatible and custom all speak
        # the OpenAI dialect.
        return OpenAICompatibleProvider(
            base_url=base_url, model=model, api_key=key, timeout=timeout
        )

    # -- usage -------------------------------------------------------------

    async def complete(self, request: AIRequest) -> AIResponse:
        """Run a completion using the active configuration."""
        provider = self.build_provider()
        return await provider.complete(request)

    async def health(self) -> AiHealth:
        """Probe the active provider without raising."""
        config = self.current_config()
        descriptor = self._defaults_for(config.provider, config.edition)
        if descriptor.requires_api_key and not config.has_api_key:
            return AiHealth(
                configured=False,
                provider=config.provider.value,
                model=config.model,
                reachable=False,
                message=f"No API key configured for {descriptor.label}.",
            )
        try:
            provider = self.build_provider()
            reachable, message = await provider.health()
        except ProviderError as exc:
            return AiHealth(
                configured=True,
                provider=config.provider.value,
                model=config.model,
                reachable=False,
                message=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 - health must never raise
            return AiHealth(
                configured=True,
                provider=config.provider.value,
                model=config.model,
                reachable=False,
                message=f"{type(exc).__name__}: {exc}",
            )
        return AiHealth(
            configured=True,
            provider=config.provider.value,
            model=config.model,
            reachable=reachable,
            message=message,
        )

    async def list_models(
        self, kind: ProviderKind | None = None, base_url: str | None = None
    ) -> list[str]:
        provider = self.build_provider(kind=kind, base_url=base_url)
        return await provider.list_models()

    async def test(
        self,
        *,
        kind: ProviderKind | None = None,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> ProviderTestResult:
        """Probe a provider configuration, optionally without saving it."""
        started = _now_ms()
        try:
            provider = self.build_provider(
                kind=kind, model=model, base_url=base_url, api_key=api_key
            )
            models = await provider.list_models()
        except ProviderError as exc:
            return ProviderTestResult(
                ok=False, latency_ms=_now_ms() - started, message=str(exc), models=[]
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderTestResult(
                ok=False,
                latency_ms=_now_ms() - started,
                message=f"{type(exc).__name__}: {exc}",
                models=[],
            )
        message = "Connection successful."
        if models:
            message = f"Connection successful, {len(models)} model(s) available."
        return ProviderTestResult(
            ok=True, latency_ms=_now_ms() - started, message=message, models=models
        )


def _now_ms() -> int:
    import time

    return int(time.perf_counter() * 1000)
