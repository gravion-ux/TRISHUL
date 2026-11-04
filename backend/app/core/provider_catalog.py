"""The provider catalogue: the single source of truth for provider defaults.

This module deliberately lives in the *core* layer rather than next to the
providers themselves. Both the configuration layer (which needs to know the
documented endpoint and model of a provider when the operator switches to it)
and the AI registry (which builds the actual client) have to agree on those
defaults, and the configuration layer must not import the AI layer -- that
would be a circular import.

Nothing here touches the network, the filesystem or the credential store; it
is a static description of the providers TRISHUL can talk to.
"""

from __future__ import annotations

from backend.app.models import ProviderDescriptor, ProviderEdition, ProviderKind

PROVIDER_CATALOG: tuple[ProviderDescriptor, ...] = (
    ProviderDescriptor(
        kind=ProviderKind.OLLAMA,
        label="Ollama (local)",
        edition=ProviderEdition.LOCAL,
        default_base_url="http://localhost:11434",
        default_model="llama3.1:8b",
        requires_api_key=False,
        supports_models_discovery=True,
        notes="Local daemon. Run `ollama serve` and `ollama pull llama3.1:8b`.",
    ),
    ProviderDescriptor(
        kind=ProviderKind.LMSTUDIO,
        label="LM Studio (local)",
        edition=ProviderEdition.LOCAL,
        default_base_url="http://localhost:1234/v1",
        default_model="local-model",
        requires_api_key=False,
        supports_models_discovery=True,
        notes="Enable the local server in LM Studio and load a model.",
    ),
    ProviderDescriptor(
        kind=ProviderKind.LLAMACPP,
        label="llama.cpp server (local)",
        edition=ProviderEdition.LOCAL,
        default_base_url="http://localhost:8080/v1",
        default_model="local-model",
        requires_api_key=False,
        supports_models_discovery=True,
        notes="Start with `llama-server -m model.gguf --port 8080`.",
    ),
    ProviderDescriptor(
        kind=ProviderKind.OPENAI,
        label="OpenAI",
        edition=ProviderEdition.PROVIDER,
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        requires_api_key=True,
        supports_models_discovery=True,
        notes="Requires an OpenAI API key.",
    ),
    ProviderDescriptor(
        kind=ProviderKind.ANTHROPIC,
        label="Anthropic (Claude)",
        edition=ProviderEdition.PROVIDER,
        default_base_url="https://api.anthropic.com",
        default_model="claude-3-5-sonnet-latest",
        requires_api_key=True,
        supports_models_discovery=True,
        notes="Requires an Anthropic API key.",
    ),
    ProviderDescriptor(
        kind=ProviderKind.GEMINI,
        label="Google Gemini",
        edition=ProviderEdition.PROVIDER,
        default_base_url="https://generativelanguage.googleapis.com",
        default_model="gemini-2.0-flash",
        requires_api_key=True,
        supports_models_discovery=True,
        notes="Requires a Google AI Studio API key.",
    ),
    ProviderDescriptor(
        kind=ProviderKind.OPENAI_COMPATIBLE,
        label="OpenAI-compatible endpoint",
        edition=ProviderEdition.PROVIDER,
        default_base_url="http://localhost:8000/v1",
        default_model="local-model",
        requires_api_key=False,
        supports_models_discovery=True,
        notes="Any endpoint speaking /chat/completions: vLLM, Ollama /v1, LiteLLM, OpenRouter.",
    ),
    ProviderDescriptor(
        kind=ProviderKind.CUSTOM,
        label="Custom adapter",
        edition=ProviderEdition.PROVIDER,
        default_base_url="http://localhost:8080/v1",
        default_model="custom-model",
        requires_api_key=False,
        supports_models_discovery=True,
        notes="OpenAI-compatible transport with a custom base URL and model.",
    ),
)

DESCRIPTORS: dict[ProviderKind, ProviderDescriptor] = {item.kind: item for item in PROVIDER_CATALOG}

# Providers that run on the operator's own machine. The PROVIDER edition
# prefers a hosted provider over one of these.
LOCAL_PROVIDERS: frozenset[str] = frozenset(
    {ProviderKind.OLLAMA.value, ProviderKind.LMSTUDIO.value, ProviderKind.LLAMACPP.value}
)


def descriptor_for(provider: str) -> ProviderDescriptor | None:
    """Return the catalogue entry for a provider name, or ``None`` if unknown."""
    try:
        kind = ProviderKind(provider)
    except ValueError:
        return None
    return DESCRIPTORS.get(kind)


def endpoint_defaults(provider: str) -> tuple[str, str] | None:
    """Return the documented ``(base_url, model)`` pair for a provider.

    ``None`` is returned for an unknown provider so the caller can fall back
    to whatever the configuration already holds.
    """
    descriptor = descriptor_for(provider)
    if descriptor is None:
        return None
    return descriptor.default_base_url, descriptor.default_model


__all__ = [
    "DESCRIPTORS",
    "LOCAL_PROVIDERS",
    "PROVIDER_CATALOG",
    "descriptor_for",
    "endpoint_defaults",
]
