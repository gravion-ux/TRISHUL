"""Ollama provider — the default backend for the LOCAL edition.

Ollama exposes two APIs: the native ``/api/chat`` endpoint and an
OpenAI-compatible ``/v1`` surface. The native endpoint is used here because
it supports JSON output mode directly, which keeps the structured-verdict
parsing reliable.
"""

from __future__ import annotations

import httpx

from backend.app.ai.base import AIProvider, AIRequest, AIResponse, ProviderError
from backend.app.models import ProviderKind


class OllamaProvider(AIProvider):
    """Talks to a local Ollama daemon."""

    kind = ProviderKind.OLLAMA

    async def complete(self, request: AIRequest) -> AIResponse:
        messages: list[dict[str, str]] = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})

        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }
        if request.json_mode:
            payload["format"] = "json"

        started = self._timer()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/chat", json=payload
                )
        except httpx.HTTPError as exc:
            raise ProviderError(f"Ollama request failed: {exc}") from exc

        if response.status_code != 200:
            raise ProviderError(
                f"Ollama returned HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Ollama returned a non-JSON response.") from exc

        text = (data.get("message") or {}).get("content") or ""
        if not text:
            raise ProviderError("Ollama returned an empty completion.")
        return AIResponse(
            text=text,
            model=data.get("model") or self.model,
            provider=self.kind.value,
            latency_ms=self._elapsed(started),
            raw={"done": data.get("done"), "eval_count": data.get("eval_count")},
        )

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout, 15)) as client:
                response = await client.get(f"{self.base_url}/api/tags")
        except httpx.HTTPError as exc:
            raise ProviderError(f"Ollama is not reachable at {self.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise ProviderError(f"Ollama returned HTTP {response.status_code} for /api/tags")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Ollama returned a non-JSON model list.") from exc
        names: list[str] = []
        for entry in data.get("models") or []:
            name = entry.get("name") or entry.get("model")
            if name and name not in names:
                names.append(name)
        return names
