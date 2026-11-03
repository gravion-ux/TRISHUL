"""Anthropic (Claude) provider."""

from __future__ import annotations

import httpx

from backend.app.ai.base import AIProvider, AIRequest, AIResponse, ProviderError
from backend.app.models import ProviderKind


class AnthropicProvider(AIProvider):
    """Talks to the Anthropic Messages API."""

    kind = ProviderKind.ANTHROPIC

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    async def complete(self, request: AIRequest) -> AIResponse:
        payload: dict = {
            "model": self.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system:
            payload["system"] = request.system

        started = self._timer()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/v1/messages", json=payload, headers=self._headers()
                )
        except httpx.HTTPError as exc:
            raise ProviderError(f"Anthropic request failed: {exc}") from exc

        if response.status_code != 200:
            raise ProviderError(
                f"Anthropic returned HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Anthropic returned a non-JSON response.") from exc

        blocks = data.get("content") or []
        text = "".join(block.get("text", "") for block in blocks if isinstance(block, dict))
        if not text:
            raise ProviderError("Anthropic returned an empty completion.")
        return AIResponse(
            text=text,
            model=data.get("model") or self.model,
            provider=self.kind.value,
            latency_ms=self._elapsed(started),
            raw={"stop_reason": data.get("stop_reason"), "usage": data.get("usage") or {}},
        )

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout, 15)) as client:
                response = await client.get(f"{self.base_url}/v1/models", headers=self._headers())
        except httpx.HTTPError as exc:
            raise ProviderError(f"Anthropic is not reachable at {self.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise ProviderError(f"Anthropic returned HTTP {response.status_code} for /v1/models")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Anthropic returned a non-JSON model list.") from exc
        names: list[str] = []
        for entry in data.get("data") or []:
            name = entry.get("id")
            if name and name not in names:
                names.append(str(name))
        return names
