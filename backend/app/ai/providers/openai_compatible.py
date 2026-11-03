"""OpenAI-compatible provider.

This single implementation serves OpenAI itself, LM Studio, llama.cpp's
server, vLLM, Ollama's ``/v1`` surface, and any other endpoint that speaks
the ``/chat/completions`` dialect. The only differences between them are the
default base URL and whether an API key is required.
"""

from __future__ import annotations

import httpx

from backend.app.ai.base import AIProvider, AIRequest, AIResponse, ProviderError
from backend.app.models import ProviderKind


class OpenAICompatibleProvider(AIProvider):
    """Talks to any ``/chat/completions`` compatible endpoint."""

    kind = ProviderKind.OPENAI_COMPATIBLE

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def complete(self, request: AIRequest) -> AIResponse:
        messages: list[dict[str, str]] = []
        system = request.system
        if request.json_mode and "json" not in system.lower():
            # OpenAI-compatible servers reject `response_format: json_object`
            # unless the word "json" appears in the prompt.
            system = f"{system}\nRespond with a single valid JSON object.".strip()
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": request.prompt})

        payload: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "stream": False,
        }
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}

        started = self._timer()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=self._headers(),
                )
        except httpx.HTTPError as exc:
            raise ProviderError(f"AI request failed: {exc}") from exc

        if response.status_code != 200:
            raise ProviderError(
                f"AI endpoint returned HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("AI endpoint returned a non-JSON response.") from exc

        choices = data.get("choices") or []
        if not choices:
            raise ProviderError("AI endpoint returned no choices.")
        message = choices[0].get("message") or {}
        text = message.get("content") or ""
        if not text:
            raise ProviderError("AI endpoint returned an empty completion.")
        return AIResponse(
            text=text,
            model=data.get("model") or self.model,
            provider=self.kind.value,
            latency_ms=self._elapsed(started),
            raw={"usage": data.get("usage") or {}},
        )

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout, 15)) as client:
                response = await client.get(f"{self.base_url}/models", headers=self._headers())
        except httpx.HTTPError as exc:
            raise ProviderError(f"AI endpoint is not reachable at {self.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise ProviderError(f"AI endpoint returned HTTP {response.status_code} for /models")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("AI endpoint returned a non-JSON model list.") from exc
        entries = data.get("data") if isinstance(data, dict) else data
        names: list[str] = []
        for entry in entries or []:
            name = entry.get("id") if isinstance(entry, dict) else entry
            if name and name not in names:
                names.append(str(name))
        return names
