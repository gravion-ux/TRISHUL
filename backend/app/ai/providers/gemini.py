"""Google Gemini provider."""

from __future__ import annotations

import httpx

from backend.app.ai.base import AIProvider, AIRequest, AIResponse, ProviderError
from backend.app.models import ProviderKind


class GeminiProvider(AIProvider):
    """Talks to the Google Generative Language API."""

    kind = ProviderKind.GEMINI

    def _params(self) -> dict[str, str]:
        return {"key": self.api_key or ""}

    async def complete(self, request: AIRequest) -> AIResponse:
        payload: dict = {
            "contents": [{"role": "user", "parts": [{"text": request.prompt}]}],
            "generationConfig": {
                "temperature": request.temperature,
                "maxOutputTokens": request.max_tokens,
            },
        }
        if request.system:
            payload["systemInstruction"] = {"parts": [{"text": request.system}]}
        if request.json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        started = self._timer()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/v1beta/models/{self.model}:generateContent",
                    params=self._params(),
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise ProviderError(f"Gemini request failed: {exc}") from exc

        if response.status_code != 200:
            raise ProviderError(
                f"Gemini returned HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Gemini returned a non-JSON response.") from exc

        candidates = data.get("candidates") or []
        if not candidates:
            raise ProviderError("Gemini returned no candidates.")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
        if not text:
            raise ProviderError("Gemini returned an empty completion.")
        return AIResponse(
            text=text,
            model=self.model,
            provider=self.kind.value,
            latency_ms=self._elapsed(started),
            raw={"finish_reason": candidates[0].get("finishReason")},
        )

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout, 15)) as client:
                response = await client.get(
                    f"{self.base_url}/v1beta/models", params=self._params()
                )
        except httpx.HTTPError as exc:
            raise ProviderError(f"Gemini is not reachable at {self.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise ProviderError(f"Gemini returned HTTP {response.status_code} for /v1beta/models")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Gemini returned a non-JSON model list.") from exc
        names: list[str] = []
        for entry in data.get("models") or []:
            name = entry.get("name")
            if name and name not in names:
                names.append(str(name))
        return names
