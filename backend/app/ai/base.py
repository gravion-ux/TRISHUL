"""AI provider abstraction.

Every provider implements the same small interface, so the security engine
can switch between a local model and a cloud API without any change to the
agents that consume it.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any

from backend.app.core.url_guard import UrlGuard
from backend.app.models import ProviderKind


class ProviderError(RuntimeError):
    """Raised when an AI provider cannot fulfil a request.

    The message is safe to show to an operator and is always redacted before
    it reaches a log or an API response.
    """


@dataclass(slots=True)
class AIRequest:
    """A single completion request."""

    prompt: str
    system: str = ""
    max_tokens: int = 2048
    temperature: float = 0.2
    # Ask the provider for a strict JSON object when possible.
    json_mode: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AIResponse:
    """A completed request."""

    text: str
    model: str
    provider: str
    latency_ms: int
    raw: dict[str, Any] = field(default_factory=dict)


class AIProvider(abc.ABC):
    """Base class for every AI backend.

    Subclasses only need to implement :meth:`complete`; model discovery and
    health probing have sensible generic defaults.
    """

    kind: ProviderKind = ProviderKind.CUSTOM

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout: int = 120,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        # The endpoint is operator-configured, so it is validated before a
        # single byte leaves the machine. A base URL that points at the cloud
        # metadata service, carries credentials in its userinfo part or uses
        # a scheme other than http(s) is refused outright.
        self.guard = UrlGuard()
        if self.base_url:
            self.guard.check(self.base_url)
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    @abc.abstractmethod
    async def complete(self, request: AIRequest) -> AIResponse:
        """Run a completion and return the model's text output."""

    async def list_models(self) -> list[str]:
        """Return the models the backend advertises (empty when unsupported)."""
        return []

    async def health(self) -> tuple[bool, str]:
        """Probe the backend and return ``(reachable, message)``."""
        try:
            models = await self.list_models()
        except ProviderError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001 - health must never raise
            return False, f"{type(exc).__name__}: {exc}"
        if models:
            return True, f"{self.kind.value} reachable, {len(models)} model(s) advertised"
        return True, f"{self.kind.value} reachable"

    @staticmethod
    def _timer() -> float:
        return time.perf_counter()

    @staticmethod
    def _elapsed(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)
