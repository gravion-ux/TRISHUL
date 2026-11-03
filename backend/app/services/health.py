"""Health reporting for TRISHUL."""

from __future__ import annotations

import platform
from typing import Any

from backend.app.ai.registry import AIManager
from backend.app.models import HealthResponse
from backend.app.services.tooling import ToolRegistry


class HealthService:
    """Assembles the health payload shown by the CLI and the dashboard."""

    def __init__(self, tools: ToolRegistry, ai: AIManager | None = None) -> None:
        self.tools = tools
        self.ai = ai

    def get_health(self) -> HealthResponse:
        tools = self.tools.all_health()
        config = self.ai.current_config() if self.ai else None
        return HealthResponse(
            version=self.tools.settings.app.version,
            edition=config.edition if config else self.tools.settings.ai.edition,  # type: ignore[arg-type]
            platform=platform.platform(),
            ready=self.tools.core_tools_ready(),
            tools=tools,
            ai={
                "configured": bool(config and config.has_api_key) or bool(config),
                "provider": config.provider.value if config else "none",
                "model": config.model if config else "",
                "reachable": False,
                "message": "Not probed yet — use POST /api/providers/test.",
            },  # type: ignore[dict-item]
            autofix_commands=self.tools.autofix_commands(),
        )

    async def get_health_async(self) -> HealthResponse:
        """Health payload including a live AI reachability probe."""
        health = self.get_health()
        if self.ai is not None:
            ai_health = await self.ai.health()
            health.ai = ai_health  # type: ignore[assignment]
        return health

    def get_health_dict(self) -> dict[str, Any]:
        return self.get_health().model_dump(mode="json")
