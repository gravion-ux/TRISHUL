"""FuzzerAgent — controlled content discovery with ``ffuf``."""

from __future__ import annotations

from typing import Any

from backend.app.engine.base import AgentContext, BaseAgent


class FuzzerAgent(BaseAgent):
    """Performs bounded directory and parameter fuzzing.

    The fuzzing is deliberately controlled: a small bundled wordlist, a
    request budget, a status-code filter and a hard timeout. TRISHUL does
    not download or use large third-party payload sets by default.
    """

    name = "FuzzerAgent"

    async def run(self, ctx: AgentContext, live_urls: list[str]) -> dict[str, Any]:
        scan = ctx.scan
        output_dir = ctx.scan_dir / "artifacts" / "fuzz"
        results = await ctx.adapters.ffuf.run(
            live_urls, output_dir, scan.mode, scope=ctx.scope
        )
        by_mode: dict[str, int] = {}
        for item in results:
            mode = str(item.get("mode") or "unknown")
            by_mode[mode] = by_mode.get(mode, 0) + 1
        return {
            "ffuf": results,
            "total": len(results),
            "by_mode": by_mode,
            "targets": len(set(live_urls)),
        }
