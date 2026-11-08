"""ReconAgent — live host detection with ``httpx``."""

from __future__ import annotations

from typing import Any

from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import ScanRecord


class ReconAgent(BaseAgent):
    """Determines which HTTP endpoints of the target are actually alive."""

    name = "ReconAgent"

    async def run(self, ctx: AgentContext, profile: dict[str, str]) -> dict[str, Any]:
        """Probe the target and return the live URLs that responded."""
        scan = ctx.scan
        output_dir = ctx.scan_dir / "artifacts" / "recon"
        results = await ctx.adapters.httpx.run(
            [profile["raw"], profile["host"], profile["url"]],
            output_dir,
            scan.mode,
            scope=ctx.scope,
            limits=ctx.limits,
        )

        live_urls: list[str] = []
        technologies: list[str] = []
        statuses: dict[str, int] = {}
        for item in results:
            url = item.get("url") or item.get("input")
            if url and url not in live_urls:
                live_urls.append(url)
            for tech in item.get("tech") or []:
                if tech not in technologies:
                    technologies.append(tech)
            status = item.get("status_code")
            if status is not None:
                statuses[str(url)] = int(status)

        if profile["url"] not in live_urls and results:
            # httpx may report the host without a URL; keep the normalised
            # URL so downstream stages always have something to work with.
            live_urls.insert(0, profile["url"])

        return {
            "httpx": results,
            "live_urls": sorted(set(live_urls)),
            "technologies": technologies,
            "status_codes": statuses,
            "live_count": len(set(live_urls)),
        }
