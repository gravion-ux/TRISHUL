"""ScannerAgent — port scanning with ``nmap`` and template scanning with ``nuclei``."""

from __future__ import annotations

import asyncio
from typing import Any

from backend.app.engine.base import AgentContext, BaseAgent


class ScannerAgent(BaseAgent):
    """Runs the active-service and vulnerability scanners in parallel."""

    name = "ScannerAgent"

    async def run(
        self, ctx: AgentContext, profile: dict[str, str], live_urls: list[str]
    ) -> dict[str, Any]:
        scan = ctx.scan
        output_dir = ctx.scan_dir / "artifacts" / "scan"

        nmap_task = ctx.adapters.nmap.run(
            profile["host"], output_dir / "nmap", scan.mode, scope=ctx.scope
        )
        nuclei_task = ctx.adapters.nuclei.run(
            live_urls, output_dir / "nuclei", scan.mode, scope=ctx.scope
        )
        nmap_result, nuclei_results = await asyncio.gather(
            nmap_task, nuclei_task, return_exceptions=True
        )

        errors: list[str] = []
        if isinstance(nmap_result, BaseException):
            errors.append(f"nmap: {nmap_result}")
            nmap_result = {"host": profile["host"], "services": []}
        if isinstance(nuclei_results, BaseException):
            errors.append(f"nuclei: {nuclei_results}")
            nuclei_results = []

        result: dict[str, Any] = {
            "nmap": nmap_result,
            "nuclei": nuclei_results,
            "open_ports": len(nmap_result.get("services", [])) if isinstance(nmap_result, dict) else 0,
            "nuclei_matches": len(nuclei_results) if isinstance(nuclei_results, list) else 0,
        }
        if errors:
            result["errors"] = errors
        return result
