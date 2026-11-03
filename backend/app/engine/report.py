"""ReportAgent — produces the final assessment report.

The agent writes the machine-readable, human-readable and submission-ready
report formats, and asks the AI for an executive summary when a model is
reachable.
"""

from __future__ import annotations

from typing import Any

from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import ScanRecord
from backend.app.services.reporting import ReportingService

SUMMARY_SYSTEM = """You are writing the executive summary of an authorized security assessment for an engineering team.

Write three short paragraphs:
1. What was assessed and what the scan actually did.
2. The most important risk(s) found, with severity and confidence, and what would make them dangerous.
3. The recommended next actions, ordered by priority.

Do not invent findings, do not include credentials, and do not suggest destructive testing.
Plain prose only — no markdown headings, no bullet lists, no JSON."""


class ReportAgent(BaseAgent):
    """Generates the report bundle for a completed scan."""

    name = "ReportAgent"

    def __init__(self, storage, ai=None, reporting: ReportingService | None = None) -> None:
        super().__init__(storage, ai)
        self.reporting = reporting or ReportingService(_settings_placeholder())

    async def run(self, ctx: AgentContext) -> dict[str, str]:
        """Write every report format and return their paths."""
        summary = await self._executive_summary(ctx)
        paths = await self.reporting.generate_all(ctx.scan, ctx.scan_dir, summary)
        ctx.scan.report_paths = paths
        ctx.scan.artifacts["executive_summary"] = summary
        return paths

    async def _executive_summary(self, ctx: AgentContext) -> str:
        scan: ScanRecord = ctx.scan
        if not scan.findings:
            return ""
        counts: dict[str, int] = {}
        for finding in scan.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        breakdown = ", ".join(
            f"{severity}: {count}" for severity, count in sorted(counts.items())
        )
        top = "\n".join(
            f"- [{item.severity.value}] {item.title} ({item.asset}, confidence {item.confidence})"
            for item in scan.findings[:12]
        )
        prompt = (
            f"Target: {scan.target}\n"
            f"Mode: {scan.mode.value}\n"
            f"Findings: {len(scan.findings)} ({breakdown})\n"
            f"Most relevant findings:\n{top}\n"
        )
        summary = await self.ai_complete(ctx, SUMMARY_SYSTEM, prompt, max_tokens=900)
        return summary.strip() if summary else ""


def _settings_placeholder():
    """Build a minimal Settings instance for the default reporter.

    The ReportAgent is normally constructed with the application settings;
    this fallback keeps the class usable in isolation (tests, scripts).
    """
    from backend.app.core.config import Settings

    return Settings()
