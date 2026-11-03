"""Shared plumbing for the TRISHUL agents.

Every agent receives the same :class:`AgentContext`, which carries the scan
record, the configured AI manager, the integration manager, the scope policy
and the tool adapters. That keeps the agents individually testable and makes
swapping the AI backend a configuration change rather than a code change.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.app.ai.base import AIRequest
from backend.app.ai.registry import AIManager
from backend.app.core.config import Settings
from backend.app.core.events import event_bus
from backend.app.core.scope import ScopePolicy
from backend.app.core.storage import Storage
from backend.app.core.utils import redact, utcnow
from backend.app.models import Finding, ScanRecord
from backend.app.services.integrations import IntegrationManager
from backend.app.services.tool_adapters import (
    FfufAdapter,
    HttpxAdapter,
    NmapAdapter,
    NucleiAdapter,
)
from backend.app.services.tooling import ToolRegistry

_JSON_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


@dataclass
class Adapters:
    """The four tool adapters, bundled for convenient injection."""

    httpx: HttpxAdapter
    nmap: NmapAdapter
    nuclei: NucleiAdapter
    ffuf: FfufAdapter


@dataclass
class AgentContext:
    """Everything an agent needs to do its job."""

    scan: ScanRecord
    settings: Settings
    storage: Storage
    ai: AIManager
    integrations: IntegrationManager
    scope: ScopePolicy
    tools: ToolRegistry
    adapters: Adapters
    scan_dir: Path
    # Non-fatal problems encountered by the AI (used for diagnostics).
    ai_errors: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.ai_errors is None:
            self.ai_errors = []


class BaseAgent:
    """Common behaviour: progress reporting and tolerant AI access."""

    name = "BaseAgent"

    def __init__(self, storage: Storage, ai: AIManager | None = None) -> None:
        self.storage = storage
        self.ai = ai

    # -- progress ----------------------------------------------------------

    async def emit(
        self,
        scan: ScanRecord,
        stage: str,
        percent: int,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Record a progress event, persist the scan and notify subscribers."""
        from backend.app.models import ScanLog, ScanProgress

        scan.progress = ScanProgress(stage=stage, percent=max(0, min(100, percent)), message=message)
        scan.updated_at = utcnow()
        event = {
            "type": "progress",
            "timestamp": scan.updated_at.isoformat(),
            "stage": stage,
            "percent": scan.progress.percent,
            "message": message,
            "payload": redact(payload or {}),
        }
        scan.logs.append(ScanLog(**event))
        self.storage.save_scan(scan)
        await event_bus.publish(scan.id, event)

    # -- AI ----------------------------------------------------------------

    async def ai_complete(
        self,
        ctx: AgentContext,
        system: str,
        prompt: str,
        *,
        json_mode: bool = False,
        max_tokens: int | None = None,
    ) -> str | None:
        """Run a completion, returning ``None`` when the AI is unavailable.

        The AI is never allowed to break a scan: any failure is recorded in
        ``ctx.ai_errors`` and the deterministic path continues.
        """
        if self.ai is None:
            return None
        request = AIRequest(
            prompt=prompt,
            system=system,
            max_tokens=max_tokens or ctx.settings.ai.max_tokens,
            temperature=ctx.settings.ai.temperature,
            json_mode=json_mode,
        )
        try:
            response = await self.ai.complete(request)
        except Exception as exc:  # noqa: BLE001 - AI must never break a scan
            ctx.ai_errors.append(f"{self.name}: {type(exc).__name__}: {exc}")
            return None
        return response.text

    async def ai_json(
        self,
        ctx: AgentContext,
        system: str,
        prompt: str,
        *,
        max_tokens: int | None = None,
    ) -> dict[str, Any] | None:
        """Run a completion and parse it as a JSON object."""
        text = await self.ai_complete(
            ctx, system, prompt, json_mode=True, max_tokens=max_tokens
        )
        if not text:
            return None
        cleaned = _JSON_FENCE.sub("", text.strip()).strip()
        try:
            payload = json.loads(cleaned)
        except json.JSONDecodeError:
            # Some models wrap the object in prose; try to recover the first
            # balanced object in the response.
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start == -1 or end <= start:
                ctx.ai_errors.append(f"{self.name}: AI response was not valid JSON.")
                return None
            try:
                payload = json.loads(cleaned[start : end + 1])
            except json.JSONDecodeError:
                ctx.ai_errors.append(f"{self.name}: AI response was not valid JSON.")
                return None
        if not isinstance(payload, dict):
            ctx.ai_errors.append(f"{self.name}: AI response was not a JSON object.")
            return None
        return payload

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def severity_rank(severity: str) -> int:
        from backend.app.models import Severity

        order = {
            Severity.INFORMATIONAL.value: 0,
            Severity.LOW.value: 1,
            Severity.MEDIUM.value: 2,
            Severity.HIGH.value: 3,
            Severity.CRITICAL.value: 4,
        }
        return order.get(severity, 0)

    @staticmethod
    def finding_summary(finding: Finding, limit: int = 1200) -> str:
        """Render a finding for inclusion in an AI prompt."""
        evidence_lines = [f"- {item.source}: {item.summary}" for item in finding.evidence[:8]]
        return "\n".join(
            [
                f"Title: {finding.title}",
                f"Source: {finding.source}",
                f"Category: {finding.category}",
                f"Asset: {finding.asset}",
                f"Detected severity: {finding.severity.value}",
                f"Detected confidence: {finding.confidence}",
                f"Description: {finding.description[:600]}",
                "Evidence:",
                *(evidence_lines or ["- (none recorded)"]),
                f"Raw tool output: {json.dumps(finding.raw, default=str)[:limit]}",
            ]
        )
