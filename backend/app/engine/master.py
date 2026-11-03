"""MasterAgent — orchestrates the TRISHUL pipeline.

Pipeline: Recon → Scan → Fuzz → Detect → Verify → PoC → Guide → Report

The MasterAgent owns the run order, the progress reporting and the failure
handling. Every stage is allowed to degrade: a missing tool or an
unreachable AI model produces a recorded error, not a crashed scan.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from backend.app.ai.registry import AIManager
from backend.app.core.config import Settings
from backend.app.core.scope import ScopePolicy
from backend.app.core.storage import Storage
from backend.app.core.utils import normalize_target, redact, unique_id, utcnow
from backend.app.engine.base import Adapters, AgentContext
from backend.app.engine.detection import DetectionAgent
from backend.app.engine.fuzzer import FuzzerAgent
from backend.app.engine.guide import GuideEngine
from backend.app.engine.poc import PoCEngine
from backend.app.engine.reasoning import ReasoningEngine
from backend.app.engine.recon import ReconAgent
from backend.app.engine.report import ReportAgent
from backend.app.engine.scanner import ScannerAgent
from backend.app.engine.verification import VerificationAgent
from backend.app.models import (
    GuideAction,
    GuideSession,
    ScanMode,
    ScanRequest,
    ScanStatus,
)
from backend.app.services.integrations import IntegrationManager
from backend.app.services.reporting import ReportingService
from backend.app.services.tooling import ToolRegistry


class MasterAgent:
    """Runs the assessment pipeline end to end."""

    name = "MasterAgent"

    def __init__(
        self,
        *,
        storage: Storage,
        settings: Settings,
        ai: AIManager,
        integrations: IntegrationManager,
        tools: ToolRegistry,
        adapters: Adapters,
        scope: ScopePolicy,
        reporting: ReportingService | None = None,
    ) -> None:
        self.storage = storage
        self.settings = settings
        self.ai = ai
        self.integrations = integrations
        self.tools = tools
        self.adapters = adapters
        self.scope = scope
        self.reporting = reporting or ReportingService(settings)

        self.recon = ReconAgent(storage, ai)
        self.scanner = ScannerAgent(storage, ai)
        self.fuzzer = FuzzerAgent(storage, ai)
        self.detection = DetectionAgent(storage, ai)
        self.verification = VerificationAgent(storage, ai)
        self.reasoning = ReasoningEngine(storage, ai)
        self.poc = PoCEngine(storage, ai)
        self.guide = GuideEngine(storage, ai)
        self.report = ReportAgent(storage, ai, self.reporting)

    # -- lifecycle ---------------------------------------------------------

    def create_scan(self, request: ScanRequest) -> Any:
        """Create and persist a queued scan record."""
        from backend.app.models import ScanRecord

        now = utcnow()
        scan = ScanRecord(
            id=unique_id("scan", f"{request.target}:{now.isoformat()}"),
            target=request.target,
            mode=request.mode,
            status=ScanStatus.QUEUED,
            created_at=now,
            updated_at=now,
            authorized=request.authorized,
            authorization_note=request.authorization_note,
            ai_provider=self.ai.current_config().provider.value,
            ai_model=self.ai.current_config().model,
        )
        self.storage.save_scan(scan)
        return scan

    async def run_scan(self, scan_id: str) -> Any:
        """Execute the full pipeline for a scan."""
        from backend.app.models import ScanRecord

        scan = self.storage.get_scan(scan_id)
        if not scan:
            raise ValueError("Scan not found")
        if not scan.authorized:
            raise PermissionError("Explicit authorization is required before scanning.")

        missing = self.tools.missing_core_tools()
        if missing:
            raise RuntimeError(
                "Missing required tools: "
                + ", ".join(missing)
                + ". Run the installer or use the health autofix commands before scanning."
            )

        provider_config = self.ai.current_config()
        scan.ai_provider = provider_config.provider.value
        scan.ai_model = provider_config.model

        scan_dir = Path(self.settings.reports_dir) / scan.id
        scan_dir.mkdir(parents=True, exist_ok=True)

        ctx = AgentContext(
            scan=scan,
            settings=self.settings,
            storage=self.storage,
            ai=self.ai,
            integrations=self.integrations,
            scope=self.scope,
            tools=self.tools,
            adapters=self.adapters,
            scan_dir=scan_dir,
        )
        scan.artifacts["authorization_note"] = scan.authorization_note
        scan.artifacts["scope_allowlist"] = list(self.scope.authorized_targets)

        try:
            profile = normalize_target(scan.target)
            # Scope enforcement happens before any packet leaves the machine.
            await self.scope.check(profile["host"])
            scan.artifacts["target_profile"] = profile

            scan.status = ScanStatus.RUNNING
            self.storage.save_scan(scan)

            # -- Recon --------------------------------------------------
            await self.recon.emit(scan, "recon", 8, f"ReconAgent probing {profile['host']}")
            recon_result = await self.recon.run(ctx, profile)
            scan.artifacts["recon"] = redact(recon_result)

            # -- Scan ---------------------------------------------------
            await self.scanner.emit(
                scan, "scan", 26, "ScannerAgent running nmap and nuclei in parallel"
            )
            scan_result = await self.scanner.run(ctx, profile, recon_result["live_urls"])
            scan.artifacts["scan"] = redact(scan_result)

            # -- Fuzz ---------------------------------------------------
            await self.fuzzer.emit(
                scan, "fuzz", 40, "FuzzerAgent running bounded ffuf content discovery"
            )
            fuzz_result = await self.fuzzer.run(ctx, recon_result["live_urls"])
            scan.artifacts["fuzz"] = redact(fuzz_result)

            # -- Detect -------------------------------------------------
            await self.detection.emit(scan, "detect", 52, "DetectionAgent normalising tool output")
            findings = await self.detection.run(
                ctx, profile, recon_result, scan_result, fuzz_result
            )

            # -- Verify + reason ---------------------------------------
            await self.verification.emit(
                scan, "verify", 66, "VerificationAgent running multi-check validation"
            )
            findings = await self.verification.run(ctx, findings, recon_result, scan_result)
            await self.reasoning.emit(
                scan, "verify", 76, "ReasoningEngine consolidating and ranking findings"
            )
            findings = await self.reasoning.run(ctx, findings)
            scan.findings = findings

            # -- Enrichment (optional, user-configured only) ------------
            enrichment = await self._enrich(ctx, profile, findings)
            scan.enrichment = redact(enrichment)

            # -- PoC ----------------------------------------------------
            await self.poc.emit(scan, "poc", 84, "PoCEngine preparing non-destructive reproduction bundles")
            findings = await self.poc.run(ctx, findings)
            scan.findings = findings

            # -- Guide --------------------------------------------------
            await self.guide.emit(scan, "guide", 90, "GuideEngine preparing interactive validation steps")
            findings = await self.guide.prepare(ctx, findings)
            scan.findings = findings

            # -- Report -------------------------------------------------
            await self.report.emit(scan, "report", 95, "ReportAgent generating the report bundle")
            scan.report_paths = await self.report.run(ctx)

            scan.status = ScanStatus.COMPLETED
            await self.recon.emit(
                scan,
                "completed",
                100,
                f"Completed with {len(scan.findings)} findings"
                + (f" ({len(ctx.ai_errors)} AI issue(s))" if ctx.ai_errors else ""),
            )
            self.storage.save_scan(scan)
            return scan

        except asyncio.CancelledError:
            scan.status = ScanStatus.CANCELLED
            scan.error = "Scan cancelled by the operator."
            await self.recon.emit(scan, "cancelled", scan.progress.percent, scan.error)
            self.storage.save_scan(scan)
            raise
        except Exception as exc:  # noqa: BLE001 - the scan must not crash the server
            scan.status = ScanStatus.FAILED
            scan.error = redact(str(exc))
            await self.recon.emit(scan, "failed", 100, f"Scan failed: {scan.error}")
            self.storage.save_scan(scan)
            return scan

    async def _enrich(
        self, ctx: AgentContext, profile: dict[str, str], findings: list[Any]
    ) -> list[dict[str, Any]]:
        """Run the operator-configured integrations, if there are any."""
        try:
            return await ctx.integrations.enrich(
                {"host": profile["host"], "url": profile["url"], "target": ctx.scan.target}
            )
        except Exception as exc:  # noqa: BLE001 - enrichment is optional
            ctx.ai_errors.append(f"Enrichment: {type(exc).__name__}: {exc}")
            return []

    # -- guide -------------------------------------------------------------

    async def start_guide(self, scan_id: str, finding_id: str) -> GuideSession:
        scan = self.storage.get_scan(scan_id)
        if not scan:
            raise ValueError("Scan not found")
        ctx = self._context_for(scan)
        return await self.guide.start(ctx, finding_id)

    async def advance_guide(self, guide_id: str, action: GuideAction) -> GuideSession:
        guide = self.storage.get_guide(guide_id)
        if not guide:
            raise ValueError("Guide not found")
        scan = self.storage.get_scan(guide.scan_id)
        if not scan:
            raise ValueError("Scan not found")
        ctx = self._context_for(scan)
        return await self.guide.advance(ctx, guide, action)

    def _context_for(self, scan: Any) -> AgentContext:
        return AgentContext(
            scan=scan,
            settings=self.settings,
            storage=self.storage,
            ai=self.ai,
            integrations=self.integrations,
            scope=self.scope,
            tools=self.tools,
            adapters=self.adapters,
            scan_dir=Path(self.settings.reports_dir) / scan.id,
        )
