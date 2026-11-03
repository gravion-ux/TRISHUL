"""GuideEngine — interactive, step-by-step manual validation guidance."""

from __future__ import annotations

from typing import Any

from backend.app.core.utils import stable_id, utcnow
from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import Finding, GuideAction, GuideSession, GuideStep

GUIDE_SYSTEM = """You are guiding a security engineer through a manual, non-destructive validation of a finding.

Give short, practical hints (one or two sentences) that help the engineer gather evidence.
Never instruct destructive actions, exploitation, credential attacks or bypassing access controls.
Never suggest running a tool against a host outside the stated scope.

Respond with a single JSON object and nothing else:
{"hint": "<one or two sentences>"}"""


class GuideEngine(BaseAgent):
    """Prepares and drives the interactive guide sessions."""

    name = "GuideEngine"

    async def prepare(self, ctx: AgentContext, findings: list[Finding]) -> list[Finding]:
        """Attach guide steps to every finding."""
        for finding in findings:
            steps = list(finding.poc.steps_to_reproduce) if finding.poc else [finding.description]
            if not steps:
                steps = [f"Review the evidence recorded for {finding.asset}."]
            finding.guide_steps = [
                GuideStep(
                    index=index,
                    instruction=step,
                    hint=self._hint_for_step(step, finding),
                    status="active" if index == 0 else "pending",
                )
                for index, step in enumerate(steps)
            ]
        return findings

    async def start(self, ctx: AgentContext, finding_id: str) -> GuideSession:
        """Open a guide session for a finding."""
        finding = next((item for item in ctx.scan.findings if item.id == finding_id), None)
        if not finding:
            raise ValueError("Finding not found")
        guide = GuideSession(
            id=stable_id("guide", f"{ctx.scan.id}:{finding_id}"),
            scan_id=ctx.scan.id,
            finding_id=finding_id,
            current_step=0,
            status="active",
            steps=finding.guide_steps,
            updated_at=utcnow(),
        )
        self.storage.save_guide(guide)
        return guide

    async def advance(self, ctx: AgentContext, guide: GuideSession, action: GuideAction) -> GuideSession:
        """Apply an operator action to a guide session."""
        if action == GuideAction.HINT and guide.steps:
            current = guide.steps[min(guide.current_step, len(guide.steps) - 1)]
            enhanced = await self._ai_hint(ctx, guide, current)
            current.hint = enhanced or current.hint
            guide.history.append(f"hint:{current.hint}")
        elif action == GuideAction.RETRY and guide.steps:
            current = guide.steps[min(guide.current_step, len(guide.steps) - 1)]
            current.status = "retrying"
            guide.history.append(f"retry:{current.index}")
        elif action == GuideAction.NEXT:
            if guide.current_step < len(guide.steps):
                guide.steps[guide.current_step].status = "completed"
                guide.current_step += 1
                if guide.current_step < len(guide.steps):
                    guide.steps[guide.current_step].status = "active"
            if guide.current_step >= len(guide.steps):
                guide.status = "completed"
        elif action == GuideAction.DONE:
            if guide.steps:
                guide.steps[min(guide.current_step, len(guide.steps) - 1)].status = "completed"
            guide.status = "completed"

        guide.updated_at = utcnow()
        self.storage.save_guide(guide)
        return guide

    async def _ai_hint(self, ctx: AgentContext, guide: GuideSession, step: GuideStep) -> str:
        finding = next(
            (item for item in ctx.scan.findings if item.id == guide.finding_id), None
        )
        if finding is None:
            return ""
        prompt = (
            f"Finding: {finding.title}\n"
            f"Asset: {finding.asset}\n"
            f"Current step: {step.instruction}\n"
            f"Operator hint requested.\n"
        )
        payload = await self.ai_json(ctx, GUIDE_SYSTEM, prompt, max_tokens=300)
        if not payload:
            return ""
        hint = str(payload.get("hint") or "").strip()
        return hint

    @staticmethod
    def _hint_for_step(step: str, finding: Finding) -> str:
        """Deterministic hint used when the AI is unavailable."""
        lowered = step.lower()
        if "curl" in lowered or "replay" in lowered:
            return (
                "Use a clean session and `curl -isk`; capture only the minimal response "
                "that proves the issue."
            )
        if "nmap" in lowered:
            return (
                "Confirm service reachability only. Do not attempt authentication, "
                "brute force or exploitation."
            )
        if "scope" in lowered:
            return "Check the engagement reference and the authorised target list before continuing."
        return f"Keep the validation non-destructive and scoped to `{finding.asset}`."
