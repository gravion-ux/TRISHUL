"""PoCEngine — non-destructive reproduction bundles.

Every generated proof of concept is read-only by construction: a replay of
the original request, a description of what to capture, and remediation
guidance. TRISHUL never emits an exploit, a payload or a destructive step.
"""

from __future__ import annotations

from typing import Any

from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import Finding, PocBundle

POC_SYSTEM = """You are writing a bug-bounty proof of concept for an authorized security assessment.

Rules you must follow:
- Every step MUST be non-destructive. No data deletion, no modification, no exploitation, no credential attacks, no denial of service.
- Use only read-only requests (GET/HEAD) or a harmless, minimal validation request.
- Never include a working exploit payload, a shell command that changes state, or a brute-force loop.
- Be specific about what evidence to capture (status code, header, banner, response snippet).

Respond with a single JSON object and nothing else:
{
  "steps_to_reproduce": ["step 1", "step 2", "step 3"],
  "request_example": "a single safe read-only request or command",
  "response_example": "what the expected benign response looks like",
  "impact": "one or two sentences on real-world impact",
  "remediation": "one or two sentences of concrete remediation",
  "screenshot_guide": ["what to capture in screenshot 1", "..."],
  "video_script": ["scene 1", "..."]
}"""


class PoCEngine(BaseAgent):
    """Builds a reproduction bundle for every finding."""

    name = "PoCEngine"

    async def run(self, ctx: AgentContext, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            deterministic = self._deterministic_bundle(ctx, finding)
            ai_bundle = await self._ai_bundle(ctx, finding)
            finding.poc = ai_bundle or deterministic
        return findings

    # -- deterministic -----------------------------------------------------

    def _deterministic_bundle(self, ctx: AgentContext, finding: Finding) -> PocBundle:
        asset = finding.asset
        host = asset.split(":")[0]
        is_port_finding = finding.source == "nmap" and ":" in asset and asset.rsplit(":", 1)[1].isdigit()

        if is_port_finding:
            port = asset.rsplit(":", 1)[1]
            request_example = f"nmap -Pn -p {port} -sV {host}"
            steps = [
                f"Confirm `{host}` is inside the approved scope of this engagement.",
                f"Run `{request_example}` to confirm the service is still reachable.",
                "Capture the reported service banner and version in a screenshot.",
                "Record whether the service needs to be reachable from the public internet.",
            ]
            impact = (
                "An exposed service enlarges the attack surface of the target and may expose "
                "an administrative or data interface to unauthenticated users."
            )
            remediation = (
                "Restrict the service to the networks that need it, bind it to an internal "
                "interface, and enforce authentication and access controls."
            )
        else:
            url = asset if asset.startswith(("http://", "https://")) else ctx.scan.target
            request_example = f"curl -isk --max-time 10 {url}"
            steps = [
                f"Confirm `{url}` is inside the approved scope of this engagement.",
                f"Replay `{request_example}` from a clean, authenticated-free session.",
                "Capture the response status line, the relevant headers and the minimal "
                "response snippet that proves the issue.",
                "Repeat the request once to confirm the behaviour is stable and not transient.",
            ]
            impact = (
                "The observed behaviour may expose sensitive functionality or a known "
                "weakness to unauthenticated users."
            )
            remediation = (
                "Patch or upgrade the affected component, restrict exposure to the required "
                "paths, and add server-side validation and access control as appropriate."
            )

        screenshot_guide = [
            "Capture the target URL or host together with the scope confirmation.",
            "Capture the exact, benign validation request that was sent.",
            "Capture the status code, response snippet or service banner proving the issue.",
        ]
        video_script = [
            "Open with the engagement reference and the scope confirmation.",
            "Show the exact non-destructive validation request.",
            "Pause on the response that proves the issue.",
            "Close with the impact and the recommended remediation.",
        ]

        evidence_lines = [
            f"- {item.source}: {item.summary}" for item in finding.evidence[:8]
        ] or ["- (none recorded)"]

        bounty_report = "\n".join(
            [
                f"## {finding.title}",
                f"- Severity: {finding.severity.value}",
                f"- Confidence: {finding.confidence}",
                f"- Verified: {'yes' if finding.verified else 'no'}",
                f"- Asset: {asset}",
                "",
                "### Summary",
                finding.description,
                "",
                "### Steps to Reproduce",
                *[f"{index + 1}. {step}" for index, step in enumerate(steps)],
                "",
                "### Evidence",
                *evidence_lines,
                "",
                "### Impact",
                impact,
                "",
                "### Remediation",
                remediation,
            ]
        )

        return PocBundle(
            steps_to_reproduce=steps,
            request_example=request_example,
            response_example=finding.evidence[0].summary if finding.evidence else "",
            impact=impact,
            remediation=remediation,
            screenshot_guide=screenshot_guide,
            video_script=video_script,
            bounty_report=bounty_report,
            generated_by="deterministic",
        )

    # -- AI ----------------------------------------------------------------

    async def _ai_bundle(self, ctx: AgentContext, finding: Finding) -> PocBundle | None:
        prompt = (
            f"Finding:\n{self.finding_summary(finding)}\n\n"
            f"Current severity: {finding.severity.value}\n"
            f"Current confidence: {finding.confidence}\n"
        )
        payload = await self.ai_json(ctx, POC_SYSTEM, prompt, max_tokens=1200)
        if not payload:
            return None

        steps = [str(item) for item in payload.get("steps_to_reproduce") or [] if str(item).strip()]
        if not steps:
            return None

        deterministic = self._deterministic_bundle(ctx, finding)
        return PocBundle(
            steps_to_reproduce=steps,
            request_example=str(payload.get("request_example") or deterministic.request_example),
            response_example=str(payload.get("response_example") or deterministic.response_example),
            impact=str(payload.get("impact") or deterministic.impact),
            remediation=str(payload.get("remediation") or deterministic.remediation),
            screenshot_guide=[
                str(item) for item in payload.get("screenshot_guide") or []
            ] or deterministic.screenshot_guide,
            video_script=[str(item) for item in payload.get("video_script") or []]
            or deterministic.video_script,
            bounty_report=deterministic.bounty_report,
            generated_by="ai",
        )
