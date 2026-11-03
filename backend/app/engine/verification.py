"""VerificationAgent — multi-check evidence scoring with AI adjudication.

The agent runs a set of independent, *non-destructive* checks against every
finding. Those checks produce a deterministic ``baseline_confidence`` score.

When an AI model is reachable it is then asked to adjudicate the finding.
The AI verdict has full authority over the published severity, confidence and
verified state — the deterministic baseline is preserved separately so the
override remains auditable.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.app.core.utils import redact_text
from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import AiVerdict, Evidence, Finding, Severity

# Base score per severity before any check contributes.
SEVERITY_BASE = {
    Severity.INFORMATIONAL: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 40,
    Severity.HIGH: 55,
    Severity.CRITICAL: 70,
}

VERIFICATION_SYSTEM = """You are a senior application-security analyst reviewing a single finding produced by an authorized security scan.

You will receive the finding, the evidence that was collected, and a deterministic baseline score.

Judge the finding on its merits:
- Is the evidence sufficient to conclude the issue is real?
- Is the stated severity appropriate for the described impact?
- What confidence (0-100) should an engineer have that this is a genuine, reproducible issue?
- Should the finding be marked as verified?

Be conservative with confidence when the evidence is thin or generic. Penalise results that merely re-state what the scanner reported.

Respond with a single JSON object and nothing else:
{
  "severity": "Informational" | "Low" | "Medium" | "High" | "Critical",
  "confidence": <integer 0-100>,
  "verified": true | false,
  "false_positive": true | false,
  "reasoning": "<two or three sentences explaining the verdict>",
  "remediation": "<one or two sentences of concrete remediation advice>"
}"""


class VerificationAgent(BaseAgent):
    """Runs the multi-check verification and applies the AI verdict."""

    name = "VerificationAgent"

    async def run(
        self,
        ctx: AgentContext,
        findings: list[Finding],
        recon_result: dict[str, Any],
        scan_result: dict[str, Any],
    ) -> list[Finding]:
        if not findings:
            return []

        open_ports = {
            (entry.get("host"), int(entry.get("port", 0)))
            for entry in (scan_result.get("nmap") or {}).get("services", []) or []
        }
        live_hosts = {
            (urlparse(url).hostname or url).lower()
            for url in recon_result.get("live_urls", []) or []
        }
        # A second source touching the same asset counts as corroboration.
        source_by_asset: dict[str, set[str]] = {}
        for finding in findings:
            source_by_asset.setdefault(finding.asset, set()).add(finding.source)

        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=True, verify=True
        ) as client:
            for finding in findings:
                checks = await self._run_checks(
                    ctx, finding, open_ports, live_hosts, source_by_asset, client
                )
                baseline = self._score(finding, checks)
                finding.baseline_confidence = baseline
                finding.confidence = baseline
                finding.verified = checks["active_successes"] > 0 and baseline >= 50

        await self._apply_ai_verdicts(ctx, findings)
        return findings

    # -- checks ------------------------------------------------------------

    async def _run_checks(
        self,
        ctx: AgentContext,
        finding: Finding,
        open_ports: set[tuple[Any, int]],
        live_hosts: set[str],
        source_by_asset: dict[str, set[str]],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        checks: dict[str, Any] = {
            "http_status": None,
            "http_ok": False,
            "http_blocked": False,
            "tcp_open": False,
            "asset_live": False,
            "corroborated": len(source_by_asset.get(finding.asset, set())) > 1,
            "active_successes": 0,
            "notes": [],
        }

        host = (urlparse(finding.asset).hostname or finding.attack_surface or finding.asset).lower()
        checks["asset_live"] = host in live_hosts
        if checks["asset_live"]:
            checks["active_successes"] += 1
        if checks["corroborated"]:
            checks["active_successes"] += 1

        if finding.source == "nmap":
            _, _, port_text = finding.asset.rpartition(":")
            try:
                port = int(port_text)
            except ValueError:
                port = 0
            if port:
                checks["tcp_open"] = await self._tcp_probe(host, port)
                if checks["tcp_open"]:
                    checks["active_successes"] += 1
                if (finding.asset.split(":")[0], port) in open_ports:
                    checks["notes"].append("Port confirmed by the nmap scan result.")

        if finding.source in {"nuclei", "ffuf", "httpx"}:
            asset = finding.asset if finding.asset.startswith(("http://", "https://")) else ctx.scan.target
            status, body_preview, blocked = await self._http_probe(client, asset)
            checks["http_status"] = status
            checks["http_blocked"] = blocked
            if status is not None:
                finding.evidence.append(
                    Evidence(
                        source="verification",
                        summary=f"HTTP verification returned {status} for {asset}",
                        raw={"status_code": status, "body_preview": body_preview[:400]},
                    )
                )
                if status < 500 and not blocked:
                    checks["http_ok"] = True
                    checks["active_successes"] += 1
                elif blocked:
                    checks["notes"].append(
                        "The response looked like an error or WAF block page rather than the "
                        "vulnerable behaviour."
                    )

        return checks

    @staticmethod
    async def _tcp_probe(host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        except (OSError, asyncio.TimeoutError, ValueError):
            return False
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass
        return True

    @staticmethod
    async def _http_probe(
        client: httpx.AsyncClient, url: str
    ) -> tuple[int | None, str, bool]:
        """Fetch ``url`` without mutating anything.

        Returns ``(status_code, body_preview, looks_like_a_block_page)``.
        """
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            # A TLS failure is common on assessment targets; retry without
            # certificate verification and record that we did so.
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as insecure:
                    response = await insecure.get(url)
            except httpx.HTTPError:
                return None, redact_text(str(exc)), False

        body = response.text[:800]
        lowered = body.lower()
        blocked_markers = (
            "access denied",
            "blocked by",
            "forbidden",
            "captcha",
            "cloudflare",
            "request blocked",
            "not found</title>",
        )
        looks_blocked = any(marker in lowered for marker in blocked_markers)
        return response.status_code, body, looks_blocked

    # -- scoring -----------------------------------------------------------

    def _score(self, finding: Finding, checks: dict[str, Any]) -> int:
        """Compute the deterministic evidence score (0-100)."""
        score = SEVERITY_BASE.get(finding.severity, 20)

        if checks["corroborated"]:
            score += 15
        if checks["asset_live"]:
            score += 12
        if checks["http_ok"]:
            score += 12
        if checks["tcp_open"]:
            score += 12
        if len(finding.evidence) >= 2:
            score += 8
        if finding.references:
            score += 5
        if finding.source == "nuclei" and checks["http_status"] is not None:
            score += 5
        if finding.source == "nmap" and not (finding.raw or {}).get("version"):
            # A port with no version banner is weaker evidence.
            score -= 8

        # Negative signals.
        if checks["http_blocked"]:
            score -= 20
        if checks["http_status"] in {404, 410}:
            score -= 25
        if finding.source == "ffuf" and checks["http_status"] in {401, 403}:
            score -= 15
        if not checks["asset_live"] and not checks["tcp_open"] and not checks["http_ok"]:
            score -= 20

        return max(0, min(100, score))

    # -- AI adjudication ---------------------------------------------------

    async def _apply_ai_verdicts(self, ctx: AgentContext, findings: list[Finding]) -> None:
        """Ask the AI to adjudicate each finding and apply its verdict."""
        for finding in findings:
            prompt = (
                "Finding under review:\n"
                f"{self.finding_summary(finding)}\n\n"
                f"Deterministic baseline confidence: {finding.baseline_confidence}\n"
                f"Verification checks: {checks_summary(finding)}\n"
            )
            payload = await self.ai_json(ctx, VERIFICATION_SYSTEM, prompt, max_tokens=900)
            if not payload:
                continue
            verdict = self._parse_verdict(payload)
            if verdict is None:
                continue

            finding.ai_adjusted = True
            finding.ai_analysis = verdict.reasoning or payload.get("reasoning", "")

            if verdict.severity is not None:
                finding.severity = verdict.severity
            if verdict.confidence is not None:
                finding.confidence = max(0, min(100, verdict.confidence))
            if verdict.verified is not None:
                finding.verified = verdict.verified

            if verdict.false_positive:
                finding.verified = False
                finding.severity = verdict.severity or Severity.INFORMATIONAL
                finding.confidence = min(finding.confidence, verdict.confidence or 15)
                finding.category = f"{finding.category}:likely-false-positive"

            if verdict.remediation:
                finding.evidence.append(
                    Evidence(
                        source="ai",
                        summary=f"AI remediation advice: {verdict.remediation}",
                        raw={"remediation": verdict.remediation},
                    )
                )
                finding.raw = {**(finding.raw or {}), "ai_remediation": verdict.remediation}

    @staticmethod
    def _parse_verdict(payload: dict[str, Any]) -> AiVerdict | None:
        severity: Severity | None = None
        raw_severity = payload.get("severity")
        if isinstance(raw_severity, str):
            for candidate in Severity:
                if candidate.value.lower() == raw_severity.strip().lower():
                    severity = candidate
                    break

        confidence: int | None = None
        raw_confidence = payload.get("confidence")
        if isinstance(raw_confidence, (int, float)):
            confidence = max(0, min(100, int(raw_confidence)))

        verified: bool | None = None
        raw_verified = payload.get("verified")
        if isinstance(raw_verified, bool):
            verified = raw_verified

        false_positive = bool(payload.get("false_positive"))
        if false_positive and verified is None:
            verified = False

        if severity is None and confidence is None and verified is None and not false_positive:
            return None

        return AiVerdict(
            severity=severity,
            confidence=confidence,
            verified=verified,
            false_positive=false_positive,
            reasoning=str(payload.get("reasoning") or ""),
            remediation=str(payload.get("remediation") or ""),
        )


def checks_summary(finding: Finding) -> str:
    """Human-readable summary of the evidence attached to a finding."""
    lines = [f"- {item.source}: {item.summary}" for item in finding.evidence]
    return "\n".join(lines) if lines else "(no checks recorded)"
