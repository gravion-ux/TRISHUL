"""ReasoningEngine — deduplication, false-positive triage and ranking.

The engine first removes obvious duplicates deterministically, then asks the
AI to identify *semantic* duplicates and likely false positives that a
keyword match cannot catch. It finally ranks the surviving findings.
"""

from __future__ import annotations

import re
from typing import Any

from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import Evidence, Finding, Severity

REASONING_SYSTEM = """You are triaging the findings of an authorized security scan.

You will be given a numbered list of findings with their identifiers, titles, assets, severities and confidences.

Identify:
1. "duplicates": findings that describe the same underlying issue. For each group give the identifier to KEEP and the identifiers to MERGE into it.
2. "false_positives": findings that are almost certainly not real issues (for example a directory listing that is simply the application's normal home page, or a port that is simply the application's intended public port).

Be careful: only mark something as a false positive when the evidence clearly supports it. Err on the side of keeping a finding.

Respond with a single JSON object and nothing else:
{
  "duplicates": [{"keep": "<id>", "merge": ["<id>", "..."]}],
  "false_positives": ["<id>", "..."],
  "notes": "<optional short commentary>"
}"""

_NOISE = re.compile(r"[^a-z0-9]+")


class ReasoningEngine(BaseAgent):
    """Consolidates and ranks the verified findings."""

    name = "ReasoningEngine"

    async def run(self, ctx: AgentContext, findings: list[Finding]) -> list[Finding]:
        deduped = self._deterministic_dedup(findings)
        adjudicated = await self._ai_triage(ctx, deduped)
        return self._rank(adjudicated)

    # -- deterministic pass ------------------------------------------------

    @staticmethod
    def _normalise_title(title: str) -> str:
        return _NOISE.sub(" ", title.lower()).strip()

    def _deterministic_dedup(self, findings: list[Finding]) -> list[Finding]:
        merged: dict[tuple[str, str], Finding] = {}
        for finding in findings:
            key = (self._normalise_title(finding.title), finding.asset)
            existing = merged.get(key)
            if existing is None:
                merged[key] = finding
                continue
            existing.evidence.extend(finding.evidence)
            existing.references = sorted(set(existing.references + finding.references))
            existing.enrichment.extend(finding.enrichment)
            existing.confidence = max(existing.confidence, finding.confidence)
            existing.baseline_confidence = max(
                existing.baseline_confidence, finding.baseline_confidence
            )
            existing.verified = existing.verified or finding.verified
            existing.ai_adjusted = existing.ai_adjusted or finding.ai_adjusted
            if existing.severity != finding.severity:
                # Keep the more severe of the two.
                if self.severity_rank(finding.severity.value) > self.severity_rank(
                    existing.severity.value
                ):
                    existing.severity = finding.severity
        return list(merged.values())

    # -- AI pass -----------------------------------------------------------

    async def _ai_triage(self, ctx: AgentContext, findings: list[Finding]) -> list[Finding]:
        if not findings or len(findings) < 2:
            return findings

        listing = "\n".join(
            f"- id={finding.id} | severity={finding.severity.value} | "
            f"confidence={finding.confidence} | asset={finding.asset} | title={finding.title}"
            for finding in findings[:120]
        )
        payload = await self.ai_json(
            ctx,
            REASONING_SYSTEM,
            f"Findings:\n{listing}",
            max_tokens=1500,
        )
        if not payload:
            return findings

        by_id = {finding.id: finding for finding in findings}
        dropped: set[str] = set()

        for group in payload.get("duplicates") or []:
            if not isinstance(group, dict):
                continue
            keep_id = str(group.get("keep") or "")
            keep = by_id.get(keep_id)
            if keep is None:
                continue
            for merge_id in group.get("merge") or []:
                merge = by_id.get(str(merge_id))
                if merge is None or merge.id == keep.id:
                    continue
                keep.evidence.extend(merge.evidence)
                keep.references = sorted(set(keep.references + merge.references))
                keep.enrichment.extend(merge.enrichment)
                keep.confidence = max(keep.confidence, merge.confidence)
                keep.baseline_confidence = max(keep.baseline_confidence, merge.baseline_confidence)
                keep.verified = keep.verified or merge.verified
                dropped.add(merge.id)

        for false_positive_id in payload.get("false_positives") or []:
            finding = by_id.get(str(false_positive_id))
            if finding is None or finding.id in dropped:
                continue
            finding.verified = False
            finding.severity = Severity.INFORMATIONAL
            finding.confidence = min(finding.confidence, 15)
            finding.category = f"{finding.category}:likely-false-positive"
            finding.evidence.append(
                Evidence(
                    source="ai",
                    summary="AI triage marked this finding as a likely false positive.",
                    raw={"adjudication": "false_positive"},
                )
            )

        return [finding for finding in findings if finding.id not in dropped]

    # -- ranking -----------------------------------------------------------

    @staticmethod
    def _rank(findings: list[Finding]) -> list[Finding]:
        def sort_key(finding: Finding) -> tuple[Any, ...]:
            rank = {
                Severity.CRITICAL.value: 4,
                Severity.HIGH.value: 3,
                Severity.MEDIUM.value: 2,
                Severity.LOW.value: 1,
                Severity.INFORMATIONAL.value: 0,
            }
            return (
                rank.get(finding.severity.value, 0),
                finding.confidence,
                1 if finding.verified else 0,
                finding.title.lower(),
            )

        return sorted(findings, key=sort_key, reverse=True)
