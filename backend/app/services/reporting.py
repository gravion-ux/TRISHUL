"""Report rendering for TRISHUL.

Produces four output formats from one scan record:

* ``report.json`` — the complete machine-readable record,
* ``report.md`` — a readable Markdown summary,
* ``report.html`` — a standalone HTML document,
* ``bug_bounty.md`` — a submission-ready write-up.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.app.core.config import ROOT_DIR, Settings
from backend.app.core.utils import ensure_directory, redact
from backend.app.models import Finding, ScanRecord

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")


class ReportingService:
    """Renders the four report formats."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        template_dir = ROOT_DIR / "backend" / "app" / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def generate_all(
        self, scan: ScanRecord, scan_dir: Path, executive_summary: str = ""
    ) -> dict[str, str]:
        """Write every report format and return their paths."""
        report_dir = ensure_directory(scan_dir / "reports")
        json_path = report_dir / "report.json"
        markdown_path = report_dir / "report.md"
        html_path = report_dir / "report.html"
        bounty_path = report_dir / "bug_bounty.md"

        payload = redact(scan.model_dump(mode="json"))
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

        # Every format is rendered from the redacted record. A credential
        # that a tool captured must not reach the Markdown, the HTML or
        # the bug-bounty write-up either.
        safe_scan = self._redacted_scan(scan)
        safe_summary = redact(executive_summary)
        markdown_path.write_text(
            self._markdown(safe_scan, safe_summary), encoding="utf-8"
        )
        html_path.write_text(
            self._html(safe_scan, safe_summary), encoding="utf-8"
        )
        bounty_path.write_text(self._bounty(safe_scan), encoding="utf-8")

        return {
            "json": str(json_path),
            "markdown": str(markdown_path),
            "html": str(html_path),
            "bug_bounty": str(bounty_path),
        }

    @staticmethod
    def _redacted_scan(scan: ScanRecord) -> ScanRecord:
        """Return a copy of ``scan`` with every credential redacted."""
        return ScanRecord.model_validate(redact(scan.model_dump(mode="json")))

    # -- markdown ----------------------------------------------------------

    def _markdown(self, scan: ScanRecord, executive_summary: str = "") -> str:
        counts = self._counts(scan)
        lines = [
            f"# TRISHUL Security Assessment Report: {scan.target}",
            "",
            f"- Scan ID: `{scan.id}`",
            f"- Status: `{scan.status.value}`",
            f"- Mode: `{scan.mode.value}`",
            f"- Started: `{scan.created_at.isoformat()}`",
            f"- Finished: `{scan.updated_at.isoformat()}`",
            f"- AI provider: `{scan.ai_provider}` (`{scan.ai_model or 'n/a'}`)",
            f"- Findings: `{len(scan.findings)}`",
            "",
            "## Severity Breakdown",
            "",
            "| Severity | Count |",
            "| --- | --- |",
            *[f"| {severity} | {counts.get(severity, 0)} |" for severity in SEVERITY_ORDER],
            "",
        ]
        if executive_summary:
            lines.extend(["## Executive Summary", "", executive_summary.strip(), ""])
        lines.extend(["## Findings", ""])
        if not scan.findings:
            lines.extend(["No findings were produced by this scan.", ""])
        for finding in scan.findings:
            lines.extend(self._finding_markdown(finding))
        lines.extend(
            [
                "---",
                "",
                "Produced by TRISHUL — an authorized security testing platform.",
                "All validation steps in this report are non-destructive.",
            ]
        )
        return "\n".join(lines).strip() + "\n"

    def _finding_markdown(self, finding: Finding) -> list[str]:
        evidence = finding.evidence[0].summary if finding.evidence else "No evidence recorded."
        poc = finding.poc.steps_to_reproduce if finding.poc else []
        lines = [
            f"### {finding.title}",
            f"- Severity: `{finding.severity.value}`",
            f"- Confidence: `{finding.confidence}` (evidence baseline `{finding.baseline_confidence}`)",
            f"- Verified: `{finding.verified}`",
            f"- Asset: `{finding.asset}`",
            f"- Source: `{finding.source}`",
            "",
            finding.description,
            "",
            f"Evidence: {evidence}",
            "",
        ]
        if finding.ai_analysis:
            lines.extend([f"AI analysis: {finding.ai_analysis}", ""])
        if poc:
            lines.append("Reproduction:")
            lines.extend([f"{index + 1}. {step}" for index, step in enumerate(poc)])
            lines.append("")
        return lines

    # -- html --------------------------------------------------------------

    def _html(self, scan: ScanRecord, executive_summary: str = "") -> str:
        template = self.env.get_template("report.html.j2")
        return template.render(scan=scan, executive_summary=executive_summary)

    # -- bug bounty --------------------------------------------------------

    def _bounty(self, scan: ScanRecord) -> str:
        sections = [
            f"# Bug Bounty Submission: {scan.target}",
            "",
            f"Scan ID: `{scan.id}` — generated by TRISHUL",
            "",
        ]
        if not scan.findings:
            sections.extend(["No findings were produced by this scan.", ""])
        for finding in scan.findings:
            if finding.poc:
                sections.append(finding.poc.bounty_report)
            else:
                sections.extend(
                    [
                        f"## {finding.title}",
                        f"Severity: {finding.severity.value}",
                        f"Confidence: {finding.confidence}",
                        "",
                        finding.description,
                        "",
                    ]
                )
            sections.append("")
        return "\n".join(sections).strip() + "\n"

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _counts(scan: ScanRecord) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in scan.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts
