"""Secrets must never reach a report, in any of the four formats.

The JSON report was redacted; the Markdown, bug-bounty and HTML reports
were not, and the raw tool payloads that feed them were not redacted
either. A credential that a tool captured in a response body therefore
ended up in ``report.md``, ``bug_bounty.md`` and ``report.html``.

These tests pin the redaction at its source (the detection agent) and in
every report format.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.core.utils import redact, utcnow
from backend.app.engine.detection import DetectionAgent
from backend.app.models import (
    Evidence,
    Finding,
    PocBundle,
    ScanMode,
    ScanRecord,
    ScanStatus,
    Severity,
)
from backend.app.services.reporting import ReportingService

SECRET_PASSWORD = "s3cr3t-passphrase"
SECRET_TOKEN = "ghp_0123456789abcdefghij"
SECRET_KEY = "AIzaSyD-NotARealKey-0123456789"


def build_scan() -> ScanRecord:
    now = utcnow()
    return ScanRecord(
        id="scan-redaction",
        target=f"https://admin:{SECRET_PASSWORD}@example.com/",
        mode=ScanMode.DEEP,
        status=ScanStatus.COMPLETED,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="TEST-1234",
        ai_provider="ollama",
        ai_model="llama3.1:8b",
        findings=[
            Finding(
                id="finding-1",
                source="nuclei",
                category="scanner-match",
                title="Exposed configuration",
                description=f"The response contained Authorization: Bearer {SECRET_TOKEN}.",
                severity=Severity.HIGH,
                confidence=80,
                asset=f"https://admin:{SECRET_PASSWORD}@example.com/.env",
                evidence=[
                    Evidence(
                        source="nuclei",
                        summary=f"matched api_key={SECRET_KEY}",
                        raw={"api_key": SECRET_KEY, "authorization": f"Bearer {SECRET_TOKEN}"},
                    )
                ],
                raw={"api_key": SECRET_KEY, "password": SECRET_PASSWORD},
                poc=PocBundle(
                    steps_to_reproduce=[f"Replay the request with token: {SECRET_TOKEN}"],
                    request_example=f"curl -isk https://admin:{SECRET_PASSWORD}@example.com/.env",
                    bounty_report=f"## Exposed configuration\n\nUse token: {SECRET_TOKEN}",
                    generated_by="deterministic",
                ),
            )
        ],
    )


@pytest.fixture()
async def reports(tmp_path, settings) -> dict[str, Path]:
    service = ReportingService(settings)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    paths = await service.generate_all(build_scan(), scan_dir)
    return {name: Path(path) for name, path in paths.items()}


# ---------------------------------------------------------------------------
# Report formats
# ---------------------------------------------------------------------------


def test_every_report_format_redacts_the_target_password(reports):
    for name, path in reports.items():
        text = path.read_text(encoding="utf-8")
        assert SECRET_PASSWORD not in text, f"{name} leaked the target password"


def test_every_report_format_redacts_evidence_secrets(reports):
    for name, path in reports.items():
        text = path.read_text(encoding="utf-8")
        assert SECRET_TOKEN not in text, f"{name} leaked the bearer token"
        assert SECRET_KEY not in text, f"{name} leaked the api key"


def test_the_json_report_stays_machine_readable(reports):
    payload = json.loads(reports["json"].read_text(encoding="utf-8"))
    assert payload["id"] == "scan-redaction"
    assert payload["findings"][0]["title"] == "Exposed configuration"


def test_the_markdown_report_keeps_the_finding(reports):
    text = reports["markdown"].read_text(encoding="utf-8")
    assert "Exposed configuration" in text
    assert "Severity: `High`" in text


def test_the_bug_bounty_report_keeps_the_finding(reports):
    text = reports["bug_bounty"].read_text(encoding="utf-8")
    assert "Exposed configuration" in text


def test_the_html_report_keeps_the_finding(reports):
    text = reports["html"].read_text(encoding="utf-8")
    assert "Exposed configuration" in text
    assert "<html" in text


# ---------------------------------------------------------------------------
# Redaction at the source
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detection_redacts_the_raw_tool_output(storage):
    agent = DetectionAgent(storage, None)
    profile = {"host": "example.com", "url": "https://example.com"}
    scan_result = {
        "nuclei": [
            {
                "template-id": "exposed-env",
                "matched-at": "https://example.com/.env",
                "info": {
                    "name": "Exposed .env",
                    "severity": "high",
                    "description": f"The file contains api_key={SECRET_KEY}",
                },
                "extra": {"authorization": f"Bearer {SECRET_TOKEN}"},
            }
        ]
    }

    findings = await agent.run(
        _ctx(storage), profile, {}, scan_result, {}
    )

    finding = findings[0]
    dumped = json.dumps(finding.raw, default=str)
    assert SECRET_KEY not in dumped
    assert SECRET_TOKEN not in dumped
    assert SECRET_KEY not in finding.evidence[0].raw.get("extra", {}).get("authorization", "***")


@pytest.mark.asyncio
async def test_detection_redacts_the_finding_description(storage):
    agent = DetectionAgent(storage, None)
    profile = {"host": "example.com", "url": "https://example.com"}
    scan_result = {
        "nuclei": [
            {
                "template-id": "exposed-env",
                "matched-at": "https://example.com/.env",
                "info": {
                    "name": "Exposed .env",
                    "severity": "high",
                    "description": f"The file contains api_key={SECRET_KEY}",
                },
            }
        ]
    }

    findings = await agent.run(_ctx(storage), profile, {}, scan_result, {})

    assert SECRET_KEY not in findings[0].description


def test_redaction_keeps_the_structure_intact():
    payload = {"a": ["x", {"b": f"password={SECRET_PASSWORD}"}]}
    cleaned = redact(payload)
    assert cleaned["a"][0] == "x"
    assert SECRET_PASSWORD not in json.dumps(cleaned)


def _ctx(storage):
    """The detection agent does not read the context, so a stub is enough."""
    return None
