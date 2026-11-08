"""CLI tests.

Covers argument parsing, the authorisation gate, the scan flow, the health
report and the provider report. The master agent and the health service are
replaced with stubs so no test launches real tooling or touches the network.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from backend.app.core.events import event_bus
from backend.app.models import (
    AiHealth,
    Evidence,
    Finding,
    HealthResponse,
    ProviderEdition,
    ScanMode,
    ScanRecord,
    ScanStatus,
    Severity,
    ToolHealth,
)
from backend.app.core.utils import utcnow


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def test_parser_accepts_the_documented_invocation():
    from cli.trishul import build_parser

    args = build_parser().parse_args(["example.com", "--mode", "deep"])

    assert args.target == "example.com"
    assert args.mode == "deep"
    # The limits are not defaulted here: an omitted flag means "use the
    # configured scan limits", so the configuration is not silently overridden
    # by a hard-coded number.
    assert args.threads is None
    assert args.timeout is None
    assert args.interactive is True
    assert args.yes is False


def test_parser_supports_quick_mode_and_overrides():
    from cli.trishul import build_parser

    args = build_parser().parse_args(
        ["example.com", "--mode", "quick", "--threads", "4", "--timeout", "120", "--no-interactive"]
    )

    assert args.mode == "quick"
    assert args.threads == 4
    assert args.timeout == 120
    assert args.interactive is False


def test_parser_rejects_an_unknown_mode():
    from cli.trishul import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["example.com", "--mode", "extreme"])


def test_parser_target_is_optional_for_utility_flags():
    from cli.trishul import build_parser

    args = build_parser().parse_args(["--health"])

    assert args.target is None
    assert args.health is True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_render_progress_formats_the_bar():
    from cli.trishul import render_progress

    assert render_progress(0) == "[" + "-" * 30 + "]   0%"
    assert render_progress(50) == "[" + "#" * 15 + "-" * 15 + "]  50%"
    assert render_progress(100) == "[" + "#" * 30 + "] 100%"


def test_cli_source_never_uses_shell_true():
    """A shell would turn a target into a command. The CLI must not have one."""
    root = Path(__file__).resolve().parents[1]
    for relative in ("cli/trishul.py", "backend/app/services/tool_runner.py"):
        source = (root / relative).read_text(encoding="utf-8")
        assert "shell=True" not in source, f"{relative} must never use shell=True"
        assert "shell = True" not in source, f"{relative} must never use shell=True"


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


def healthy_response() -> HealthResponse:
    return HealthResponse(
        version="1.0.0",
        edition=ProviderEdition.LOCAL,
        platform="linux",
        ready=True,
        tools=[],
        ai=AiHealth(
            configured=True,
            provider="ollama",
            model="llama3.1",
            reachable=True,
            message="ollama reachable",
        ),
    )


class FakeHealthService:
    def __init__(self, response: HealthResponse | None = None) -> None:
        self.response = response or healthy_response()

    async def get_health_async(self) -> HealthResponse:
        return self.response


class FakeStorage:
    def __init__(self, scan: ScanRecord) -> None:
        self.scan = scan

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        return self.scan if self.scan.id == scan_id else None


class FakeMasterAgent:
    def __init__(self, scan: ScanRecord) -> None:
        self.scan = scan
        self.request = None

    def create_scan(self, request):
        self.request = request
        return self.scan

    async def run_scan(self, scan_id: str):
        self.scan.status = ScanStatus.COMPLETED
        self.scan.findings = [
            Finding(
                id="f1",
                source="nuclei",
                category="scanner-match",
                title="Exposed .git directory",
                description="A .git directory was reachable.",
                severity=Severity.HIGH,
                confidence=78,
                baseline_confidence=61,
                verified=True,
                asset="https://example.com/.git/config",
                evidence=[Evidence(source="nuclei", summary="matched", raw={})],
            )
        ]
        self.scan.report_paths = {
            "json": "/tmp/trishul/report.json",
            "markdown": "/tmp/trishul/report.md",
        }
        await event_bus.publish(
            scan_id,
            {
                "type": "progress",
                "timestamp": utcnow().isoformat(),
                "stage": "completed",
                "percent": 100,
                "message": "Completed",
                "payload": {},
            },
        )
        return self.scan


def make_scan() -> ScanRecord:
    now = utcnow()
    return ScanRecord(
        id="cli-scan",
        target="example.com",
        mode=ScanMode.DEEP,
        status=ScanStatus.QUEUED,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="TICKET-2026-0001",
    )


# ---------------------------------------------------------------------------
# Authorisation gate
# ---------------------------------------------------------------------------


def test_scan_refuses_without_the_confirmation(monkeypatch, capsys):
    from cli import trishul

    scan = make_scan()
    monkeypatch.setattr(trishul, "health_service", FakeHealthService())
    monkeypatch.setattr(trishul, "master_agent", FakeMasterAgent(scan))
    monkeypatch.setattr(trishul, "storage", FakeStorage(scan))
    monkeypatch.setattr("builtins.input", lambda *args: "NO")

    args = trishul.build_parser().parse_args(["example.com", "--auth-note", "TICKET-2026-0001"])
    exit_code = asyncio.run(trishul.run_scan(args))

    assert exit_code == 1
    assert "Authorization confirmation not provided" in capsys.readouterr().out


def test_scan_refuses_a_short_authorization_note(monkeypatch, capsys):
    from cli import trishul

    scan = make_scan()
    monkeypatch.setattr(trishul, "health_service", FakeHealthService())
    monkeypatch.setattr(trishul, "master_agent", FakeMasterAgent(scan))
    monkeypatch.setattr(trishul, "storage", FakeStorage(scan))

    args = trishul.build_parser().parse_args(
        ["example.com", "--yes", "--auth-note", "abc"]
    )
    exit_code = asyncio.run(trishul.run_scan(args))

    assert exit_code == 1
    assert "at least 5 characters" in capsys.readouterr().out


def test_scan_refuses_when_required_tools_are_missing(monkeypatch, capsys):
    from cli import trishul

    broken = healthy_response()
    broken.ready = False
    broken.tools = [
        ToolHealth(
            name="nmap",
            installed=False,
            path=None,
            version=None,
            fix_command="sudo apt-get install -y nmap",
            required=True,
        )
    ]

    monkeypatch.setattr(trishul, "health_service", FakeHealthService(broken))

    args = trishul.build_parser().parse_args(["example.com", "--yes", "--auth-note", "TICKET-2026-0001"])
    exit_code = asyncio.run(trishul.run_scan(args))

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "Missing required tools" in output
    assert "nmap" in output


# ---------------------------------------------------------------------------
# Scan flow
# ---------------------------------------------------------------------------


def test_scan_runs_and_prints_the_report_paths(monkeypatch, capsys):
    from cli import trishul

    scan = make_scan()
    master = FakeMasterAgent(scan)
    monkeypatch.setattr(trishul, "health_service", FakeHealthService())
    monkeypatch.setattr(trishul, "master_agent", master)
    monkeypatch.setattr(trishul, "storage", FakeStorage(scan))

    args = trishul.build_parser().parse_args(
        ["example.com", "--mode", "deep", "--yes", "--auth-note", "TICKET-2026-0001", "--no-interactive"]
    )
    exit_code = asyncio.run(trishul.run_scan(args))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Authorized security testing platform" in output
    assert "AUTHORIZED SECURITY TESTING ONLY" in output
    assert "Scan status   : completed" in output
    assert "Findings      : 1" in output
    assert "report.json" in output
    assert "Exposed .git directory" in output
    # The authorisation note is forwarded to the scan request.
    assert master.request is not None
    assert master.request.authorized is True
    assert master.request.authorization_note == "TICKET-2026-0001"
    assert master.request.mode == ScanMode.DEEP


def test_print_findings_shows_the_baseline_and_the_ai_state(capsys):
    from cli.trishul import print_findings

    scan = make_scan()
    scan.findings = [
        Finding(
            id="f1",
            source="nuclei",
            category="scanner-match",
            title="Exposed .git directory",
            description="A .git directory was reachable.",
            severity=Severity.HIGH,
            confidence=78,
            baseline_confidence=61,
            verified=True,
            ai_adjusted=True,
            asset="https://example.com/.git/config",
            evidence=[Evidence(source="nuclei", summary="matched", raw={})],
        )
    ]

    print_findings(scan)
    output = capsys.readouterr().out

    assert "Confidence : 78 (evidence baseline 61) | verified: True" in output
    assert "adjudicated this finding" in output


# ---------------------------------------------------------------------------
# Utility commands
# ---------------------------------------------------------------------------


def test_health_command_reports_the_tools(monkeypatch, capsys):
    from cli import trishul

    monkeypatch.setattr(trishul, "health_service", FakeHealthService())

    exit_code = trishul.run_health()
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Ready      : yes" in output
    assert "Edition    : local" in output


def test_provider_command_lists_the_available_providers(monkeypatch, capsys):
    from cli import trishul

    exit_code = trishul.run_provider(trishul.build_parser().parse_args(["--provider"]))
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Available providers:" in output
    assert "ollama" in output
    assert "anthropic" in output


def test_provider_command_rejects_an_unknown_provider(capsys):
    from cli import trishul

    args = trishul.build_parser().parse_args(["--provider-set", "not-a-provider"])
    exit_code = trishul.run_provider(args)

    assert exit_code == 1
    assert "Unknown provider" in capsys.readouterr().out


def test_autofix_refuses_without_confirmation(monkeypatch, capsys):
    from cli import trishul

    class FakeRegistry:
        def autofix_commands(self):
            return ["sudo apt-get install -y nmap"]

    monkeypatch.setattr(trishul, "tool_registry", FakeRegistry())
    monkeypatch.setattr("builtins.input", lambda *args: "n")

    exit_code = trishul.run_autofix()
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Nothing was executed." in output
