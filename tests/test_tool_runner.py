"""Tests for the safe subprocess runner."""

from __future__ import annotations

import sys

import pytest

from backend.app.services.tool_runner import ToolExecutionError, ToolPolicyError, ToolRunner


def test_runner_rejects_binaries_outside_the_allowlist():
    runner = ToolRunner(allowed_binaries=["httpx", "nuclei"])
    with pytest.raises(ToolPolicyError):
        runner._assert_allowed("bash", "/usr/bin/bash")
    with pytest.raises(ToolPolicyError):
        runner._assert_allowed("rm", "/bin/rm")


def test_runner_allows_listed_binaries():
    runner = ToolRunner(allowed_binaries=["httpx"])
    runner._assert_allowed("httpx", "/usr/local/bin/httpx")
    runner._assert_allowed("httpx", "/usr/local/bin/httpx.exe")


@pytest.mark.asyncio
async def test_runner_reports_missing_tool():
    runner = ToolRunner(allowed_binaries=["definitely-not-installed-xyz"])
    with pytest.raises(ToolExecutionError):
        await runner.run("definitely-not-installed-xyz", ["--help"])


@pytest.mark.asyncio
async def test_runner_executes_without_a_shell(tmp_path):
    """Shell metacharacters in arguments must be treated as literal text."""
    runner = ToolRunner(allowed_binaries=["python3", "python"])
    marker = tmp_path / "pwned.txt"
    result = await runner.run(
        sys.executable,
        ["-c", f"print('hello'); open({str(marker)!r}, 'w').write('x')", "safe; echo pwned"],
        timeout=30,
        allow_non_zero=True,
    )
    assert "hello" in result.stdout
    assert marker.exists()
    assert "pwned" not in result.stdout


@pytest.mark.asyncio
async def test_runner_raises_on_non_zero_exit():
    runner = ToolRunner(allowed_binaries=["python3", "python"])
    with pytest.raises(ToolExecutionError):
        await runner.run(sys.executable, ["-c", "import sys; sys.exit(3)"], timeout=30)


@pytest.mark.asyncio
async def test_runner_allows_non_zero_when_requested():
    runner = ToolRunner(allowed_binaries=["python3", "python"])
    result = await runner.run(
        sys.executable, ["-c", "import sys; sys.exit(3)"], timeout=30, allow_non_zero=True
    )
    assert result.returncode == 3


@pytest.mark.asyncio
async def test_runner_enforces_timeout():
    runner = ToolRunner(allowed_binaries=["python3", "python"])
    with pytest.raises(ToolExecutionError):
        await runner.run(sys.executable, ["-c", "import time; time.sleep(30)"], timeout=2)


def test_version_probe_returns_first_line(tmp_path):
    runner = ToolRunner()
    path, version = runner.version(sys.executable, [["--version"]])
    assert path is not None
    assert version is not None


class TestVersionExtraction:
    """The probe output of several scanners starts with an ASCII banner."""

    def test_picks_the_version_line_out_of_an_ascii_banner(self):
        lines = [
            "     __    __  __       _  __",
            "   / /_  / /_/ /_____ | |/ /",
            "/_/ /_/\\__/\\__/ .___/_/|_|",
            "             /_/",
            "",
            "\t\tprojectdiscovery.io",
            "",
            "[\x1b[34mINF\x1b[0m] Current Version: v1.9.0",
        ]

        assert ToolRunner._extract_version_line(lines) == "[INF] Current Version: v1.9.0"

    def test_strips_ansi_escape_sequences(self):
        lines = ["[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.7.1"]

        assert ToolRunner._extract_version_line(lines) == "[INF] Nuclei Engine Version: v3.7.1"

    def test_falls_back_to_a_bare_version(self):
        assert ToolRunner._extract_version_line(["v24.14.0"]) == "v24.14.0"

    def test_falls_back_to_the_first_meaningful_line(self):
        assert ToolRunner._extract_version_line(["", "  ", "ffuf version"]) == "ffuf version"

    def test_returns_none_for_empty_output(self):
        assert ToolRunner._extract_version_line([]) is None
        assert ToolRunner._extract_version_line(["", "   "]) is None

    def test_keeps_a_usage_line_for_the_httpx_validator(self):
        """The unrelated Python httpx package must still be rejected."""
        lines = ["usage: httpx [options] <url>"]

        assert ToolRunner._extract_version_line(lines) == "usage: httpx [options] <url>"
