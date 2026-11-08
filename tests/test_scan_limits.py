"""Per-scan execution limits must reach the tools that run the scan.

``POST /api/scans`` accepts ``thread_limit`` and ``timeout_seconds``, but
the values were dropped when the scan record was created and every tool
adapter read the global configuration instead. The operator's choice was
therefore accepted, validated, and then ignored.

These tests pin the whole chain: request -> scan record -> agent context
-> tool adapter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.models import ScanLimits, ScanMode, ScanRequest
from backend.app.services.tool_adapters import FfufAdapter, HttpxAdapter

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeRegistry:
    def resolve(self, name: str) -> str:
        return f"/usr/bin/{name}"


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], int]] = []

    async def run(
        self,
        executable: str,
        args: list[str],
        timeout: int = 600,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        allow_non_zero: bool = False,
        input_text: str | None = None,
    ):
        from backend.app.services.tool_runner import CompletedCommand

        self.calls.append((executable, list(args), timeout))
        if "-o" in args:
            index = args.index("-o")
            if index + 1 < len(args):
                target = Path(args[index + 1])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}", encoding="utf-8")
        return CompletedCommand(
            executable=executable,
            args=list(args),
            returncode=0,
            stdout="",
            stderr="",
            duration_ms=1,
        )


# ---------------------------------------------------------------------------
# Scan record
# ---------------------------------------------------------------------------


@pytest.fixture()
def ctx(
    storage,
    settings,
    ai_manager,
    integration_manager,
    tool_registry,
    adapters,
    scope,
    tmp_path,
):
    from backend.app.core.utils import utcnow
    from backend.app.engine.base import AgentContext
    from backend.app.models import ScanRecord, ScanStatus

    now = utcnow()
    record = ScanRecord(
        id="scan-limits",
        target="https://example.com",
        mode=ScanMode.DEEP,
        status=ScanStatus.RUNNING,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="TEST-1234",
    )
    return AgentContext(
        scan=record,
        settings=settings,
        storage=storage,
        ai=ai_manager,
        integrations=integration_manager,
        scope=scope,
        tools=tool_registry,
        adapters=adapters,
        scan_dir=tmp_path / "scan",
    )


def test_the_requested_limits_are_persisted_on_the_scan_record(master_agent, settings):
    request = ScanRequest(
        target="https://example.com",
        authorized=True,
        authorization_note="TEST-1234",
        thread_limit=3,
        timeout_seconds=120,
    )

    scan = master_agent.create_scan(request)

    assert scan.thread_limit == 3
    assert scan.timeout_seconds == 120


def test_omitted_limits_fall_back_to_the_configured_defaults(master_agent, settings):
    request = ScanRequest(
        target="https://example.com",
        authorized=True,
        authorization_note="TEST-1234",
    )

    scan = master_agent.create_scan(request)

    assert scan.thread_limit == settings.scan.thread_limit
    assert scan.timeout_seconds == settings.scan.timeout_seconds


def test_the_agent_context_exposes_the_effective_limits(ctx):
    ctx.scan.thread_limit = 5
    ctx.scan.timeout_seconds = 240

    limits = ctx.limits

    assert isinstance(limits, ScanLimits)
    assert limits.thread_limit == 5
    assert limits.timeout_seconds == 240


def test_the_agent_context_falls_back_to_the_configured_limits(ctx, settings):
    ctx.scan.thread_limit = None
    ctx.scan.timeout_seconds = None

    limits = ctx.limits

    assert limits.thread_limit == settings.scan.thread_limit
    assert limits.timeout_seconds == settings.scan.timeout_seconds


# ---------------------------------------------------------------------------
# Tool adapters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_httpx_uses_the_per_scan_thread_limit_and_timeout(settings, tmp_path):
    runner = FakeRunner()
    adapter = HttpxAdapter(runner, settings, FakeRegistry())

    await adapter.run(
        ["https://example.com"],
        tmp_path / "httpx",
        ScanMode.QUICK,
        limits=ScanLimits(thread_limit=3, timeout_seconds=120),
    )

    _executable, args, timeout = runner.calls[0]
    assert args[args.index("-threads") + 1] == "3"
    assert timeout == 120


@pytest.mark.asyncio
async def test_ffuf_uses_the_per_scan_thread_limit_and_timeout(settings, tmp_path):
    runner = FakeRunner()
    adapter = FfufAdapter(runner, settings, FakeRegistry())

    await adapter.run(
        ["https://example.com"],
        tmp_path / "ffuf",
        ScanMode.QUICK,
        limits=ScanLimits(thread_limit=4, timeout_seconds=150),
    )

    assert runner.calls
    for _executable, args, timeout in runner.calls:
        assert args[args.index("-t") + 1] == "4"
        assert args[args.index("-maxtime") + 1] == "50"
        assert timeout == 150


@pytest.mark.asyncio
async def test_the_adapters_fall_back_to_the_configured_limits(settings, tmp_path):
    runner = FakeRunner()
    adapter = HttpxAdapter(runner, settings, FakeRegistry())

    await adapter.run(["https://example.com"], tmp_path / "httpx", ScanMode.QUICK)

    _executable, args, timeout = runner.calls[0]
    assert args[args.index("-threads") + 1] == str(settings.scan.thread_limit)
    assert timeout == settings.scan.timeout_seconds


# ---------------------------------------------------------------------------
# The ffuf request budget
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ffuf_honours_the_configured_request_budget(settings, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(f"word-{index}" for index in range(20)) + "\n", encoding="utf-8")
    settings.scan.wordlist = str(wordlist)
    settings.scan.param_wordlist = str(wordlist)
    settings.scan.ffuf_max_requests = 4

    runner = FakeRunner()
    adapter = FfufAdapter(runner, settings, FakeRegistry())

    await adapter.run(["https://example.com"], tmp_path / "ffuf", ScanMode.QUICK)

    wordlists = [args[args.index("-w") + 1] for _executable, args, _timeout in runner.calls]
    assert wordlists, "ffuf must be invoked with a wordlist"
    total = 0
    for path in wordlists:
        words = Path(path).read_text(encoding="utf-8").splitlines()
        total += len(words)
    assert total <= settings.scan.ffuf_max_requests
