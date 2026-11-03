"""Tool adapter tests.

The four adapters (httpx, nmap, nuclei, ffuf) are exercised against a fake
runner so the tests never launch a real scanner and never touch the network.
The fake runner still honours the adapter's contract: it receives an argv
list, and it writes the output files the adapter asked for.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.core.scope import ScopeError, ScopePolicy
from backend.app.models import ScanMode
from backend.app.services.tool_adapters import (
    FfufAdapter,
    HttpxAdapter,
    NmapAdapter,
    NucleiAdapter,
    _host_of,
)
from backend.app.services.tool_runner import CompletedCommand, ToolExecutionError


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeRegistry:
    """A ToolRegistry stand-in that always resolves."""

    def __init__(self) -> None:
        self.resolved: list[str] = []

    def resolve(self, name: str) -> str:
        self.resolved.append(name)
        return f"/usr/bin/{name}"


class FakeRunner:
    """A ToolRunner stand-in that returns canned output."""

    def __init__(self, stdout: str = "", stderr: str = "", files: dict[str, str] | None = None) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.files = files or {}
        self.calls: list[tuple[str, list[str]]] = []
        self.fail_with: Exception | None = None

    async def run(
        self,
        executable: str,
        args: list[str],
        timeout: int = 600,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        allow_non_zero: bool = False,
        input_text: str | None = None,
    ) -> CompletedCommand:
        self.calls.append((executable, list(args)))
        if self.fail_with is not None:
            raise self.fail_with

        # Honour "-o <file>" so adapters that read their own output files work.
        if "-o" in args:
            index = args.index("-o")
            if index + 1 < len(args):
                target = Path(args[index + 1])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(self.files.get(target.name, "{}"), encoding="utf-8")

        return CompletedCommand(
            executable=executable,
            args=list(args),
            returncode=0,
            stdout=self.stdout,
            stderr=self.stderr,
            duration_ms=1,
        )


NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="conn-refused"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

HTTPX_JSONL = "\n".join(
    [
        json.dumps(
            {
                "url": "https://example.com",
                "status_code": 200,
                "title": "Example Domain",
                "tech": ["Nginx", "PHP"],
                "host": "93.184.216.34",
            }
        ),
        "this line is not json and must be skipped",
        json.dumps(
            {
                "url": "http://example.com",
                "status_code": 301,
                "title": "Redirect",
                "tech": [],
                "host": "93.184.216.34",
            }
        ),
    ]
)

NUCLEI_JSONL = "\n".join(
    [
        json.dumps(
            {
                "template-id": "exposed-git",
                "matched-at": "https://example.com/.git/config",
                "info": {"name": "Exposed .git", "severity": "high"},
            }
        ),
        json.dumps(
            {
                "template-id": "ssl-issuer",
                "host": "https://example.com",
                "info": {"name": "SSL issuer", "severity": "info"},
            }
        ),
    ]
)

FFUF_JSON = json.dumps(
    {
        "commandline": "ffuf -w wordlist -u https://example.com/FUZZ",
        "results": [
            {
                "url": "https://example.com/.env",
                "status": 200,
                "length": 120,
                "words": 10,
                "lines": 5,
                "input": {"FUZZ": ".env"},
            },
            {
                "url": "https://example.com/admin",
                "status": 403,
                "length": 80,
                "words": 4,
                "lines": 3,
                "input": {"FUZZ": "admin"},
            },
        ],
    }
)

# ffuf writes one file per URL and per mode; the adapter reads them back.
FFUF_FILES = {
    "000-https-example-com-dirs.json": FFUF_JSON,
    "000-https-example-com-params.json": FFUF_JSON,
}


@pytest.fixture()
def registry() -> FakeRegistry:
    return FakeRegistry()


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_httpx_parses_jsonl_and_writes_artifacts(settings, registry, tmp_path):
    runner = FakeRunner(stdout=HTTPX_JSONL)
    adapter = HttpxAdapter(runner, settings, registry)
    out = tmp_path / "httpx"

    results = await adapter.run(["https://example.com", "http://example.com"], out, ScanMode.DEEP)

    assert len(results) == 2
    assert results[0]["status_code"] == 200
    assert "Nginx" in results[0]["tech"]

    assert (out / "httpx.jsonl").exists()
    assert (out / "httpx-summary.json").exists()
    summary = json.loads((out / "httpx-summary.json").read_text(encoding="utf-8"))
    assert len(summary) == 2


@pytest.mark.asyncio
async def test_httpx_returns_empty_for_no_targets(settings, registry, tmp_path):
    runner = FakeRunner()
    adapter = HttpxAdapter(runner, settings, registry)

    results = await adapter.run([], tmp_path / "httpx", ScanMode.QUICK)

    assert results == []
    assert runner.calls == []


@pytest.mark.asyncio
async def test_httpx_deduplicates_targets(settings, registry, tmp_path):
    runner = FakeRunner(stdout=HTTPX_JSONL)
    adapter = HttpxAdapter(runner, settings, registry)
    out = tmp_path / "httpx"

    await adapter.run(["https://example.com", "https://example.com"], out, ScanMode.QUICK)

    targets_file = (out / "httpx-targets.txt").read_text(encoding="utf-8")
    assert targets_file.strip().splitlines() == ["https://example.com"]


@pytest.mark.asyncio
async def test_httpx_passes_target_as_separate_argv_entry(settings, registry, tmp_path):
    runner = FakeRunner(stdout="")
    adapter = HttpxAdapter(runner, settings, registry)

    await adapter.run(["https://example.com"], tmp_path / "httpx", ScanMode.QUICK)

    _executable, args = runner.calls[0]
    assert isinstance(args, list)
    assert "-l" in args
    # The target is in a file, never concatenated into a shell string.
    assert all(";" not in arg and "|" not in arg for arg in args)


@pytest.mark.asyncio
async def test_httpx_enforces_scope(settings, registry, tmp_path):
    runner = FakeRunner(stdout="")
    adapter = HttpxAdapter(runner, settings, registry)
    scope = ScopePolicy(authorized_targets=["allowed.example"])

    with pytest.raises(ScopeError):
        await adapter.run(["https://blocked.example"], tmp_path / "httpx", ScanMode.QUICK, scope)

    assert runner.calls == [], "no tool may run before the scope check passes"


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nmap_parses_open_ports_only(settings, registry, tmp_path):
    runner = FakeRunner(stdout=NMAP_XML)
    adapter = NmapAdapter(runner, settings, registry)
    out = tmp_path / "nmap"

    summary = await adapter.run("example.com", out, ScanMode.DEEP)

    assert summary["host"] == "example.com"
    ports = {service["port"] for service in summary["services"]}
    assert ports == {22, 80}
    ssh = next(item for item in summary["services"] if item["port"] == 22)
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.9p1"
    assert ssh["state"] == "open"

    assert (out / "nmap.xml").exists()
    assert (out / "nmap-summary.json").exists()


@pytest.mark.asyncio
async def test_nmap_quick_mode_uses_fast_scan(settings, registry, tmp_path):
    runner = FakeRunner(stdout=NMAP_XML)
    adapter = NmapAdapter(runner, settings, registry)

    await adapter.run("example.com", tmp_path / "nmap", ScanMode.QUICK)

    _executable, args = runner.calls[0]
    assert "-F" in args
    assert "-sV" not in args


@pytest.mark.asyncio
async def test_nmap_deep_mode_uses_service_detection(settings, registry, tmp_path):
    runner = FakeRunner(stdout=NMAP_XML)
    adapter = NmapAdapter(runner, settings, registry)

    await adapter.run("example.com", tmp_path / "nmap", ScanMode.DEEP)

    _executable, args = runner.calls[0]
    assert "-sV" in args
    assert "--top-ports" in args


@pytest.mark.asyncio
async def test_nmap_survives_malformed_xml(settings, registry, tmp_path):
    runner = FakeRunner(stdout="not xml at all")
    adapter = NmapAdapter(runner, settings, registry)

    summary = await adapter.run("example.com", tmp_path / "nmap", ScanMode.QUICK)

    assert summary["services"] == []


@pytest.mark.asyncio
async def test_nmap_enforces_scope(settings, registry, tmp_path):
    runner = FakeRunner(stdout=NMAP_XML)
    adapter = NmapAdapter(runner, settings, registry)
    scope = ScopePolicy(authorized_targets=["allowed.example"])

    with pytest.raises(ScopeError):
        await adapter.run("blocked.example", tmp_path / "nmap", ScanMode.QUICK, scope)

    assert runner.calls == []


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nuclei_parses_jsonl(settings, registry, tmp_path):
    runner = FakeRunner(stdout=NUCLEI_JSONL)
    adapter = NucleiAdapter(runner, settings, registry)
    out = tmp_path / "nuclei"

    results = await adapter.run(["https://example.com"], out, ScanMode.DEEP)

    assert len(results) == 2
    assert results[0]["template-id"] == "exposed-git"
    assert (out / "nuclei.jsonl").exists()
    assert (out / "nuclei-summary.json").exists()


@pytest.mark.asyncio
async def test_nuclei_deep_mode_disables_update_check(settings, registry, tmp_path):
    runner = FakeRunner(stdout="")
    adapter = NucleiAdapter(runner, settings, registry)

    await adapter.run(["https://example.com"], tmp_path / "nuclei", ScanMode.DEEP)

    _executable, args = runner.calls[0]
    assert "-duc" in args


@pytest.mark.asyncio
async def test_nuclei_quick_mode_keeps_update_check(settings, registry, tmp_path):
    runner = FakeRunner(stdout="")
    adapter = NucleiAdapter(runner, settings, registry)

    await adapter.run(["https://example.com"], tmp_path / "nuclei", ScanMode.QUICK)

    _executable, args = runner.calls[0]
    assert "-duc" not in args


@pytest.mark.asyncio
async def test_nuclei_enforces_scope(settings, registry, tmp_path):
    runner = FakeRunner(stdout="")
    adapter = NucleiAdapter(runner, settings, registry)
    scope = ScopePolicy(authorized_targets=["allowed.example"])

    with pytest.raises(ScopeError):
        await adapter.run(["https://blocked.example"], tmp_path / "nuclei", ScanMode.QUICK, scope)

    assert runner.calls == []


# ---------------------------------------------------------------------------
# ffuf
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ffuf_reads_its_output_file(settings, registry, tmp_path):
    runner = FakeRunner(files=dict(FFUF_FILES))
    adapter = FfufAdapter(runner, settings, registry)
    out = tmp_path / "ffuf"

    results = await adapter.run(["https://example.com"], out, ScanMode.QUICK)

    assert len(results) == 4
    assert results[0]["input"]["FUZZ"] == ".env"
    assert results[0]["mode"] == "directory"
    assert (out / "ffuf-summary.json").exists()


@pytest.mark.asyncio
async def test_ffuf_labels_directory_and_parameter_results(settings, registry, tmp_path):
    runner = FakeRunner(files=dict(FFUF_FILES))
    adapter = FfufAdapter(runner, settings, registry)

    results = await adapter.run(["https://example.com"], tmp_path / "ffuf", ScanMode.QUICK)

    modes = {item["mode"] for item in results}
    assert modes == {"directory", "parameter"}


@pytest.mark.asyncio
async def test_ffuf_bounds_the_request(settings, registry, tmp_path):
    runner = FakeRunner(files={})
    adapter = FfufAdapter(runner, settings, registry)

    await adapter.run(["https://example.com"], tmp_path / "ffuf", ScanMode.QUICK)

    assert runner.calls, "ffuf must be invoked"
    for _executable, args in runner.calls:
        assert "-maxtime" in args
        assert "-t" in args
        assert "-mc" in args


@pytest.mark.asyncio
async def test_ffuf_survives_tool_failure(settings, registry, tmp_path):
    runner = FakeRunner()
    runner.fail_with = ToolExecutionError("ffuf crashed")
    adapter = FfufAdapter(runner, settings, registry)

    results = await adapter.run(["https://example.com"], tmp_path / "ffuf", ScanMode.QUICK)

    assert results == []


@pytest.mark.asyncio
async def test_ffuf_returns_empty_for_no_urls(settings, registry, tmp_path):
    runner = FakeRunner()
    adapter = FfufAdapter(runner, settings, registry)

    results = await adapter.run([], tmp_path / "ffuf", ScanMode.QUICK)

    assert results == []
    assert runner.calls == []


@pytest.mark.asyncio
async def test_ffuf_enforces_scope(settings, registry, tmp_path):
    runner = FakeRunner()
    adapter = FfufAdapter(runner, settings, registry)
    scope = ScopePolicy(authorized_targets=["allowed.example"])

    with pytest.raises(ScopeError):
        await adapter.run(["https://blocked.example"], tmp_path / "ffuf", ScanMode.QUICK, scope)

    assert runner.calls == []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_host_of_extracts_hostname_from_url():
    assert _host_of("https://example.com/path?x=1") == "example.com"
    assert _host_of("http://example.com:8443/path") == "example.com"


def test_host_of_handles_bare_host():
    assert _host_of("example.com") == "example.com"
    assert _host_of("example.com:443") == "example.com"
