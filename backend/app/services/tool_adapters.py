"""Adapters that drive the external security tools.

Each adapter owns the command line for one tool, writes its raw output into
the scan's artifact directory and returns a normalised Python structure.

Safety properties:
* Targets are validated against the scope policy before a tool runs.
* Every command is an argv list executed without a shell.
* ffuf is bounded by a request budget and a per-run timeout.
"""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from backend.app.core.config import ROOT_DIR, Settings
from backend.app.core.scope import ScopePolicy
from backend.app.core.utils import dump_json, ensure_directory, slugify
from backend.app.models import ScanMode
from backend.app.services.tool_runner import ToolExecutionError, ToolRunner
from backend.app.services.tooling import ToolRegistry


class ToolAdapter:
    """Common base for the tool adapters."""

    def __init__(self, runner: ToolRunner, settings: Settings, tools: ToolRegistry) -> None:
        self.runner = runner
        self.settings = settings
        self.tools = tools

    @property
    def timeout(self) -> int:
        return self.settings.scan.timeout_seconds


class HttpxAdapter(ToolAdapter):
    """Live host detection using projectdiscovery ``httpx``."""

    async def run(
        self,
        targets: list[str],
        output_dir: Path,
        mode: ScanMode,
        scope: ScopePolicy | None = None,
    ) -> list[dict[str, Any]]:
        targets = sorted({target for target in targets if target})
        if not targets:
            return []
        ensure_directory(output_dir)

        if scope is not None:
            for target in targets:
                await scope.check(_host_of(target))

        input_file = output_dir / "httpx-targets.txt"
        input_file.write_text("\n".join(targets), encoding="utf-8")

        args = [
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-threads",
            str(self.settings.scan.thread_limit),
            "-l",
            str(input_file),
        ]
        result = await self.runner.run(
            self.tools.resolve("httpx"), args, timeout=self.timeout
        )
        (output_dir / "httpx.jsonl").write_text(result.stdout, encoding="utf-8")

        parsed: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                parsed.append(item)
        dump_json(output_dir / "httpx-summary.json", parsed)
        return parsed


class NmapAdapter(ToolAdapter):
    """Port scanning and service detection using ``nmap``."""

    async def run(
        self,
        host: str,
        output_dir: Path,
        mode: ScanMode,
        scope: ScopePolicy | None = None,
    ) -> dict[str, Any]:
        ensure_directory(output_dir)
        if scope is not None:
            await scope.check(host)

        args = ["-Pn", "-T4", "-oX", "-"]
        if mode == ScanMode.DEEP:
            args.extend(["-sV", "--top-ports", "1000"])
        else:
            args.extend(["-F"])
        args.append(host)

        result = await self.runner.run(self.tools.resolve("nmap"), args, timeout=self.timeout)
        (output_dir / "nmap.xml").write_text(result.stdout, encoding="utf-8")

        services: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(result.stdout or "<nmaprun />")
        except ET.ParseError:
            root = None
        if root is not None:
            for host_node in root.findall("host"):
                address_node = host_node.find("address")
                address = (
                    address_node.attrib.get("addr", host) if address_node is not None else host
                )
                for port_node in host_node.findall(".//port"):
                    state = port_node.find("state")
                    if state is None or state.attrib.get("state") != "open":
                        continue
                    service = port_node.find("service")
                    services.append(
                        {
                            "host": address,
                            "port": int(port_node.attrib.get("portid", "0")),
                            "protocol": port_node.attrib.get("protocol", "tcp"),
                            "state": "open",
                            "service": service.attrib.get("name", "") if service is not None else "",
                            "product": service.attrib.get("product", "") if service is not None else "",
                            "version": service.attrib.get("version", "") if service is not None else "",
                        }
                    )
        summary = {"host": host, "services": services}
        dump_json(output_dir / "nmap-summary.json", summary)
        return summary


class NucleiAdapter(ToolAdapter):
    """Template-based vulnerability scanning using ``nuclei``."""

    async def run(
        self,
        targets: list[str],
        output_dir: Path,
        mode: ScanMode,
        scope: ScopePolicy | None = None,
    ) -> list[dict[str, Any]]:
        targets = sorted({target for target in targets if target})
        if not targets:
            return []
        ensure_directory(output_dir)

        if scope is not None:
            for target in targets:
                await scope.check(_host_of(target))

        input_file = output_dir / "nuclei-targets.txt"
        input_file.write_text("\n".join(targets), encoding="utf-8")

        args = [
            "-jsonl",
            "-silent",
            "-severity",
            "low,medium,high,critical",
            "-rl",
            "50",
            "-l",
            str(input_file),
        ]
        if mode == ScanMode.DEEP:
            # Disable update checks so a scan never reaches out to the
            # network for template updates in the middle of an engagement.
            args.extend(["-duc"])
        result = await self.runner.run(
            self.tools.resolve("nuclei"),
            args,
            timeout=self.timeout,
            allow_non_zero=True,
        )
        (output_dir / "nuclei.jsonl").write_text(result.stdout, encoding="utf-8")

        parsed: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                parsed.append(item)
        dump_json(output_dir / "nuclei-summary.json", parsed)
        return parsed


class FfufAdapter(ToolAdapter):
    """Controlled content discovery and parameter fuzzing using ``ffuf``."""

    async def run(
        self,
        urls: list[str],
        output_dir: Path,
        mode: ScanMode,
        scope: ScopePolicy | None = None,
    ) -> list[dict[str, Any]]:
        urls = sorted({url for url in urls if url})
        if not urls:
            return []
        ensure_directory(output_dir)

        if scope is not None:
            for url in urls:
                await scope.check(_host_of(url))

        semaphore = asyncio.Semaphore(self.settings.scan.thread_limit)
        tasks = [
            self._fuzz_url(index, url, output_dir, semaphore)
            for index, url in enumerate(urls)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        flattened: list[dict[str, Any]] = []
        for result in results:
            if isinstance(result, BaseException):
                continue
            flattened.extend(result)
        dump_json(output_dir / "ffuf-summary.json", flattened)
        return flattened

    async def _fuzz_url(
        self, index: int, url: str, output_dir: Path, semaphore: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        async with semaphore:
            slug = slugify(url) or f"target-{index}"
            # A unique prefix keeps concurrent runs from overwriting each
            # other's output files.
            prefix = f"{index:03d}-{slug}"
            directory_results = await self._run_ffuf(
                url=url.rstrip("/") + "/FUZZ",
                wordlist=str(self.settings.wordlist_path),
                output_file=output_dir / f"{prefix}-dirs.json",
                mode_name="directory",
            )
            separator = "&" if "?" in url else "?"
            parameter_results = await self._run_ffuf(
                url=f"{url}{separator}FUZZ=test",
                wordlist=str(self.settings.param_wordlist_path),
                output_file=output_dir / f"{prefix}-params.json",
                mode_name="parameter",
            )
            return directory_results + parameter_results

    async def _run_ffuf(
        self, url: str, wordlist: str, output_file: Path, mode_name: str
    ) -> list[dict[str, Any]]:
        args = [
            "-w",
            wordlist,
            "-u",
            url,
            "-t",
            str(self.settings.scan.thread_limit),
            "-mc",
            ",".join(str(code) for code in self.settings.scan.ffuf_status_filter),
            "-maxtime",
            str(max(30, self.settings.scan.timeout_seconds // 3)),
            "-timeout",
            "10",
            "-of",
            "json",
            "-o",
            str(output_file),
        ]
        try:
            await self.runner.run(
                self.tools.resolve("ffuf"),
                args,
                timeout=self.timeout,
                allow_non_zero=True,
            )
        except ToolExecutionError:
            return []
        if not output_file.exists():
            return []
        try:
            raw = json.loads(output_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        results: list[dict[str, Any]] = []
        for item in raw.get("results", []) or []:
            payload = dict(item)
            payload["mode"] = mode_name
            results.append(payload)
        return results


def _host_of(target: str) -> str:
    """Extract the hostname from a URL or bare host string."""
    if "://" in target:
        from urllib.parse import urlparse

        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/")[0].split(":")[0]


def resolve_wordlist(settings: Settings, relative: str) -> Path:
    """Resolve a wordlist path relative to the project root."""
    candidate = Path(relative)
    return candidate if candidate.is_absolute() else ROOT_DIR / candidate
