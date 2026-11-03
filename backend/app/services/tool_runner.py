"""Safe subprocess execution for external security tools.

Design rules enforced here:

* No shell is ever used — arguments are passed as an argv list, so a target
  containing shell metacharacters cannot become a command.
* Only executables on the allowlist may run.
* Output is capped so a runaway tool cannot exhaust memory.
* Timeouts kill the whole process group, not just the direct child.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

MAX_OUTPUT_BYTES = 32 * 1024 * 1024

# Tools colour their output; the escape sequences must not leak into the
# health report.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# A version-looking token, e.g. "v1.9.0", "2.1.0-dev", "7.94".
_VERSION_TOKEN = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?")


@dataclass
class CompletedCommand:
    """The result of one external command."""

    executable: str
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int = 0
    timed_out: bool = False


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot be run or fails."""


class ToolPolicyError(ToolExecutionError):
    """Raised when a tool is not permitted to run."""


class ToolRunner:
    """Runs allowlisted external binaries with strict limits."""

    def __init__(self, allowed_binaries: list[str] | None = None) -> None:
        self.allowed_binaries = {
            item.lower() for item in (allowed_binaries or ["httpx", "nuclei", "ffuf", "nmap", "git", "go"])
        }

    # -- resolution --------------------------------------------------------

    def _resolve_executable(self, executable: str) -> str | None:
        candidate = Path(executable)
        if candidate.exists() and candidate.is_file():
            return str(candidate)
        return shutil.which(executable)

    def _assert_allowed(self, executable: str, resolved: str) -> None:
        name = Path(resolved).name.lower()
        if name.endswith(".exe"):
            name = name[:-4]
        if name not in self.allowed_binaries:
            raise ToolPolicyError(
                f"Refusing to execute {resolved!r}: only these binaries are permitted: "
                f"{', '.join(sorted(self.allowed_binaries))}."
            )

    # -- execution ---------------------------------------------------------

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
        """Execute ``executable`` with ``args`` and return its output.

        Raises
        ------
        ToolPolicyError
            When the executable is not on the allowlist.
        ToolExecutionError
            When the tool is missing, times out, or exits non-zero (unless
            ``allow_non_zero`` is set).
        """
        resolved = self._resolve_executable(executable)
        if not resolved:
            raise ToolExecutionError(f"Tool not installed: {executable}")
        self._assert_allowed(executable, resolved)

        merged_env = os.environ.copy()
        # Keep the child environment predictable and non-interactive.
        merged_env.setdefault("LC_ALL", "C")
        if env:
            merged_env.update(env)

        started = asyncio.get_event_loop().time()
        try:
            process = await asyncio.create_subprocess_exec(
                resolved,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
                cwd=str(cwd) if cwd else None,
                env=merged_env,
            )
        except OSError as exc:
            raise ToolExecutionError(f"Could not start {resolved}: {exc}") from exc

        try:
            if input_text is not None:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input_text.encode("utf-8")), timeout=timeout
                )
            else:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            await self._terminate(process)
            raise ToolExecutionError(
                f"Command timed out after {timeout}s: {resolved}"
            ) from exc

        duration_ms = int((asyncio.get_event_loop().time() - started) * 1000)
        stdout_bytes = stdout[:MAX_OUTPUT_BYTES]
        stderr_bytes = stderr[:MAX_OUTPUT_BYTES]

        result = CompletedCommand(
            executable=resolved,
            args=list(args),
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_ms=duration_ms,
        )
        if result.returncode != 0 and not allow_non_zero:
            raise ToolExecutionError(
                f"Command failed ({result.returncode}): {resolved} {' '.join(args)}\n"
                f"{result.stderr.strip()[:2000]}"
            )
        return result

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process) -> None:
        """Kill the process and any children it spawned."""
        try:
            if hasattr(os, "killpg") and process.pid:
                os.killpg(os.getpgid(process.pid), 9)
            else:
                process.kill()
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except (asyncio.TimeoutError, ProcessLookupError):
            pass

    # -- discovery ---------------------------------------------------------

    def version(self, executable: str, probes: list[list[str]]) -> tuple[str | None, str | None]:
        """Return ``(resolved_path, version_line)`` for a tool.

        Runs synchronously because it is only used during health checks.
        """
        resolved = self._resolve_executable(executable)
        if not resolved:
            return None, None
        for probe in probes:
            try:
                completed = subprocess.run(
                    [resolved, *probe],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                    shell=False,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            output = (completed.stdout or completed.stderr or "").strip().splitlines()
            version_line = self._extract_version_line(output)
            if version_line:
                return resolved, version_line
        return resolved, None

    @staticmethod
    def _extract_version_line(lines: list[str]) -> str | None:
        """Pick the most useful version line out of a tool's probe output.

        Several scanners print an ASCII banner before the version, so the
        first line is often artwork rather than a version. Prefer a line that
        names a version and carries a version-shaped token, then any line with
        such a token, and only then fall back to the first meaningful line.
        """
        cleaned = [text for text in (_ANSI_ESCAPE.sub("", line).strip() for line in lines) if text]
        if not cleaned:
            return None
        for text in cleaned:
            if "version" in text.lower() and _VERSION_TOKEN.search(text):
                return text
        for text in cleaned:
            if _VERSION_TOKEN.search(text):
                return text
        return cleaned[0]
