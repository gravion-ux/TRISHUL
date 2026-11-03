"""Discovery and health reporting for the external security tools."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from backend.app.core.config import Settings
from backend.app.models import ToolHealth
from backend.app.services.tool_runner import ToolExecutionError, ToolRunner

Validator = Callable[[str, str | None], bool]

CORE_TOOLS = ("httpx", "nuclei", "ffuf", "nmap")


@dataclass(frozen=True)
class ToolSpec:
    """How to find one tool and how to prove the binary is the right one."""

    name: str
    candidates: list[str]
    probes: list[list[str]]
    fix_command: str
    required: bool = False
    validator: Validator | None = None


class ToolRegistry:
    """Locates the external binaries and reports on their availability."""

    def __init__(self, runner: ToolRunner, settings: Settings) -> None:
        self.runner = runner
        self.settings = settings
        self._specs = self._build_specs()

    def _build_specs(self) -> dict[str, ToolSpec]:
        home = Path.home()
        go_bin = Path(os.environ.get("GOPATH", str(home / "go"))) / "bin"
        return {
            "httpx": ToolSpec(
                name="httpx",
                candidates=[
                    self.settings.tools.httpx,
                    str(go_bin / "httpx"),
                    str(go_bin / "httpx.exe"),
                ],
                probes=[["-version"]],
                fix_command="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
                required=True,
                validator=self._validate_projectdiscovery_httpx,
            ),
            "nuclei": ToolSpec(
                name="nuclei",
                candidates=[
                    self.settings.tools.nuclei,
                    str(go_bin / "nuclei"),
                    str(go_bin / "nuclei.exe"),
                ],
                probes=[["-version"]],
                fix_command="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                required=True,
            ),
            "ffuf": ToolSpec(
                name="ffuf",
                candidates=[
                    self.settings.tools.ffuf,
                    str(go_bin / "ffuf"),
                    str(go_bin / "ffuf.exe"),
                ],
                probes=[["-V"], ["-version"]],
                fix_command="sudo apt-get install -y ffuf",
                required=True,
            ),
            "nmap": ToolSpec(
                name="nmap",
                candidates=[
                    self.settings.tools.nmap,
                    r"C:\Program Files\Nmap\nmap.exe",
                    r"C:\Program Files (x86)\Nmap\nmap.exe",
                    "/usr/bin/nmap",
                ],
                probes=[["--version"]],
                fix_command="sudo apt-get install -y nmap",
                required=True,
            ),
            "python3": ToolSpec(
                name="python3",
                candidates=["python3", "python"],
                probes=[["--version"]],
                fix_command="sudo apt-get install -y python3 python3-venv",
                validator=self._validate_python,
            ),
            "node": ToolSpec(
                name="node",
                candidates=["node", r"C:\Program Files\nodejs\node.exe"],
                probes=[["--version"]],
                fix_command="sudo apt-get install -y nodejs npm",
            ),
            "npm": ToolSpec(
                name="npm",
                candidates=["npm", r"C:\Program Files\nodejs\npm.cmd", r"C:\Program Files\nodejs\npm.exe"],
                probes=[["--version"]],
                fix_command="sudo apt-get install -y npm",
            ),
            "git": ToolSpec(
                name="git",
                candidates=["git", r"C:\Program Files\Git\cmd\git.exe", r"C:\Program Files\Git\bin\git.exe"],
                probes=[["--version"]],
                fix_command="sudo apt-get install -y git",
            ),
            "go": ToolSpec(
                name="go",
                candidates=["go", r"C:\Program Files\Go\bin\go.exe", "/usr/local/go/bin/go"],
                probes=[["version"]],
                fix_command="sudo apt-get install -y golang",
            ),
            "ollama": ToolSpec(
                name="ollama",
                candidates=[
                    "ollama",
                    r"C:\Program Files\Ollama\ollama.exe",
                    str(home / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe"),
                    "/usr/local/bin/ollama",
                    "/usr/bin/ollama",
                ],
                probes=[["--version"]],
                fix_command="install Ollama from https://ollama.com/download",
            ),
        }

    # -- lookup ------------------------------------------------------------

    def spec(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError as exc:
            raise ToolExecutionError(f"Unknown tool: {name}") from exc

    def resolve(self, name: str) -> str:
        """Return the absolute path of a usable tool binary."""
        spec = self.spec(name)
        for candidate in spec.candidates:
            path, version = self.runner.version(candidate, spec.probes)
            if not path:
                continue
            if spec.validator and not spec.validator(path, version):
                continue
            return path
        raise ToolExecutionError(
            f"Tool not installed or invalid: {name}. Suggested fix: {spec.fix_command}"
        )

    def health(self, name: str) -> ToolHealth:
        spec = self.spec(name)
        for candidate in spec.candidates:
            path, version = self.runner.version(candidate, spec.probes)
            if not path:
                continue
            if spec.validator and not spec.validator(path, version):
                continue
            return ToolHealth(
                name=name,
                installed=True,
                path=path,
                version=version,
                fix_command=spec.fix_command,
                required=spec.required,
            )
        return ToolHealth(
            name=name,
            installed=False,
            path=None,
            version=None,
            fix_command=spec.fix_command,
            required=spec.required,
        )

    def all_health(self) -> list[ToolHealth]:
        ordered = [
            "httpx",
            "nuclei",
            "ffuf",
            "nmap",
            "python3",
            "node",
            "npm",
            "git",
            "go",
            "ollama",
        ]
        return [self.health(name) for name in ordered]

    def core_tools_ready(self) -> bool:
        """True when every required scanning tool is present."""
        return all(self.health(name).installed for name in CORE_TOOLS)

    def missing_core_tools(self) -> list[str]:
        return [name for name in CORE_TOOLS if not self.health(name).installed]

    # -- remediation -------------------------------------------------------

    def autofix_commands(self, missing: list[str] | None = None) -> list[str]:
        """Return the shell commands that would install the missing tools.

        The commands are only ever *returned*. TRISHUL never executes package
        management on the operator's behalf without an explicit, interactive
        confirmation in the CLI.
        """
        requested = missing or [name for name in self._specs if not self.health(name).installed]
        system = platform.system().lower()
        commands: list[str] = []
        if system == "linux":
            apt_packages: list[str] = []
            if any(name in requested for name in ["git"]):
                apt_packages.append("git")
            if any(name in requested for name in ["nmap"]):
                apt_packages.append("nmap")
            if any(name in requested for name in ["python3"]):
                apt_packages.extend(["python3", "python3-venv", "python3-pip"])
            if any(name in requested for name in ["node", "npm"]):
                apt_packages.extend(["nodejs", "npm"])
            if any(name in requested for name in ["go", "httpx", "nuclei"]):
                apt_packages.append("golang")
            if "ffuf" in requested:
                apt_packages.append("ffuf")
            if apt_packages:
                commands.append("sudo apt-get update")
                commands.append(f"sudo apt-get install -y {' '.join(sorted(set(apt_packages)))}")
            if any(name in requested for name in ["httpx"]):
                commands.append("go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
            if any(name in requested for name in ["nuclei"]):
                commands.append("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            if any(name in requested for name in ["ffuf"]):
                commands.append("go install github.com/ffuf/ffuf/v2@latest")
        elif system == "windows":
            if any(name in requested for name in ["git"]):
                commands.append(
                    "winget install Git.Git --silent --accept-package-agreements --accept-source-agreements"
                )
            if any(name in requested for name in ["nmap"]):
                commands.append(
                    "winget install Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements"
                )
            if any(name in requested for name in ["node", "npm"]):
                commands.append(
                    "winget install OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements"
                )
            if any(name in requested for name in ["go", "httpx", "nuclei", "ffuf"]):
                commands.append(
                    "winget install GoLang.Go --silent --accept-package-agreements --accept-source-agreements"
                )
                commands.append("go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
                commands.append("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
                commands.append("go install github.com/ffuf/ffuf/v2@latest")
            if any(name in requested for name in ["ollama"]):
                commands.append("winget install Ollama.Ollama --silent")
        return commands

    # -- validators --------------------------------------------------------

    @staticmethod
    def _validate_projectdiscovery_httpx(path: str, version: str | None) -> bool:
        """Reject the unrelated Python package that also calls itself httpx."""
        if not version:
            return False
        version_text = version.lower()
        path_text = path.lower()
        if "python" in path_text and "scripts" in path_text and version_text.startswith("usage:"):
            return False
        return "usage:" not in version_text

    @staticmethod
    def _validate_python(_path: str, version: str | None) -> bool:
        if not version:
            return False
        return "python was not found" not in version.lower()
