"""Controlled update of the external tool templates and payload lists.

The updater never installs software on the operator's behalf: it refreshes the
data that the already-installed tools consume and merges any wordlists the
operator has supplied locally.

Deliberately absent: TRISHUL's own code never clones, fetches or calls a GitHub
repository. The nuclei template refresh is performed by the upstream ``nuclei``
binary updating its own signature database, and it can be skipped entirely by
pointing nuclei at a local template directory. Wordlists are merged from files
the operator places on disk, so the update path is entirely local.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.app.core.config import ROOT_DIR, Settings
from backend.app.core.utils import redact
from backend.app.services.tool_runner import ToolExecutionError, ToolRunner
from backend.app.services.tooling import ToolRegistry

# Where an operator may drop additional, authorised wordlists. The two
# sub-directories map onto the two active lists, so a corpus never leaks into
# the wrong kind of scan.
EXTRA_WORDLIST_ROOT = ROOT_DIR / "config" / "wordlists" / "extra"
EXTRA_COMMON_DIR = EXTRA_WORDLIST_ROOT / "common"
EXTRA_PARAMS_DIR = EXTRA_WORDLIST_ROOT / "params"


class UpdaterService:
    """Refreshes templates and merges local wordlists in a controlled, reversible way."""

    def __init__(self, runner: ToolRunner, settings: Settings, tools: ToolRegistry) -> None:
        self.runner = runner
        self.settings = settings
        self.tools = tools

    async def update_all(self) -> dict[str, Any]:
        return {
            "nuclei_templates": await self._update_nuclei_templates(),
            "wordlists": await self._update_wordlists(),
        }

    async def _update_nuclei_templates(self) -> dict[str, Any]:
        try:
            result = await self.runner.run(
                self.tools.resolve("nuclei"),
                ["-ut"],
                timeout=900,
                allow_non_zero=True,
            )
            return {
                "success": result.returncode == 0,
                "stdout": redact(result.stdout[-1000:]),
                "stderr": redact(result.stderr[-1000:]),
            }
        except ToolExecutionError as exc:
            return {"success": False, "error": redact(str(exc))}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": f"{type(exc).__name__}: {exc}"}

    async def _update_wordlists(self) -> dict[str, Any]:
        """Merge operator-supplied wordlists into the bundled lists.

        The bundled lists in ``config/wordlists/`` are the baseline. An
        operator who is authorised to use a larger corpus drops ``.txt`` files
        into ``config/wordlists/extra/`` and runs ``trishul --update`` to fold
        them into the active lists. Nothing is downloaded: the merge is a
        purely local, deterministic operation that can be undone by restoring
        the bundled file.

        The corpus is split by kind so it never leaks into the wrong scan:
        ``config/wordlists/extra/common/`` feeds host and path discovery and
        ``config/wordlists/extra/params/`` feeds query-parameter discovery.
        """
        try:
            return self._merge_wordlists_inner()
        except OSError as exc:
            return {"success": False, "error": redact(str(exc))}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": f"{type(exc).__name__}: {exc}"}

    def _merge_wordlists_inner(self) -> dict[str, Any]:
        targets = {
            "common": (self.settings.wordlist_path, EXTRA_COMMON_DIR),
            "params": (self.settings.param_wordlist_path, EXTRA_PARAMS_DIR),
        }

        merged: dict[str, Any] = {}
        changed = False
        all_sources: list[str] = []
        for label, (target, extra_dir) in targets.items():
            extra_files = (
                sorted(path for path in extra_dir.glob("*.txt") if path.is_file())
                if extra_dir.is_dir()
                else []
            )
            all_sources.extend(str(path) for path in extra_files)

            base = _read_entries(target)
            additions: list[str] = []
            for source in extra_files:
                additions.extend(_read_entries(source))
            combined = sorted({entry for entry in base + additions if entry})
            merged[label] = {
                "path": str(target),
                "entries_before": len(base),
                "entries_after": len(combined),
                "added": len(combined) - len(base),
                "sources": [str(path) for path in extra_files],
            }
            if combined != base:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("\n".join(combined) + "\n", encoding="utf-8")
                changed = True

        return {
            "success": True,
            "changed": changed,
            "extra_sources": all_sources,
            "lists": merged,
            "message": (
                "Merged the local wordlists in config/wordlists/extra/."
                if all_sources
                else "No extra wordlists found. Drop .txt files into "
                "config/wordlists/extra/common/ or config/wordlists/extra/params/ "
                "and run this again to merge them."
            ),
        }


def _read_entries(path: Path) -> list[str]:
    """Read a wordlist, ignoring blank lines and ``#`` comments."""
    if not path.is_file():
        return []
    entries: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(stripped)
    return entries
