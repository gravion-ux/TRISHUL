"""Updater tests and the "no remote repository dependency" invariant.

The predecessor project fetched a public API catalogue from a GitHub raw URL
at runtime. That integration was removed outright, and TRISHUL must never grow
one back: the application's own code may not read from a remote repository.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.services.updater import UpdaterService

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Invariant: no remote repository as a runtime dependency
# ---------------------------------------------------------------------------


def _python_sources() -> list[Path]:
    paths: list[Path] = []
    for directory in ("backend", "cli", "tests"):
        for path in sorted((ROOT / directory).rglob("*.py")):
            # This file names the forbidden patterns on purpose.
            if path.name == Path(__file__).name:
                continue
            paths.append(path)
    return paths


def test_no_raw_githubusercontent_url_anywhere():
    """The old public-apis integration read from raw.githubusercontent.com."""
    offenders: list[str] = []
    for path in _python_sources():
        text = path.read_text(encoding="utf-8")
        if "raw.githubusercontent.com" in text:
            offenders.append(str(path.relative_to(ROOT)))

    assert offenders == [], f"raw.githubusercontent.com is referenced in: {offenders}"


def test_the_public_apis_integration_is_gone():
    assert not (ROOT / "backend" / "app" / "services" / "osint.py").exists()

    for path in _python_sources():
        text = path.read_text(encoding="utf-8").lower()
        assert "public-apis" not in text, f"{path} still references public-apis"
        assert "public_apis" not in text, f"{path} still references public_apis"


def test_the_updater_never_clones_a_repository():
    source = (ROOT / "backend" / "app" / "services" / "updater.py").read_text(encoding="utf-8")
    lowered = source.lower()

    assert "github.com" not in lowered
    assert "git clone" not in lowered
    assert ".clone(" not in lowered
    assert "repo.clone" not in lowered


def test_no_module_clones_a_git_repository():
    """A `git clone` in the backend would be a repository dependency."""
    for path in _python_sources():
        lowered = path.read_text(encoding="utf-8").lower()
        assert "git clone" not in lowered, f"{path} clones a repository"
        assert "repo.clone" not in lowered, f"{path} clones a repository"


# ---------------------------------------------------------------------------
# Updater behaviour
# ---------------------------------------------------------------------------


class FakeRunner:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.calls: list[tuple[str, list[str]]] = []

    async def run(self, executable, args, timeout=600, cwd=None, env=None, allow_non_zero=False,
                  input_text=None):
        from backend.app.services.tool_runner import CompletedCommand

        self.calls.append((executable, list(args)))
        return CompletedCommand(
            executable=executable,
            args=list(args),
            returncode=self.returncode,
            stdout="templates updated",
            stderr="",
            duration_ms=1,
        )


class FakeTools:
    def resolve(self, name: str) -> str:
        return f"/usr/bin/{name}"


@pytest.fixture()
def updater(settings, tool_registry):
    return UpdaterService(FakeRunner(), settings, tool_registry)


@pytest.mark.asyncio
async def test_update_all_reports_both_steps(updater):
    result = await updater.update_all()

    assert set(result) == {"nuclei_templates", "wordlists"}
    assert result["nuclei_templates"]["success"] is True
    assert result["wordlists"]["success"] is True


@pytest.mark.asyncio
async def test_nuclei_template_refresh_uses_the_nuclei_binary(updater):
    await updater.update_all()

    executable, args = updater.runner.calls[0]
    assert Path(executable).stem.lower() == "nuclei"
    assert args == ["-ut"]


@pytest.mark.asyncio
async def test_wordlist_merge_is_local_and_idempotent(updater, tmp_path, monkeypatch):
    import backend.app.services.updater as updater_module

    common = tmp_path / "common.txt"
    params = tmp_path / "params.txt"
    common.write_text("admin\nlogin\n", encoding="utf-8")
    params.write_text("id\n", encoding="utf-8")

    extra_common = tmp_path / "extra" / "common"
    extra_params = tmp_path / "extra" / "params"
    extra_common.mkdir(parents=True)
    extra_params.mkdir(parents=True)
    (extra_common / "more.txt").write_text("login\nbackup\n# comment\n\n", encoding="utf-8")
    (extra_params / "q.txt").write_text("page\nsort\n", encoding="utf-8")

    monkeypatch.setattr(updater_module, "EXTRA_COMMON_DIR", extra_common)
    monkeypatch.setattr(updater_module, "EXTRA_PARAMS_DIR", extra_params)
    monkeypatch.setattr(type(updater.settings), "wordlist_path", property(lambda self: common))
    monkeypatch.setattr(type(updater.settings), "param_wordlist_path", property(lambda self: params))

    result = await updater._update_wordlists()

    assert result["success"] is True
    assert result["changed"] is True
    assert result["lists"]["common"]["entries_before"] == 2
    assert result["lists"]["common"]["entries_after"] == 3
    assert result["lists"]["params"]["entries_before"] == 1
    assert result["lists"]["params"]["entries_after"] == 3
    # Each corpus lands in its own list and nowhere else.
    assert common.read_text(encoding="utf-8").split() == ["admin", "backup", "login"]
    assert params.read_text(encoding="utf-8").split() == ["id", "page", "sort"]
    assert set(result["extra_sources"]) == {
        str(extra_common / "more.txt"),
        str(extra_params / "q.txt"),
    }

    # Running it again must not change anything.
    second = await updater._update_wordlists()
    assert second["changed"] is False
    assert second["lists"]["common"]["entries_after"] == 3


@pytest.mark.asyncio
async def test_wordlist_merge_without_extra_files_is_a_no_op(updater, tmp_path, monkeypatch):
    import backend.app.services.updater as updater_module

    common = tmp_path / "common.txt"
    params = tmp_path / "params.txt"
    common.write_text("admin\n", encoding="utf-8")
    params.write_text("id\n", encoding="utf-8")

    monkeypatch.setattr(updater_module, "EXTRA_COMMON_DIR", tmp_path / "missing" / "common")
    monkeypatch.setattr(updater_module, "EXTRA_PARAMS_DIR", tmp_path / "missing" / "params")
    monkeypatch.setattr(type(updater.settings), "wordlist_path", property(lambda self: common))
    monkeypatch.setattr(type(updater.settings), "param_wordlist_path", property(lambda self: params))

    result = await updater._update_wordlists()

    assert result["success"] is True
    assert result["changed"] is False
    assert result["extra_sources"] == []
    assert common.read_text(encoding="utf-8").strip() == "admin"


@pytest.mark.asyncio
async def test_update_reports_a_missing_nuclei_without_crashing(settings, tool_registry):
    class BrokenTools:
        def resolve(self, name: str) -> str:
            from backend.app.services.tool_runner import ToolExecutionError

            raise ToolExecutionError(f"Tool not installed: {name}")

    service = UpdaterService(FakeRunner(), settings, BrokenTools())
    result = await service.update_all()

    assert result["nuclei_templates"]["success"] is False
    assert "not installed" in result["nuclei_templates"]["error"]
    assert result["wordlists"]["success"] is True
