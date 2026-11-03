#!/usr/bin/env python3
"""Build the three TRISHUL release archives and verify their contents.

All three archives are produced from one source tree, so they can never drift
apart:

* ``TRISHUL-LOCAL.zip``    — the LOCAL edition is the default configuration.
* ``TRISHUL-PROVIDER.zip`` — the PROVIDER edition is the default configuration.
* ``TRISHUL-SOURCE.zip``   — the neutral configuration, with both editions
  selectable at runtime.

Every archive contains the complete project — backend, frontend, CLI, tests,
migrations and documentation — plus a prebuilt ``frontend/dist`` so the
dashboard works without a Node toolchain.

Archives never contain credentials, databases or scan output.

Usage::

    python scripts/build_release.py --output dist
"""

from __future__ import annotations

import argparse
import compileall
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ARCHIVE_ROOT = "TRISHUL"

# Directory names that are never packaged.
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".idea",
    ".vscode",
    "dist-info",
}

# Exact file names that are never packaged.
EXCLUDED_FILES = {
    ".master_key",
    ".api_secret",
    "admin-credentials.txt",
    "credentials.enc",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
}

# File suffixes that are never packaged.
EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".env",
}

# Paths (relative, POSIX form) that are never packaged.
EXCLUDED_PATHS = {
    "data",
    "reports",
    "frontend/node_modules",
}

# Files that are packaged from an empty directory rather than skipped.
KEEP_EMPTY_DIRS = {"data", "reports"}


def _excluded(relative: Path) -> bool:
    parts = relative.parts
    # The top-level release output directory is never packaged. The frontend
    # build inside frontend/dist is.
    if parts and parts[0] == "dist" and len(parts) > 1:
        return True
    for part in parts:
        if part in EXCLUDED_DIRS:
            return True
        if part.startswith(".") and part not in {".gitignore"}:
            return True
    if relative.name in EXCLUDED_FILES:
        return True
    if relative.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    posix = relative.as_posix()
    for excluded in EXCLUDED_PATHS:
        if posix == excluded or posix.startswith(excluded + "/"):
            # The directory itself is kept (as an empty dir), its contents are not.
            if posix.count("/") == excluded.count("/"):
                return False
            return True
    return False


def collect(source: Path) -> list[Path]:
    """Return every file that belongs in a release, relative to ``source``."""
    collected: list[Path] = []
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        if _excluded(relative):
            continue
        collected.append(relative)
    return collected


def build_archive(
    source: Path,
    destination: Path,
    config_name: str,
) -> tuple[int, int]:
    """Write one archive. Returns ``(file_count, byte_count)``."""
    files = collect(source)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in files:
            archive_name = f"{ARCHIVE_ROOT}/{relative.as_posix()}"
            if relative.as_posix() == "config/default.yaml":
                # Each edition ships its own default configuration.
                payload = (source / "config" / config_name).read_bytes()
                archive.writestr(archive_name, payload)
                continue
            archive.write(source / relative, archive_name)

        # The runtime directories ship empty so a fresh install has them.
        for empty in sorted(KEEP_EMPTY_DIRS):
            archive.writestr(f"{ARCHIVE_ROOT}/{empty}/.gitkeep", "")

    with zipfile.ZipFile(destination) as archive:
        infos = archive.infolist()
        return len(infos), sum(info.file_size for info in infos)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


REQUIRED_ENTRIES = (
    "TRISHUL/README.md",
    "TRISHUL/LICENSE",
    "TRISHUL/install.sh",
    "TRISHUL/update.sh",
    "TRISHUL/.gitignore",
    "TRISHUL/requirements.txt",
    "TRISHUL/requirements-dev.txt",
    "TRISHUL/pytest.ini",
    "TRISHUL/config/default.yaml",
    "TRISHUL/config/default.local.yaml",
    "TRISHUL/config/default.provider.yaml",
    "TRISHUL/config/wordlists/common.txt",
    "TRISHUL/config/wordlists/params.txt",
    "TRISHUL/migrations/001_initial_schema.sql",
    "TRISHUL/migrations/002_chat_and_events.sql",
    "TRISHUL/backend/app/main.py",
    "TRISHUL/backend/app/engine/master.py",
    "TRISHUL/backend/app/ai/registry.py",
    "TRISHUL/cli/trishul.py",
    "TRISHUL/tests/conftest.py",
    "TRISHUL/docs/ARCHITECTURE.md",
    "TRISHUL/docs/SECURITY.md",
    "TRISHUL/docs/USER-GUIDE.md",
    "TRISHUL/docs/EDITIONS.md",
    "TRISHUL/docs/PROVIDERS.md",
    "TRISHUL/docs/API-CONTRACT.md",
    "TRISHUL/frontend/dist/index.html",
)

# Nothing in these categories may ever appear in a release archive.
FORBIDDEN_PATTERNS = (
    ".master_key",
    ".api_secret",
    "admin-credentials.txt",
    "credentials.enc",
    ".db",
    ".db-wal",
    ".db-shm",
    "node_modules",
    "__pycache__",
    ".venv",
    "KAAL",
    "kaal",
    "_kaal_package",
    "public-apis",
    "raw.githubusercontent.com",
)


def verify_archive(path: Path, expected_config: str) -> list[str]:
    """Return a list of problems. An empty list means the archive is good."""
    problems: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        broken = archive.testzip()
        if broken is not None:
            problems.append(f"corrupt entry: {broken}")

        for required in REQUIRED_ENTRIES:
            if required not in names:
                problems.append(f"missing required entry: {required}")

        for name in names:
            for pattern in FORBIDDEN_PATTERNS:
                if pattern in name:
                    problems.append(f"forbidden entry ({pattern}): {name}")

        # The shipped configuration must be the edition this archive promises.
        config_entry = f"{ARCHIVE_ROOT}/config/default.yaml"
        if config_entry in names:
            config_text = archive.read(config_entry).decode("utf-8")
            if expected_config == "default.local.yaml":
                if "edition: local" not in config_text:
                    problems.append("the LOCAL archive does not ship edition: local")
                if "provider: ollama" not in config_text:
                    problems.append("the LOCAL archive does not default to ollama")
            elif expected_config == "default.provider.yaml":
                if "edition: provider" not in config_text:
                    problems.append("the PROVIDER archive does not ship edition: provider")
                if "provider: openai" not in config_text:
                    problems.append("the PROVIDER archive does not default to openai")
            else:
                if "edition:" not in config_text:
                    problems.append("the SOURCE archive does not declare an edition")

        # Every Python file must compile.
        with tempfile.TemporaryDirectory() as tmp:
            archive.extractall(tmp)
            extracted = Path(tmp) / ARCHIVE_ROOT
            if not compileall.compile_dir(
                str(extracted), quiet=2, force=True, legacy=False
            ):
                problems.append("the extracted Python sources do not compile")

    return problems


def verify_extracted_imports(path: Path) -> list[str]:
    """Extract an archive and confirm the backend imports from it."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(path) as archive:
            archive.extractall(tmp)
        extracted = Path(tmp) / ARCHIVE_ROOT
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import backend.app.main as m; print('ROUTES', len(m.app.routes))",
            ],
            cwd=str(extracted),
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            problems.append(
                f"the extracted backend does not import: {result.stderr.strip()[-400:]}"
            )
        elif "ROUTES" not in result.stdout:
            problems.append(f"unexpected import output: {result.stdout.strip()[-200:]}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "dist"),
        help="Directory the archives are written to.",
    )
    parser.add_argument(
        "--source", default=str(PROJECT_ROOT), help="The project root to package."
    )
    parser.add_argument(
        "--skip-import-check",
        action="store_true",
        help="Do not extract and import the archives (faster).",
    )
    args = parser.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    editions = (
        ("TRISHUL-LOCAL.zip", "default.local.yaml", "LOCAL"),
        ("TRISHUL-PROVIDER.zip", "default.provider.yaml", "PROVIDER"),
        ("TRISHUL-SOURCE.zip", "default.yaml", "SOURCE"),
    )

    failed = False
    for filename, config_name, label in editions:
        destination = output / filename
        count, size = build_archive(source, destination, config_name)
        print(f"{filename:24} {count:5} entries  {size / 1024:9.1f} KiB")

        problems = verify_archive(destination, config_name)
        if not args.skip_import_check:
            problems.extend(verify_extracted_imports(destination))
        if problems:
            failed = True
            print(f"  FAILED ({label}):")
            for problem in problems:
                print(f"    - {problem}")
        else:
            print(f"  verified ({label}): contents and imports are good")

    print()
    print(f"Archives written to {output}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
