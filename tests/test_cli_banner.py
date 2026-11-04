"""Regression tests for the TRISHUL CLI banner and console encoding safety.

The banner used to be drawn with ``U+2588 FULL BLOCK`` and the CLI printed
``U+2713 CHECK MARK`` / ``U+2717 BALLOT X`` and ``U+2014 EM DASH``.  On a
terminal that still uses a legacy code page (cp437, cp1252) every one of
those characters raised :class:`UnicodeEncodeError`, so the banner collapsed
into replacement glyphs -- or crashed the CLI outright.

The banner is now pure ASCII and the CLI degrades unencodable characters
instead of raising.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cli import trishul

ROOT = Path(__file__).resolve().parents[1]
CLI_SOURCE = ROOT / "cli" / "trishul.py"

EXPECTED_ART = [
    "######## ########  ####  ######  ##     ## ##     ## ##",
    "   ##    ##     ##  ##  ##    ## ##     ## ##     ## ##",
    "   ##    ##     ##  ##  ##       ##     ## ##     ## ##",
    "   ##    ########   ##   ######  ######### ##     ## ##",
    "   ##    ##   ##    ##        ## ##     ## ##     ## ##",
    "   ##    ##    ##   ##  ##    ## ##     ## ##     ## ##",
    "   ##    ##     ## ####  ######  ##     ##  #######  ########",
]


def _run_python(code: str, **env_overrides: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env.update(env_overrides)
    # The child may emit bytes in the requested code page, so the output is
    # captured as bytes and decoded leniently by the parent.
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        timeout=180,
        check=False,
    )
    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
    )


# ---------------------------------------------------------------------------
# The banner itself
# ---------------------------------------------------------------------------


def test_banner_is_pure_ascii():
    assert trishul.BANNER.isascii()


def test_safety_notice_is_pure_ascii():
    assert trishul.SAFETY_NOTICE.isascii()


def test_banner_art_is_exactly_the_expected_block():
    rows = trishul.BANNER.splitlines()
    art = [row for row in rows if row and set(row) <= {"#", " "}]
    assert art == EXPECTED_ART


def test_banner_fits_a_standard_80_column_terminal():
    widest = max(len(row) for row in trishul.BANNER.splitlines())
    assert widest <= 80


def test_banner_has_no_trailing_whitespace():
    for row in trishul.BANNER.splitlines():
        assert row == row.rstrip()


# ---------------------------------------------------------------------------
# Nothing in the CLI may print a character the host code page rejects
# ---------------------------------------------------------------------------


def test_every_string_literal_in_the_cli_is_ascii():
    tree = ast.parse(CLI_SOURCE.read_text(encoding="utf-8"))
    offenders = [
        (node.lineno, node.value[:60])
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and not node.value.isascii()
    ]
    assert offenders == [], f"non-ASCII string literals in cli/trishul.py: {offenders}"


def test_health_markers_are_ascii():
    source = CLI_SOURCE.read_text(encoding="utf-8")
    assert "[ok]" in source
    assert "[!!]" in source


# ---------------------------------------------------------------------------
# End-to-end: a legacy code page must not break the CLI
# ---------------------------------------------------------------------------


def test_banner_renders_on_a_legacy_windows_codepage():
    result = _run_python(
        "from cli.trishul import print_banner; print_banner()",
        PYTHONIOENCODING="cp437",
    )
    assert result.returncode == 0, result.stderr
    assert "UnicodeEncodeError" not in result.stderr
    assert EXPECTED_ART[0] in result.stdout


def test_health_renders_on_a_legacy_windows_codepage():
    result = _run_python(
        "from cli.trishul import run_health; raise SystemExit(run_health())",
        PYTHONIOENCODING="cp437",
    )
    # Exit code 1 simply means "not ready" (nmap/ollama are absent in CI).
    assert result.returncode in (0, 1), result.stderr
    assert "UnicodeEncodeError" not in result.stderr
    assert "UnicodeEncodeError" not in result.stdout
    assert EXPECTED_ART[0] in result.stdout


def test_model_output_with_exotic_characters_does_not_crash_the_cli():
    """AI output is the most likely source of non-ASCII text at runtime."""
    result = _run_python(
        "from backend.app.core.console import protect_streams; "
        "protect_streams(); "
        "print('finding: caf\u00e9 \u2588 \u2192')",
        PYTHONIOENCODING="cp437",
    )
    assert result.returncode == 0, result.stderr
    assert "UnicodeEncodeError" not in result.stderr


def test_print_banner_never_raises_on_a_hostile_stream(monkeypatch, capsys):
    class _Hostile:
        encoding = "ascii"

        def write(self, text: str) -> int:
            raise UnicodeEncodeError("ascii", text, 0, 1, "boom")

        def flush(self) -> None:
            return None

    monkeypatch.setattr(sys, "stdout", _Hostile())
    trishul.print_banner()  # must not raise


# ---------------------------------------------------------------------------
# The API key hint is printed to the console, so it has to be ASCII too
# ---------------------------------------------------------------------------


def test_api_key_hint_is_ascii():
    from backend.app.core.security import api_key_hint

    hint = api_key_hint("sk-abcdefghijklmnopqrstuvwxyz")
    assert hint.isascii()
    assert hint == "sk-ab...wxyz"


@pytest.mark.parametrize("path", ["/api/health", "/api/providers/current"])
def test_public_api_responses_are_ascii(client, path):
    headers = {}
    if path != "/api/health":
        token = client.post(
            "/api/auth/token",
            json={"username": "admin", "password": "trishul-test-password"},
        ).json()["access_token"]
        headers["Authorization"] = f"Bearer {token}"
    response = client.get(path, headers=headers)
    assert response.status_code == 200, response.text
    assert response.content.decode("utf-8").isascii()
