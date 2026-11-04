"""``docs/API-CONTRACT.md`` must describe the API that actually exists.

The dashboard is checked against the OpenAPI schema in
``test_frontend_contract.py``; this test closes the loop on the written
contract, so a renamed route cannot quietly drift away from its
documentation.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "API-CONTRACT.md"

TABLE_ROW = re.compile(r"^\|\s*(GET|POST|PUT|DELETE|PATCH)\s*\|\s*`([^`]+)`", re.M)
INLINE = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH)\s+(/api/[A-Za-z0-9_\-/{}/\.]+)")


def _normalise(path: str) -> str:
    path = path.split("?", 1)[0]
    return re.sub(r"\{[^}]*\}", "{}", path)


def _documented() -> set[tuple[str, str]]:
    text = CONTRACT.read_text(encoding="utf-8")
    calls: set[tuple[str, str]] = set()
    for match in TABLE_ROW.finditer(text):
        calls.add((match.group(1), match.group(2)))
    for match in INLINE.finditer(text):
        calls.add((match.group(1), match.group(2).rstrip(".,`")))
    return {(method, _normalise(path)) for method, path in calls}


def _live() -> set[tuple[str, str]]:
    from backend.app.main import app

    schema = app.openapi()
    pairs: set[tuple[str, str]] = set()
    for path, operations in schema["paths"].items():
        for method in operations:
            if method.lower() != "parameters":
                pairs.add((method.upper(), _normalise(path)))
    return pairs


def test_the_contract_document_exists():
    assert CONTRACT.is_file()


def test_every_live_endpoint_is_documented():
    missing = sorted(_live() - _documented())
    assert missing == [], f"endpoints missing from docs/API-CONTRACT.md: {missing}"


def test_the_contract_does_not_describe_endpoints_that_do_not_exist():
    extra = sorted(_documented() - _live())
    assert extra == [], f"docs/API-CONTRACT.md describes endpoints that do not exist: {extra}"


def test_the_contract_lists_every_endpoint():
    # A sanity floor: the contract must not silently shrink to a handful of
    # routes and still satisfy the two checks above.
    assert len(_documented()) >= 20
