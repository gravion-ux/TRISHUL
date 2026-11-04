"""The dashboard and the API must not drift apart.

TRISHUL ships a React dashboard that talks to the FastAPI backend over a
plain ``fetch`` wrapper.  Nothing in the type system connects the two: a
renamed or removed backend route would only show up as a runtime 404 in the
browser.

This test parses ``frontend/src/api.ts``, extracts every request the
dashboard can make and checks it against the *live* OpenAPI schema.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
API_TS = ROOT / "frontend" / "src" / "api.ts"

# request<Something>("path", { ... method: "POST" ... })
REQUEST_RE = re.compile(r"\brequest<[^>]*>\s*\(\s*(?P<path>`[^`]*`|\"[^\"]*\")")
METHOD_RE = re.compile(r"""\bmethod\s*:\s*["'](?P<method>[A-Za-z]+)["']""")
PARAM_RE = re.compile(r"\{[^}]*\}")


def _canonical(path: str) -> str:
    """Reduce a path to a comparable shape.

    ``/api/scans/${encodeURIComponent(id)}`` and ``/api/scans/{scan_id}``
    both become ``/api/scans/{}``, so the two sides can be compared without
    depending on parameter *names*.

    A template that expands to a *query string* -- such as
    ``${query ? `?${query}` : ""}`` -- is dropped entirely, because it does
    not contribute a path segment.
    """
    path = path.strip().strip("`\"")
    pieces: list[str] = []
    index = 0
    while index < len(path):
        if path.startswith("${", index):
            depth = 1
            cursor = index + 2
            while cursor < len(path) and depth:
                if path.startswith("${", cursor):
                    depth += 1
                    cursor += 2
                elif path[cursor] == "}":
                    depth -= 1
                    cursor += 1
                else:
                    cursor += 1
            expression = path[index + 2 : max(index + 2, cursor - 1)]
            if "?" not in expression:
                pieces.append("{}")
            index = cursor
        else:
            pieces.append(path[index])
            index += 1
    path = "".join(pieces)
    path = path.split("?", 1)[0]
    path = PARAM_RE.sub("{}", path)
    return path.rstrip("/") or "/"


def _matching_paren(text: str, open_index: int) -> int:
    """Return the index of the parenthesis that closes ``open_index``."""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unbalanced parentheses at offset {open_index}")


def _frontend_calls() -> list[tuple[str, str]]:
    """Return every ``(method, path)`` pair the dashboard can issue."""
    source = API_TS.read_text(encoding="utf-8")
    calls: list[tuple[str, str]] = []
    for match in REQUEST_RE.finditer(source):
        raw_path = match.group("path")
        open_index = source.index("(", match.start())
        close_index = _matching_paren(source, open_index)
        body = source[open_index:close_index]
        method_match = METHOD_RE.search(body)
        method = method_match.group("method").upper() if method_match else "GET"
        calls.append((method, _canonical(raw_path)))

    # downloadReport() uses fetch() against the report endpoint.
    report_match = re.search(r"API_BASE\}/api/reports/\$\{encodeURIComponent\([^)]*\)\}/\$\{format\}", source)
    assert report_match, "the report download route disappeared from api.ts"
    calls.append(("GET", _canonical("/api/reports/{scan_id}/{format}")))

    return calls


@pytest.fixture(scope="module")
def openapi_paths() -> dict[str, set[str]]:
    from backend.app.main import app

    schema = app.openapi()
    paths: dict[str, set[str]] = {}
    for raw_path, operations in schema.get("paths", {}).items():
        paths[_canonical(raw_path)] = {method.upper() for method in operations if method.lower() != "parameters"}
    return paths


def test_frontend_uses_at_least_twenty_endpoints():
    calls = _frontend_calls()
    assert len({path for _, path in calls}) >= 20


def test_every_frontend_request_matches_a_backend_route(openapi_paths):
    missing = []
    for method, path in _frontend_calls():
        allowed = openapi_paths.get(path)
        if allowed is None:
            missing.append(f"{method} {path} -> no such backend path")
        elif method not in allowed:
            missing.append(f"{method} {path} -> backend allows {sorted(allowed)}")
    assert missing == [], "frontend/backend route mismatch:\n" + "\n".join(missing)


def test_every_backend_route_is_reachable_from_the_dashboard(openapi_paths):
    """No dead API endpoints: every documented path is used by the UI."""
    used = {path for _, path in _frontend_calls()}
    unused = sorted(set(openapi_paths) - used)
    assert unused == [], f"backend routes the dashboard never calls: {unused}"


def test_the_scan_websocket_exists():
    from backend.app.main import app

    websocket_paths = {
        route.path for route in app.routes if getattr(route, "__class__", None).__name__ == "APIWebSocketRoute"
    }
    assert "/ws/scans/{scan_id}" in websocket_paths


def test_the_frontend_uses_the_configured_api_base():
    source = API_TS.read_text(encoding="utf-8")
    assert "import.meta.env.VITE_API_BASE" in source
    assert "http://localhost:8000" in source
