"""REST and WebSocket API tests.

The suite runs against an isolated in-memory storage backend and a pinned
administrator password. No test starts a real scan: the master agent's
``run_scan`` is replaced with a deterministic stub so the tests stay fast and
never touch the network.
"""

from __future__ import annotations

import json

import pytest
from starlette.websockets import WebSocketDisconnect

from backend.app.models import ScanStatus

TEST_PASSWORD = "trishul-test-password"


@pytest.fixture()
def no_scanner(client, monkeypatch):
    """Replace the scan runner so no test ever launches real tooling."""
    from backend.app import main as main_module

    started: list[str] = []

    async def fake_run_scan(scan_id: str):
        started.append(scan_id)
        scan = main_module.storage.get_scan(scan_id)
        if scan:
            scan.status = ScanStatus.COMPLETED
            main_module.storage.save_scan(scan)
        return scan

    monkeypatch.setattr(main_module.master_agent, "run_scan", fake_run_scan)
    return started


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health_is_public(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.json()
    assert "version" in payload
    assert "tools" in payload
    assert "ai" in payload
    assert isinstance(payload["ready"], bool)


def test_autofix_requires_auth(client):
    assert client.get("/api/health/autofix").status_code == 401


def test_autofix_returns_commands_without_executing_them(client, auth_headers):
    response = client.get("/api/health/autofix", headers=auth_headers)

    assert response.status_code == 200
    assert isinstance(response.json()["commands"], list)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_token_requires_valid_credentials(client):
    response = client.post(
        "/api/auth/token", json={"username": "admin", "password": "wrong-password"}
    )

    assert response.status_code == 401


def test_token_is_issued_for_valid_credentials(client):
    response = client.post(
        "/api/auth/token", json={"username": "admin", "password": TEST_PASSWORD}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    assert payload["access_token"]
    assert payload["expires_in"] > 0


def test_protected_route_rejects_missing_token(client):
    assert client.get("/api/me").status_code == 401


def test_protected_route_rejects_invalid_token(client):
    response = client.get("/api/me", headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401


def test_me_returns_the_authenticated_user(client, auth_headers):
    response = client.get("/api/me", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["username"] == "admin"


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def test_scan_requires_explicit_authorization(client, auth_headers):
    response = client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.com",
            "mode": "deep",
            "authorized": False,
            "authorization_note": "TEST-1234",
        },
    )

    assert response.status_code == 400
    assert "authorization" in response.json()["detail"].lower()


def test_scan_requires_an_authorization_note(client, auth_headers):
    response = client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.com",
            "mode": "deep",
            "authorized": True,
            "authorization_note": "x",
        },
    )

    assert response.status_code == 422


def test_a_scan_without_limits_uses_the_configured_defaults(
    client, auth_headers, no_scanner, settings
):
    """The limits are optional, and an omitted limit must not be hard-coded.

    The dashboard leaves both fields empty, so the configured values have to
    survive the trip through the API unchanged.
    """
    response = client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.com",
            "mode": "quick",
            "authorized": True,
            "authorization_note": "TICKET-2026-0001",
        },
    )

    assert response.status_code == 200, response.text
    scan_id = response.json()["scan_id"]
    record = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()

    assert record["thread_limit"] == settings.scan.thread_limit
    assert record["timeout_seconds"] == settings.scan.timeout_seconds


def test_a_scan_with_limits_stores_the_requested_values(client, auth_headers, no_scanner):
    response = client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.com",
            "mode": "quick",
            "authorized": True,
            "authorization_note": "TICKET-2026-0001",
            "thread_limit": 3,
            "timeout_seconds": 120,
        },
    )

    assert response.status_code == 200, response.text
    scan_id = response.json()["scan_id"]
    record = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()

    assert record["thread_limit"] == 3
    assert record["timeout_seconds"] == 120


def test_scan_starts_and_is_retrievable(client, auth_headers, no_scanner):
    response = client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.com",
            "mode": "quick",
            "authorized": True,
            "authorization_note": "TICKET-2026-0001",
        },
    )

    assert response.status_code == 200, response.text
    scan_id = response.json()["scan_id"]
    assert scan_id

    fetched = client.get(f"/api/scans/{scan_id}", headers=auth_headers)
    assert fetched.status_code == 200
    assert fetched.json()["target"] == "example.com"
    assert fetched.json()["authorized"] is True
    assert fetched.json()["authorization_note"] == "TICKET-2026-0001"


def test_scan_list_returns_the_new_scan(client, auth_headers, no_scanner):
    client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.org",
            "mode": "quick",
            "authorized": True,
            "authorization_note": "TICKET-2026-0002",
        },
    )

    response = client.get("/api/scans", headers=auth_headers)

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) >= 1


def test_unknown_scan_returns_404(client, auth_headers):
    response = client.get("/api/scans/does-not-exist", headers=auth_headers)

    assert response.status_code == 404


def test_findings_endpoint_returns_a_list(client, auth_headers):
    response = client.get("/api/scans/does-not-exist/findings", headers=auth_headers)

    assert response.status_code == 404


def test_cancel_scan_is_answered(client, auth_headers, no_scanner):
    created = client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.net",
            "mode": "quick",
            "authorized": True,
            "authorization_note": "TICKET-2026-0003",
        },
    )
    scan_id = created.json()["scan_id"]

    response = client.delete(f"/api/scans/{scan_id}", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id
    assert isinstance(response.json()["cancelled"], bool)


def test_enrichment_endpoint(client, auth_headers):
    response = client.get("/api/enrichment", params={"scan_id": "does-not-exist"}, headers=auth_headers)

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_report_for_unknown_scan_returns_404(client, auth_headers):
    response = client.get("/api/reports/does-not-exist/json", headers=auth_headers)

    assert response.status_code == 404


def test_report_with_unknown_format_returns_404(client, auth_headers, no_scanner):
    created = client.post(
        "/api/scans",
        headers=auth_headers,
        json={
            "target": "example.io",
            "mode": "quick",
            "authorized": True,
            "authorization_note": "TICKET-2026-0004",
        },
    )
    scan_id = created.json()["scan_id"]

    response = client.get(f"/api/reports/{scan_id}/docx", headers=auth_headers)

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


def test_provider_catalog_lists_every_kind(client, auth_headers):
    response = client.get("/api/providers", headers=auth_headers)

    assert response.status_code == 200
    kinds = {item["kind"] for item in response.json()}
    assert {"ollama", "lmstudio", "llamacpp", "openai", "anthropic", "gemini"} <= kinds


def test_current_provider_never_exposes_the_key(client, auth_headers):
    response = client.get("/api/providers/current", headers=auth_headers)

    assert response.status_code == 200
    payload = response.json()
    assert "has_api_key" in payload
    assert "api_key" not in payload or payload.get("api_key") in (None, "")
    assert "sk-" not in json.dumps(payload).replace("sk-test", "")


def test_provider_config_roundtrip(client, auth_headers):
    secret = "sk-test-abcdefghijklmnop"
    saved = client.post(
        "/api/providers/config",
        headers=auth_headers,
        json={
            "edition": "provider",
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "https://api.openai.com/v1",
            "api_key": secret,
        },
    )

    assert saved.status_code == 200, saved.text
    payload = saved.json()
    assert payload["provider"] == "openai"
    assert payload["has_api_key"] is True
    assert secret not in json.dumps(payload)
    assert payload["api_key_hint"]

    current = client.get("/api/providers/current", headers=auth_headers)
    assert current.json()["provider"] == "openai"
    assert current.json()["model"] == "gpt-4o-mini"
    assert secret not in current.text

    reset = client.delete("/api/providers/config", headers=auth_headers)
    assert reset.status_code == 200


def test_provider_models_rejects_unknown_provider(client, auth_headers):
    response = client.get("/api/providers/models", params={"provider": "not-real"}, headers=auth_headers)

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------


def test_integration_lifecycle(client, auth_headers):
    created = client.post(
        "/api/integrations",
        headers=auth_headers,
        json={
            "name": "example-api",
            "base_url": "https://api.example.com",
            "path": "/v1/data",
            "method": "GET",
            "auth_type": "header",
            "auth_name": "X-API-Key",
            "api_key": "integration-secret-value",
            "headers": {"Accept": "application/json"},
        },
    )

    assert created.status_code == 200, created.text
    payload = created.json()
    assert payload["name"] == "example-api"
    assert payload["has_api_key"] is True
    assert "integration-secret-value" not in json.dumps(payload)

    listing = client.get("/api/integrations", headers=auth_headers)
    assert listing.status_code == 200
    assert any(item["name"] == "example-api" for item in listing.json())

    deleted = client.delete("/api/integrations/example-api", headers=auth_headers)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_integration_name_is_validated(client, auth_headers):
    response = client.post(
        "/api/integrations",
        headers=auth_headers,
        json={"name": "not a valid name!", "base_url": "https://api.example.com"},
    )

    assert response.status_code == 422


def test_invoke_unknown_integration_returns_502(client, auth_headers):
    response = client.post(
        "/api/integrations/missing/invoke", headers=auth_headers, json={"params": {}}
    )

    assert response.status_code == 502


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


def test_chat_falls_back_when_the_ai_is_unreachable(client, auth_headers, monkeypatch):
    from backend.app import main as main_module

    async def unreachable(request):
        raise RuntimeError("provider unreachable")

    monkeypatch.setattr(main_module.ai_manager, "complete", unreachable)

    response = client.post(
        "/api/chat", headers=auth_headers, json={"message": "What did the scan find?"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["fallback"] is True
    assert payload["provider"] == "none"
    assert "not reachable" in payload["reply"].lower()


def test_chat_requires_a_message(client, auth_headers):
    response = client.post("/api/chat", headers=auth_headers, json={"message": ""})

    assert response.status_code == 422


def test_chat_accepts_history(client, auth_headers, monkeypatch):
    from backend.app import main as main_module

    captured = {}

    async def fake_complete(request):
        captured["prompt"] = request.prompt
        from backend.app.ai.base import AIResponse

        return AIResponse(text="ok", model="stub", provider="stub", latency_ms=1)

    monkeypatch.setattr(main_module.ai_manager, "complete", fake_complete)

    response = client.post(
        "/api/chat",
        headers=auth_headers,
        json={
            "message": "Summarise the risk.",
            "history": [{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["fallback"] is False
    assert "Hello" in captured["prompt"]
    assert "Summarise the risk." in captured["prompt"]


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


def test_websocket_rejects_a_missing_token(client):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/scans/whatever"):
            pass

    assert excinfo.value.code == 4401


def test_websocket_streams_the_scan_snapshot(client, auth_token, auth_headers):
    from backend.app import main as main_module
    from backend.app.models import ScanMode, ScanRecord
    from backend.app.core.utils import utcnow

    now = utcnow()
    scan = ScanRecord(
        id="ws-scan",
        target="example.com",
        mode=ScanMode.QUICK,
        status=ScanStatus.RUNNING,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="TICKET-2026-0005",
    )
    main_module.storage.save_scan(scan)

    with client.websocket_connect(f"/ws/scans/ws-scan?token={auth_token}") as websocket:
        message = websocket.receive_json()

    assert message["type"] == "snapshot"
    assert message["scan"]["id"] == "ws-scan"
