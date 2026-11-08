"""The verification agent must honour the scope policy on every request.

A finding names an asset that came out of tool output, so it can point at
anything at all: a host that was never authorised, the cloud metadata
service, or a public address that redirects into the private network.

The verification agent therefore asks the scope policy before it opens a
socket, and it re-validates every redirect hop instead of letting the HTTP
client follow the chain blindly.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from backend.app.core.scope import ScopePolicy
from backend.app.core.utils import utcnow
from backend.app.engine.base import AgentContext
from backend.app.engine.verification import VerificationAgent
from backend.app.models import (
    Evidence,
    Finding,
    ScanMode,
    ScanRecord,
    ScanStatus,
    Severity,
)

IN_SCOPE_IP = "93.184.216.34"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"


def make_finding(**overrides) -> Finding:
    data = {
        "id": "finding-1",
        "source": "nuclei",
        "category": "scanner-match",
        "title": "Example finding",
        "description": "Something was detected.",
        "severity": Severity.MEDIUM,
        "asset": f"http://{IN_SCOPE_IP}/.env",
        "attack_surface": IN_SCOPE_IP,
        "evidence": [Evidence(source="nuclei", summary="matched", raw={})],
    }
    data.update(overrides)
    return Finding(**data)


@pytest.fixture()
def scan() -> ScanRecord:
    now = utcnow()
    return ScanRecord(
        id="scan-test",
        target=f"http://{IN_SCOPE_IP}",
        mode=ScanMode.DEEP,
        status=ScanStatus.RUNNING,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="TEST-1234",
    )


@pytest.fixture()
def make_ctx(
    scan,
    storage,
    settings,
    ai_manager,
    integration_manager,
    tool_registry,
    adapters,
    tmp_path,
):
    def factory(scope: ScopePolicy) -> AgentContext:
        return AgentContext(
            scan=scan,
            settings=settings,
            storage=storage,
            ai=ai_manager,
            integrations=integration_manager,
            scope=scope,
            tools=tool_registry,
            adapters=adapters,
            scan_dir=tmp_path / "scan",
        )

    return factory


def build_agent(storage, handler, seen: list[str]) -> VerificationAgent:
    """A verification agent whose HTTP client talks to a mock transport."""

    def factory(*, verify: bool = True) -> httpx.AsyncClient:
        def wrapper(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return handler(request)

        return httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            verify=verify,
            transport=httpx.MockTransport(wrapper),
        )

    return VerificationAgent(storage, None, client_factory=factory)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_in_scope_asset_is_still_probed(storage, make_ctx):
    seen: list[str] = []
    scope = ScopePolicy(authorized_targets=[IN_SCOPE_IP])
    agent = build_agent(storage, lambda request: httpx.Response(200, text="ok"), seen)
    finding = make_finding()

    result = await agent.run(make_ctx(scope), [finding], {}, {})

    assert seen == [f"http://{IN_SCOPE_IP}/.env"]
    assert result[0].verified is True


@pytest.mark.asyncio
async def test_an_out_of_scope_asset_is_never_contacted(storage, make_ctx):
    seen: list[str] = []
    scope = ScopePolicy(authorized_targets=["allowed.example"])
    agent = build_agent(storage, lambda request: httpx.Response(200, text="ok"), seen)
    finding = make_finding(asset="https://blocked.example/.env", attack_surface="blocked.example")

    result = await agent.run(make_ctx(scope), [finding], {}, {})

    assert seen == [], "the verification agent must not contact an unauthorised host"
    assert result[0].verified is False


@pytest.mark.asyncio
async def test_a_redirect_into_a_blocked_host_is_not_followed(storage, make_ctx):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.env":
            return httpx.Response(302, headers={"location": METADATA_URL})
        return httpx.Response(200, text="secret")

    scope = ScopePolicy(authorized_targets=[IN_SCOPE_IP])
    agent = build_agent(storage, handler, seen)
    finding = make_finding()

    result = await agent.run(make_ctx(scope), [finding], {}, {})

    assert seen == [f"http://{IN_SCOPE_IP}/.env"], "the redirect target must not be requested"
    assert result[0].verified is False


@pytest.mark.asyncio
async def test_an_out_of_scope_host_is_not_probed_over_tcp(storage, make_ctx, monkeypatch):
    connections: list[tuple[str, int]] = []

    async def fake_open_connection(host, port):
        connections.append((host, port))
        raise OSError("refused")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    scope = ScopePolicy(authorized_targets=["allowed.example"])
    agent = build_agent(storage, lambda request: httpx.Response(200, text="ok"), [])
    finding = make_finding(source="nmap", asset="blocked.example:22", attack_surface="blocked.example")

    await agent.run(make_ctx(scope), [finding], {}, {})

    assert connections == [], "the verification agent must not open a socket to an unauthorised host"


@pytest.mark.asyncio
async def test_the_scope_decision_is_recorded_on_the_finding(storage, make_ctx):
    scope = ScopePolicy(authorized_targets=["allowed.example"])
    agent = build_agent(storage, lambda request: httpx.Response(200, text="ok"), [])
    finding = make_finding(asset="https://blocked.example/.env", attack_surface="blocked.example")

    result = await agent.run(make_ctx(scope), [finding], {}, {})

    summaries = " ".join(item.summary for item in result[0].evidence)
    assert "scope" in summaries.lower()
