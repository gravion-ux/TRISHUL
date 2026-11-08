"""Operator-configured endpoints must be validated, redirect hops included.

Two separate paths could be abused to make TRISHUL talk to a host the
operator never intended:

* the AI provider base URL and the integration base URL, which are
  operator-configured but were sent to verbatim -- including a URL that
  carried credentials in its userinfo part or that pointed at the cloud
  metadata service;
* the HTTP client, which followed redirects on its own, so a remote
  endpoint could bounce TRISHUL into the private network with the
  configured credentials still attached.

The same class of problem existed in the scanning tools: ``httpx`` was
invoked with ``-follow-redirects``, so a scanned host could redirect the
scanner into the metadata service.
"""

from __future__ import annotations

import httpx
import pytest

from backend.app.ai.providers.openai_compatible import OpenAICompatibleProvider
from backend.app.core.url_guard import UrlGuard, UrlGuardError, request_with_safe_redirects
from backend.app.models import (
    IntegrationAuthType,
    IntegrationConfigRequest,
    ProviderConfigRequest,
    ProviderKind,
    ScanMode,
)
from backend.app.services.integrations import IntegrationError
from backend.app.services.tool_adapters import HttpxAdapter

METADATA_IP = "169.254.169.254"
METADATA_URL = f"http://{METADATA_IP}/latest/meta-data/"


# ---------------------------------------------------------------------------
# The guard itself
# ---------------------------------------------------------------------------


def test_the_guard_refuses_a_non_http_scheme():
    with pytest.raises(UrlGuardError):
        UrlGuard().check("file:///etc/passwd")


def test_the_guard_refuses_embedded_credentials():
    with pytest.raises(UrlGuardError):
        UrlGuard().check("https://user:pass@example.com/v1")


def test_the_guard_refuses_the_cloud_metadata_address():
    with pytest.raises(UrlGuardError):
        UrlGuard().check(METADATA_URL)


def test_the_guard_refuses_the_cloud_metadata_hostname():
    with pytest.raises(UrlGuardError):
        UrlGuard().check("http://metadata.google.internal/computeMetadata/v1/")


def test_the_guard_allows_a_local_inference_server():
    assert UrlGuard().check("http://localhost:11434") == "localhost"


def test_the_guard_allows_a_public_endpoint():
    assert UrlGuard().check("https://api.openai.com/v1") == "api.openai.com"


@pytest.mark.asyncio
async def test_the_guard_allows_the_ipv6_loopback_when_private_addresses_are_allowed():
    # Python classifies "::1" as reserved as well as loopback, so the
    # loopback rule has to be applied first -- otherwise a local inference
    # server that resolves to "::1" could never be reached.
    guard = UrlGuard(allow_private=True)

    assert await guard.check_url("http://[::1]:11434") == "::1"


@pytest.mark.asyncio
async def test_the_guard_refuses_the_ipv6_loopback_when_private_addresses_are_refused():
    guard = UrlGuard(allow_private=False)

    with pytest.raises(UrlGuardError):
        await guard.check_url("http://[::1]:11434")


@pytest.mark.asyncio
async def test_the_guard_refuses_a_link_local_address_even_when_private_is_allowed():
    guard = UrlGuard(allow_private=True)

    with pytest.raises(UrlGuardError):
        await guard.check_url("http://169.254.10.10/")


# ---------------------------------------------------------------------------
# Redirect hops
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_redirect_into_the_metadata_service_is_not_followed():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": METADATA_URL})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(UrlGuardError):
            await request_with_safe_redirects(
                client, "https://api.example.test/lookup", guard=UrlGuard()
            )

    assert seen == ["https://api.example.test/lookup"]


@pytest.mark.asyncio
async def test_credentials_are_not_forwarded_to_another_origin():
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("authorization")))
        if request.url.host == "api.example.test":
            return httpx.Response(302, headers={"location": "https://other.example.test/"})
        return httpx.Response(200, text="ok")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await request_with_safe_redirects(
            client,
            "https://api.example.test/lookup",
            guard=UrlGuard(),
            headers={"Authorization": "Bearer secret-token"},
        )

    assert response.status_code == 200
    assert seen[0][1] == "Bearer secret-token"
    assert seen[1][1] is None, "the credential must not cross the origin boundary"


# ---------------------------------------------------------------------------
# AI providers
# ---------------------------------------------------------------------------


def test_a_provider_refuses_a_metadata_base_url():
    with pytest.raises(UrlGuardError):
        OpenAICompatibleProvider(base_url=METADATA_URL, model="m")


def test_saving_a_provider_configuration_refuses_a_metadata_base_url(ai_manager):
    request = ProviderConfigRequest(
        provider=ProviderKind.OPENAI,
        model="gpt-4o-mini",
        base_url=METADATA_URL,
    )

    with pytest.raises(ValueError):
        ai_manager.save_config(request)


@pytest.mark.asyncio
async def test_a_provider_does_not_follow_a_redirect_into_the_metadata_service(monkeypatch):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": METADATA_URL})

    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)

    provider = OpenAICompatibleProvider(
        base_url="https://api.openai.com/v1", model="gpt-4o-mini", api_key="sk-test"
    )

    with pytest.raises(Exception):
        await provider.list_models()

    assert seen == ["https://api.openai.com/v1/models"]


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------


def test_saving_an_integration_refuses_a_metadata_base_url(integration_manager):
    request = IntegrationConfigRequest(
        name="demo",
        base_url=METADATA_URL,
        auth_type=IntegrationAuthType.NONE,
    )

    with pytest.raises(ValueError):
        integration_manager.save(request)


@pytest.mark.asyncio
async def test_an_integration_does_not_follow_a_redirect_into_the_metadata_service(
    integration_manager, monkeypatch
):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": METADATA_URL})

    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)

    integration_manager.save(
        IntegrationConfigRequest(
            name="demo",
            base_url="https://api.example.test",
            path="/lookup",
            auth_type=IntegrationAuthType.NONE,
        )
    )

    with pytest.raises(IntegrationError):
        await integration_manager.invoke("demo")

    assert seen == ["https://api.example.test/lookup"]


# ---------------------------------------------------------------------------
# Scanning tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_httpx_scanner_does_not_follow_redirects(settings, tmp_path):
    class FakeRegistry:
        def resolve(self, name: str) -> str:
            return f"/usr/bin/{name}"

    class FakeRunner:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        async def run(self, executable, args, timeout=600, **kwargs):
            from backend.app.services.tool_runner import CompletedCommand

            self.calls.append(list(args))
            return CompletedCommand(
                executable=executable,
                args=list(args),
                returncode=0,
                stdout="",
                stderr="",
                duration_ms=1,
            )

    runner = FakeRunner()
    adapter = HttpxAdapter(runner, settings, FakeRegistry())

    await adapter.run(["https://example.com"], tmp_path / "httpx", ScanMode.QUICK)

    assert runner.calls
    for args in runner.calls:
        assert "-follow-redirects" not in args
