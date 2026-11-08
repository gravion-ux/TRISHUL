"""Shared pytest fixtures for TRISHUL.

The administrator password is pinned *before* the application is imported so
that the API tests can authenticate deterministically.

The pin is unconditional on purpose.  With ``setdefault`` an ambient
``TRISHUL_ADMIN_PASSWORD`` in the operator's shell would leak into the test
session and desynchronise the test credentials from the pinned ones.

The AI provider environment variables are *removed* rather than pinned to a
fixed provider.  Each release archive ships its own ``config/default.yaml``
-- the LOCAL archive selects Ollama, the PROVIDER archive selects OpenAI --
and the test suite has to exercise the edition it was shipped with instead of
hard-coding one provider.  Pinning a provider here used to make the PROVIDER
archive's own test suite fail.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

TEST_PASSWORD = "trishul-test-password"

os.environ["TRISHUL_ADMIN_PASSWORD"] = TEST_PASSWORD

# An ambient provider selection would silently override the configuration file
# the archive ships, so the test session always starts from the shipped file.
for _variable in (
    "TRISHUL_EDITION",
    "TRISHUL_AI_PROVIDER",
    "TRISHUL_AI_MODEL",
    "TRISHUL_AI_BASE_URL",
    "TRISHUL_AI_TIMEOUT",
):
    os.environ.pop(_variable, None)
os.environ["TRISHUL_CONFIG"] = str(ROOT_DIR / "config" / "default.yaml")

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.ai.registry import AIManager  # noqa: E402
from backend.app.core.config import get_settings  # noqa: E402
from backend.app.core.scope import ScopePolicy  # noqa: E402
from backend.app.core.secrets import CredentialStore  # noqa: E402
from backend.app.core.security import RateLimiter, hash_password  # noqa: E402
from backend.app.core.storage import Storage  # noqa: E402
from backend.app.engine.base import Adapters  # noqa: E402
from backend.app.engine.master import MasterAgent  # noqa: E402
from backend.app.engine.tasks import TaskManager  # noqa: E402
from backend.app.services.health import HealthService  # noqa: E402
from backend.app.services.integrations import IntegrationManager  # noqa: E402
from backend.app.services.reporting import ReportingService  # noqa: E402
from backend.app.services.tool_adapters import (  # noqa: E402
    FfufAdapter,
    HttpxAdapter,
    NmapAdapter,
    NucleiAdapter,
)
from backend.app.services.tool_runner import ToolRunner  # noqa: E402
from backend.app.services.tooling import ToolRegistry  # noqa: E402


@pytest.fixture()
def settings():
    return get_settings()


@pytest.fixture()
def storage(tmp_path) -> Storage:
    return Storage(tmp_path / "trishul-test.db")


@pytest.fixture()
def credentials(tmp_path) -> CredentialStore:
    return CredentialStore(tmp_path / "credentials.enc")


@pytest.fixture()
def ai_manager(storage, credentials, settings) -> AIManager:
    return AIManager(storage, credentials, settings)


@pytest.fixture()
def integration_manager(storage, credentials, settings) -> IntegrationManager:
    return IntegrationManager(storage, credentials, settings)


@pytest.fixture()
def tool_registry(settings) -> ToolRegistry:
    return ToolRegistry(ToolRunner(allowed_binaries=settings.tools.allowed_binaries), settings)


@pytest.fixture()
def scope() -> ScopePolicy:
    return ScopePolicy(allow_private=False, authorized_targets=[])


@pytest.fixture()
def adapters(settings, tool_registry) -> Adapters:
    runner = ToolRunner(allowed_binaries=settings.tools.allowed_binaries)
    return Adapters(
        httpx=HttpxAdapter(runner, settings, tool_registry),
        nmap=NmapAdapter(runner, settings, tool_registry),
        nuclei=NucleiAdapter(runner, settings, tool_registry),
        ffuf=FfufAdapter(runner, settings, tool_registry),
    )


@pytest.fixture()
def master_agent(storage, settings, ai_manager, integration_manager, tool_registry, adapters, scope):
    return MasterAgent(
        storage=storage,
        settings=settings,
        ai=ai_manager,
        integrations=integration_manager,
        tools=tool_registry,
        adapters=adapters,
        scope=scope,
        reporting=ReportingService(settings),
    )


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A TestClient wired to an isolated storage backend."""
    from backend.app import main as main_module

    local_settings = get_settings()
    local_storage = Storage(tmp_path / "api-test.db")
    local_credentials = CredentialStore(tmp_path / "api-credentials.enc")
    # Mirror startup: the administrator password hash lives in the credential
    # store, and the isolated store starts empty.
    local_credentials.set("admin:password_hash", hash_password(TEST_PASSWORD))
    local_ai = AIManager(local_storage, local_credentials, local_settings)
    local_integrations = IntegrationManager(local_storage, local_credentials, local_settings)
    local_tools = ToolRegistry(
        ToolRunner(allowed_binaries=local_settings.tools.allowed_binaries), local_settings
    )
    local_health = HealthService(local_tools, local_ai)
    local_scope = ScopePolicy()
    runner = ToolRunner(allowed_binaries=local_settings.tools.allowed_binaries)
    local_adapters = Adapters(
        httpx=HttpxAdapter(runner, local_settings, local_tools),
        nmap=NmapAdapter(runner, local_settings, local_tools),
        nuclei=NucleiAdapter(runner, local_settings, local_tools),
        ffuf=FfufAdapter(runner, local_settings, local_tools),
    )
    local_master = MasterAgent(
        storage=local_storage,
        settings=local_settings,
        ai=local_ai,
        integrations=local_integrations,
        tools=local_tools,
        adapters=local_adapters,
        scope=local_scope,
        reporting=ReportingService(local_settings),
    )
    local_tasks = TaskManager(local_storage, max_concurrent=2)

    monkeypatch.setattr(main_module, "storage", local_storage)
    monkeypatch.setattr(main_module, "credentials", local_credentials)
    monkeypatch.setattr(main_module, "ai_manager", local_ai)
    monkeypatch.setattr(main_module, "integration_manager", local_integrations)
    monkeypatch.setattr(main_module, "tool_registry", local_tools)
    monkeypatch.setattr(main_module, "health_service", local_health)
    monkeypatch.setattr(main_module, "master_agent", local_master)
    monkeypatch.setattr(main_module, "task_manager", local_tasks)
    # The rate limiters are module-level singletons. A fresh one per test
    # keeps one test's traffic from consuming the next test's budget.
    monkeypatch.setattr(
        main_module,
        "rate_limiter",
        RateLimiter(
            limit=local_settings.security.rate_limit_requests,
            window_seconds=local_settings.security.rate_limit_window_seconds,
        ),
    )
    monkeypatch.setattr(
        main_module,
        "login_limiter",
        RateLimiter(
            limit=local_settings.security.login_rate_limit_attempts,
            window_seconds=local_settings.security.login_rate_limit_window_seconds,
        ),
    )

    with TestClient(main_module.app) as test_client:
        yield test_client


@pytest.fixture()
def auth_token(client) -> str:
    response = client.post(
        "/api/auth/token",
        json={"username": "admin", "password": TEST_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture()
def auth_headers(auth_token) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth_token}"}
