"""TRISHUL FastAPI application.

Exposes the REST API, the scan progress WebSocket and the dashboard.
Authentication, rate limiting and scope enforcement are applied here so that
no route can accidentally bypass them.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.ai.registry import AIManager
from backend.app.core.config import get_settings
from backend.app.core.events import event_bus
from backend.app.core.scope import ScopePolicy
from backend.app.core.secrets import CredentialStore
from backend.app.core.security import (
    RateLimiter,
    TokenManager,
    api_key_hint,
    ensure_admin_credentials,
    hash_password,
    verify_password,
)
from backend.app.core.storage import Storage
from backend.app.core.utils import redact, utcnow
from backend.app.engine.base import Adapters
from backend.app.engine.master import MasterAgent
from backend.app.engine.tasks import TaskManager
from backend.app.models import (
    AutofixResponse,
    ChatRequest,
    ChatResponse,
    DeleteResponse,
    EnrichmentResponse,
    GuideAction,
    GuideActionRequest,
    GuideRequest,
    HealthResponse,
    IntegrationConfig,
    IntegrationConfigRequest,
    IntegrationInvokeResult,
    IntegrationTestResult,
    MeResponse,
    ProviderConfig,
    ProviderConfigRequest,
    ProviderDescriptor,
    ProviderTestRequest,
    ProviderTestResult,
    ScanCancelResponse,
    ScanRequest,
    ScanStartResponse,
    TokenRequest,
    TokenResponse,
    UpdateResponse,
)
from backend.app.services.health import HealthService
from backend.app.services.integrations import IntegrationManager
from backend.app.services.reporting import ReportingService
from backend.app.services.tool_adapters import (
    FfufAdapter,
    HttpxAdapter,
    NmapAdapter,
    NucleiAdapter,
)
from backend.app.services.tool_runner import ToolRunner
from backend.app.services.tooling import ToolRegistry
from backend.app.services.updater import UpdaterService

settings = get_settings()

storage = Storage(settings.database_path)
credentials = CredentialStore(settings.data_dir / "credentials.enc")
ai_manager = AIManager(storage, credentials, settings)
integration_manager = IntegrationManager(storage, credentials, settings)

runner = ToolRunner(allowed_binaries=settings.tools.allowed_binaries)
tool_registry = ToolRegistry(runner, settings)
health_service = HealthService(tool_registry, ai_manager)
reporting_service = ReportingService(settings)

scope_policy = ScopePolicy(
    allow_private=settings.security.allow_private_targets,
    authorized_targets=settings.security.authorized_targets,
    blocked_hostnames=settings.security.blocked_hostnames,
)

adapters = Adapters(
    httpx=HttpxAdapter(runner, settings, tool_registry),
    nmap=NmapAdapter(runner, settings, tool_registry),
    nuclei=NucleiAdapter(runner, settings, tool_registry),
    ffuf=FfufAdapter(runner, settings, tool_registry),
)

master_agent = MasterAgent(
    storage=storage,
    settings=settings,
    ai=ai_manager,
    integrations=integration_manager,
    tools=tool_registry,
    adapters=adapters,
    scope=scope_policy,
    reporting=reporting_service,
)

task_manager = TaskManager(storage, max_concurrent=settings.scan.max_concurrent_scans)
updater_service = UpdaterService(runner, settings, tool_registry)
rate_limiter = RateLimiter(
    limit=settings.security.rate_limit_requests,
    window_seconds=settings.security.rate_limit_window_seconds,
)
token_manager = TokenManager(settings.data_dir / ".api_secret", settings.auth.token_ttl_seconds)

# Resolve the administrator credentials once at startup. A generated
# password is written to data/admin-credentials.txt.
ADMIN_USER, ADMIN_PASSWORD, ADMIN_GENERATED = ensure_admin_credentials(
    settings.auth.username, settings.auth.password or None, settings.data_dir
)
if settings.auth.password:
    # An explicitly configured password always wins, so rotating
    # TRISHUL_ADMIN_PASSWORD takes effect on the next start instead of being
    # shadowed by the hash stored on the first run.
    credentials.set("admin:password_hash", hash_password(settings.auth.password))
elif not credentials.get("admin:password_hash"):
    # A generated password is written once and then kept.
    credentials.set("admin:password_hash", hash_password(ADMIN_PASSWORD))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    storage.purge_expired_cache()
    try:
        yield
    finally:
        await task_manager.shutdown()
        event_bus._subscribers.clear()


app = FastAPI(
    title="TRISHUL",
    version=settings.app.version,
    description="Authorized-scope AI-powered security testing platform.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.app.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# ---------------------------------------------------------------------------
# Authentication and rate limiting
# ---------------------------------------------------------------------------


def _client_key(request: Request) -> str:
    client = request.client.host if request.client else "unknown"
    return client


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.query_params.get("token", "")


async def require_auth(request: Request) -> str:
    """Validate the bearer token and enforce the rate limit."""
    if not settings.auth.enabled:
        return "anonymous"

    token = _bearer_token(request)
    payload = token_manager.verify(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired access token.")

    allowed, remaining, retry_after = rate_limiter.allow(
        f"{payload.get('sub', 'user')}:{_client_key(request)}"
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Retry in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    return str(payload.get("sub", "user"))


Auth = Depends(require_auth)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/api/health", response_model=HealthResponse)
async def get_health():
    """Public health endpoint."""
    return await health_service.get_health_async()


@app.get("/api/health/autofix", response_model=AutofixResponse)
async def get_autofix(_user: str = Auth):
    """Return the commands that would install missing tools (never executed)."""
    return AutofixResponse(commands=tool_registry.autofix_commands())


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@app.post("/api/auth/token", response_model=TokenResponse)
async def issue_token(request: TokenRequest) -> TokenResponse:
    """Exchange administrator credentials for a bearer token."""
    if not settings.auth.enabled:
        token, ttl = token_manager.issue("anonymous")
        return TokenResponse(access_token=token, expires_in=ttl)

    user_ok = hmac.compare_digest(request.username, ADMIN_USER)
    stored_hash = credentials.get("admin:password_hash") or ""
    password_ok = verify_password(request.password, stored_hash)
    if not (user_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token, ttl = token_manager.issue(ADMIN_USER)
    return TokenResponse(access_token=token, expires_in=ttl)


@app.get("/api/me", response_model=MeResponse)
async def whoami(user: str = Auth) -> MeResponse:
    return MeResponse(username=user, edition=ai_manager.current_config().edition)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@app.get("/api/scans")
async def list_scans(_user: str = Auth):
    return [item.model_dump(mode="json") for item in storage.list_scans()]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, _user: str = Auth):
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.model_dump(mode="json")


@app.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str, _user: str = Auth):
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [item.model_dump(mode="json") for item in scan.findings]


@app.post("/api/scans", response_model=ScanStartResponse)
async def start_scan(request: ScanRequest, _user: str = Auth):
    """Queue an authorized scan."""
    if not request.authorized:
        raise HTTPException(
            status_code=400,
            detail="Explicit authorization is required before a scan can start.",
        )
    if not request.authorization_note.strip():
        raise HTTPException(status_code=400, detail="An authorization note is required.")

    scan = master_agent.create_scan(request)
    try:
        await task_manager.start(scan.id, lambda: master_agent.run_scan(scan.id))
    except RuntimeError as exc:
        storage.delete_scan(scan.id)
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return ScanStartResponse(scan_id=scan.id, status=scan.status, message="Scan queued")


@app.delete("/api/scans/{scan_id}", response_model=ScanCancelResponse)
async def cancel_scan(scan_id: str, _user: str = Auth):
    """Cancel a running scan."""
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    cancelled = await task_manager.cancel(scan_id)
    refreshed = storage.get_scan(scan_id)
    return ScanCancelResponse(
        scan_id=scan_id,
        status=refreshed.status if refreshed else scan.status,
        cancelled=cancelled,
    )


# ---------------------------------------------------------------------------
# Guides
# ---------------------------------------------------------------------------


@app.post("/api/guides/start")
async def start_guide(request: GuideRequest, scan_id: str = Query(...), _user: str = Auth):
    try:
        guide = await master_agent.start_guide(scan_id, request.finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return guide.model_dump(mode="json")


@app.post("/api/guides/{guide_id}/action")
async def advance_guide(guide_id: str, request: GuideActionRequest, _user: str = Auth):
    try:
        guide = await master_agent.advance_guide(guide_id, request.action)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return guide.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@app.get("/api/reports/{scan_id}/{fmt}")
async def get_report(scan_id: str, fmt: str, _user: str = Auth):
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    path = scan.report_paths.get(fmt)
    if not path:
        raise HTTPException(status_code=404, detail=f"Unknown report format: {fmt}")
    report_path = Path(path)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    media_type = {
        "json": "application/json",
        "markdown": "text/markdown",
        "html": "text/html",
        "bug_bounty": "text/markdown",
    }.get(fmt, "application/octet-stream")
    return FileResponse(report_path, media_type=media_type, filename=report_path.name)


# ---------------------------------------------------------------------------
# AI providers
# ---------------------------------------------------------------------------


@app.get("/api/providers", response_model=list[ProviderDescriptor])
async def list_providers(_user: str = Auth):
    return ai_manager.catalog()


@app.get("/api/providers/current", response_model=ProviderConfig)
async def get_provider_config(_user: str = Auth):
    return ai_manager.current_config()


@app.post("/api/providers/config", response_model=ProviderConfig)
async def set_provider_config(request: ProviderConfigRequest, _user: str = Auth):
    try:
        return ai_manager.save_config(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/providers/config", response_model=ProviderConfig)
async def reset_provider_config(_user: str = Auth):
    return ai_manager.reset_config()


@app.post("/api/providers/test", response_model=ProviderTestResult)
async def test_provider(request: ProviderTestRequest, _user: str = Auth):
    return await ai_manager.test(
        kind=request.provider,
        model=request.model,
        base_url=request.base_url,
        api_key=request.api_key,
    )


@app.get("/api/providers/models")
async def list_provider_models(
    provider: str | None = Query(default=None),
    base_url: str | None = Query(default=None),
    _user: str = Auth,
):
    from backend.app.models import ProviderKind

    kind: ProviderKind | None = None
    if provider:
        try:
            kind = ProviderKind(provider)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}") from exc
    try:
        models = await ai_manager.list_models(kind=kind, base_url=base_url)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=redact(str(exc))) from exc
    return {"models": models}


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

CHAT_SYSTEM = """You are TRISHUL's security analyst assistant.

You help the operator understand the results of an authorized security assessment.
Base every statement on the scan data you are given. If the data does not support a
conclusion, say so explicitly. Never recommend destructive actions, exploitation,
credential attacks or anything outside the authorised scope. Never reveal API keys,
tokens or other secrets, even if they appear in the scan data."""


@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, _user: str = Auth):
    """Answer a question about the assessment using the configured AI."""
    scan_context = ""
    if request.scan_id:
        scan = storage.get_scan(request.scan_id)
        if scan:
            scan_context = _scan_digest(scan)

    history_lines = [
        f"{item.get('role', 'user')}: {item.get('content', '')}" for item in request.history[-10:]
    ]
    prompt = "\n".join(
        part
        for part in (
            "Conversation so far:\n" + "\n".join(history_lines) if history_lines else "",
            scan_context,
            f"Operator question: {request.message}",
        )
        if part
    )

    config = ai_manager.current_config()
    try:
        from backend.app.ai.base import AIRequest

        response = await ai_manager.complete(
            AIRequest(
                prompt=prompt,
                system=CHAT_SYSTEM,
                max_tokens=settings.ai.max_tokens,
                temperature=settings.ai.temperature,
            )
        )
        reply = response.text
        provider, model = response.provider, response.model
        fallback = False
    except Exception as exc:  # noqa: BLE001 - the chat must always answer
        reply = _fallback_chat_reply(request, scan_context, exc)
        provider, model = "none", ""
        fallback = True

    storage.save_chat_message(
        uuid.uuid4().hex, "assistant", reply, request.scan_id, provider, model
    )
    storage.save_chat_message(uuid.uuid4().hex, "user", request.message, request.scan_id)
    return ChatResponse(reply=reply, provider=provider, model=model, fallback=fallback)


def _scan_digest(scan: Any) -> str:
    lines = [
        f"Target: {scan.target}",
        f"Status: {scan.status.value}",
        f"Mode: {scan.mode.value}",
        f"Findings: {len(scan.findings)}",
    ]
    for finding in scan.findings[:25]:
        lines.append(
            f"- [{finding.severity.value}] {finding.title} | asset={finding.asset} "
            f"| confidence={finding.confidence} | verified={finding.verified}"
        )
        lines.append(f"  {finding.description[:240]}")
    return "Scan data:\n" + "\n".join(lines)


def _fallback_chat_reply(request: ChatRequest, scan_context: str, error: Exception) -> str:
    """Answer without an AI model.

    The reply is explicit about the fact that no model was reachable so the
    operator is never misled into thinking the AI produced the answer.
    """
    reason = redact(str(error))
    if scan_context:
        return (
            f"The AI provider is not reachable ({reason}), so this answer was generated "
            "without a model from the scan record only.\n\n"
            f"{scan_context}\n\n"
            "Configure a provider in Settings → AI Provider to get a model-backed analysis."
        )
    return (
        f"The AI provider is not reachable ({reason}), so this answer was generated "
        "without a model. Configure a provider in Settings → AI Provider, then retry."
    )


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------


@app.get("/api/integrations", response_model=list[IntegrationConfig])
async def list_integrations(_user: str = Auth):
    return integration_manager.list()


@app.post("/api/integrations", response_model=IntegrationConfig)
async def save_integration(request: IntegrationConfigRequest, _user: str = Auth):
    return integration_manager.save(request)


@app.delete("/api/integrations/{name}", response_model=DeleteResponse)
async def delete_integration(name: str, _user: str = Auth):
    return DeleteResponse(deleted=integration_manager.delete(name))


@app.post("/api/integrations/{name}/test", response_model=IntegrationTestResult)
async def test_integration(name: str, params: dict[str, Any] | None = None, _user: str = Auth):
    return await integration_manager.test(name, params or {})


@app.post("/api/integrations/{name}/invoke", response_model=IntegrationInvokeResult)
async def invoke_integration(
    name: str, params: dict[str, Any] | None = None, _user: str = Auth
):
    try:
        return await integration_manager.invoke(name, params or {})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=redact(str(exc))) from exc


@app.get("/api/enrichment", response_model=EnrichmentResponse)
async def get_enrichment(scan_id: str = Query(...), _user: str = Auth):
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return EnrichmentResponse(scan_id=scan_id, results=scan.enrichment)


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------


@app.post("/api/update", response_model=UpdateResponse)
async def update_all(_user: str = Auth):
    details = await updater_service.update_all()
    success = all(item.get("success", False) for item in details.values())
    return UpdateResponse(success=success, details=details)


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


@app.websocket("/ws/scans/{scan_id}")
async def scan_events(websocket: WebSocket, scan_id: str):
    """Stream scan progress to the dashboard."""
    if settings.auth.enabled:
        token = websocket.query_params.get("token", "")
        if not token:
            header = websocket.headers.get("authorization", "")
            if header.lower().startswith("bearer "):
                token = header[7:].strip()
        if token_manager.verify(token) is None:
            await websocket.close(code=4401, reason="Invalid or missing access token")
            return

    await websocket.accept()
    queue = event_bus.subscribe(scan_id)
    try:
        scan = storage.get_scan(scan_id)
        if scan:
            await websocket.send_json({"type": "snapshot", "scan": scan.model_dump(mode="json")})
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - a broken socket must not raise into the app
        pass
    finally:
        event_bus.unsubscribe(scan_id, queue)


# ---------------------------------------------------------------------------
# Static dashboard (mounted last so the API routes win)
# ---------------------------------------------------------------------------

frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(prog="trishul-server")
    parser.add_argument("--host", default=settings.app.host)
    parser.add_argument("--port", type=int, default=settings.app.port)
    parser.add_argument("--health", action="store_true", help="Print the health report and exit.")
    parser.add_argument("--migrate", action="store_true", help="Apply database migrations and exit.")
    args = parser.parse_args()

    if args.migrate:
        from backend.app.core.migrations import current_version, run_migrations

        result = run_migrations(settings.database_path, Path(__file__).resolve().parents[2] / "migrations")
        print(f"Applied: {result['applied'] or 'nothing new'}")
        print(f"Schema version: {current_version(settings.database_path)}")
        return

    if args.health:
        health = asyncio.run(health_service.get_health_async())
        print(health.model_dump_json(indent=2))
        return

    if ADMIN_GENERATED:
        print(
            f"[!] Generated administrator credentials written to "
            f"{settings.data_dir / 'admin-credentials.txt'}"
        )
    uvicorn.run(
        "backend.app.main:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level=settings.app.log_level.lower(),
    )


if __name__ == "__main__":
    main()
