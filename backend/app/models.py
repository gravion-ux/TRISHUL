"""Pydantic schemas shared by the API, the CLI and the scanning engine.

These models are the single source of truth for the wire format. The
frontend contract in ``docs/API-CONTRACT.md`` mirrors them field for field.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Impact rating assigned to a finding."""

    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ScanMode(str, Enum):
    """How aggressively the pipeline probes the target."""

    QUICK = "quick"
    DEEP = "deep"


class ScanStatus(str, Enum):
    """Lifecycle of a scan."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GuideAction(str, Enum):
    """Operator action inside an interactive guide session."""

    NEXT = "next"
    DONE = "done"
    HINT = "hint"
    RETRY = "retry"


class ProviderEdition(str, Enum):
    """Which AI edition the deployment is configured for."""

    LOCAL = "local"
    PROVIDER = "provider"


class ProviderKind(str, Enum):
    """Supported AI backends."""

    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    LLAMACPP = "llamacpp"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OPENAI_COMPATIBLE = "openai-compatible"
    CUSTOM = "custom"


class IntegrationAuthType(str, Enum):
    """How an external integration authenticates."""

    NONE = "none"
    BEARER = "bearer"
    HEADER = "header"
    QUERY = "query"


# --------------------------------------------------------------------------
# Evidence and findings
# --------------------------------------------------------------------------


class Evidence(BaseModel):
    """A single observation supporting (or refuting) a finding."""

    source: str
    summary: str
    raw: dict[str, Any] = Field(default_factory=dict)


class PocBundle(BaseModel):
    """Non-destructive reproduction material for one finding."""

    steps_to_reproduce: list[str] = Field(default_factory=list)
    request_example: str = ""
    response_example: str = ""
    impact: str = ""
    remediation: str = ""
    screenshot_guide: list[str] = Field(default_factory=list)
    video_script: list[str] = Field(default_factory=list)
    bounty_report: str = ""
    generated_by: Literal["ai", "deterministic"] = "deterministic"


class GuideStep(BaseModel):
    """One interactive step of a manual validation guide."""

    index: int
    instruction: str
    hint: str = ""
    status: Literal["pending", "active", "completed", "retrying"] = "pending"


class Finding(BaseModel):
    """A single security finding.

    ``confidence`` is the effective score published to the operator. It is
    produced by the deterministic evidence checks and then, when an AI model
    is reachable, refined by the AI verdict. ``baseline_confidence`` always
    preserves the deterministic value so that an AI override remains auditable.
    """

    id: str
    source: str
    category: str
    title: str
    description: str
    severity: Severity
    confidence: int = 0
    baseline_confidence: int = 0
    ai_adjusted: bool = False
    verified: bool = False
    asset: str
    attack_surface: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    enrichment: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    poc: PocBundle | None = None
    guide_steps: list[GuideStep] = Field(default_factory=list)
    ai_analysis: str = ""


class AiVerdict(BaseModel):
    """Structured judgement returned by an AI provider about one finding.

    The verdict is parsed from a strict JSON payload. When parsing fails the
    engine keeps the deterministic result and records the failure.
    """

    severity: Severity | None = None
    confidence: int | None = None
    verified: bool | None = None
    is_false_positive: bool | None = None
    reasoning: str = ""
    remediation: str = ""
    false_positive: bool = False


# --------------------------------------------------------------------------
# Scans
# --------------------------------------------------------------------------


class ScanProgress(BaseModel):
    """Where the pipeline currently is."""

    stage: str = "queued"
    percent: int = 0
    message: str = "Queued"


class ScanLog(BaseModel):
    """One progress/log line attached to a scan."""

    type: str = "progress"
    timestamp: datetime = Field(default_factory=lambda: datetime.now().astimezone())
    stage: str = ""
    percent: int = 0
    message: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class ScanRecord(BaseModel):
    """The persistent state of one assessment."""

    id: str
    target: str
    mode: ScanMode
    status: ScanStatus
    progress: ScanProgress = Field(default_factory=ScanProgress)
    findings: list[Finding] = Field(default_factory=list)
    enrichment: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    logs: list[ScanLog] = Field(default_factory=list)
    report_paths: dict[str, str] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    authorized: bool
    authorization_note: str = ""
    error: str | None = None
    ai_provider: str = "none"
    ai_model: str = ""


class ScanRequest(BaseModel):
    """Inbound request to start an assessment."""

    target: str = Field(min_length=1, max_length=512)
    mode: ScanMode = ScanMode.DEEP
    authorized: bool
    authorization_note: str = Field(min_length=5, max_length=1000)
    thread_limit: int = Field(default=8, ge=1, le=32)
    timeout_seconds: int = Field(default=900, ge=30, le=7200)


class ScanStartResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str


class ScanCancelResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    cancelled: bool


# --------------------------------------------------------------------------
# Guide sessions
# --------------------------------------------------------------------------


class GuideSession(BaseModel):
    """State of an interactive manual-validation session."""

    id: str
    scan_id: str
    finding_id: str
    current_step: int = 0
    status: Literal["active", "completed"] = "active"
    steps: list[GuideStep] = Field(default_factory=list)
    history: list[str] = Field(default_factory=list)
    updated_at: datetime


class GuideRequest(BaseModel):
    finding_id: str


class GuideActionRequest(BaseModel):
    action: GuideAction


# --------------------------------------------------------------------------
# Health and tooling
# --------------------------------------------------------------------------


class ToolHealth(BaseModel):
    """Availability of one external dependency."""

    name: str
    installed: bool
    path: str | None = None
    version: str | None = None
    fix_command: str | None = None
    required: bool = False


class AiHealth(BaseModel):
    """Status of the configured AI provider."""

    configured: bool = False
    provider: str = "none"
    model: str = ""
    reachable: bool = False
    message: str = ""


class HealthResponse(BaseModel):
    """Payload of ``GET /api/health``."""

    version: str
    edition: ProviderEdition
    platform: str
    ready: bool
    tools: list[ToolHealth]
    ai: AiHealth
    autofix_commands: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# AI providers
# --------------------------------------------------------------------------


class ProviderDescriptor(BaseModel):
    """Static metadata describing one supported AI backend."""

    kind: ProviderKind
    label: str
    edition: ProviderEdition
    default_base_url: str
    default_model: str
    requires_api_key: bool
    supports_models_discovery: bool
    notes: str = ""


class ProviderConfig(BaseModel):
    """The active AI provider configuration (never contains the secret)."""

    edition: ProviderEdition
    provider: ProviderKind
    model: str
    base_url: str
    timeout_seconds: int = 120
    has_api_key: bool = False
    api_key_hint: str = ""
    updated_at: datetime | None = None


class ProviderConfigRequest(BaseModel):
    """Inbound request to change the AI provider configuration."""

    edition: ProviderEdition | None = None
    provider: ProviderKind
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    timeout_seconds: int | None = Field(default=None, ge=5, le=600)


class ProviderTestRequest(BaseModel):
    """Inbound request to probe a provider without saving it."""

    provider: ProviderKind | None = None
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None


class ProviderTestResult(BaseModel):
    ok: bool
    latency_ms: int
    message: str
    models: list[str] = Field(default_factory=list)


class ChatRequest(BaseModel):
    """Inbound AI chat message."""

    message: str = Field(min_length=1, max_length=8000)
    scan_id: str | None = None
    history: list[dict[str, str]] = Field(default_factory=list)


class ChatResponse(BaseModel):
    reply: str
    provider: str
    model: str
    fallback: bool = False


# --------------------------------------------------------------------------
# External API integrations
# --------------------------------------------------------------------------


class IntegrationConfig(BaseModel):
    """A user-configured external enrichment API."""

    name: str
    base_url: str
    path: str = ""
    method: Literal["GET", "POST"] = "GET"
    auth_type: IntegrationAuthType = IntegrationAuthType.NONE
    auth_name: str = "Authorization"
    has_api_key: bool = False
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    response_json_path: str = ""
    enabled: bool = True
    rate_limit_per_minute: int = 30
    cache_ttl_seconds: int = 3600
    created_at: datetime


class IntegrationConfigRequest(BaseModel):
    """Inbound request to create or update an integration."""

    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    base_url: str = Field(min_length=1, max_length=2048)
    path: str = Field(default="", max_length=1024)
    method: Literal["GET", "POST"] = "GET"
    auth_type: IntegrationAuthType = IntegrationAuthType.NONE
    auth_name: str = Field(default="Authorization", max_length=128)
    api_key: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    response_json_path: str = Field(default="", max_length=256)
    enabled: bool = True
    rate_limit_per_minute: int = Field(default=30, ge=1, le=600)
    cache_ttl_seconds: int = Field(default=3600, ge=0, le=86400)


class IntegrationTestResult(BaseModel):
    ok: bool
    status_code: int
    latency_ms: int
    message: str
    preview: dict[str, Any] | None = None


class IntegrationInvokeResult(BaseModel):
    ok: bool
    data: Any = None
    cached: bool = False
    latency_ms: int = 0
    message: str = ""


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------


class TokenRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MeResponse(BaseModel):
    username: str
    edition: ProviderEdition


# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------


class UpdateResponse(BaseModel):
    success: bool
    details: dict[str, Any] = Field(default_factory=dict)


class AutofixResponse(BaseModel):
    commands: list[str] = Field(default_factory=list)


class EnrichmentResponse(BaseModel):
    scan_id: str
    results: list[dict[str, Any]] = Field(default_factory=list)


class DeleteResponse(BaseModel):
    deleted: bool
