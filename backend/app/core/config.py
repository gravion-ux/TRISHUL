"""Runtime configuration for TRISHUL.

Configuration is layered:

1. ``config/default.yaml`` — checked-in defaults.
2. ``TRISHUL_CONFIG`` env var — optional alternative YAML path.
3. Environment variables — highest precedence for operational knobs.

The settings object is immutable for the lifetime of the process so that
long-running scans cannot observe a half-applied configuration change.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# backend/app/core/config.py -> parents[3] is the project root.
ROOT_DIR = Path(__file__).resolve().parents[3]


class AppConfig(BaseModel):
    """Top-level application identity and filesystem layout."""

    name: str = "TRISHUL"
    version: str = "2.0.0"
    db_path: str = "data/trishul.db"
    reports_dir: str = "reports"
    plugins_dir: str = "plugins"
    log_level: str = "INFO"
    # Bind to loopback by default: exposing the control plane on every
    # interface is an unnecessary risk for a security tool.
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )


class ScanConfig(BaseModel):
    """Execution limits for the scanning pipeline."""

    default_mode: str = "deep"
    timeout_seconds: int = 900
    thread_limit: int = 8
    max_concurrent_scans: int = 3
    # Controlled fuzzing: the ffuf wordlist is capped so a scan cannot
    # turn into an unbounded request storm against the target.
    ffuf_max_requests: int = 2000
    ffuf_status_filter: list[int] = Field(
        default_factory=lambda: [200, 204, 301, 302, 307, 401, 403]
    )
    wordlist: str = "config/wordlists/common.txt"
    param_wordlist: str = "config/wordlists/params.txt"


class ToolConfig(BaseModel):
    """External binary locations and the allowlist of permitted executables."""

    httpx: str = "httpx"
    nuclei: str = "nuclei"
    ffuf: str = "ffuf"
    nmap: str = "nmap"
    ffuf_wordlist: str = "config/wordlists/common.txt"
    param_wordlist: str = "config/wordlists/params.txt"
    # Only these binaries may ever be executed. The runner refuses anything
    # else even if a caller passes an arbitrary path.
    allowed_binaries: list[str] = Field(
        default_factory=lambda: ["httpx", "nuclei", "ffuf", "nmap", "git", "go"]
    )


class AIConfig(BaseModel):
    """AI provider selection and request shaping.

    ``edition`` drives the defaults only. The security engine never branches
    on it — it always talks to the provider abstraction.
    """

    edition: str = "local"
    provider: str = "ollama"
    model: str = "llama3.1:8b"
    base_url: str = "http://localhost:11434"
    timeout_seconds: int = 120
    max_tokens: int = 2048
    temperature: float = 0.2
    # When the AI cannot be reached the deterministic pipeline still completes.
    fail_open: bool = True


class AuthConfig(BaseModel):
    """Bearer-token authentication for the control plane."""

    enabled: bool = True
    username: str = "admin"
    # Populated from TRISHUL_ADMIN_PASSWORD, or generated on first run.
    password: str = ""
    token_ttl_seconds: int = 86400


class SecurityConfig(BaseModel):
    """Network and operational safety controls."""

    # Private/link-local ranges are refused unless the operator opts in,
    # which blocks the classic SSRF pivots (cloud metadata, loopback admin
    # panels) while still allowing internal pentest engagements.
    allow_private_targets: bool = False
    # When non-empty, only these hosts (or their subdomains) may be scanned.
    # This is the hard scope boundary for an engagement.
    authorized_targets: list[str] = Field(default_factory=list)
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    blocked_hostnames: list[str] = Field(
        default_factory=lambda: [
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.goog",
        ]
    )


class IntegrationsConfig(BaseModel):
    """Defaults for the modular external-API integration system."""

    cache_ttl_seconds: int = 3600
    rate_limit_per_minute: int = 30
    timeout_seconds: int = 20
    max_response_bytes: int = 512_000


class Settings(BaseModel):
    """Fully resolved runtime configuration."""

    app: AppConfig = Field(default_factory=AppConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    tools: ToolConfig = Field(default_factory=ToolConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    integrations: IntegrationsConfig = Field(default_factory=IntegrationsConfig)

    @property
    def database_path(self) -> Path:
        return self._resolve(self.app.db_path)

    @property
    def reports_dir(self) -> Path:
        return self._resolve(self.app.reports_dir)

    @property
    def plugins_dir(self) -> Path:
        return self._resolve(self.app.plugins_dir)

    @property
    def data_dir(self) -> Path:
        return self.database_path.parent

    @property
    def wordlist_path(self) -> Path:
        return self._resolve(self.scan.wordlist)

    @property
    def param_wordlist_path(self) -> Path:
        return self._resolve(self.scan.param_wordlist)

    def _resolve(self, relative: str) -> Path:
        candidate = Path(relative)
        return candidate if candidate.is_absolute() else ROOT_DIR / candidate


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML document, tolerating a missing or empty file."""
    if not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _apply_env_overrides(settings: Settings) -> Settings:
    """Overlay environment variables on top of the YAML configuration."""
    if value := os.environ.get("TRISHUL_EDITION"):
        settings.ai.edition = value.strip().lower()
    if value := os.environ.get("TRISHUL_AI_PROVIDER"):
        settings.ai.provider = value.strip().lower()
    if value := os.environ.get("TRISHUL_AI_MODEL"):
        settings.ai.model = value.strip()
    if value := os.environ.get("TRISHUL_AI_BASE_URL"):
        settings.ai.base_url = value.strip().rstrip("/")
    if value := os.environ.get("TRISHUL_AI_TIMEOUT"):
        settings.ai.timeout_seconds = int(value)
    if value := os.environ.get("TRISHUL_ADMIN_USER"):
        settings.auth.username = value.strip()
    if value := os.environ.get("TRISHUL_ADMIN_PASSWORD"):
        settings.auth.password = value
    if value := os.environ.get("TRISHUL_API_HOST"):
        settings.app.host = value.strip()
    if value := os.environ.get("TRISHUL_API_PORT"):
        settings.app.port = int(value)
    if value := os.environ.get("TRISHUL_ALLOW_PRIVATE_TARGETS"):
        settings.security.allow_private_targets = _env_bool(
            "TRISHUL_ALLOW_PRIVATE_TARGETS", settings.security.allow_private_targets
        )
    if value := os.environ.get("TRISHUL_LOG_LEVEL"):
        settings.app.log_level = value.strip().upper()
    return settings


def _apply_edition_defaults(settings: Settings) -> Settings:
    """Fill in edition-appropriate provider defaults.

    Only *defaults* are touched. Once a user has saved a provider
    configuration it is persisted separately and always wins over these.
    """
    if settings.ai.edition == "provider":
        if settings.ai.provider in {"ollama", "lmstudio", "llamacpp"}:
            settings.ai.provider = "openai"
            settings.ai.base_url = "https://api.openai.com/v1"
            settings.ai.model = "gpt-4o-mini"
    return settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and cache the process-wide settings.

    Directories that TRISHUL writes to are created eagerly so that a
    first-run scan does not fail halfway through on a missing parent.
    """
    config_path = Path(os.environ.get("TRISHUL_CONFIG", ROOT_DIR / "config" / "default.yaml"))
    raw = _read_yaml(config_path)
    settings = Settings(**raw)
    settings = _apply_env_overrides(settings)
    settings = _apply_edition_defaults(settings)

    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.plugins_dir.mkdir(parents=True, exist_ok=True)
    return settings


def reload_settings() -> Settings:
    """Drop the cached settings and re-read them from disk.

    Used by the CLI after it rewrites the provider configuration.
    """
    get_settings.cache_clear()
    return get_settings()
