"""Modular external API integration system.

TRISHUL ships with **no** hardcoded third-party API dependencies. Every
enrichment source is an integration that the operator configures:

* a base URL and path,
* an authentication scheme (none, bearer, custom header, query parameter),
* custom headers and query parameters,
* a response validation rule (a dot-path into the JSON body),
* a local cache TTL and a per-integration rate limit.

Integrations are entirely optional. With none configured the pipeline still
completes and simply reports no enrichment.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx

from backend.app.core.config import Settings
from backend.app.core.secrets import CredentialStore, integration_secret_name
from backend.app.core.storage import Storage
from backend.app.core.utils import redact_text, utcnow_iso
from backend.app.models import (
    IntegrationAuthType,
    IntegrationConfig,
    IntegrationConfigRequest,
    IntegrationInvokeResult,
    IntegrationTestResult,
)


class IntegrationError(RuntimeError):
    """Raised when an integration cannot be executed."""


class IntegrationManager:
    """Stores, validates and invokes user-configured enrichment APIs."""

    def __init__(
        self,
        storage: Storage,
        credentials: CredentialStore,
        settings: Settings,
    ) -> None:
        self.storage = storage
        self.credentials = credentials
        self.settings = settings
        # Per-integration sliding window of call timestamps.
        self._calls: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()
        self._migrate_plaintext_secrets()

    # -- secret handling ----------------------------------------------------

    def _secret_for(self, name: str) -> str | None:
        """Return the encrypted secret for an integration, if there is one."""
        if not name:
            return None
        return self.credentials.get(integration_secret_name(name))

    def _migrate_plaintext_secrets(self) -> None:
        """Move legacy plaintext API keys into the encrypted credential store.

        Earlier builds stored the integration key in the clear inside the
        ``integrations`` table. The encrypted store is the only place a secret
        belongs, so any legacy value is moved across and the plaintext column
        is cleared.
        """
        try:
            configs = self.storage.list_integrations()
        except Exception:  # noqa: BLE001 - never block startup on a migration
            return
        for raw in configs:
            legacy = str(raw.get("api_key") or "")
            if not legacy:
                continue
            name = str(raw.get("name") or "")
            if name and not self._secret_for(name):
                self.credentials.set(integration_secret_name(name), legacy)
            cleaned = {key: value for key, value in raw.items() if key != "api_key"}
            self.storage.save_integration(name, cleaned)

    # -- configuration -----------------------------------------------------

    def list(self) -> list[IntegrationConfig]:
        return [self._as_model(item) for item in self.storage.list_integrations()]

    def get(self, name: str) -> IntegrationConfig | None:
        raw = self.storage.get_integration(name)
        return self._as_model(raw) if raw else None

    def _as_model(self, raw: dict[str, Any]) -> IntegrationConfig:
        """Build the public view of an integration.

        The key itself is never part of the model; only the boolean that says
        whether one is configured.
        """
        payload = dict(raw)
        payload.pop("api_key", None)
        payload["has_api_key"] = bool(self._secret_for(str(payload.get("name") or "")))
        return IntegrationConfig(**payload)

    def save(self, request: IntegrationConfigRequest) -> IntegrationConfig:
        """Create or replace an integration definition."""
        existing = self.storage.get_integration(request.name)
        created_at = (existing or {}).get("created_at") or utcnow_iso()

        api_key = request.api_key
        if api_key is None and existing:
            # Keep the previously stored key when the operator does not
            # supply a new one. The encrypted store is the source of truth.
            api_key = self._secret_for(request.name)

        payload = {
            "name": request.name,
            "base_url": request.base_url.rstrip("/"),
            "path": request.path,
            "method": request.method,
            "auth_type": request.auth_type.value,
            "auth_name": request.auth_name,
            "headers": request.headers,
            "params": request.params,
            "response_json_path": request.response_json_path,
            "enabled": request.enabled,
            "rate_limit_per_minute": request.rate_limit_per_minute,
            "cache_ttl_seconds": request.cache_ttl_seconds,
            "created_at": created_at,
        }
        self.storage.save_integration(request.name, payload)
        # The key is written to the encrypted store only — never to the
        # plaintext database row.
        self.credentials.set(integration_secret_name(request.name), api_key or None)
        return self._as_model(payload)

    def delete(self, name: str) -> bool:
        deleted = self.storage.delete_integration(name)
        self.credentials.delete(integration_secret_name(name))
        return deleted

    # -- invocation --------------------------------------------------------

    def _rate_limit_ok(self, name: str, limit_per_minute: int) -> bool:
        now = time.time()
        window = [stamp for stamp in self._calls.get(name, []) if stamp > now - 60]
        if len(window) >= limit_per_minute:
            self._calls[name] = window
            return False
        window.append(now)
        self._calls[name] = window
        return True

    def _build_request(
        self,
        config: dict[str, Any],
        params: dict[str, Any],
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        base_url = str(config["base_url"]).rstrip("/")
        path = str(config.get("path") or "")
        url = f"{base_url}{path}" if path.startswith("/") else (f"{base_url}/{path}" if path else base_url)

        headers = {str(k): str(v) for k, v in (config.get("headers") or {}).items()}
        query: dict[str, Any] = {str(k): str(v) for k, v in (config.get("params") or {}).items()}
        query.update({str(k): v for k, v in (params or {}).items() if v is not None})

        auth_type = config.get("auth_type", IntegrationAuthType.NONE.value)
        auth_name = config.get("auth_name") or "Authorization"
        secret = self._secret_for(str(config.get("name") or "")) or str(config.get("api_key") or "")

        if auth_type == IntegrationAuthType.BEARER.value and secret:
            headers["Authorization"] = f"Bearer {secret}"
        elif auth_type == IntegrationAuthType.HEADER.value and secret:
            headers[auth_name] = secret
        elif auth_type == IntegrationAuthType.QUERY.value and secret:
            query[auth_name] = secret
        return url, headers, query

    @staticmethod
    def _extract(payload: Any, json_path: str) -> Any:
        """Pull a value out of a JSON body using a dot path."""
        if not json_path:
            return payload
        current = payload
        for part in json_path.split("."):
            if part == "":
                continue
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return current

    async def invoke(
        self,
        name: str,
        params: dict[str, Any] | None = None,
        *,
        use_cache: bool = True,
    ) -> IntegrationInvokeResult:
        """Call an integration and return its validated response."""
        config = self.storage.get_integration(name)
        if not config:
            raise IntegrationError(f"Integration {name!r} is not configured.")
        if not config.get("enabled", True):
            raise IntegrationError(f"Integration {name!r} is disabled.")

        limit = int(config.get("rate_limit_per_minute") or self.settings.integrations.rate_limit_per_minute)
        async with self._lock:
            if not self._rate_limit_ok(name, limit):
                raise IntegrationError(
                    f"Integration {name!r} exceeded its rate limit of {limit} requests/minute."
                )

        cache_key = f"integration:{name}:{json.dumps(params or {}, sort_keys=True)}"
        ttl = int(config.get("cache_ttl_seconds") or 0)
        if use_cache and ttl > 0:
            cached = self.storage.cache_get(cache_key)
            if cached is not None:
                return IntegrationInvokeResult(
                    ok=True, data=cached, cached=True, latency_ms=0, message="Served from local cache."
                )

        url, headers, query = self._build_request(config, params or {})
        method = str(config.get("method") or "GET").upper()
        timeout = self.settings.integrations.timeout_seconds

        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                if method == "POST":
                    response = await client.post(url, headers=headers, params=query, json=dict(params or {}))
                else:
                    response = await client.get(url, headers=headers, params=query)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Integration {name!r} request failed: {redact_text(str(exc))}") from exc

        latency_ms = int((time.perf_counter() - started) * 1000)
        if response.status_code >= 400:
            raise IntegrationError(
                f"Integration {name!r} returned HTTP {response.status_code}: "
                f"{redact_text(response.text[:200])}"
            )
        if len(response.content) > self.settings.integrations.max_response_bytes:
            raise IntegrationError(
                f"Integration {name!r} response exceeded "
                f"{self.settings.integrations.max_response_bytes} bytes."
            )
        try:
            body = response.json()
        except ValueError:
            body = {"text": response.text[:10000]}

        validated = self._extract(body, str(config.get("response_json_path") or ""))
        if validated is None and config.get("response_json_path"):
            raise IntegrationError(
                f"Integration {name!r} response did not contain the configured path "
                f"{config.get('response_json_path')!r}."
            )

        if use_cache and ttl > 0:
            self.storage.cache_set(cache_key, validated, ttl)
        return IntegrationInvokeResult(
            ok=True,
            data=validated,
            cached=False,
            latency_ms=latency_ms,
            message="OK",
        )

    async def test(self, name: str, params: dict[str, Any] | None = None) -> IntegrationTestResult:
        """Call an integration without touching the cache."""
        try:
            result = await self.invoke(name, params, use_cache=False)
        except IntegrationError as exc:
            return IntegrationTestResult(
                ok=False, status_code=0, latency_ms=0, message=str(exc), preview=None
            )
        preview: dict[str, Any] | None = None
        if isinstance(result.data, dict):
            preview = {key: result.data[key] for key in list(result.data)[:10]}
        elif isinstance(result.data, list):
            preview = {"items": len(result.data)}
        return IntegrationTestResult(
            ok=True,
            status_code=200,
            latency_ms=result.latency_ms,
            message="Request succeeded.",
            preview=preview,
        )

    async def enrich(self, values: dict[str, str]) -> list[dict[str, Any]]:
        """Run every enabled integration against the supplied values.

        A failing integration is reported as an error entry instead of
        aborting the enrichment pass.
        """
        results: list[dict[str, Any]] = []
        configs = [item for item in self.storage.list_integrations() if item.get("enabled", True)]
        if not configs:
            return results

        async def run_one(config: dict[str, Any]) -> dict[str, Any]:
            name = config["name"]
            try:
                outcome = await self.invoke(name, values)
                return {
                    "provider": name,
                    "cached": outcome.cached,
                    "latency_ms": outcome.latency_ms,
                    "data": outcome.data,
                }
            except IntegrationError as exc:
                return {"provider": name, "cached": False, "error": str(exc), "data": None}

        outcomes = await asyncio.gather(*(run_one(config) for config in configs))
        results.extend(outcomes)
        return results


def write_integration_export(path: Path, integrations: list[IntegrationConfig]) -> None:
    """Export integration definitions (without secrets) for backup."""
    payload = [item.model_dump(mode="json") for item in integrations]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
