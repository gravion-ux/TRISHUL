"""Small shared helpers: identifiers, time, target parsing and redaction."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Patterns that must never reach a log file, an API response or a report.
_REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{12,}\b")),
    # A Google API key is "AIza" followed by 35 URL-safe characters. The
    # threshold is deliberately lower than the real length so a shortened or
    # mistyped key still cannot leak.
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{10,}\b")),
    # Matches "Authorization: Bearer <token>", "Authorization: <token>" and
    # "bearer=<token>". The scheme is kept, the secret is replaced.
    ("bearer_token", re.compile(r"(?i)\b(authorization|bearer)\b(\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[A-Za-z0-9._\-+/=]{8,}")),
    ("api_key_assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*\S{6,}")),
    ("basic_auth_url", re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
)


def utcnow() -> datetime:
    """Timezone-aware current time.

    ``datetime.utcnow()`` is deprecated since Python 3.12 and returns a naive
    value, which silently mixes with aware timestamps.
    """
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def slugify(value: str) -> str:
    """Convert an arbitrary string into a filesystem-safe slug."""
    return re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()[:120]


def stable_id(prefix: str, value: str) -> str:
    """Deterministic short identifier derived from ``value``.

    Deterministic ids let re-scanning the same target produce the same
    finding identifiers, which keeps reports diffable.
    """
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def unique_id(prefix: str, value: str) -> str:
    """Deterministic id with a timestamp suffix (used for scans)."""
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]
    stamp = utcnow().strftime("%Y%m%d%H%M%S%f")
    return f"{prefix}-{digest}-{stamp}"


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_target(target: str) -> dict[str, str]:
    """Split a user-supplied target into its raw, URL and host components.

    Only the host is used for network operations; the scheme is inferred so
    that ``example.com`` and ``https://example.com`` behave the same way.
    """
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Target must not be empty.")
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
        host = parsed.hostname
        if not host:
            raise ValueError(f"Could not determine host from target: {raw}")
        port = parsed.port
        netloc = f"{host}:{port}" if port else host
        url = f"{parsed.scheme}://{netloc}{parsed.path or ''}".rstrip("/")
        return {"raw": raw, "url": url, "host": host}
    host = raw.split("/")[0].split(":")[0]
    if not host:
        raise ValueError(f"Could not determine host from target: {raw}")
    return {"raw": raw, "url": f"https://{host}", "host": host}


def extract_cves(text: str) -> list[str]:
    """Return the CVE identifiers mentioned in ``text``."""
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))


def redact(value: Any) -> Any:
    """Recursively replace credential-looking substrings with ``***``.

    Applied to every log line, error message and report payload so that an
    accidentally captured API key never leaves the process.
    """
    if isinstance(value, str):
        redacted = value
        for _label, pattern in _REDACTION_PATTERNS:
            if _label == "api_key_assignment":
                redacted = pattern.sub(lambda match: f"{match.group(1)}=***", redacted)
            elif _label == "basic_auth_url":
                redacted = pattern.sub(lambda match: f"{match.group(1)}***:***@", redacted)
            elif _label == "bearer_token":
                # Keep the scheme, drop the secret.
                redacted = pattern.sub(
                    lambda match: f"{match.group(1)}{match.group(2)}***", redacted
                )
            else:
                redacted = pattern.sub("***", redacted)
        return redacted
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


def redact_text(value: str) -> str:
    """Redact a single string."""
    return redact(value)


def safe_child_path(parent: Path, name: str) -> Path:
    """Join ``name`` under ``parent`` while refusing path traversal.

    ``name`` may contain separators (scan ids are prefixed), but the result
    must still resolve inside ``parent``.
    """
    cleaned = Path(name).name
    if not cleaned or cleaned in {".", ".."}:
        raise ValueError(f"Invalid path component: {name!r}")
    candidate = parent / cleaned
    parent_resolved = parent.resolve()
    candidate_resolved = candidate.resolve()
    if parent_resolved != candidate_resolved and parent_resolved not in candidate_resolved.parents:
        raise ValueError(f"Path escapes the allowed directory: {name!r}")
    return candidate
