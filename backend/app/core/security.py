"""Authentication, token handling and request rate limiting."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from backend.app.core.utils import utcnow

PBKDF2_ROUNDS = 240_000


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256.

    Returns ``pbkdf2_sha256$<rounds>$<salt_b64>$<hash_b64>``.
    """
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ROUNDS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verification of a password against a stored hash."""
    try:
        algorithm, rounds_text, salt_b64, digest_b64 = encoded.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        rounds = int(rounds_text)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(actual, expected)


# ---------------------------------------------------------------------------
# Bearer tokens
# ---------------------------------------------------------------------------


class TokenManager:
    """Issues and validates signed, expiring bearer tokens.

    The signing secret is generated on first use and stored next to the
    database with owner-only permissions, so no token can be forged without
    access to the host filesystem.
    """

    def __init__(self, secret_path: Path, ttl_seconds: int = 86_400) -> None:
        self.secret_path = secret_path
        self.ttl_seconds = ttl_seconds
        self._secret = self._load_or_create_secret()

    def _load_or_create_secret(self) -> bytes:
        if self.secret_path.exists():
            material = self.secret_path.read_bytes().strip()
            if material:
                return base64.urlsafe_b64decode(material)
        secret = os.urandom(48)
        self.secret_path.parent.mkdir(parents=True, exist_ok=True)
        self.secret_path.write_bytes(base64.urlsafe_b64encode(secret))
        try:
            os.chmod(self.secret_path, 0o600)
        except OSError:
            # Windows does not implement POSIX permission bits; the file is
            # still protected by the user's profile ACL.
            pass
        return secret

    def _sign(self, payload: bytes) -> str:
        digest = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def issue(self, subject: str) -> tuple[str, int]:
        """Create a token for ``subject`` and return ``(token, expires_in)``."""
        now = int(time.time())
        expires = now + self.ttl_seconds
        body = {"sub": subject, "iat": now, "exp": expires, "jti": secrets.token_hex(8)}
        payload = base64.urlsafe_b64encode(json.dumps(body).encode("utf-8")).decode("ascii").rstrip("=")
        token = f"{payload}.{self._sign(payload.encode('ascii'))}"
        return token, self.ttl_seconds

    def verify(self, token: str) -> dict[str, Any] | None:
        """Return the token payload, or ``None`` when the token is invalid."""
        if not token or "." not in token:
            return None
        payload, _, signature = token.rpartition(".")
        expected = self._sign(payload.encode("ascii"))
        if not hmac.compare_digest(expected, signature):
            return None
        try:
            padding = "=" * (-len(payload) % 4)
            body = json.loads(base64.urlsafe_b64decode(payload + padding).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return None
        if int(body.get("exp", 0)) < int(time.time()):
            return None
        return body


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class RateLimiter:
    """Fixed-window rate limiter keyed by client identity.

    Used to keep a single operator (or a runaway script) from saturating the
    control plane or the upstream target.
    """

    def __init__(self, limit: int = 120, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = __import__("threading").Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        window_start = now - self.window_seconds
        hits = [stamp for stamp in self._hits.get(key, []) if stamp > window_start]
        self._hits[key] = hits
        return hits

    def allow(self, key: str) -> tuple[bool, int, int]:
        """Return ``(allowed, remaining, retry_after_seconds)``."""
        now = time.time()
        with self._lock:
            hits = self._prune(key, now)
            if len(hits) >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - hits[0])) + 1)
                return False, 0, retry_after
            hits.append(now)
            self._hits[key] = hits
            return True, max(0, self.limit - len(hits)), 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


# ---------------------------------------------------------------------------
# Admin credentials
# ---------------------------------------------------------------------------


def ensure_admin_credentials(
    username: str, password: str | None, data_dir: Path
) -> tuple[str, str, bool]:
    """Resolve the admin credentials, generating them on first run.

    Returns ``(username, password, generated)``. A generated password is
    written to ``data/admin-credentials.txt`` with owner-only permissions so
    the operator can log into the dashboard without hunting through logs.
    """
    credential_file = data_dir / "admin-credentials.txt"
    if password:
        return username, password, False

    if credential_file.exists():
        content = credential_file.read_text(encoding="utf-8").splitlines()
        stored_user = username
        stored_password = ""
        for line in content:
            if line.lower().startswith("username:"):
                stored_user = line.split(":", 1)[1].strip()
            elif line.lower().startswith("password:"):
                stored_password = line.split(":", 1)[1].strip()
        if stored_password:
            return stored_user, stored_password, False

    generated = secrets.token_urlsafe(18)
    credential_file.parent.mkdir(parents=True, exist_ok=True)
    credential_file.write_text(
        "TRISHUL administrator credentials\n"
        f"username: {username}\n"
        f"password: {generated}\n",
        encoding="utf-8",
    )
    try:
        os.chmod(credential_file, 0o600)
    except OSError:
        pass
    return username, generated, True


def api_key_hint(value: str | None) -> str:
    """Return a non-reversible hint for an API key such as ``sk-...abcd``.

    The hint is pure ASCII so it can be printed to a legacy console, piped
    into a log file or embedded in a JSON response without any re-encoding.
    """
    if not value:
        return ""
    if len(value) <= 10:
        return "*" * len(value)
    return f"{value[:5]}...{value[-4:]}"


def utcnow_epoch() -> int:
    return int(utcnow().timestamp())
