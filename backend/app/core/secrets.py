"""Encrypted credential storage for AI provider keys and integration keys.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a master
key that lives in ``data/.master_key``. The master key may also be supplied
through ``TRISHUL_MASTER_KEY`` so that deployments can keep it outside the
project tree.

Only ciphertext is ever written to disk; the plaintext key is held in memory
for the lifetime of the process.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from backend.app.core.utils import utcnow_iso


class SecretStorageError(RuntimeError):
    """Raised when a secret cannot be encrypted or decrypted."""


class CredentialStore:
    """Persists encrypted credentials in a single JSON document."""

    def __init__(self, path: Path, master_key: str | None = None) -> None:
        self.path = path
        self._fernet = Fernet(self._resolve_master_key(master_key))
        self._cache: dict[str, str] = {}
        self._load()

    # -- master key --------------------------------------------------------

    def _resolve_master_key(self, master_key: str | None) -> bytes:
        if master_key:
            candidate = master_key.strip().encode("utf-8")
            try:
                Fernet(candidate)
            except (ValueError, TypeError) as exc:
                raise SecretStorageError(
                    "TRISHUL_MASTER_KEY must be a valid Fernet key "
                    "(generate one with `python -c \"from cryptography.fernet import Fernet;"
                    " print(Fernet.generate_key().decode())\"`)."
                ) from exc
            return candidate

        key_file = self.path.parent / ".master_key"
        if key_file.exists():
            material = key_file.read_text(encoding="utf-8").strip()
            if material:
                return material.encode("utf-8")

        generated = Fernet.generate_key()
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(generated.decode("ascii"), encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return generated

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            self._cache = {}
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt store must not crash startup; the operator can
            # re-enter the key through the dashboard.
            self._cache = {}
            return
        decrypted: dict[str, str] = {}
        for name, blob in (payload.get("credentials") or {}).items():
            try:
                decrypted[name] = self._fernet.decrypt(blob.encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError, UnicodeDecodeError):
                continue
        self._cache = decrypted

    def _persist(self) -> None:
        payload = {
            "version": 1,
            "updated_at": utcnow_iso(),
            "credentials": {
                name: self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
                for name, value in self._cache.items()
            },
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- public API --------------------------------------------------------

    def get(self, name: str) -> str | None:
        return self._cache.get(name)

    def set(self, name: str, value: str | None) -> None:
        """Store ``value`` under ``name``; ``None`` removes the entry."""
        if value is None or value == "":
            self._cache.pop(name, None)
        else:
            self._cache[name] = value
        self._persist()

    def delete(self, name: str) -> bool:
        existed = name in self._cache
        self._cache.pop(name, None)
        self._persist()
        return existed

    def has(self, name: str) -> bool:
        return bool(self._cache.get(name))

    def names(self) -> list[str]:
        return sorted(self._cache)

    def dump_redacted(self) -> dict[str, Any]:
        """Return a description of the store that contains no secret values."""
        return {
            "path": str(self.path),
            "entries": [
                {"name": name, "present": True, "length": len(value)}
                for name, value in sorted(self._cache.items())
            ],
        }


def provider_secret_name(provider: str) -> str:
    """Credential-store key for an AI provider's API key."""
    return f"provider:{provider}"


def integration_secret_name(name: str) -> str:
    """Credential-store key for an integration's API key."""
    return f"integration:{name}"


def encode_key_for_display(value: str | None) -> str:
    if not value:
        return ""
    raw = value.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")[:0] or value[-4:]
