"""Tests for the encrypted credential store."""

from __future__ import annotations

import json

from backend.app.core.secrets import (
    CredentialStore,
    integration_secret_name,
    provider_secret_name,
)


def test_secret_roundtrip(tmp_path):
    store = CredentialStore(tmp_path / "credentials.enc")
    store.set("provider:openai", "sk-supersecretvalue")
    assert store.get("provider:openai") == "sk-supersecretvalue"
    assert store.has("provider:openai")


def test_secret_is_encrypted_at_rest(tmp_path):
    path = tmp_path / "credentials.enc"
    store = CredentialStore(path)
    store.set("provider:openai", "sk-supersecretvalue")

    raw = path.read_text(encoding="utf-8")
    assert "sk-supersecretvalue" not in raw
    payload = json.loads(raw)
    assert payload["credentials"]["provider:openai"] != "sk-supersecretvalue"


def test_secret_survives_reload(tmp_path):
    path = tmp_path / "credentials.enc"
    CredentialStore(path).set("provider:openai", "sk-value123456")
    reloaded = CredentialStore(path)
    assert reloaded.get("provider:openai") == "sk-value123456"


def test_set_none_removes_secret(tmp_path):
    store = CredentialStore(tmp_path / "credentials.enc")
    store.set("provider:openai", "sk-value")
    store.set("provider:openai", None)
    assert store.get("provider:openai") is None


def test_delete_secret(tmp_path):
    store = CredentialStore(tmp_path / "credentials.enc")
    store.set("provider:openai", "sk-value")
    assert store.delete("provider:openai") is True
    assert store.delete("provider:openai") is False


def test_corrupt_store_does_not_crash(tmp_path):
    path = tmp_path / "credentials.enc"
    path.write_text("this is not json", encoding="utf-8")
    store = CredentialStore(path)
    assert store.get("provider:openai") is None


def test_dump_redacted_has_no_values(tmp_path):
    store = CredentialStore(tmp_path / "credentials.enc")
    store.set("provider:openai", "sk-value")
    dump = store.dump_redacted()
    assert "sk-value" not in json.dumps(dump)
    assert dump["entries"][0]["name"] == "provider:openai"


def test_secret_names_are_namespaced():
    assert provider_secret_name("openai") == "provider:openai"
    assert integration_secret_name("shodan") == "integration:shodan"
