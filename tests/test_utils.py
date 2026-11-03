"""Tests for the shared helper functions."""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.core.utils import (
    is_ip,
    normalize_target,
    redact,
    safe_child_path,
    slugify,
    stable_id,
    unique_id,
)


def test_slugify_strips_unsafe_characters():
    assert slugify("https://example.com/path?x=1") == "https-example-com-path-x-1"


def test_stable_id_is_deterministic():
    assert stable_id("finding", "abc") == stable_id("finding", "abc")
    assert stable_id("finding", "abc") != stable_id("finding", "abd")


def test_unique_id_varies_between_calls():
    assert unique_id("scan", "target") != unique_id("scan", "target")


@pytest.mark.parametrize(
    "target,expected_host",
    [
        ("example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com:8443/app", "example.com"),
    ],
)
def test_normalize_target_extracts_host(target, expected_host):
    profile = normalize_target(target)
    assert profile["host"] == expected_host
    assert profile["url"].startswith(("http://", "https://"))


def test_normalize_target_rejects_empty():
    with pytest.raises(ValueError):
        normalize_target("   ")


def test_normalize_target_rejects_unsupported_scheme():
    with pytest.raises(ValueError):
        normalize_target("ftp://example.com")


def test_is_ip():
    assert is_ip("127.0.0.1")
    assert is_ip("::1")
    assert not is_ip("example.com")


class TestRedaction:
    def test_redacts_openai_key(self):
        assert "sk-abcdefghijklmnop" not in redact("token sk-abcdefghijklmnop end")

    def test_redacts_anthropic_key(self):
        assert "sk-ant-abcdefghijklmnop" not in redact("sk-ant-abcdefghijklmnop")

    def test_redacts_google_key(self):
        assert "AIzaSyABCDEFGHIJKLMNOP" not in redact("AIzaSyABCDEFGHIJKLMNOP")

    def test_redacts_bearer_header(self):
        redacted = redact("Authorization: Bearer abcdefghijklmnopqrst")
        assert "abcdefghijklmnopqrst" not in redacted

    def test_redacts_password_assignment(self):
        redacted = redact("password: supersecretvalue")
        assert "supersecretvalue" not in redacted

    def test_redacts_basic_auth_url(self):
        redacted = redact("https://user:hunter2222@example.com/path")
        assert "hunter2222" not in redacted

    def test_redacts_nested_structures(self):
        payload = {"a": ["sk-abcdefghijklmnop"], "b": {"c": "password: topsecret"}}
        text = str(redact(payload))
        assert "sk-abcdefghijklmnop" not in text
        assert "topsecret" not in text

    def test_leaves_ordinary_text_untouched(self):
        assert redact("nothing sensitive here") == "nothing sensitive here"


def test_safe_child_path_blocks_traversal(tmp_path: Path):
    result = safe_child_path(tmp_path, "scan-1")
    assert result.parent == tmp_path.resolve() or result.parent == tmp_path

    with pytest.raises(ValueError):
        safe_child_path(tmp_path, "..")
