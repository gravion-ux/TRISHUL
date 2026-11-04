"""Tests for the encoding-safe console helpers.

TRISHUL must survive terminals that still use a legacy Windows code page.
These tests pin the behaviour that guarantees that: output is degraded to
``?`` instead of raising :class:`UnicodeEncodeError`.
"""

from __future__ import annotations

import io
import sys

import pytest

from backend.app.core import console


class _Cp437Stream(io.TextIOWrapper):
    """A text stream that encodes with cp437 and rejects anything else."""

    def __init__(self) -> None:
        super().__init__(io.BytesIO(), encoding="cp437", errors="strict")

    def writable(self) -> bool:
        return True


class _HostileStream:
    """A stream that always raises :class:`UnicodeEncodeError` on write."""

    encoding = "utf-8"

    def write(self, text: str) -> int:
        raise UnicodeEncodeError("utf-8", text, 0, 1, "boom")

    def flush(self) -> None:
        return None


def test_stream_encoding_falls_back_to_ascii():
    class _NoEncoding:
        encoding = None

    assert console.stream_encoding(_NoEncoding()) == "ascii"
    assert console.stream_encoding(sys.stdout) == sys.stdout.encoding.lower()


def test_supports_rich_text_is_false_for_a_legacy_codepage():
    assert console.supports_rich_text(_Cp437Stream()) is False


def test_supports_rich_text_is_true_for_utf8():
    assert console.supports_rich_text(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")) is True


def test_make_safe_reports_whether_the_stream_was_reconfigured():
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
    assert console.make_safe(stream) is True
    assert stream.errors == "replace"


def test_make_safe_ignores_streams_without_reconfigure():
    class _Plain:
        encoding = "utf-8"

    assert console.make_safe(_Plain()) is False


def test_make_safe_ignores_a_missing_stream(monkeypatch):
    monkeypatch.setattr(sys, "stdout", None)
    assert console.make_safe() is False


def test_to_ascii_replaces_every_non_ascii_character():
    assert console.to_ascii("caf\u00e9 \u2588 \u2014") == "caf? ? ?"


def test_safe_write_writes_plain_text():
    stream = io.StringIO()
    console.safe_write("hello", stream)
    assert stream.getvalue() == "hello\n"


def test_safe_write_degrades_instead_of_raising():
    stream = _Cp437Stream()
    console.safe_write("dash \u2014 block \u2588", stream)
    stream.flush()
    decoded = stream.buffer.getvalue().decode("cp437")
    # cp437 has no EM DASH, so it is degraded to '?'.
    assert "dash ?" in decoded
    # cp437 does have FULL BLOCK, so that one survives unchanged.
    assert "block \u2588" in decoded


def test_safe_write_survives_a_hostile_stream():
    # The fallback path must not raise even when the stream rejects the
    # already-encoded fallback as well.
    stream = _HostileStream()
    console.safe_write("caf\u00e9", stream)


def test_protect_streams_never_raises(monkeypatch):
    class _Plain:
        encoding = "utf-8"

    monkeypatch.setattr(sys, "stdout", _Plain())
    monkeypatch.setattr(sys, "stderr", _Plain())
    console.protect_streams()


@pytest.mark.parametrize("payload", ["\u2713", "\u2717", "\u26a0", "\u2014", "\u2026"])
def test_rich_glyphs_are_rejected_by_a_legacy_codepage(payload):
    with pytest.raises(UnicodeEncodeError):
        payload.encode("cp437")
