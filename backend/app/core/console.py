"""Encoding-safe console output.

TRISHUL has to run on terminals that still speak a legacy code page
(``cp437``, ``cp1252``).  Writing a character such as ``█`` or ``—`` to
such a stream raises :class:`UnicodeEncodeError` and kills the CLI in the
middle of a scan — and the text that most often contains exotic characters
is *model output*, which TRISHUL cannot control.

Two layers of protection are used:

``protect_streams()``
    Reconfigures stdout and stderr so unencodable characters degrade to
    ``?`` instead of raising.  This covers every ``print()`` in the process,
    including text produced at runtime by an AI provider.

``safe_write()``
    Writes to an arbitrary stream without ever raising an encoding error.
    Used for the banner, which is rendered for the *destination* stream and
    therefore has to be encoded explicitly.

The banner itself is stored as pure ASCII (see :mod:`cli.trishul`), so the
decorative artwork never depends on the host code page.
"""

from __future__ import annotations

import sys
from typing import Any

#: Glyphs used by decorative artwork.  They are used as the probe set when
#: deciding whether a stream can render rich text.
RICH_GLYPHS = "\u2588\u2593\u2713\u2717\u2014\u2026\u26a0"

#: Character substituted for anything the destination encoding rejects.
REPLACEMENT = "?"

__all__ = [
    "RICH_GLYPHS",
    "REPLACEMENT",
    "make_safe",
    "protect_streams",
    "safe_write",
    "stream_encoding",
    "supports_rich_text",
    "to_ascii",
]


def stream_encoding(stream: Any) -> str:
    """Return the encoding of ``stream``, falling back to ``ascii``.

    ``ascii`` is the conservative fallback: it is the one encoding that is
    guaranteed to exist on every platform.
    """
    encoding = getattr(stream, "encoding", None)
    if not isinstance(encoding, str) or not encoding.strip():
        return "ascii"
    return encoding.lower()


def supports_rich_text(stream: Any = None) -> bool:
    """Return ``True`` when ``stream`` can encode every glyph in :data:`RICH_GLYPHS`."""
    target = sys.stdout if stream is None else stream
    encoding = stream_encoding(target)
    try:
        RICH_GLYPHS.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def make_safe(stream: Any = None) -> bool:
    """Make ``stream`` tolerate characters its encoding cannot represent.

    Returns ``True`` when the stream was reconfigured.  Streams that do not
    support :meth:`io.TextIOBase.reconfigure` (captured output, pipes, custom
    wrappers) are left untouched — :func:`safe_write` covers those.
    """
    target = sys.stdout if stream is None else stream
    if target is None:
        return False
    reconfigure = getattr(target, "reconfigure", None)
    if reconfigure is None:
        return False
    try:
        reconfigure(errors="replace")
    except (ValueError, OSError, TypeError):
        return False
    return True


def protect_streams() -> None:
    """Apply :func:`make_safe` to stdout and stderr."""
    make_safe(sys.stdout)
    make_safe(sys.stderr)


def to_ascii(text: str) -> str:
    """Return ``text`` with every non-ASCII character replaced by ``?``."""
    return text.encode("ascii", errors="replace").decode("ascii")


def safe_write(text: str, stream: Any = None, end: str = "\n") -> None:
    """Write ``text`` to ``stream`` without ever raising an encoding error."""
    target = sys.stdout if stream is None else stream
    if target is None:
        return
    try:
        target.write(text + end)
    except UnicodeEncodeError:
        encoding = stream_encoding(target)
        try:
            fallback = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        except (LookupError, UnicodeEncodeError, ValueError):
            fallback = to_ascii(text)
        try:
            target.write(fallback + end)
        except (UnicodeEncodeError, LookupError, OSError, ValueError):
            # The stream itself is unusable; there is nowhere left to write.
            return
    try:
        target.flush()
    except (UnicodeEncodeError, OSError, ValueError):
        pass
