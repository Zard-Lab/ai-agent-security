"""Console I/O setup shared by the CLI and the `scripts/` entry points.

agentsec prints non-ASCII (`✓`, `→`, `§`, em-dashes, the 🔴 severity emoji). On Windows the
console — and a redirected stdout — defaults to cp1252, which cannot encode any of it, so the
process dies with a `UnicodeEncodeError` on output it produced correctly. Forcing UTF-8 on the
streams is the stdout/stderr analogue of the repo-wide "always pass an explicit encoding" rule
for file I/O.

This lives in its own module rather than in `cli.py` so the `scripts/` entry points can adopt it
without importing the whole CLI: they are separate processes with the same problem, and fixing
the character in one script (#453) treated the symptom while five other scripts kept it.
"""
from __future__ import annotations

import contextlib
import sys
from typing import TextIO


def force_utf8_stdio() -> None:
    """Reconfigure stdout/stderr to UTF-8. Never raises — a detached or closed stream is a no-op.

    Idempotent, so an entry point that calls it and then invokes another that also calls it is
    fine. On a stream with no `reconfigure` (a non-TextIOWrapper substitute, e.g. a test double)
    it does nothing rather than failing."""
    streams: tuple[TextIO, TextIO] = (sys.stdout, sys.stderr)
    for stream in streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):  # stream detached/closed
            reconfigure(encoding="utf-8")
