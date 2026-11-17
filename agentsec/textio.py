"""Newline-preserving UTF-8 text I/O for target-repo file edits.

Editing helpers (fix.py, js_harden.py, deps_apply.py) must not silently rewrite a
file's line endings: read + write with newline="" so an existing CRLF stays CRLF
(a bare read_text/write_text universal-newlines round-trip flattens CRLF -> LF,
breaking the "diff shown = diff applied" promise). See CLAUDE.md (cross-platform I/O).
"""
from __future__ import annotations

from pathlib import Path


def read_text_preserve(path: Path) -> str:
    """Read UTF-8 text without newline translation (an existing CRLF stays CRLF)."""
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write_text_preserve(path: Path, text: str) -> None:
    """Write UTF-8 text without newline translation (don't re-translate CRLF)."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
