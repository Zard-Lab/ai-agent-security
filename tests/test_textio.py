"""Tests for the newline-preserving text I/O helpers (H6 CRLF-flatten fix)."""
from __future__ import annotations

from pathlib import Path

from agentsec.textio import read_text_preserve, write_text_preserve


def test_read_preserves_crlf(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    p.write_bytes(b"a\r\nb\r\n")
    assert read_text_preserve(p) == "a\r\nb\r\n"  # CRLF not flattened to \n


def test_write_preserves_crlf(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    write_text_preserve(p, "x\r\ny\r\n")
    assert p.read_bytes() == b"x\r\ny\r\n"  # CRLF written verbatim, not re-translated


def test_roundtrip_mixed_and_lf(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    original = b"lf\ncrlf\r\nlast"  # mixed endings, no trailing newline
    p.write_bytes(original)
    text = read_text_preserve(p)
    write_text_preserve(p, text)
    assert p.read_bytes() == original  # byte-exact round-trip
