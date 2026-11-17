from __future__ import annotations

from agentsec.guards.js_buffer_noassert import JsBufferNoassertGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_buffer_noassert_flags_read_call(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "function parseHeader(buf, offset) {\n"
        "  return buf.readUInt32LE(offset, true);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsBufferNoassertGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-buffer-noassert/noassert-true"
    assert findings[0].severity == "medium"


def test_js_buffer_noassert_flags_write_call(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "function writeByte(buf, offset, value) {\n"
        "  buf.writeInt8(value, offset, true);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsBufferNoassertGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_js_buffer_noassert_silent_without_noassert_arg(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "function parseHeader(buf, offset) {\n"
        "  return buf.readUInt32LE(offset);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsBufferNoassertGuard().run(tmp_path, profile) == []


def test_js_buffer_noassert_silent_when_noassert_false(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "buf.readUInt32LE(offset, false);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsBufferNoassertGuard().run(tmp_path, profile) == []


def test_js_buffer_noassert_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "buf.readUInt32LE(offset, true);  // security: allow-js-buffer-noassert\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsBufferNoassertGuard().run(tmp_path, profile) == []


def test_js_buffer_noassert_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    # A doc/instructional comment describing the anti-pattern must NOT fire (FP-bait) — only
    # real code should. The actual call here passes `false`, i.e. is safe.
    (tmp_path / "parse.js").write_text(
        "// Avoid: buf.readUInt32LE(offset, true) is unsafe, see docs\n"
        "function parseHeader(buf, offset) {\n"
        "  return buf.readUInt32LE(offset, false);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsBufferNoassertGuard().run(tmp_path, profile) == []


def test_js_buffer_noassert_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "buf.readUInt32LE(offset, true);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features=set())
    assert not JsBufferNoassertGuard().applies(profile)


def test_js_buffer_noassert_silent_on_jsdoc_block_comment(tmp_path: Path) -> None:
    # Regression (PR #407 review #5): a JSDoc / block comment mentioning the vulnerable call must
    # not fire when the real call is safe (the earlier fix only skipped `^\s*//` line comments).
    (tmp_path / "app.js").write_text(
        "/**\n"
        " * Legacy: buf.readUInt32LE(offset, true) was used before the fix.\n"
        " */\n"
        "return buf.readUInt32LE(offset, false);\n",
        encoding="utf-8",
    )
    assert JsBufferNoassertGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []
