from __future__ import annotations

from agentsec.findings import Finding
from agentsec.guards.js_xxe_unsafe_parsing import JsXxeUnsafeParsingGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_xxe_flags_libxmljs_noent_true(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "const libxml = require('libxmljs');\n"
        "let doc = libxml.parseXml(xmlSrc, { noent: true });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsXxeUnsafeParsingGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-xxe-unsafe-parsing/libxmljs-noent-true"
    assert findings[0].severity == "critical"
    assert findings[0].location == "parse.js:2"


def test_js_xxe_silent_no_options_object(tmp_path: Path) -> None:
    # No options argument at all -> libxmljs's safe default (noent off) applies.
    (tmp_path / "parse.js").write_text(
        "const libxml = require('libxmljs');\n"
        "let doc = libxml.parseXml(xmlSrc);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsXxeUnsafeParsingGuard().run(tmp_path, profile) == []


def test_js_xxe_silent_noent_false(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "const libxml = require('libxmljs');\n"
        "let doc = libxml.parseXml(xmlSrc, { noent: false });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsXxeUnsafeParsingGuard().run(tmp_path, profile) == []


def test_js_xxe_silent_on_commented_pattern(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "// let doc = libxml.parseXml(xmlSrc, { noent: true });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsXxeUnsafeParsingGuard().run(tmp_path, profile) == []


def test_js_xxe_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "const libxml = require('libxmljs');\n"
        "let doc = libxml.parseXml(xmlSrc, { noent: true }); // security: allow-js-xxe\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsXxeUnsafeParsingGuard().run(tmp_path, profile) == []


def test_js_xxe_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "parse.js").write_text(
        "libxml.parseXml(xmlSrc, { noent: true });\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features=set())
    assert not JsXxeUnsafeParsingGuard().applies(profile)


def test_js_xxe_applies_for_typescript(tmp_path: Path) -> None:
    (tmp_path / "parse.ts").write_text(
        "libxml.parseXml(xmlSrc, { noent: true });\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsXxeUnsafeParsingGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_js_xxe_flags_multiline_options_object(tmp_path: Path) -> None:
    # Adversarial self-test #1: Prettier-formatted multi-line options object, `noent: true` on
    # its own line inside a multi-line `{...}` — must still fire (whole-call-span scan, not a
    # same-line regex).
    (tmp_path / "parse.js").write_text(
        "const libxml = require('libxmljs');\n"
        "let doc = libxml.parseXml(\n"
        "  xmlSrc,\n"
        "  {\n"
        "    noent: true,\n"
        "  }\n"
        ");\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsXxeUnsafeParsingGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-xxe-unsafe-parsing/libxmljs-noent-true"


def test_js_xxe_silent_unrelated_noent_variable(tmp_path: Path) -> None:
    # Adversarial self-test #2: a variable literally named `noent`, unrelated to XML parsing and
    # never passed into a parseXml(...) call, must not fire on its own.
    (tmp_path / "unrelated.js").write_text(
        "const noent = true;\n"
        "if (noent) {\n"
        "  console.log('unrelated flag');\n"
        "}\n"
        "libxml.parseXml(xmlSrc);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsXxeUnsafeParsingGuard().run(tmp_path, profile) == []


# --- #1055 batch 1b: only live code counts, and the bracket walks skip string content ---------


def _xxe_run(tmp_path: Path, body: str) -> list[Finding]:
    (tmp_path / "parse.js").write_text("const libxml = require('libxmljs');\n" + body, encoding="utf-8")
    return JsXxeUnsafeParsingGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))


def test_js_xxe_paren_in_the_source_string_does_not_end_the_call(tmp_path: Path) -> None:
    # #1055 sub-class 2: the walk counted the `)` inside `')'` as the call's close, so the options
    # object was never reached and a CRITICAL went silent. Walked on the anchor mask it fires.
    findings = _xxe_run(tmp_path, "let doc = libxml.parseXml(src.replace(')', ''), { noent: true });\n")
    assert [f.location for f in findings] == ["parse.js:2"]


def test_js_xxe_comma_and_paren_in_the_source_string_do_not_split_the_args(tmp_path: Path) -> None:
    # A `,(` inside the first argument's string made the first-top-level-comma walk stop early.
    findings = _xxe_run(tmp_path, "let doc = libxml.parseXml(wrap(',(', src), { noent: true });\n")
    assert len(findings) == 1


def test_js_xxe_paren_in_a_template_source_does_not_end_the_call(tmp_path: Path) -> None:
    findings = _xxe_run(tmp_path, "let doc = libxml.parseXml(`<a>)</a>${src}`, { noent: true });\n")
    assert len(findings) == 1


def test_js_xxe_call_inside_a_substitution_still_fires(tmp_path: Path) -> None:
    # The shortcut-separating test: plain strip_strings=True would blank this live call.
    findings = _xxe_run(tmp_path, "const out = `${libxml.parseXml(src, { noent: true })}`;\n")
    assert [f.location for f in findings] == ["parse.js:2"]


def test_js_xxe_call_spelled_in_a_string_is_silent(tmp_path: Path) -> None:
    body = (
        "console.warn('never call libxml.parseXml(src, { noent: true }) on uploads');\n"
        "const help = `example: libxml.parseXml(src, { noent: true })`;\n"
    )
    assert _xxe_run(tmp_path, body) == []


def test_js_xxe_real_call_after_a_quoted_copy_on_the_line_still_fires(tmp_path: Path) -> None:
    findings = _xxe_run(tmp_path, "log('parseXml(x)'); let doc = libxml.parseXml(src, { noent: true });\n")
    assert len(findings) == 1


def test_js_xxe_noent_spelled_in_an_option_value_is_silent(tmp_path: Path) -> None:
    # A real call whose options carry the phrase only as a string VALUE: not the option.
    assert _xxe_run(tmp_path, "let doc = libxml.parseXml(src, { note: 'noent: true is unsafe' });\n") == []


def test_js_xxe_real_noent_after_a_quoted_copy_in_the_options_still_fires(tmp_path: Path) -> None:
    findings = _xxe_run(tmp_path, "let doc = libxml.parseXml(src, { note: 'noent: true', noent: true });\n")
    assert len(findings) == 1


def test_js_xxe_walk_stops_at_the_real_close_fp_bait(tmp_path: Path) -> None:
    # FP-bait for the widened walk: past the quoted `)` it must still end at the call's own close,
    # so a neighbouring call's `noent: true` is not read as this call's option.
    body = (
        "let doc = libxml.parseXml(src.replace(')', ''), { noent: false });\n"
        "other(x, { noent: true });\n"
    )
    assert _xxe_run(tmp_path, body) == []


def test_js_xxe_pragma_still_suppresses_after_the_mask_walk(tmp_path: Path) -> None:
    # Rule 4: the pragma reaches a finding that only the mask walk can see.
    body = "let doc = libxml.parseXml(src.replace(')', ''), { noent: true }); // security: allow-js-xxe\n"
    assert _xxe_run(tmp_path, body) == []


def test_js_xxe_regex_literal_paren_is_a_known_limit(tmp_path: Path) -> None:
    # Pinned residual (#1055): the anchor mask keeps regex-literal bodies as code, so the `)` in
    # `/\)/g` still ends the call walk early. Silent before and after; flip this when fixed.
    assert _xxe_run(tmp_path, "let doc = libxml.parseXml(src.replace(/\\)/g, ''), { noent: true });\n") == []
