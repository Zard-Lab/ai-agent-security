from __future__ import annotations

from agentsec.guards.xpath_injection import XpathInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_template_literal_interpolation(tmp_path: Path) -> None:
    (tmp_path / "query.js").write_text(
        "const xpath = require('xpath');\n"
        "function f(doc, userTag) {\n"
        "  return xpath.select(`//item[@id=\"${userTag}\"]`, doc);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = XpathInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "xpath-injection/untrusted-expression"
    assert findings[0].severity == "medium"

def test_flags_concatenation(tmp_path: Path) -> None:
    (tmp_path / "query.js").write_text(
        "const xpath = require('xpath');\n"
        "function f(doc, userTag) {\n"
        "  return xpath.select1('//item[@id=\"' + userTag + '\"]', doc);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert len(XpathInjectionGuard().run(tmp_path, profile)) == 1

def test_flags_dom_evaluate_from_location(tmp_path: Path) -> None:
    (tmp_path / "query.js").write_text(
        "function f(doc) {\n"
        "  return document.evaluate(`//item[@id=\"${location.hash}\"]`, doc, null);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = XpathInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_silent_on_static_expression(tmp_path: Path) -> None:
    (tmp_path / "query.js").write_text(
        "const xpath = require('xpath');\n"
        "function f(doc) {\n"
        "  return xpath.select('//item[@id=\"fixed\"]', doc);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert XpathInjectionGuard().run(tmp_path, profile) == []

def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "query.js").write_text(
        "// security: allow-xpath-injection\n"
        "const xpath = require('xpath');\n"
        "function f(doc, userTag) {\n"
        "  return xpath.select(`//item[@id=\"${userTag}\"]`, doc);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert XpathInjectionGuard().run(tmp_path, profile) == []

def test_flags_multiline_call(tmp_path: Path) -> None:
    # #395 H4: a call whose interpolated expression is wrapped across lines must still fire.
    (tmp_path / "query.js").write_text(
        "const xpath = require('xpath');\n"
        "function f(doc, userTag) {\n"
        "  return xpath.select(\n"
        "    `//item[@id=\"${userTag}\"]`,\n"
        "    doc,\n"
        "  );\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert len(XpathInjectionGuard().run(tmp_path, profile)) == 1

def test_prose_mention_does_not_suppress(tmp_path: Path) -> None:
    # #395 M9: a file that merely QUOTES the pragma phrase in prose (no `//` comment) must not
    # go blind — the pragma is anchored to an actual line comment.
    (tmp_path / "query.js").write_text(
        "const help = 'to ignore, add security: allow-xpath-injection to the line';\n"
        "const xpath = require('xpath');\n"
        "function f(doc, userTag) {\n"
        "  return xpath.select(`//item[@id=\"${userTag}\"]`, doc);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert len(XpathInjectionGuard().run(tmp_path, profile)) == 1

def test_not_applicable_without_frontend() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert XpathInjectionGuard().applies(prof) is False


def test_prose_mention_with_the_comment_marker_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the sibling above quotes the phrase WITHOUT the `//`, the weaker shape; the documented
    # `// security: …` form inside a string literal must not suppress either (comment-only view).
    (tmp_path / "query.js").write_text(
        "const help = 'to ignore, add // security: allow-xpath-injection to the line';\n"
        "const xpath = require('xpath');\n"
        "function f(doc, userTag) {\n"
        "  return xpath.select(`//item[@id=\"${userTag}\"]`, doc);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert len(XpathInjectionGuard().run(tmp_path, profile)) == 1
