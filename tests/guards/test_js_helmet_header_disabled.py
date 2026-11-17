from __future__ import annotations

from agentsec.guards.js_helmet_header_disabled import JsHelmetHeaderDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_helmet_header_disabled_flags_disabled_flags(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const helmet = require('helmet');\n"
        "const app = require('express')();\n"
        "app.use(helmet({\n"
        "  contentSecurityPolicy: false,\n"
        "  hsts: false,\n"
        "  xssFilter: false\n"
        "}));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsHelmetHeaderDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 3
    assert all(f.rule == "js-helmet-header-disabled/helmet-feature-disabled" for f in findings)
    assert all(f.severity == "medium" for f in findings)


def test_js_helmet_header_disabled_silent_with_bare_helmet(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const helmet = require('helmet');\n"
        "const app = require('express')();\n"
        "app.use(helmet());\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsHelmetHeaderDisabledGuard().run(tmp_path, profile) == []


def test_js_helmet_header_disabled_silent_when_configured_not_disabled(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const helmet = require('helmet');\n"
        "app.use(helmet({\n"
        "  contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } },\n"
        "  hsts: { maxAge: 31536000 }\n"
        "}));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsHelmetHeaderDisabledGuard().run(tmp_path, profile) == []


def test_js_helmet_header_disabled_silent_without_helmet_context(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const config = { hsts: false, someOtherThing: true };\n"
        "module.exports = config;\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsHelmetHeaderDisabledGuard().run(tmp_path, profile) == []


def test_js_helmet_header_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.use(helmet({ hsts: false }));  // security: allow-js-helmet-header-disabled\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsHelmetHeaderDisabledGuard().run(tmp_path, profile) == []


def test_js_helmet_header_disabled_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.use(helmet({ hsts: false }));\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features=set())
    assert not JsHelmetHeaderDisabledGuard().applies(profile)


def test_js_helmet_header_disabled_per_line_pragma_only_suppresses_its_line(tmp_path: Path) -> None:
    # #423: a per-line pragma must suppress ONLY its own flag — the un-pragma'd sibling on
    # the next line still fires (the file-level skip used to silence the whole file).
    (tmp_path / "app.js").write_text(
        "app.use(helmet({\n"
        "  contentSecurityPolicy: false,  // security: allow-js-helmet-header-disabled\n"
        "  hsts: false\n"
        "}));\n",
        encoding="utf-8",
    )
    findings = JsHelmetHeaderDisabledGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":3")  # the un-pragma'd hsts line, not the CSP line


def test_js_helmet_header_disabled_silent_on_commented_flag(tmp_path: Path) -> None:
    # Regression (PR #407 review, disclosed comment-blindness): a commented `hsts: false` inside a
    # real helmet() call must not fire.
    (tmp_path / "app.js").write_text(
        "app.use(helmet({\n"
        "  // hsts: false was here\n"
        "}));\n",
        encoding="utf-8",
    )
    assert JsHelmetHeaderDisabledGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []
