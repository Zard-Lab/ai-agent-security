from __future__ import annotations

import pytest

from agentsec.guards.nosql_injection_js import NoSqlInjectionJsGuard
from tests.guards._common import *  # noqa: F401,F403

_MONGOOSE_IMPORT = "const mongoose = require('mongoose');\n"
_MONGODB_IMPORT = "const { MongoClient } = require('mongodb');\n"


def test_flags_raw_request_body_in_find_one(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "Users.findOne({ username: req.body.username });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = NoSqlInjectionJsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "nosql-injection-js/unvalidated-filter-value"
    assert findings[0].severity == "critical"
    assert "CWE-943" in findings[0].standards


def test_flags_raw_request_query_in_update_one(tmp_path: Path) -> None:
    (tmp_path / "profile.ts").write_text(
        _MONGODB_IMPORT
        + "collection.updateOne({ id: req.query.id }, { $set: { active: true } });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = NoSqlInjectionJsGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_flags_bracket_form_request_input(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "Users.findOne({ username: req.body['username'] });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = NoSqlInjectionJsGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_on_string_cast(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "Users.findOne({ username: String(req.body.username) });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


def test_silent_on_sanitizer_call(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "Users.findOne({ username: mongoSanitize(req.body.username) });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


def test_silent_on_static_literal_filter(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "Users.findOne({ role: 'admin' });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


def test_silent_without_driver_import(tmp_path: Path) -> None:
    # Precision choice: scoping to files that import mongoose/mongodb avoids false-positiving on
    # unrelated .find()/.findOne()-named methods (a search client, a cache, an ORM query builder).
    (tmp_path / "search.js").write_text(
        "elastic.findOne({ username: req.body.username });\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "// Users.findOne({ username: req.body.username });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "// security: allow-js-nosql-injection\n"
        + _MONGOOSE_IMPORT
        + "Users.findOne({ username: req.body.username });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert not NoSqlInjectionJsGuard().applies(profile)


def test_applies_with_typescript(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert NoSqlInjectionJsGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        _MONGOOSE_IMPORT + "Users.findOne({ username: req.body.username });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


@pytest.mark.parametrize(
    "quoted",
    [
        'const docExample = "Users.findOne({ username: req.body.username })";',
        "throw new Error(`bad call Users.find({ id: req.query.id })`);",
    ],
    ids=["docs-string", "error-template"],
)
def test_silent_on_filter_spelled_out_in_a_string_literal(tmp_path: Path, quoted: str) -> None:
    # #749 (the issue's b.js): a string that spells out a vulnerable lookup is not a call. Its `(`
    # anchor is string content (or template TEXT) in the anchor mask. Both fired CRITICAL before.
    (tmp_path / "auth.js").write_text(_MONGOOSE_IMPORT + quoted + "\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    assert NoSqlInjectionJsGuard().run(tmp_path, profile) == []


def test_flags_filter_nested_in_a_template_substitution(tmp_path: Path) -> None:
    # #749, the traded direction: a real lookup inside a `${...}` substitution is CODE, and must keep
    # firing. Anchoring against plain `strip_strings=True` output would lose it silently.
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "log(`user: ${await Users.findOne({ username: req.body.username })}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = NoSqlInjectionJsGuard().run(tmp_path, profile)
    assert [f.location for f in findings] == ["auth.js:2"]


def test_filter_between_two_desyncing_substitutions_fires(tmp_path: Path) -> None:
    # #543, formerly the accepted trade #749 made (PR #1057 round-1 review): a `{` in a regex inside
    # one substitution and a `}` in a later one left the file balanced, so the lexer's restore caps
    # did not fire and a real lookup between them read as template text (pair.js). The lexer now
    # consumes a substitution's regexes and comments whole, so all three placements fire.
    # Lexer-level pin: `test_strip_js_comments_anchor_mask_rebalancing_regex_pair_reads_as_code`.
    opens = "const t = `a ${ s.replace(/{/g, '') } b`;\n"
    closes = "const u = `a ${ s.replace(/}/g, '') } b`;\n"
    lookup = "Users.findOne({ username: req.body.username });\n"
    (tmp_path / "pair.js").write_text(_MONGOOSE_IMPORT + opens + lookup + closes, encoding="utf-8")
    (tmp_path / "single.js").write_text(_MONGOOSE_IMPORT + opens + lookup, encoding="utf-8")
    (tmp_path / "after.js").write_text(_MONGOOSE_IMPORT + opens + closes + lookup, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    locations = sorted(f.location for f in NoSqlInjectionJsGuard().run(tmp_path, profile))
    assert locations == ["after.js:4", "pair.js:3", "single.js:3"]


def test_flags_where_template_holding_request_input(tmp_path: Path) -> None:
    # #749: only the call's anchor is tested against the mask. The filter argument is still read
    # from the strings-intact line, so request input interpolated into a `$where` template, which
    # sits inside template text, is still seen.
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT + "Users.find({ $where: `this.name === '${req.body.name}'` });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(NoSqlInjectionJsGuard().run(tmp_path, profile)) == 1


def test_quoted_filter_does_not_hide_a_real_one_on_the_same_line(tmp_path: Path) -> None:
    # #749: the filter drops one ANCHOR, not the line.
    (tmp_path / "auth.js").write_text(
        _MONGOOSE_IMPORT
        + 'log("Users.findOne({ u: req.body.u })"); Users.findOne({ username: req.body.username });\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert [f.location for f in NoSqlInjectionJsGuard().run(tmp_path, profile)] == ["auth.js:2"]
