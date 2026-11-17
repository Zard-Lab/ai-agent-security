from __future__ import annotations

import pytest

from agentsec.guards.js_sql_injection import JsSqlInjectionGuard
from tests.guards._common import *  # noqa: F401,F403

_PG_IMPORT = "const { Pool } = require('pg');\nconst db = new Pool();\n"
_MYSQL2_IMPORT = "const mysql = require('mysql2');\nconst db = mysql.createConnection({});\n"


def test_flags_template_literal_interpolation(tmp_path: Path) -> None:
    (tmp_path / "users.js").write_text(
        _PG_IMPORT + "db.query(`SELECT * FROM users WHERE id = ${userId}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsSqlInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-sql-injection/interpolated-query-string"
    assert findings[0].severity == "high"
    assert "CWE-89" in findings[0].standards


def test_flags_string_concatenation(tmp_path: Path) -> None:
    (tmp_path / "users.js").write_text(
        _PG_IMPORT
        + "pool.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsSqlInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-sql-injection/interpolated-query-string"


def test_flags_mysql2_import(tmp_path: Path) -> None:
    (tmp_path / "users.ts").write_text(
        _MYSQL2_IMPORT + "db.execute(`SELECT * FROM users WHERE id = ${userId}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsSqlInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_flags_sql_key_in_options_object(tmp_path: Path) -> None:
    (tmp_path / "users.js").write_text(
        _PG_IMPORT
        + "db.query({ sql: `SELECT * FROM users WHERE id = ${userId}`, values: [] });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsSqlInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_on_parameterized_query(tmp_path: Path) -> None:
    (tmp_path / "users.js").write_text(
        _PG_IMPORT + 'db.query("SELECT * FROM users WHERE id = ?", [userId]);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_fully_static_query(tmp_path: Path) -> None:
    (tmp_path / "users.js").write_text(
        _PG_IMPORT + 'db.query("SELECT * FROM users WHERE active = true");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_silent_without_driver_import(tmp_path: Path) -> None:
    # Precision choice: scoping to files that import a known SQL driver avoids false-positiving
    # on unrelated .query()-named methods (an ORM, a search client, a job queue).
    (tmp_path / "search.js").write_text(
        "elastic.query(`FIND * WHERE tag = ${tag}`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "users.js").write_text(
        _PG_IMPORT + "// db.query(`SELECT * FROM users WHERE id = ${userId}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "users.js").write_text(
        "// security: allow-js-sql-injection\n"
        + _PG_IMPORT
        + "db.query(`SELECT * FROM users WHERE id = ${userId}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert not JsSqlInjectionGuard().applies(profile)


def test_applies_with_typescript(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsSqlInjectionGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        _PG_IMPORT + "db.query(`SELECT * FROM users WHERE id = ${userId}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_js_sql_injection_trailing_comment_sink_silent(tmp_path: Path) -> None:
    # #395 H1: an interpolated `.query()` in a TRAILING same-line comment must not fire.
    (tmp_path / "repo.js").write_text(
        _PG_IMPORT
        + "const ok = true;  // db.query(`SELECT * FROM users WHERE id = ${userId}`) was here\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_pragma_quoted_in_a_template_literal_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the whole-file check reads the comment-only view, so a template literal quoting the
    # documented `// security: …` form is content, not a pragma - only a real comment opts out.
    (tmp_path / "users.js").write_text(
        "const help = `opt out with // security: allow-js-sql-injection`;\n"
        + _PG_IMPORT
        + "db.query(`SELECT * FROM users WHERE id = ${userId}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsSqlInjectionGuard().run(tmp_path, profile)) == 1


@pytest.mark.parametrize(
    "quoted",
    [
        'const doc = "pool.query(`SELECT * FROM users WHERE id = ${id}`)";',
        "const doc = 'db.query(\"SELECT * FROM users WHERE id = \" + id)';",
    ],
    ids=["template-in-a-string", "concat-in-a-string"],
)
def test_silent_on_query_spelled_out_in_a_string_literal(tmp_path: Path, quoted: str) -> None:
    # #749: a docs or error string that merely SPELLS OUT an interpolated query is not a call. Its
    # `(` anchor is string content in the anchor mask, so the match is dropped. Both fired HIGH before.
    (tmp_path / "users.js").write_text(_PG_IMPORT + quoted + "\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSqlInjectionGuard().run(tmp_path, profile) == []


def test_flags_query_nested_in_a_template_substitution(tmp_path: Path) -> None:
    # #749, the traded direction: a real call inside a `${...}` substitution is CODE. Anchoring
    # against plain `strip_strings=True` output would blank it with the template text and drop this
    # finding silently, and no other test here would notice.
    (tmp_path / "users.js").write_text(
        _PG_IMPORT + "res.send(`rows: ${await pool.query(`SELECT * FROM users WHERE id = ${id}`)}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsSqlInjectionGuard().run(tmp_path, profile)
    assert [f.location for f in findings] == ["users.js:3"]


def test_query_between_two_desyncing_substitutions_fires(tmp_path: Path) -> None:
    # #543, formerly the accepted trade #749 made (PR #1057 round-1 review): a `{` in a regex inside
    # one substitution and a `}` in a later one left the file balanced, so the lexer's restore caps
    # did not fire and a real query between them read as template text (pair.js). The lexer now
    # consumes a substitution's regexes and comments whole, so all three placements fire.
    # Lexer-level pin: `test_strip_js_comments_anchor_mask_rebalancing_regex_pair_reads_as_code`.
    opens = "const t = `a ${ s.replace(/{/g, '') } b`;\n"
    closes = "const u = `a ${ s.replace(/}/g, '') } b`;\n"
    query = "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n"
    (tmp_path / "pair.js").write_text(_PG_IMPORT + opens + query + closes, encoding="utf-8")
    (tmp_path / "single.js").write_text(_PG_IMPORT + opens + query, encoding="utf-8")
    (tmp_path / "after.js").write_text(_PG_IMPORT + opens + closes + query, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    locations = sorted(f.location for f in JsSqlInjectionGuard().run(tmp_path, profile))
    assert locations == ["after.js:5", "pair.js:4", "single.js:4"]


def test_quoted_query_does_not_hide_a_real_one_on_the_same_line(tmp_path: Path) -> None:
    # #749: the filter drops one ANCHOR, not the line. A quoted example sharing a line with a real
    # interpolated query still leaves the real one firing.
    (tmp_path / "users.js").write_text(
        _PG_IMPORT
        + 'log("pool.query(`x ${id}`)"); db.query(`SELECT * FROM users WHERE id = ${userId}`);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsSqlInjectionGuard().run(tmp_path, profile)
    assert [f.location for f in findings] == ["users.js:3"]
