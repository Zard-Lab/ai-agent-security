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


# --- variable-bound queries (mined from js-x-ray's sql-injection probe) ---------------------------


def _bound_rules(tmp_path: Path, body: str, imp: str = _PG_IMPORT) -> list[tuple[str, int]]:
    (tmp_path / "users.js").write_text(imp + body, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    out = []
    for f in JsSqlInjectionGuard().run(tmp_path, profile):
        out.append((f.rule, int(f.location.rsplit(":", 1)[1])))
    return out


@pytest.mark.parametrize(
    "body",
    [
        "const q = `SELECT * FROM t WHERE n = '${req.query.n}'`;\nawait db.query(q);\n",
        "const q = \"SELECT * FROM t WHERE n = '\" + req.query.n + \"'\";\ndb.execute(q);\n",
        "let sql: string = `DELETE FROM t WHERE id = ${id}`;\nconst r = await pool.query(sql);\n",
        "const q = `UPDATE t SET a = 1\n WHERE id = ${id}`;\ndb.query(q, []);\n",
        "const q = 'SELECT * FROM t WHERE n = ' +\n  name;\ndb.query(q);\n",
    ],
)
def test_variable_bound_query_fires(tmp_path: Path, body: str) -> None:
    rules = _bound_rules(tmp_path, body)
    assert [r for r, _ in rules] == ["js-sql-injection/variable-bound-query"]


def test_variable_bound_query_reports_the_call_line(tmp_path: Path) -> None:
    body = "const q = `SELECT * FROM t WHERE n = ${n}`;\n\ndb.query(q);\n"
    ((_, line),) = _bound_rules(tmp_path, body)
    assert line == len((_PG_IMPORT + body).splitlines())


def test_variable_bound_mysql2_import_fires(tmp_path: Path) -> None:
    body = "const q = `SELECT * FROM t WHERE n = ${n}`;\ndb.query(q);\n"
    assert _bound_rules(tmp_path, body, _MYSQL2_IMPORT)


@pytest.mark.parametrize(
    "body",
    [
        'const q = "SELECT * FROM t WHERE id = $1";\ndb.query(q, [id]);\n',
        "const q = `SELECT * FROM ${TABLE_NAME} WHERE id = $1`;\ndb.query(q, [id]);\n",
        "const q = `SELECT * FROM t LIMIT ${Number(limit)}`;\ndb.query(q);\n",
        "const q = `SELECT * FROM t WHERE n = ${pool.escape(n)}`;\ndb.query(q);\n",
        "let q = `SELECT * FROM t WHERE n = ${n}`;\nq = 'SELECT 1';\ndb.query(q);\n",
        "const q = `SELECT * FROM t WHERE n = ${n}`;\ndb.query(other);\n",
        "// const q = `SELECT * FROM t WHERE n = ${n}`;\nconst q = 'SELECT 1';\ndb.query(q);\n",
        "const q = `hello ${name}`;\ndb.query(q);\n",
    ],
)
def test_variable_bound_query_silent(tmp_path: Path, body: str) -> None:
    assert _bound_rules(tmp_path, body) == []


def test_variable_bound_query_needs_driver_import(tmp_path: Path) -> None:
    body = "const q = `SELECT * FROM t WHERE n = ${n}`;\nelastic.query(q);\n"
    assert _bound_rules(tmp_path, body, imp="const elastic = require('elastic');\n") == []


def test_variable_bound_query_pragma_suppresses(tmp_path: Path) -> None:
    body = (
        "// security: allow-js-sql-injection\n"
        "const q = `SELECT * FROM t WHERE n = ${n}`;\ndb.query(q);\n"
    )
    assert _bound_rules(tmp_path, body) == []


def test_variable_bound_query_rebound_per_function(tmp_path: Path) -> None:
    body = (
        "function a(n) { const q = `SELECT * FROM t WHERE n = ${n}`; return db.query(q); }\n"
        "function b() { const q = 'SELECT 1'; return db.query(q); }\n"
    )
    rules = _bound_rules(tmp_path, body)
    assert len(rules) == 1


def test_variable_bound_query_function_parameter_is_a_fresh_binding(tmp_path: Path) -> None:
    body = (
        "function listA(req) { const q = `SELECT * FROM t WHERE n = '${req.query.n}'`; return db.query(q, []); }\n"
        "function run(q) { return db.query(q); }\n"
    )
    rules = _bound_rules(tmp_path, body)
    assert [line for _, line in rules] == [len(_PG_IMPORT.splitlines()) + 1]  # only the real binding's call


@pytest.mark.parametrize(
    "param_form",
    [
        "function run(q) { return db.query(q); }",
        "const run = (q) => db.query(q);",
        "const run = q => db.query(q);",
        "const run = async (a, q = 1) => { return db.query(q); };",
        "const o = { run(q) { return db.query(q); } };",
        "function run(a, { q }) { return db.query(q); }",
    ],
)
def test_variable_bound_query_parameter_forms_silent(tmp_path: Path, param_form: str) -> None:
    body = "const q = `SELECT * FROM t WHERE n = ${n}`;\n" + param_form + "\n"
    assert _bound_rules(tmp_path, body) == []


def test_variable_bound_query_real_binding_still_fires_beside_a_parameter(tmp_path: Path) -> None:
    body = "function other(q) { return q; }\nconst q = `SELECT * FROM t WHERE n = ${n}`;\ndb.query(q);\n"
    assert [r for r, _ in _bound_rules(tmp_path, body)] == ["js-sql-injection/variable-bound-query"]



@pytest.mark.parametrize(
    "control_flow",
    [
        "if (q) { db.query(q); }",
        "while (q) { db.query(q); }",
        "switch (q) { default: db.query(q); }",
        "for (q; ;) { db.query(q); }",
    ],
)
def test_variable_bound_query_control_flow_condition_is_not_a_parameter(
    tmp_path: Path, control_flow: str
) -> None:
    # A tracked name in an `if (...)` / `while (...)` condition is a USE, not a fresh parameter
    # binding: the keyword exclusion must hold, or the real binding above goes silent (#1202 r2 H1).
    body = "const q = `SELECT * FROM t WHERE n = '${req.query.n}'`;\n" + control_flow + "\n"
    assert [r for r, _ in _bound_rules(tmp_path, body)] == ["js-sql-injection/variable-bound-query"]


def test_guard_source_has_no_control_characters() -> None:
    # A `\b` decoded to a literal backspace byte by an editing tool silently broke two patterns
    # (#1202 r2 H1); a raw string can never need a C0 control byte here.
    import re

    import agentsec.guards.js_sql_injection as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    controls = re.finditer(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", src)
    bad = [(src.count("\n", 0, m.start()) + 1, hex(ord(m.group()))) for m in controls]
    assert not bad, f"control characters in js_sql_injection.py (line, byte): {bad}"


@pytest.mark.parametrize(
    "prefix",
    # with a `:` the run belongs to the annotation (r2 H2, cubic); without one it sits between the
    # name or `)` and the `=`/`=>`/`{` that never comes (r3 M1, quadratic)
    [
        "const q: ", "const run = (x): ", "const o = { run(x): ",
        "const q", "const run = (x)", "const o = { run(x)",
    ],
)
def test_variable_bound_annotation_scan_is_linear_on_a_run_of_spaces(prefix: str) -> None:
    # Overlapping `\s*` around the optional annotation backtracked on a long run of spaces
    # (#1202 r2 H2: 3 KB took about 21 s; r3 M1: 64 KB with no annotation took about 14 s).
    from agentsec.guards.js_sql_injection import _variable_bound_lines
    from tests._timing import assert_growth

    head = "const q = `SELECT * FROM t WHERE n = ${n}`;\ndb.query(q);\n"
    sizes = [2000, 4000, 8000, 16000]
    texts = {n: head + prefix + " " * n + "z\n" for n in sizes}

    def scan(n: int) -> None:
        _variable_bound_lines(texts[n], texts[n])

    assert_growth(scan, sizes, expected="linear")

def test_sql_verb_detection_is_linear_in_the_number_of_openers() -> None:
    # Many `select ` / `update ` openers and no `from` / `set` closer: a lazy `select ... from` regex
    # rescans to the end of the literal from every opener (quadratic).
    from agentsec.guards.js_sql_injection import _bound_value
    from tests._timing import assert_growth

    sizes = [4000, 8000, 16000, 32000]
    texts = {n: "`" + "select update " * n + "${x}`" for n in sizes}

    def scan(n: int) -> None:
        assert _bound_value(texts[n], 0) is None

    assert_growth(scan, sizes, expected="linear")


def test_sql_verb_detection_keeps_its_matches() -> None:
    from agentsec.guards.js_sql_injection import _has_sql_verb

    for yes in ("SELECT a FROM t", "select\n*\nfrom t", "update t set a = 1", "insert into t", "delete from t",
                "select update x from y"):
        assert _has_sql_verb(yes), yes
    for no in ("select from", "select a", "update t", "hello world", "selectfrom", "update set x"):
        assert not _has_sql_verb(no), no
