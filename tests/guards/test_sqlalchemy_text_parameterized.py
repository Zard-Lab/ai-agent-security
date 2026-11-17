from __future__ import annotations

from agentsec.guards.sqlalchemy_text_parameterized import SqlalchemyTextParameterizedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_sqlalchemy_flags_fstring(tmp_path: Path) -> None:
    (tmp_path / "q.py").write_text(
        "db.execute(text(f\"SELECT * FROM users WHERE email = '{email}'\"))\n", encoding="utf-8"
    )
    findings = SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "sqlalchemy-text-parameterized/string-built-sql"
    assert findings[0].severity == "high"

def test_sqlalchemy_flags_format_and_concat(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('s.execute(text("SELECT * FROM t WHERE n = {}".format(n)))\n', encoding="utf-8")
    (tmp_path / "b.py").write_text('conn.execute("UPDATE t SET x=1 WHERE id = " + uid)\n', encoding="utf-8")
    assert len(SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path))) == 2

def test_sqlalchemy_flags_concat_after_paren_in_query(tmp_path: Path) -> None:
    # H8 (FN): a `)` in the SQL text (e.g. COUNT(*)) must not stop the concat detector —
    # the old [^)]*? bailed at the first `)`, missing real string-concat injection.
    (tmp_path / "q.py").write_text(
        "db.execute(text(\"SELECT COUNT(*) FROM users WHERE name = '\" + name))\n", encoding="utf-8"
    )
    findings = SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "sqlalchemy-text-parameterized/string-built-sql"

def test_sqlalchemy_silent_on_interp_in_sibling_arg(tmp_path: Path) -> None:
    # H-2 (FP fix): a safe bound-param query must stay silent when an interpolation is on a
    # SIBLING argument (after the call's real `)`), including when that sibling is itself a
    # string literal that closes and is concatenated/formatted. Detection is scoped to the
    # call's FIRST argument (bracket/quote-aware `_first_arg`), so none of these fire.
    g = SqlalchemyTextParameterizedGuard()
    for line in (
        'db.execute(text("SELECT * FROM t WHERE id = :id"), conf.format(x))',        # bare-ident .format
        'db.execute(text("SELECT * FROM t WHERE id = :id"), "prefix_" + suffix)',    # sibling string concat
        'db.execute(text("SELECT * FROM t WHERE id = :id"), "tmpl {}".format(x))',   # sibling string .format
        'db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid}); q("done " + str(uid))',  # later stmt
    ):
        (tmp_path / "q.py").write_text(line + "\n", encoding="utf-8")
        assert g.run(tmp_path, _pyprof(tmp_path)) == [], line

def test_sqlalchemy_passes_bound_params(tmp_path: Path) -> None:
    (tmp_path / "q.py").write_text(
        'db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})\n'
        'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n', encoding="utf-8"
    )
    assert SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_sqlalchemy_ignores_non_sql_execute(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text('logger.info(f"processed {n}")\nrunner.execute(f"job {job_id}")\n', encoding="utf-8")
    assert SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_sqlalchemy_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "q.py").write_text(
        'db.execute(text(f"SELECT * FROM t WHERE id = {i}"))  # security: allow-raw-sql\n', encoding="utf-8"
    )
    assert SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_sqlalchemy_na_without_python() -> None:
    g = SqlalchemyTextParameterizedGuard()
    assert g.applies(mkprofile(Path("/tmp"), features={"frontend"})) is False

def test_sqlalchemy_test_file_silent(tmp_path: Path) -> None:
    # FP fix: test files should not fire (is_nonproduct_path skips them).
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_queries.py").write_text(
        'db.execute(text(f"SELECT * FROM t WHERE id = {user_id}"))\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["tests"])
    assert SqlalchemyTextParameterizedGuard().run(tmp_path, profile) == []

def test_sqlalchemy_docstring_example_silent(tmp_path: Path) -> None:
    # FP fix: strip_python_strings prevents firing on docstring anti-pattern examples.
    (tmp_path / "q.py").write_text(
        '"""\nDon\'t do: db.execute(text(f"SELECT * FROM t WHERE id = {user_id}"))\n"""\n',
        encoding="utf-8",
    )
    assert SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_sqlalchemy_trailing_comment_example_silent(tmp_path: Path) -> None:
    # FP-bait (#424 / #362): a `text(f"SELECT ...")` mention inside a TRAILING `#` comment on an
    # otherwise-benign line must not fire (strip_python_line_comment handles the trailing case).
    (tmp_path / "q.py").write_text(
        'x = 5  # avoid db.execute(text(f"SELECT * FROM t WHERE id = {x}"))\n',
        encoding="utf-8",
    )
    assert SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path)) == []



def test_sqlalchemy_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-raw-sql"):
        (tmp_path / "q.py").write_text(
            f'db.execute(text(f"SELECT * FROM t WHERE id = {{i}}")); _note = "{note}"\n', encoding="utf-8"
        )
        assert len(SqlalchemyTextParameterizedGuard().run(tmp_path, _pyprof(tmp_path))) == 1, note
