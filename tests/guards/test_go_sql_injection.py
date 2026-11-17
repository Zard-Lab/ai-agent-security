from __future__ import annotations

from agentsec.guards.go_sql_injection import GoSqlInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def _goprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"go"}, go_dirs=["."])


def test_flags_sprintf_inline_in_query(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func getUser(db *sql.DB, userID string) {\n"
        '\tdb.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))\n'
        "}\n",
        encoding="utf-8",
    )
    findings = GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "go-sql-injection/sprintf-query"
    assert findings[0].severity == "high"
    assert findings[0].location.endswith(":4")


def test_flags_string_concat_in_exec(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func revoke(db *sql.DB, token string) {\n"
        "\tdb.Exec(\"DELETE FROM sessions WHERE token = '\" + token + \"'\")\n"
        "}\n",
        encoding="utf-8",
    )
    findings = GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "go-sql-injection/string-concat-query"
    assert findings[0].severity == "high"


def test_flags_sprintf_via_nearby_variable(tmp_path: Path) -> None:
    # Shape 1's variable form: fmt.Sprintf assigned to a var, passed to the sink a few lines later.
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func getUser(db *sql.DB, userID string) {\n"
        '\tquery := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)\n'
        "\trows, err := db.Query(query)\n"
        "\t_ = rows\n"
        "\t_ = err\n"
        "}\n",
        encoding="utf-8",
    )
    findings = GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "go-sql-injection/sprintf-query"
    assert findings[0].location.endswith(":5")  # anchored at the sink call, not the assignment


def test_flags_queryrow_and_execcontext_variants(tmp_path: Path) -> None:
    (tmp_path / "a.go").write_text(
        "package main\n"
        "func f(db *sql.DB, id string) {\n"
        '\tdb.QueryRow(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "b.go").write_text(
        "package main\n"
        "func g(db *sql.DB, ctx context.Context, id string) {\n"
        '\tdb.ExecContext(ctx, fmt.Sprintf("DELETE FROM t WHERE id = %s", id))\n'
        "}\n",
        encoding="utf-8",
    )
    findings = GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path))
    assert len(findings) == 2
    assert {f.rule for f in findings} == {"go-sql-injection/sprintf-query"}


def test_silent_on_parameterized_placeholder_query(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func getUser(db *sql.DB, userID string) {\n"
        '\tdb.Query("SELECT * FROM users WHERE id = ?", userID)\n'
        "}\n",
        encoding="utf-8",
    )
    assert GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_silent_on_fully_static_query(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func listActive(db *sql.DB) {\n"
        '\tdb.Query("SELECT * FROM users WHERE active = true")\n'
        "}\n",
        encoding="utf-8",
    )
    assert GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_silent_on_sprintf_not_feeding_a_sql_sink(tmp_path: Path) -> None:
    # fmt.Sprintf building a log message / HTTP response string, never passed to a
    # Query/Exec-family call, must stay silent — the guard anchors to the sink call, not to
    # "fmt.Sprintf" appearing anywhere in the file.
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func logRequest(userID string) {\n"
        '\tmsg := fmt.Sprintf("handling request for user %s", userID)\n'
        "\tlog.Println(msg)\n"
        "}\n"
        "\n"
        "func writeResponse(w http.ResponseWriter, name string) {\n"
        '\tfmt.Fprintf(w, "hello %s", name)\n'
        "}\n",
        encoding="utf-8",
    )
    assert GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_silent_on_commented_out_vulnerable_pattern(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func getUser(db *sql.DB, userID string) {\n"
        '\t// db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))\n'
        '\tdb.Query("SELECT * FROM users WHERE id = ?", userID)\n'
        "}\n",
        encoding="utf-8",
    )
    assert GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_pragma_suppresses_sprintf_inline(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func getUser(db *sql.DB, userID string) {\n"
        '\tdb.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)) '
        "// security: allow-go-sql-injection\n"
        "}\n",
        encoding="utf-8",
    )
    assert GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_pragma_suppresses_string_concat(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func revoke(db *sql.DB, token string) {\n"
        "\tdb.Exec(\"DELETE FROM sessions WHERE token = '\" + token + \"'\") "
        "// security: allow-go-sql-injection\n"
        "}\n",
        encoding="utf-8",
    )
    assert GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_pragma_on_assignment_line_suppresses_variable_form(tmp_path: Path) -> None:
    # The variable form's pragma may be placed on the fmt.Sprintf assignment line itself,
    # not only on the sink call line.
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func getUser(db *sql.DB, userID string) {\n"
        '\tquery := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID) '
        "// security: allow-go-sql-injection\n"
        "\trows, err := db.Query(query)\n"
        "\t_ = rows\n"
        "\t_ = err\n"
        "}\n",
        encoding="utf-8",
    )
    assert GoSqlInjectionGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_na_without_go(tmp_path: Path) -> None:
    g = GoSqlInjectionGuard()
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False


def test_applies_with_go(tmp_path: Path) -> None:
    g = GoSqlInjectionGuard()
    assert g.applies(mkprofile(tmp_path, features={"go"})) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "main_test.go").write_text(
        "package main\n"
        "\n"
        "func getUser(db *sql.DB, userID string) {\n"
        '\tdb.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["tests"])
    assert GoSqlInjectionGuard().run(tmp_path, profile) == []
