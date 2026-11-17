from __future__ import annotations

from agentsec.guards.java_sql_injection import JavaSqlInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_sql_injection_flags_inline_concatenation(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { ResultSet lookup(Statement stmt, String userId) throws Exception {\n"
        '    return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-sql-injection/concatenated-query"
    assert findings[0].severity == "high"


def test_java_sql_injection_flags_variable_form(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { void m(Statement stmt, String userId) throws Exception {\n"
        '    String sql = "SELECT * FROM users WHERE id = " + userId;\n'
        "    stmt.executeQuery(sql);\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-sql-injection/concatenated-query"


def test_java_sql_injection_flags_execute_update_delete_concat(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { void m(Statement stmt, String token) throws Exception {\n"
        "    stmt.executeUpdate(\"DELETE FROM sessions WHERE token = '\" + token + \"'\");\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-sql-injection/concatenated-query"


def test_java_sql_injection_flags_prepare_statement_concatenation(tmp_path: Path) -> None:
    # PreparedStatement built by concatenation (no ? placeholder) is still vulnerable.
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { void m(Connection conn, String userId) throws Exception {\n"
        '    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = " + userId);\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-sql-injection/concatenated-query"


def test_java_sql_injection_silent_on_placeholder_prepared_statement(tmp_path: Path) -> None:
    # FP-bait: the safe idiom — a ?-placeholder PreparedStatement with no concatenation.
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { void m(Connection conn) throws Exception {\n"
        '    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
        '    ps.setString(1, "x");\n'
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_sql_injection_silent_on_all_literal_query(tmp_path: Path) -> None:
    # FP-bait: a fully static query string, no concatenation.
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { void m(Statement stmt) throws Exception {\n"
        '    stmt.executeQuery("SELECT * FROM users WHERE active = 1");\n'
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_sql_injection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { void m(Statement stmt, String userId) throws Exception {\n"
        '    stmt.executeQuery("SELECT * FROM users WHERE id = " + userId); '
        "// security: allow-java-sql-injection\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_sql_injection_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        "import java.sql.*;\n"
        "class T { void m(Statement stmt) throws Exception {\n"
        '    // stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n'
        "    int real = 1;\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_sql_injection_silent_in_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait: an example inside a real Javadoc block comment must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n"
        ' * Example: stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n'
        " */\n"
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_sql_injection_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaSqlInjectionGuard().applies(prof) is False


def test_java_sql_injection_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        "import java.sql.*;\n"
        "class T { ResultSet lookup(Statement stmt, String userId) throws Exception {\n"
        '    return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n'
        "} }\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaSqlInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
