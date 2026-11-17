from __future__ import annotations

from agentsec.guards.php_sql_injection import PhpSqlInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_sql_injection_flags_mysqli_query_concatenated_get(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($conn) { return mysqli_query($conn, \"SELECT * FROM users WHERE id = \" "
        ". $_GET['id']); }\n",
        encoding="utf-8",
    )
    findings = PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-sql-injection/concatenated-query"
    assert findings[0].severity == "critical"


def test_php_sql_injection_flags_mysql_query_concatenated_request(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { return mysql_query(\"SELECT * FROM users WHERE id = \" "
        ". $_REQUEST['id']); }\n",
        encoding="utf-8",
    )
    findings = PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-sql-injection/concatenated-query"


def test_php_sql_injection_flags_pg_query_concatenated_post(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($conn) { return pg_query($conn, \"SELECT * FROM t WHERE name = '\" "
        ". $_POST['name'] . \"'\"); }\n",
        encoding="utf-8",
    )
    findings = PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-sql-injection/concatenated-query"


def test_php_sql_injection_flags_object_style_query_call(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($mysqli, $id) { return $mysqli->query(\"SELECT * FROM users WHERE id = \" "
        ". $id); }\n",
        encoding="utf-8",
    )
    findings = PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-sql-injection/concatenated-query"


def test_php_sql_injection_silent_on_pdo_prepared_statement(tmp_path: Path) -> None:
    # FP-bait: the safe idiom — PDO prepared statement with a placeholder, then ->execute([...]).
    (tmp_path / "T.php").write_text(
        "<?php\n"
        "function f($pdo, $id) {\n"
        "    $stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = ?\");\n"
        "    $stmt->execute([$id]);\n"
        "    return $stmt;\n"
        "}\n",
        encoding="utf-8",
    )
    assert PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_sql_injection_silent_on_all_literal_query(tmp_path: Path) -> None:
    # FP-bait: a fully static query string, no concatenation, must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($conn) { return mysqli_query($conn, \"SELECT * FROM users WHERE active = 1\"); }\n",
        encoding="utf-8",
    )
    assert PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_sql_injection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($conn) { return mysqli_query($conn, \"SELECT * FROM users WHERE id = \" "
        ". $_GET['id']); // security: allow-php-sql-injection\n}\n",
        encoding="utf-8",
    )
    assert PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_sql_injection_silent_in_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n// mysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $_GET['id']); example only\n"
        "real();\n",
        encoding="utf-8",
    )
    assert PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_sql_injection_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a real `#` line comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n# mysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $_GET['id']); is an example\n"
        "real();\n",
        encoding="utf-8",
    )
    assert PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_sql_injection_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpSqlInjectionGuard().applies(prof) is False


def test_php_sql_injection_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the same-length PHP comment-only view, so a string on the
    # finding's own line quoting the pragma is content - only a real `//` comment opts out.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($conn) { $d = \"add // security: allow-php-sql-injection\"; "
        "return mysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $_GET['id']); }\n",
        encoding="utf-8",
    )
    assert len(PhpSqlInjectionGuard().run(tmp_path, _phpprof(tmp_path))) == 1
