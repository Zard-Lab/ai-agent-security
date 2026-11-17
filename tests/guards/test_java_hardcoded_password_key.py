from __future__ import annotations

from agentsec.guards.java_hardcoded_password_key import JavaHardcodedPasswordKeyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_hardcoded_password_key_flags_literal_jdbc_password(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() throws Exception {\n'
        '  DriverManager.getConnection("jdbc:mysql://db/app", "dbuser", "s3cr3tP@ss");\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-hardcoded-password-key/literal-jdbc-password"
    assert findings[0].severity == "critical"


def test_java_hardcoded_password_key_flags_pbe_key_spec_literal(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() {\n'
        '  PBEKeySpec spec = new PBEKeySpec("mypassword".toCharArray(), salt, 1000, 256);\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-hardcoded-password-key/literal-pbe-key-spec"
    assert findings[0].severity == "critical"


def test_java_hardcoded_password_key_flags_secret_key_spec_literal(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() {\n'
        '  SecretKeySpec key = new SecretKeySpec("mysecretkey12345".getBytes(), "AES");\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-hardcoded-password-key/literal-secret-key-spec"
    assert findings[0].severity == "critical"


def test_java_hardcoded_password_key_silent_on_variable_password(tmp_path: Path) -> None:
    # FP-bait: a variable password argument must not fire.
    (tmp_path / "T.java").write_text(
        'class T { void m() throws Exception {\n'
        "  DriverManager.getConnection(url, user, password);\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_hardcoded_password_key_silent_on_env_var_password(tmp_path: Path) -> None:
    # FP-bait: an env-var lookup for the password argument must not fire.
    (tmp_path / "T.java").write_text(
        'class T { void m() throws Exception {\n'
        '  DriverManager.getConnection(url, user, System.getenv("DB_PASSWORD"));\n'
        "} }\n",
        encoding="utf-8",
    )
    assert JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_hardcoded_password_key_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() throws Exception {\n'
        '  DriverManager.getConnection(url, "user", "s3cr3tP@ss"); '
        "// security: allow-hardcoded-password-key\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_hardcoded_password_key_silent_in_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        'class T { void m() { // DriverManager.getConnection(url, "user", "pass") is bad\n'
        "int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_hardcoded_password_key_ignores_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real
    # Javadoc block comment must not fire.
    (tmp_path / "T.java").write_text(
        '/**\n * DriverManager.getConnection(url, "user", "pass") is an example, do not use\n */\n'
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_hardcoded_password_key_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaHardcodedPasswordKeyGuard().applies(prof) is False


def _plant(tmp_path: Path, *rel_dirs: str) -> None:
    """The same literal-JDBC-password violation planted in each of `rel_dirs`."""
    for d in rel_dirs:
        target = tmp_path / d
        target.mkdir(parents=True, exist_ok=True)
        (target / "T.java").write_text(
            "class T { void m() throws Exception {\n"
            '  DriverManager.getConnection("jdbc:mysql://db/app", "dbuser", "s3cr3tP@ss");\n'
            "} }\n",
            encoding="utf-8",
        )


def test_java_hardcoded_password_key_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product, and a JDBC password in a test is
    # deliberately fake. Both trees carry the SAME violation in one run, so this pins the skip AND
    # the direction traded against it — production code under `src/main/java` must still fire.
    _plant(tmp_path, "src/main/java", "src/test/java")
    findings = JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}


def test_java_hardcoded_password_key_still_scans_flyway_migration_tree(tmp_path: Path) -> None:
    # The `credential_scan=True` half of the same decision. Flyway's Java-based migrations live at
    # `src/main/java/db/migration/`, whose `migration` segment is in the shared NONPRODUCT list — so
    # a PLAIN skip would silently drop this guard on a tree holding REAL deployment credentials, the
    # exact password-in-`alembic/env.py` regression `credential_scan` exists to prevent (#483).
    _plant(tmp_path, "src/main/java/db/migration")
    findings = JavaHardcodedPasswordKeyGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-hardcoded-password-key/literal-jdbc-password"
