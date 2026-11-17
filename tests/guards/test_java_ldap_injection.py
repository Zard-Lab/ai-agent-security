from __future__ import annotations

from agentsec.guards.java_ldap_injection import JavaLdapInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_ldap_injection_flags_ctx_search_inline_concat(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import javax.naming.directory.DirContext;\n"
        "class T {\n"
        "  void m(DirContext ctx, String username) throws Exception {\n"
        '    ctx.search("ou=users,dc=example,dc=com", "(uid=" + username + ")", null);\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-ldap-injection/concatenated-filter"
    assert findings[0].severity == "medium"


def test_java_ldap_injection_flags_dircontext_named_variable(tmp_path: Path) -> None:
    # Receiver named `dirContext` (not literal `ctx`) still matches the name-convention scoping.
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m(javax.naming.directory.DirContext dirContext, String username) throws Exception {\n"
        '    dirContext.search("ou=users", "(uid=" + username + ")", null);\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-ldap-injection/concatenated-filter"


def test_java_ldap_injection_flags_ldap_template_search(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m(LdapTemplate ldapTemplate, String username) {\n"
        '    ldapTemplate.search("dc=example,dc=com", "(uid=" + username + ")");\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-ldap-injection/concatenated-filter"


def test_java_ldap_injection_flags_ldap_template_lookup(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m(LdapTemplate ldapTemplate, String username) {\n"
        '    ldapTemplate.lookup("uid=" + username + ",ou=users");\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-ldap-injection/concatenated-filter"


def test_java_ldap_injection_silent_on_all_literal_filter(tmp_path: Path) -> None:
    # FP-bait: a fully static filter has no `+` concatenation and must not fire.
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m(javax.naming.directory.DirContext ctx) throws Exception {\n"
        '    ctx.search("ou=users,dc=example,dc=com", "(uid=admin)", null);\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ldap_injection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m(javax.naming.directory.DirContext ctx, String username) throws Exception {\n"
        '    ctx.search("ou=users", "(uid=" + username + ")", null); // security: allow-ldap-injection\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ldap_injection_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m() {\n"
        '    // ctx.search("ou=users", "(uid=" + username + ")", null);\n'
        "    int real = 1;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ldap_injection_ignores_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real Javadoc
    # block comment must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n"
        ' * ctx.search("ou=users", "(uid=" + username + ")", null) is an example, do not use\n'
        " */\n"
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ldap_injection_silent_on_unrelated_search_call(tmp_path: Path) -> None:
    # FP-bait: an obviously non-LDAP receiver's `.search(` (e.g. a List) must not fire even
    # though its argument does contain a `+` concatenation.
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m(java.util.List<String> results, String prefix, String suffix) {\n"
        "    results.search(prefix + suffix);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ldap_injection_silent_on_separate_line_filter_variable(tmp_path: Path) -> None:
    # Documented known bypass: the concatenation happens on a prior line, then the built
    # variable is passed into the call on a later line. This guard is textual/single-line
    # (same tradeoff as java-weak-crypto), so this is NOT flagged.
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m(javax.naming.directory.DirContext ctx, String username) throws Exception {\n"
        '    String filter = "(uid=" + username + ")";\n'
        '    ctx.search("ou=users", filter, null);\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ldap_injection_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaLdapInjectionGuard().applies(prof) is False


def test_java_ldap_injection_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        "import javax.naming.directory.DirContext;\n"
        "class T {\n"
        "  void m(DirContext ctx, String username) throws Exception {\n"
        '    ctx.search("ou=users,dc=example,dc=com", "(uid=" + username + ")", null);\n'
        "  }\n"
        "}\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaLdapInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
