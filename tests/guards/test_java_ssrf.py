from __future__ import annotations

from agentsec.guards.java_ssrf import JavaSsrfGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_ssrf_flags_chained_open_connection(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m(String target) throws Exception {\n"
        "  new URL(target).openConnection();\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-ssrf/tainted-url-open-connection"
    assert findings[0].severity == "high"


def test_java_ssrf_flags_chained_open_stream(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m(String target) throws Exception {\n"
        "  new URL(target).openStream();\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-ssrf/tainted-url-open-connection"


def test_java_ssrf_flags_two_statement_variable_pattern(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "import java.net.URLConnection;\n"
        "class T { void m(String target) throws Exception {\n"
        "  URL url = new URL(target);\n"
        "  URLConnection conn = url.openConnection();\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-ssrf/tainted-url-open-connection"


def test_java_ssrf_flags_concatenation_with_a_variable(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m(String host) throws Exception {\n"
        '  new URL("https://" + host).openConnection();\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_java_ssrf_flags_request_getparameter(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m(HttpServletRequest request) throws Exception {\n"
        '  new URL(request.getParameter("url")).getContent();\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_java_ssrf_silent_on_hardcoded_literal_url(tmp_path: Path) -> None:
    # FP-bait: a fully static literal URL must not fire.
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m() throws Exception {\n"
        '  new URL("https://api.example.com/status").openConnection();\n'
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ssrf_silent_on_literal_concatenation(tmp_path: Path) -> None:
    # FP-bait: `+`-concatenation of only string literals is still fully static.
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m() throws Exception {\n"
        '  new URL("https://" + "api.example.com").openConnection();\n'
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ssrf_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m(String target) throws Exception {\n"
        "  new URL(target).openConnection(); // security: allow-java-ssrf\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ssrf_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        "import java.net.URL;\n"
        "class T { void m() throws Exception {\n"
        "  // new URL(target).openConnection() is dangerous\n"
        "  int real = 1;\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ssrf_ignores_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real
    # Javadoc block comment must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n"
        " * new URL(target).openConnection() is an example, do not use\n"
        " */\n"
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_ssrf_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaSsrfGuard().applies(prof) is False


def test_java_ssrf_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        "import java.net.URL;\n"
        "class T { void m(String target) throws Exception {\n"
        "  new URL(target).openConnection();\n"
        "} }\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaSsrfGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
