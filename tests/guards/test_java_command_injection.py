from __future__ import annotations

from agentsec.guards.java_command_injection import JavaCommandInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_command_injection_flags_runtime_exec_concatenated(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m(String service) throws Exception {\n'
        '  Runtime.getRuntime().exec("systemctl restart " + service);\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-command-injection/runtime-exec-tainted"
    assert findings[0].severity == "critical"


def test_java_command_injection_flags_runtime_exec_bare_variable(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m(String cmd) throws Exception {\n"
        "  Runtime.getRuntime().exec(cmd);\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-command-injection/runtime-exec-tainted"


def test_java_command_injection_flags_new_process_builder_bare_variable(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m(String cmd) throws Exception {\n"
        "  new ProcessBuilder(cmd).start();\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-command-injection/process-builder-tainted"


def test_java_command_injection_flags_process_builder_command_bare_variable(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m(ProcessBuilder pb, String cmd) throws Exception {\n"
        "  pb.command(cmd);\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-command-injection/process-builder-command-tainted"


def test_java_command_injection_silent_on_all_literal_exec(tmp_path: Path) -> None:
    # FP-bait: a fully static exec() call must not fire.
    (tmp_path / "T.java").write_text(
        'class T { void m() throws Exception { Runtime.getRuntime().exec("ls -la"); } }\n',
        encoding="utf-8",
    )
    assert JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_command_injection_silent_on_array_literal(tmp_path: Path) -> None:
    # FP-bait: the array-argument form with all-literal elements doesn't invoke a shell.
    (tmp_path / "T.java").write_text(
        'class T { void m() throws Exception {\n'
        '  Runtime.getRuntime().exec(new String[]{"ls", "-la"});\n'
        "} }\n",
        encoding="utf-8",
    )
    assert JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_command_injection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m(String cmd) throws Exception {\n"
        "  Runtime.getRuntime().exec(cmd); // security: allow-java-command-injection\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_command_injection_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  // Runtime.getRuntime().exec(cmd) is dangerous\n"
        "  int real = 1;\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_command_injection_ignores_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real
    # Javadoc block comment must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n"
        " * Runtime.getRuntime().exec(cmd) is an example, do not use\n"
        " */\n"
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_command_injection_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaCommandInjectionGuard().applies(prof) is False


def test_java_command_injection_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        'class T { void m(String service) throws Exception {\n'
        '  Runtime.getRuntime().exec("systemctl restart " + service);\n'
        "} }\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaCommandInjectionGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
