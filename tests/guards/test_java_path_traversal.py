from __future__ import annotations

from agentsec.guards.java_path_traversal import JavaPathTraversalGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_path_traversal_flags_new_file_bare_variable(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { File m(String userInput) { return new File(userInput); } }\n",
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-path-traversal/tainted-file-construction"
    assert findings[0].severity == "high"


def test_java_path_traversal_silent_on_mojo_plugin_parameter(tmp_path: Path) -> None:
    # FP-bait (#848 corpus scan, keycloak/keycloak docs/maven-plugin/.../GuideMojo.java): a Maven
    # plugin ("Mojo") class's `@Parameter` fields are build-time plugin configuration (populated
    # from a project's pom.xml at build time), not runtime request input -- constructing a File/
    # Paths from one is not the same trust boundary this guard targets.
    (tmp_path / "GuideMojo.java").write_text(
        "import java.nio.file.Paths;\n"
        "import org.apache.maven.plugin.AbstractMojo;\n"
        "import org.apache.maven.plugins.annotations.Mojo;\n"
        "import org.apache.maven.plugins.annotations.Parameter;\n\n"
        '@Mojo(name = "keycloak-guide")\n'
        "public class GuideMojo extends AbstractMojo {\n"
        '    @Parameter(property = "project.build.sourceDirectory")\n'
        "    private String sourceDir;\n\n"
        "    public void execute() {\n"
        "        java.nio.file.Path src = Paths.get(sourceDir);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_path_traversal_flags_ordinary_class_with_mojo_mentioned_in_comment(
    tmp_path: Path,
) -> None:
    # PR #884 review regression (Dean's exact repro): the Mojo check used to run against the RAW
    # text, before comment-stripping, so a comment merely MENTIONING `@Mojo(`/`extends
    # AbstractMojo` (a migration note, stale javadoc) exempted the entire file -- including a
    # genuinely vulnerable, unrelated class with no actual Mojo inheritance at all.
    (tmp_path / "FileService.java").write_text(
        "import java.nio.file.Paths;\n"
        '// Migration note: this used to be @Mojo(name = "legacy-guide") before we dropped the plugin\n'
        "class FileService {\n"
        "    void run(String sourceDir) { java.nio.file.Path p = Paths.get(sourceDir); }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-path-traversal/tainted-file-construction"


def test_java_path_traversal_flags_tainted_construction_in_ordinary_class(tmp_path: Path) -> None:
    # The direction traded against (CLAUDE.md Rule 1): an ORDINARY (non-Mojo) class using the
    # exact same `Paths.get(field)` shape must still fire -- the exemption is keyed on the class
    # actually being a Maven plugin, not on the sink/argument shape alone.
    (tmp_path / "T.java").write_text(
        "import java.nio.file.Paths;\n\n"
        "class FileService {\n"
        "    private String sourceDir;\n"
        "    void run() { java.nio.file.Path p = Paths.get(sourceDir); }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-path-traversal/tainted-file-construction"


def test_java_path_traversal_flags_new_file_two_arg_ctor(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { File m(String baseDir, String userInput) {\n"
        "  return new File(baseDir, userInput);\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_java_path_traversal_flags_random_access_file(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m(String userInput) throws Exception {\n"
        '  new RandomAccessFile(userInput, "r");\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-path-traversal/tainted-file-construction"


def test_java_path_traversal_flags_paths_get(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m(String userInput) { Paths.get(userInput); } }\n",
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_java_path_traversal_flags_files_create_temp_file(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m(String prefix, String suffix) throws Exception {\n"
        "  Files.createTempFile(prefix, suffix);\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_java_path_traversal_flags_concatenated_path(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { File m(String userInput) { return new File("base/" + userInput); } }\n',
        encoding="utf-8",
    )
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_java_path_traversal_silent_on_string_literal_only(tmp_path: Path) -> None:
    # FP-bait: a sole string-literal argument is fully static — nothing to taint.
    (tmp_path / "T.java").write_text(
        'class T { File m() { return new File("config.json"); } }\n',
        encoding="utf-8",
    )
    assert JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_path_traversal_silent_on_two_literal_args(tmp_path: Path) -> None:
    # FP-bait: a two-argument constructor where BOTH arguments are literals is fully static.
    (tmp_path / "T.java").write_text(
        'class T { File m() { return new File("base", "config.json"); } }\n',
        encoding="utf-8",
    )
    assert JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_path_traversal_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { File m(String userInput) {\n"
        "  return new File(userInput); // security: allow-path-traversal\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_path_traversal_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        "class T { void m() { // new File(userInput) is bad\n"
        "int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_path_traversal_silent_in_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real
    # Javadoc block comment must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n * new File(userInput) is an example, do not use directly\n */\n"
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_path_traversal_silent_on_unrelated_class_name(tmp_path: Path) -> None:
    # FP-bait: a similarly-named but unrelated method (`MyFileHelper.get(...)`) is not a
    # java.io.File / RandomAccessFile / Paths / Files sink and must not fire.
    (tmp_path / "T.java").write_text(
        "class T { void m(String userInput) { MyFileHelper.get(userInput); } }\n",
        encoding="utf-8",
    )
    assert JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_path_traversal_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaPathTraversalGuard().applies(prof) is False


def test_java_path_traversal_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        "class T { File m(String userInput) { return new File(userInput); } }\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaPathTraversalGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
