from __future__ import annotations

from agentsec.guards.go_pprof_exposed import GoPprofExposedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_go_pprof_exposed_fires_on_standalone_blank_import(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        'import _ "net/http/pprof"\n'
        "\n"
        "func main() {}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoPprofExposedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "go-pprof-exposed/blank-import-default-mux"
    assert findings[0].severity == "high"
    assert findings[0].standards == ["CWE-215"]
    assert findings[0].location.endswith(":3")


def test_go_pprof_exposed_fires_inside_grouped_import_block(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "import (\n"
        '\t"fmt"\n'
        '\t"net/http"\n'
        '\t_ "net/http/pprof"\n'
        ")\n"
        "\n"
        "func main() {\n"
        "\thttp.ListenAndServe(\":8080\", nil)\n"
        "\tfmt.Println(\"up\")\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoPprofExposedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "go-pprof-exposed/blank-import-default-mux"
    assert findings[0].location.endswith(":6")


def test_go_pprof_exposed_silent_on_explicit_handler_mount(tmp_path: Path) -> None:
    # FP-bait: the legitimate, gated pattern — a NON-blank import used explicitly to
    # mount pprof's handler on a private/custom mux, never touching DefaultServeMux.
    (tmp_path / "debug.go").write_text(
        "package main\n"
        "\n"
        "import (\n"
        '\t"net/http"\n'
        '\t"net/http/pprof"\n'
        ")\n"
        "\n"
        "func registerDebugRoutes(mux *http.ServeMux) {\n"
        '\tmux.Handle("/internal/debug/pprof/", pprof.Handler("goroutine"))\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoPprofExposedGuard().run(tmp_path, profile) == []


def test_go_pprof_exposed_silent_when_import_string_only_in_comment(tmp_path: Path) -> None:
    (tmp_path / "notes.go").write_text(
        "package main\n"
        "\n"
        '// TODO: consider `import _ "net/http/pprof"` for local debugging\n'
        "\n"
        "func main() {}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoPprofExposedGuard().run(tmp_path, profile) == []


def test_go_pprof_exposed_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        'import _ "net/http/pprof" // security: allow-go-pprof-exposed\n'
        "\n"
        "func main() {}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoPprofExposedGuard().run(tmp_path, profile) == []


def test_go_pprof_exposed_nonproduct_path_skipped(tmp_path: Path) -> None:
    # Independent review finding: run() never called is_nonproduct_path, so a project's own
    # test fixture demonstrating the blank-import idiom would false-fire on every scan.
    tests_dir = tmp_path / "tests" / "fixtures"
    tests_dir.mkdir(parents=True)
    (tests_dir / "vulnerable_example.go").write_text(
        'package fixtures\n\nimport _ "net/http/pprof"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoPprofExposedGuard().run(tmp_path, profile) == []


def test_go_pprof_exposed_not_applies_without_go(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert GoPprofExposedGuard().applies(profile) is False


def test_go_pprof_exposed_applies_with_go(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoPprofExposedGuard().applies(profile) is True
