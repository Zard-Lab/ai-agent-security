from __future__ import annotations

from agentsec.guards.go_tls_verify_disabled import GoTlsVerifyDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_go_tls_verify_disabled_fires_on_struct_literal(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        "package client\n"
        "\n"
        'import "crypto/tls"\n'
        'import "net/http"\n'
        "\n"
        "func newClient() *http.Client {\n"
        "\ttransport := &http.Transport{\n"
        "\t\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n"
        "\t}\n"
        "\treturn &http.Client{Transport: transport}\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoTlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "go-tls-verify-disabled/insecure-skip-verify"
    assert findings[0].severity == "high"
    assert findings[0].standards == ["CWE-295"]


def test_go_tls_verify_disabled_fires_on_field_assignment(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        "package client\n"
        "\n"
        'import "crypto/tls"\n'
        "\n"
        "func configure(cfg *tls.Config) {\n"
        "\tcfg.InsecureSkipVerify = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoTlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "go-tls-verify-disabled/insecure-skip-verify"


def test_go_tls_verify_disabled_silent_on_false(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        "package client\n"
        "\n"
        'import "crypto/tls"\n'
        "\n"
        "func newConfig() *tls.Config {\n"
        "\treturn &tls.Config{InsecureSkipVerify: false}\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoTlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_go_tls_verify_disabled_silent_on_empty_config(tmp_path: Path) -> None:
    # FP-bait: a tls.Config{} with no mention of InsecureSkipVerify at all.
    (tmp_path / "client.go").write_text(
        "package client\n"
        "\n"
        'import "crypto/tls"\n'
        "\n"
        "func newConfig() *tls.Config {\n"
        "\treturn &tls.Config{MinVersion: tls.VersionTLS12}\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoTlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_go_tls_verify_disabled_silent_on_comment_only(tmp_path: Path) -> None:
    # FP-bait: the pattern appearing only inside a `//` comment must not fire.
    (tmp_path / "client.go").write_text(
        "package client\n"
        "\n"
        "// Do NOT do this: cfg := &tls.Config{InsecureSkipVerify: true}\n"
        "func newConfig() {}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoTlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_go_tls_verify_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        "package client\n"
        "\n"
        'import "crypto/tls"\n'
        "\n"
        "func newConfig() *tls.Config {\n"
        "\treturn &tls.Config{InsecureSkipVerify: true} // security: allow-go-tls-verify-disabled\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoTlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_go_tls_verify_disabled_nonproduct_path_skipped(tmp_path: Path) -> None:
    # Independent review finding: run() never called is_nonproduct_path, so a project's own
    # test fixture demonstrating the insecure pattern would false-fire on every scan.
    tests_dir = tmp_path / "tests" / "fixtures"
    tests_dir.mkdir(parents=True)
    (tests_dir / "vulnerable_example.go").write_text(
        "package fixtures\n\nvar cfg = &tls.Config{InsecureSkipVerify: true}\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoTlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_go_tls_verify_disabled_not_applies_without_go(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert GoTlsVerifyDisabledGuard().applies(profile) is False


def test_go_tls_verify_disabled_applies_with_go(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"go"})
    assert GoTlsVerifyDisabledGuard().applies(profile) is True


def test_go_tls_verify_disabled_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the same-length Go comment-only view, so a string on the
    # finding's own line quoting the pragma is content - only a real `//` comment opts out.
    (tmp_path / "client.go").write_text(
        "package client\n"
        "\n"
        'import "crypto/tls"\n'
        "\n"
        "func newConfig() *tls.Config {\n"
        '\tdoc := "add // security: allow-go-tls-verify-disabled"; _ = doc; '
        "return &tls.Config{InsecureSkipVerify: true}\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert len(GoTlsVerifyDisabledGuard().run(tmp_path, profile)) == 1
