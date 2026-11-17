from __future__ import annotations

from agentsec.findings import _is_review_finding
from agentsec.guards.mcp_overprivileged_scope import McpOverprivilegedScopeGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def _mcp_js_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "javascript"})


def test_fires_on_python_root_path_wildcard(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'ROOT_PATH = "/"\n',
        encoding="utf-8",
    )
    findings = McpOverprivilegedScopeGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-overprivileged-scope/overprivileged-scope-declaration" for f in findings)
    assert findings[0].severity == "low"


def test_findings_are_review_signals(tmp_path: Path) -> None:
    # #766: the flat `surfacing = True` used to be pinned by the checkmeta allowlist's own test,
    # which #766 deleted along with the allowlist. This is its replacement, and it runs the guard.
    (tmp_path / "config.py").write_text('ROOT_PATH = "/"\n', encoding="utf-8")
    findings = McpOverprivilegedScopeGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings
    assert all(_is_review_finding(f) for f in findings)


def test_fires_on_python_allowed_root_double_star(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'ALLOWED_ROOT = "**"\n',
        encoding="utf-8",
    )
    findings = McpOverprivilegedScopeGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-overprivileged-scope/overprivileged-scope-declaration" for f in findings)


def test_fires_on_js_allowed_origins_list_wildcard(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        'const allowed_origins = ["*"];\n',
        encoding="utf-8",
    )
    findings = McpOverprivilegedScopeGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert any(f.rule == "mcp-overprivileged-scope/overprivileged-scope-declaration" for f in findings)


def test_fires_on_bare_root_name(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'root = "/"\n',
        encoding="utf-8",
    )
    findings = McpOverprivilegedScopeGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-overprivileged-scope/overprivileged-scope-declaration" for f in findings)


def test_silent_on_scoped_path(tmp_path: Path) -> None:
    """FP-bait: a genuinely scoped, non-wildcard path stays silent."""
    (tmp_path / "config.py").write_text(
        'ROOT_PATH = "/home/mcp/project"\n',
        encoding="utf-8",
    )
    findings = McpOverprivilegedScopeGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-overprivileged-scope/overprivileged-scope-declaration" for f in findings)


def test_silent_on_unrelated_variable_name(tmp_path: Path) -> None:
    """FP-bait: a wildcard-valued variable with no scope-boundary-shaped name stays silent."""
    (tmp_path / "config.py").write_text(
        'glob_pattern = "*"\n',
        encoding="utf-8",
    )
    findings = McpOverprivilegedScopeGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-overprivileged-scope/overprivileged-scope-declaration" for f in findings)


def test_silent_without_mcp_feature(tmp_path: Path) -> None:
    guard = McpOverprivilegedScopeGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False


def test_applies_requires_mcp_plus_a_language(tmp_path: Path) -> None:
    guard = McpOverprivilegedScopeGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp"})) is False


def test_pragma_suppresses_python_finding(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "# security: allow-mcp-overprivileged-scope\n"
        'ROOT_PATH = "/"\n',
        encoding="utf-8",
    )
    assert McpOverprivilegedScopeGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_pragma_suppresses_js_finding(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        "// security: allow-mcp-overprivileged-scope\n"
        'const allowed_origins = ["*"];\n',
        encoding="utf-8",
    )
    assert McpOverprivilegedScopeGuard().run(tmp_path, _mcp_js_prof(tmp_path)) == []
