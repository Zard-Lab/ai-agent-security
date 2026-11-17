"""Tests for McpAppsUiIsolationGuard — planted-violation + FP-bait."""
from __future__ import annotations

from agentsec.guards.mcp_apps_ui_isolation import McpAppsUiIsolationGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"typescript"}, python_dirs=["."])


def test_iframe_no_sandbox_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp_ui_host.tsx").write_text(
        "import { createUIResource } from '@mcp-ui/client';\n\n"
        "function renderUiResource(html: string) {\n"
        "  return <iframe srcDoc={html} />;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-apps-ui-isolation/iframe-no-hardening-sandbox")
    assert hit.severity == "high"


def test_self_defeating_sandbox_combo_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp_ui_host.tsx").write_text(
        "import { createUIResource } from '@mcp-ui/client';\n\n"
        "function renderUiResource(html: string) {\n"
        "  return <iframe sandbox=\"allow-scripts allow-same-origin\" srcDoc={html} />;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "mcp-apps-ui-isolation/iframe-no-hardening-sandbox" for f in findings)


def test_scripts_only_sandbox_is_safe(tmp_path: Path) -> None:
    """FP-bait: sandbox="allow-scripts" alone (no allow-same-origin) is a real,
    effective sandbox -- the framed doc can run JS but can't script the host origin."""
    (tmp_path / "mcp_ui_host.tsx").write_text(
        "import { createUIResource } from '@mcp-ui/client';\n\n"
        "function renderUiResource(html: string) {\n"
        "  return <iframe sandbox=\"allow-scripts\" srcDoc={html} />;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_created_iframe_with_sandbox_set_is_safe(tmp_path: Path) -> None:
    (tmp_path / "mcp_ui_host.ts").write_text(
        "import { createUIResource } from '@mcp-ui/client';\n\n"
        "const el = document.createElement('iframe');\n"
        "el.sandbox.add('allow-scripts');\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_created_iframe_with_no_sandbox_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp_ui_host.ts").write_text(
        "import { createUIResource } from '@mcp-ui/client';\n\n"
        "const el = document.createElement('iframe');\n"
        "el.srcdoc = html;\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "mcp-apps-ui-isolation/iframe-no-hardening-sandbox" for f in findings)


def test_ordinary_iframe_outside_mcp_apps_context_is_ignored(tmp_path: Path) -> None:
    """FP-bait: a plain web-app iframe with no MCP-Apps context at all is out of scope."""
    (tmp_path / "widget.tsx") .write_text(
        "function renderWidget(url: string) {\n"
        "  return <iframe src={url} />;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "mcp_ui_host.tsx").write_text(
        "// security: allow-mcp-apps-ui-isolation\n"
        "import { createUIResource } from '@mcp-ui/client';\n\n"
        "function renderUiResource(html: string) {\n"
        "  return <iframe srcDoc={html} />;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


_MIXED_HOST = (
    "import { createUIResource } from '@mcp-ui/client';\n\n"
    "export function Host({ html }: { html: string }) {\n"
    "  return (\n"
    "    <div>\n"
    "      <iframe sandbox=\"allow-scripts\" srcDoc={html} />\n"
    "      <iframe src=\"https://www.youtube.com/embed/abc\" />\n"
    "    </div>\n"
    "  );\n"
    "}\n"
)


def test_unrelated_youtube_iframe_beside_a_sandboxed_ui_frame_is_not_flagged(tmp_path: Path) -> None:
    """A host file with a properly sandboxed ui:// frame and an unrelated YouTube embed was HIGH,
    with the YouTube frame described as an "MCP Apps UI iframe"."""
    (tmp_path / "Host.tsx").write_text(_MIXED_HOST, encoding="utf-8")
    assert McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path)) == []


def test_unsandboxed_ui_frame_beside_a_youtube_iframe_still_fires_on_the_right_line(tmp_path: Path) -> None:
    """The direction traded against: the real UI frame is still caught, and the finding points at
    it (line 6), not at the YouTube frame."""
    (tmp_path / "Host.tsx").write_text(_MIXED_HOST.replace('sandbox="allow-scripts" ', ""), encoding="utf-8")
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.replace("\\", "/") == "Host.tsx:6"
    assert "youtube" not in findings[0].message


def test_ui_scheme_src_iframe_without_sandbox_fires(tmp_path: Path) -> None:
    (tmp_path / "Host.html").write_text(
        '<script>const u = "ui://widget/x";</script>\n<iframe src="ui://widget/x"></iframe>\n',
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert [f.location.replace("\\", "/") for f in findings] == ["Host.html:2"]


def test_guard_applies_universally(tmp_path: Path) -> None:
    assert McpAppsUiIsolationGuard().applies(_prof(tmp_path)) is True


def test_mcp_apps_ui_isolation_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the js comment view, so a string literal quoting
    # the pragma is content. Only a real `//` comment (`test_pragma_suppresses_finding`) opts out.
    (tmp_path / "mcp_ui_host.tsx").write_text(
        'const help = "opt out with // security: allow-mcp-apps-ui-isolation";\n'
        "import { createUIResource } from '@mcp-ui/client';\n\n"
        "function renderUiResource(html: string) {\n"
        "  return <iframe srcDoc={html} />;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpAppsUiIsolationGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["mcp-apps-ui-isolation/iframe-no-hardening-sandbox"]
