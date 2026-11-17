"""Tests for McpTransportFlipGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.mcp_transport_flip import McpTransportFlipGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp"})


def test_dual_transport_declaration_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        '{\n'
        '  "mcpServers": {\n'
        '    "app": {\n'
        '      "url": "https://mcp.example.com/sse",\n'
        '      "transport": "sse",\n'
        '      "command": "npx",\n'
        '      "args": ["-y", "@example/mcp-server"]\n'
        '    }\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = McpTransportFlipGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-transport-flip/dual-transport-declaration")
    assert hit.severity == "high"


def test_url_only_no_command_is_safe(tmp_path: Path) -> None:
    """FP-bait: a pure network-transport entry with no stdio launcher fields is not a flip risk."""
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"app": {"url": "https://mcp.example.com/sse", "transport": "sse"}}}\n',
        encoding="utf-8",
    )
    findings = McpTransportFlipGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_command_only_no_url_is_safe(tmp_path: Path) -> None:
    """FP-bait: a pure stdio-launched entry with no network transport declared is the ordinary,
    single-transport shape."""
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"app": {"command": "npx", "args": ["-y", "@example/mcp-server"]}}}\n',
        encoding="utf-8",
    )
    findings = McpTransportFlipGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_url_without_transport_field_still_fires_with_command(tmp_path: Path) -> None:
    """A bare `url` field (no explicit transport key) is still a network-transport declaration."""
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"app": {"url": "https://mcp.example.com/", "command": "npx"}}}\n',
        encoding="utf-8",
    )
    findings = McpTransportFlipGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "mcp-transport-flip/dual-transport-declaration" for f in findings)


def test_different_entries_each_single_transport_is_safe(tmp_path: Path) -> None:
    """FP-bait: two SEPARATE server entries, each single-transport, is the correct pattern for
    offering both a remote and a local variant of a server."""
    (tmp_path / "mcp.json").write_text(
        '{\n'
        '  "mcpServers": {\n'
        '    "app-remote": {"url": "https://mcp.example.com/sse", "transport": "sse"},\n'
        '    "app-local": {"command": "npx", "args": ["-y", "@example/mcp-server"]}\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = McpTransportFlipGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        '{\n'
        '  "//": "security: allow-mcp-transport-flip",\n'
        '  "mcpServers": {\n'
        '    "app": {"url": "https://mcp.example.com/sse", "transport": "sse", "command": "npx"}\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = McpTransportFlipGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_requires_mcp(tmp_path: Path) -> None:
    guard = McpTransportFlipGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False


def test_deeply_nested_json_file_does_not_hide_other_findings(tmp_path: Path) -> None:
    """A crafted, deeply nested config raises RecursionError inside json.loads. It must be skipped
    like any unparseable file, and a real finding in another config must survive."""
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"app": {"url": "https://mcp.example.com/sse", "transport": "sse",'
        ' "command": "npx"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "mcp.json").write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
    findings = McpTransportFlipGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "mcp-transport-flip/dual-transport-declaration" for f in findings)
