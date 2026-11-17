"""Tests for SharedResourceAuthzGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.shared_resource_authz import SharedResourceAuthzGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp"})


def test_shared_mutating_tool_with_no_authz_field_fires(tmp_path: Path) -> None:
    (tmp_path / "tools.json").write_text(
        '{\n'
        '  "scope": "shared",\n'
        '  "tools": [\n'
        '    {\n'
        '      "name": "delete_file",\n'
        '      "description": "Delete a file record",\n'
        '      "inputSchema": {"properties": {"file_id": {"type": "string"}}}\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "shared-resource-authz/no-per-actor-authz" for f in findings)


def test_shared_mutating_tool_with_authz_field_is_safe(tmp_path: Path) -> None:
    """FP-bait: an owner field in the schema is a legitimate mitigation."""
    (tmp_path / "tools.json").write_text(
        '{\n'
        '  "scope": "shared",\n'
        '  "tools": [\n'
        '    {\n'
        '      "name": "delete_file",\n'
        '      "description": "Delete a file record",\n'
        '      "inputSchema": {"properties": {"file_id": {"type": "string"}, '
        '"owner_id": {"type": "string"}}}\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_non_shared_mutating_tool_is_safe(tmp_path: Path) -> None:
    """FP-bait: no multi-agent/shared-scope precondition means no finding."""
    (tmp_path / "tools.json").write_text(
        '{\n'
        '  "tools": [\n'
        '    {\n'
        '      "name": "delete_file",\n'
        '      "description": "Delete a file record",\n'
        '      "inputSchema": {"properties": {"file_id": {"type": "string"}}}\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_non_mutating_tool_is_safe(tmp_path: Path) -> None:
    """FP-bait: a read-only tool on a shared resource is not a mutation risk."""
    (tmp_path / "tools.json").write_text(
        '{\n'
        '  "scope": "shared",\n'
        '  "tools": [\n'
        '    {\n'
        '      "name": "get_file",\n'
        '      "description": "Fetch a file record",\n'
        '      "inputSchema": {"properties": {"file_id": {"type": "string"}}}\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_multi_agent_list_signal_fires(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        '{\n'
        '  "agents": ["writer", "reviewer"],\n'
        '  "tools": [\n'
        '    {\n'
        '      "name": "remove_memory_entry",\n'
        '      "description": "Removes a memory entry",\n'
        '      "parameters": {"properties": {"entry_id": {"type": "string"}}}\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "shared-resource-authz/no-per-actor-authz" for f in findings)


def test_global_ok_marker_suppresses(tmp_path: Path) -> None:
    (tmp_path / "tools.json").write_text(
        '{\n'
        '  "scope": "shared",\n'
        '  "tools": [\n'
        '    {\n'
        '      "name": "delete_file",\n'
        '      "description": "Delete a file record",\n'
        '      "x-aak-shared-authz": "global-ok",\n'
        '      "inputSchema": {"properties": {"file_id": {"type": "string"}}}\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "tools.json").write_text(
        '// security: allow-shared-resource-authz\n'
        '{\n'
        '  "scope": "shared",\n'
        '  "tools": [\n'
        '    {\n'
        '      "name": "delete_file",\n'
        '      "description": "Delete a file record",\n'
        '      "inputSchema": {"properties": {"file_id": {"type": "string"}}}\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_guard_applies_to_mcp_and_llm(tmp_path: Path) -> None:
    guard = SharedResourceAuthzGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"llm"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False


_TOOLS_JSON = (
    '{\n'
    '  "scope": "shared",\n'
    '  "tools": [\n'
    '    {\n'
    '      "name": "delete_file",\n'
    '      "description": "Delete a file record",\n'
    '      "inputSchema": {"properties": {"file_id": {"type": "string"}}}\n'
    '    }\n'
    '  ]\n'
    '}\n'
)


def test_utf8_bom_tools_file_still_fires(tmp_path: Path) -> None:
    """A Windows editor's BOM must not make the guard silently skip the file."""
    (tmp_path / "tools.json").write_text(_TOOLS_JSON, encoding="utf-8-sig")
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "shared-resource-authz/no-per-actor-authz" for f in findings)


def test_json_safe_pragma_key_suppresses_and_file_stays_valid_json(tmp_path: Path) -> None:
    """The documented pragma form is a `"//"` key: the descriptor file remains parseable by every
    other consumer (a `//` comment line makes it invalid JSON)."""
    import json

    body = '{\n  "//": "security: allow-shared-resource-authz",\n' + _TOOLS_JSON.split("{\n", 1)[1]
    path = tmp_path / "tools.json"
    path.write_text(body, encoding="utf-8")
    json.loads(path.read_text(encoding="utf-8"))  # must not raise
    assert SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path)) == []
    # Direction traded against: the same file without the pragma key still fires.
    path.write_text(_TOOLS_JSON, encoding="utf-8")
    assert SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path)) != []


def test_deeply_nested_json_file_does_not_zero_the_guard(tmp_path: Path) -> None:
    """A hostile deep-nesting tools file used to raise RecursionError; the real finding survives."""
    (tmp_path / "deep.json").write_text(
        '{"name": "x", "tools": [{"inputSchema": ' + "[" * 200_000 + "]" * 200_000 + "}]}", encoding="utf-8"
    )
    (tmp_path / "tools.json").write_text(_TOOLS_JSON, encoding="utf-8")
    findings = SharedResourceAuthzGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "shared-resource-authz/no-per-actor-authz" for f in findings)
