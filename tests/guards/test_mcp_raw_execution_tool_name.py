from __future__ import annotations

import pytest

from agentsec.findings import _is_review_finding
from agentsec.guards.mcp_raw_execution_tool_name import McpRawExecutionToolNameGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


# --- dangerous-tool-name ---------------------------------------------------------------------


@pytest.mark.parametrize("name", ["eval", "exec", "system", "subprocess", "run_shell", "shell_exec"])
def test_flags_each_raw_execution_name(tmp_path: Path, name: str) -> None:
    (tmp_path / "mcp_tools.py").write_text(
        "TOOL = {\n"
        f'    "name": "{name}",\n'
        '    "description": "Runs a thing",\n'
        '    "inputSchema": {"type": "object", "properties": {}},\n'
        "}\n",
        encoding="utf-8",
    )
    findings = McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-raw-execution-tool-name/dangerous-tool-name" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_is_a_surfacing_signal_not_a_proven_bug() -> None:
    # A name is evidence of intent, not of reachable execution: the guard ranks below a proven
    # finding of the same severity and does not claim CRITICAL on a string alone.
    assert McpRawExecutionToolNameGuard.surfacing is True


def test_findings_are_review_signals(tmp_path: Path) -> None:
    # #766: this flat `surfacing = True` was pinned by the checkmeta allowlist's own test, which
    # #766 deleted along with the allowlist. This is its replacement, and it runs the guard.
    (tmp_path / "mcp_tools.py").write_text(
        'TOOL = {"name": "exec", "description": "Runs a thing", "inputSchema": {"type": "object"}}\n',
        encoding="utf-8",
    )
    findings = McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings
    assert all(_is_review_finding(f) for f in findings)


def test_flags_uppercase_name_case_insensitively(tmp_path: Path) -> None:
    (tmp_path / "mcp_tools.py").write_text(
        "TOOL = {\n"
        '    "name": "EVAL",\n'
        '    "description": "Evaluate",\n'
        '    "inputSchema": {"type": "object", "properties": {}},\n'
        "}\n",
        encoding="utf-8",
    )
    findings = McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-raw-execution-tool-name/dangerous-tool-name" for f in findings)


def test_fires_with_description_key_only_no_inputschema(tmp_path: Path) -> None:
    # Still-fires direction for the per-file MCP marker: a description-only tool dict in a file
    # that imports the MCP SDK is a tool declaration.
    (tmp_path / "mcp_tools.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "TOOL = {\n"
        '    "name": "exec",\n'
        '    "description": "Executes a command",\n'
        "}\n",
        encoding="utf-8",
    )
    findings = McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-raw-execution-tool-name/dangerous-tool-name" for f in findings)


def test_inputschema_tool_dict_fires_in_a_file_without_an_mcp_import(tmp_path: Path) -> None:
    # Still-fires direction: tool schemas often live in their own module that the server file
    # imports. `inputSchema` is MCP's own camelCase key, so it needs no per-file import marker.
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\nfrom tools import TOOLS\n", encoding="utf-8"
    )
    (tmp_path / "tools.py").write_text(
        "TOOLS = [{\n"
        '    "name": "run_shell",\n'
        '    "description": "Run a shell command",\n'
        '    "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},\n'
        "}]\n",
        encoding="utf-8",
    )
    findings = McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location.replace("\\", "/") for f in findings] == ["tools.py:2"]


@pytest.mark.parametrize(
    "body",
    [
        'UNITS = [{"name": "system", "description": "SI measurement system"}]\n',
        'MSG = {"role": "tool", "name": "system", "description": "x"}\n',
        'DEP = {"name": "subprocess", "description": "stdlib module", "url": "https://docs"}\n',
    ],
)
def test_description_only_dict_outside_an_mcp_file_does_not_fire(tmp_path: Path, body: str) -> None:
    # FP bait: the repo is MCP (repo-level feature), but this file never touches MCP, so a
    # {"name": ..., "description": ...} dict here is ordinary data, not a tool declaration.
    (tmp_path / "server.py").write_text("from mcp.server.fastmcp import FastMCP\n", encoding="utf-8")
    (tmp_path / "models.py").write_text(body, encoding="utf-8")
    assert McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_tool_dict_under_tests_dir_is_skipped_but_fires_in_product_code(tmp_path: Path) -> None:
    # Pins the non-product path skip in both directions: the same tool dict is silent under
    # tests/ and fires under app/.
    tool = (
        "TOOL = {\n"
        '    "name": "eval",\n'
        '    "description": "Evaluate",\n'
        '    "inputSchema": {"type": "object", "properties": {}},\n'
        "}\n"
    )
    for d in ("tests", "app"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "mcp_tools.py").write_text(tool, encoding="utf-8")
    findings = McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location.replace("\\", "/") for f in findings] == ["app/mcp_tools.py:2"]


# --- FP bait: a dangerous WORD as a SEGMENT inside an ordinary name must never fire -----------


@pytest.mark.parametrize(
    "name",
    ["execute_query", "system_info", "get_system_status", "subprocess_log_viewer", "run_shell_history"],
)
def test_dangerous_word_as_segment_does_not_fire(tmp_path: Path, name: str) -> None:
    # FP bait: only the BARE primitive name is the signal (exact equality, matching the source's
    # own `tool_name.lower() in DANGEROUS_TOOLS` design) -- a word merely appearing as a segment
    # inside an ordinary, benign tool name must stay silent.
    (tmp_path / "mcp_tools.py").write_text(
        "TOOL = {\n"
        f'    "name": "{name}",\n'
        '    "description": "Does an ordinary thing",\n'
        '    "inputSchema": {"type": "object", "properties": {}},\n'
        "}\n",
        encoding="utf-8",
    )
    assert McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_mutating_verb_names_are_not_this_guards_concern(tmp_path: Path) -> None:
    # FP bait: delete/drop_table/rm/truncate are deliberately NOT in this guard's name set --
    # they're handled by mcp_tool_description_injection.py's disclosure-based mutating-verb
    # rules instead (see the module docstring). This guard must stay silent on them.
    (tmp_path / "mcp_tools.py").write_text(
        "TOOL = {\n"
        '    "name": "delete_record",\n'
        '    "description": "Deletes a record",\n'
        '    "inputSchema": {"type": "object", "properties": {}},\n'
        "}\n",
        encoding="utf-8",
    )
    assert McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_name_without_schema_or_description_does_not_fire(tmp_path: Path) -> None:
    # FP bait: an unrelated dict that happens to have a "name" key but no inputSchema/description
    # -- not a real MCP tool-schema declaration.
    (tmp_path / "config.py").write_text(
        "PAYLOAD = {\n"
        '    "name": "eval",\n'
        '    "value": 42,\n'
        "}\n",
        encoding="utf-8",
    )
    assert McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_docstring_mention_does_not_fire(tmp_path: Path) -> None:
    # FP bait: the dangerous name appearing only inside a string/comment, never as a real dict
    # literal's "name" value, must stay silent.
    (tmp_path / "notes.py").write_text(
        '"""This module never registers a tool named eval or exec."""\n'
        "# name: eval -- just documentation, not a real dict\n"
        "def run():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


# --- shared: pragma, applies() -----------------------------------------------------------------


def test_pragma_suppresses_the_rule(tmp_path: Path) -> None:
    (tmp_path / "mcp_tools.py").write_text(
        "# security: allow-mcp-raw-execution-tool-name\n"
        "TOOL = {\n"
        '    "name": "eval",\n'
        '    "description": "Evaluate",\n'
        '    "inputSchema": {"type": "object", "properties": {}},\n'
        "}\n",
        encoding="utf-8",
    )
    assert McpRawExecutionToolNameGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_applies_requires_only_mcp_feature(tmp_path: Path) -> None:
    guard = McpRawExecutionToolNameGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False
