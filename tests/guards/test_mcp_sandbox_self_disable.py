"""Tests for McpSandboxSelfDisableGuard — planted-violation + FP-bait."""
from __future__ import annotations

import json

from agentsec.guards.mcp_sandbox_self_disable import McpSandboxSelfDisableGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp"}, python_dirs=["."])


def test_dangerously_disable_sandbox_fires(tmp_path: Path) -> None:
    schema = {
        "name": "BashTool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "dangerouslyDisableSandbox": {"type": "boolean"},
            },
        },
    }
    (tmp_path / "tool-schema.json").write_text(json.dumps(schema), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-sandbox-self-disable/llm-settable-disable")
    assert hit.severity == "critical"


def test_readonly_marked_param_is_safe(tmp_path: Path) -> None:
    """FP-bait: readOnly: true means the model cannot set this parameter."""
    schema = {
        "inputSchema": {
            "properties": {
                "noSandbox": {"type": "boolean", "readOnly": True},
            },
        },
    }
    (tmp_path / "tool-schema.json").write_text(json.dumps(schema), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_ops_only_marker_is_safe(tmp_path: Path) -> None:
    """FP-bait: an explicit x-mcp-sandbox-control: ops-only annotation clears it."""
    schema = {
        "name": "BashTool",  # the tool context anchors the ambiguous `allowUnsafe` name
        "inputSchema": {
            "properties": {
                "allowUnsafe": {"type": "boolean", "x-mcp-sandbox-control": "ops-only"},
            },
        },
    }
    (tmp_path / "tool-schema.json").write_text(json.dumps(schema), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_openai_parameters_shape_fires(tmp_path: Path) -> None:
    schema = {
        "type": "function",
        "function": {
            "name": "run_shell",
            "parameters": {
                "properties": {
                    "skipIsolation": {"type": "boolean"},
                },
            },
        },
    }
    (tmp_path / "tool-schema.json").write_text(json.dumps(schema), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-sandbox-self-disable/llm-settable-disable" for f in findings)


def test_anthropic_input_schema_shape_fires(tmp_path: Path) -> None:
    schema = {
        "name": "bash",
        "input_schema": {
            "properties": {
                "disable_sandbox": {"type": "boolean"},
            },
        },
    }
    (tmp_path / "tool-schema.json").write_text(json.dumps(schema), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-sandbox-self-disable/llm-settable-disable" for f in findings)


def test_unrelated_boolean_param_is_safe(tmp_path: Path) -> None:
    """FP-bait: an ordinary, non-sandbox-related boolean parameter must not fire."""
    schema = {
        "inputSchema": {
            "properties": {
                "verbose": {"type": "boolean"},
            },
        },
    }
    (tmp_path / "tool-schema.json").write_text(json.dumps(schema), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    # The pragma is matched against the raw file text before JSON parsing, so it can live
    # in a JSON string value (a real comment isn't valid JSON) without breaking the parse.
    schema = {
        "_note": "security: allow-mcp-sandbox-self-disable",
        "inputSchema": {
            "properties": {
                "dangerouslyDisableSandbox": {"type": "boolean"},
            },
        },
    }
    (tmp_path / "tool-schema.json").write_text(json.dumps(schema), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_applies_to_llm_feature_without_mcp(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"llm"}, python_dirs=["."])
    assert McpSandboxSelfDisableGuard().applies(prof) is True


def test_guard_not_applicable_without_mcp_or_llm(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpSandboxSelfDisableGuard().applies(prof) is False


# --------------------------------------------------------------------------- PR #963 review round
def _scan(tmp_path: Path, doc: object, name: str = "tool-schema.json") -> list[tuple[str, str]]:
    (tmp_path / name).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    return [(f.rule, f.location) for f in findings]


_FIRES = "mcp-sandbox-self-disable/llm-settable-disable"


def test_allow_unsafe_html_on_a_renderer_is_not_a_sandbox_disable(tmp_path: Path) -> None:
    """The review's repro: an HTML-rendering flag is not containment."""
    schema = {
        "name": "RenderMarkdown",
        "inputSchema": {
            "properties": {"text": {"type": "string"}, "allowUnsafeHtml": {"type": "boolean"}},
        },
    }
    assert _scan(tmp_path, schema) == []


def test_allow_unsafe_on_a_tool_described_as_running_shell_commands_still_fires(tmp_path: Path) -> None:
    schema = {
        "name": "run",
        "description": "Run a shell command for the user",
        "inputSchema": {"properties": {"allowUnsafe": {"type": "boolean"}}},
    }
    assert [rule for rule, _ in _scan(tmp_path, schema)] == [_FIRES]


def test_allow_unsafe_with_an_anchor_in_the_parameter_name_still_fires(tmp_path: Path) -> None:
    schema = {
        "name": "Widget",
        "inputSchema": {"properties": {"allowUnsafeExecution": {"type": "boolean"}}},
    }
    assert [rule for rule, _ in _scan(tmp_path, schema)] == [_FIRES]


def test_allow_unsafe_with_an_anchor_in_the_property_description_still_fires(tmp_path: Path) -> None:
    schema = {
        "name": "Widget",
        "inputSchema": {
            "properties": {
                "allowUnsafe": {"type": "boolean", "description": "Disable the sandbox for this call"}
            }
        },
    }
    assert [rule for rule, _ in _scan(tmp_path, schema)] == [_FIRES]


def test_ops_only_marker_still_clears_an_anchored_allow_unsafe(tmp_path: Path) -> None:
    schema = {
        "name": "BashTool",
        "inputSchema": {
            "properties": {"allowUnsafe": {"type": "boolean", "x-llm-settable": False}}
        },
    }
    assert _scan(tmp_path, schema) == []


def test_self_anchored_names_need_no_context(tmp_path: Path) -> None:
    """Narrowing pin: `dangerouslyDisableSandbox` and friends fire with no tool context at all."""
    schema = {"inputSchema": {"properties": {"skipIsolation": {"type": "boolean"}}}}
    assert [rule for rule, _ in _scan(tmp_path, schema)] == [_FIRES]


def test_findings_carry_the_line_of_the_offending_property(tmp_path: Path) -> None:
    """Two tools in one file: each finding points at its own property, not just the file."""
    doc = {
        "tools": [
            {
                "name": "bash",
                "inputSchema": {"properties": {"dangerouslyDisableSandbox": {"type": "boolean"}}},
            },
            {
                "name": "shell",
                "inputSchema": {"properties": {"dangerouslyDisableSandbox": {"type": "boolean"}}},
            },
        ]
    }
    (tmp_path / "tools.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    lines = (tmp_path / "tools.json").read_text(encoding="utf-8").splitlines()
    expected = [i + 1 for i, ln in enumerate(lines) if '"dangerouslyDisableSandbox"' in ln]
    assert len(expected) == 2
    findings = McpSandboxSelfDisableGuard().run(tmp_path, _mcp_prof(tmp_path))
    got = sorted(int(f.location.rsplit(":", 1)[1]) for f in findings)
    assert got == expected


def test_deeply_nested_json_file_does_not_zero_the_guard(tmp_path: Path) -> None:
    """RecursionError from one hostile file used to escape the loader; the real finding must survive."""
    (tmp_path / "deep.json").write_text('{"properties": ' + '[' * 200_000 + ']' * 200_000 + "}", encoding="utf-8")
    schema = {
        "name": "Widget",
        "inputSchema": {"properties": {"allowUnsafeExecution": {"type": "boolean"}}},
    }
    assert [rule for rule, _ in _scan(tmp_path, schema)] == [_FIRES]
