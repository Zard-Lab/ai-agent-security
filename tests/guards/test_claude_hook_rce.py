"""Tests for ClaudeHookRceGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

import json

from agentsec.guards.claude_hook_rce import ClaudeHookRceGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def _hook_settings(command: str) -> dict[str, object]:
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": command}],
                },
            ],
        },
    }


def _write(root: Path, data: dict[str, object], name: str = "settings.json") -> None:
    d = root / ".claude"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(data), encoding="utf-8")


# ── unquoted-variable-interpolation ──────────────────────────────────────────

def test_unquoted_variable_interpolation_fires(tmp_path: Path) -> None:
    _write(tmp_path, _hook_settings("echo $CLAUDE_TOOL_INPUT >> /tmp/log"))
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "claude-hook-rce/unquoted-variable-interpolation")
    assert hit.severity == "high"


def test_unquoted_braced_variable_fires(tmp_path: Path) -> None:
    _write(tmp_path, _hook_settings("echo ${CLAUDE_TOOL_INPUT} >> /tmp/log"))
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "claude-hook-rce/unquoted-variable-interpolation" for f in findings)


def test_double_quoted_variable_is_safe(tmp_path: Path) -> None:
    """FP-bait: a double-quoted expansion suppresses word-splitting/globbing — not flagged."""
    _write(tmp_path, _hook_settings('echo "$CLAUDE_TOOL_INPUT" >> /tmp/log'))
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "claude-hook-rce/unquoted-variable-interpolation" for f in findings)


def test_variable_in_middle_of_double_quoted_string_is_safe(tmp_path: Path) -> None:
    """FP-bait: a variable inside a longer double-quoted string (not immediately adjacent to the
    quote characters) must still be recognized as quoted — a real quote-state walk, not a
    per-character lookaround."""
    _write(tmp_path, _hook_settings('echo "prefix $CLAUDE_TOOL_INPUT suffix" >> /tmp/log'))
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "claude-hook-rce/unquoted-variable-interpolation" for f in findings)


def test_single_quoted_variable_is_safe(tmp_path: Path) -> None:
    """FP-bait: a single-quoted expansion is fully literal (no expansion at all)."""
    _write(tmp_path, _hook_settings("echo '$CLAUDE_TOOL_INPUT' >> /tmp/log"))
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "claude-hook-rce/unquoted-variable-interpolation" for f in findings)


def test_no_variable_at_all_is_safe(tmp_path: Path) -> None:
    _write(tmp_path, _hook_settings("echo hello >> /tmp/log"))
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── settings-local-hooks-pre-trust ───────────────────────────────────────────

def test_settings_local_hooks_fires(tmp_path: Path) -> None:
    _write(tmp_path, _hook_settings('echo "$CLAUDE_TOOL_INPUT"'), name="settings.local.json")
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "claude-hook-rce/settings-local-hooks-pre-trust")
    assert hit.severity == "high"


def test_settings_json_hooks_is_not_the_local_rule(tmp_path: Path) -> None:
    """FP-bait: hooks in the checked-in settings.json (not settings.local.json) must not fire
    the pre-trust rule — that rule is specifically about the personal override file."""
    _write(tmp_path, _hook_settings('echo "$CLAUDE_TOOL_INPUT"'), name="settings.json")
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "claude-hook-rce/settings-local-hooks-pre-trust" for f in findings)


def test_settings_local_with_no_hooks_is_safe(tmp_path: Path) -> None:
    _write(tmp_path, {"permissions": {"allow": []}}, name="settings.local.json")
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_settings_local_with_empty_hooks_is_safe(tmp_path: Path) -> None:
    _write(tmp_path, {"hooks": {}}, name="settings.local.json")
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── suppression / applies() ──────────────────────────────────────────────────

def test_pragma_suppresses_all_findings(tmp_path: Path) -> None:
    data = _hook_settings("echo $CLAUDE_TOOL_INPUT")
    data["//"] = "security: allow-claude-hook-rce"
    _write(tmp_path, data)
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_universally(tmp_path: Path) -> None:
    assert ClaudeHookRceGuard().applies(_prof(tmp_path)) is True


def test_deeply_nested_json_file_does_not_hide_other_findings(tmp_path: Path) -> None:
    """A crafted, deeply nested settings file raises RecursionError inside json.loads. It must be
    skipped like any unparseable file, and a real finding in a sibling file must survive."""
    _write(tmp_path, _hook_settings("echo $CLAUDE_TOOL_INPUT >> /tmp/log"))
    (tmp_path / ".claude" / "settings.local.json").write_text(
        "[" * 200000 + "]" * 200000, encoding="utf-8"
    )
    findings = ClaudeHookRceGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "claude-hook-rce/unquoted-variable-interpolation" for f in findings)
