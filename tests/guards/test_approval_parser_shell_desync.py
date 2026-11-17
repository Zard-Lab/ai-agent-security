"""Tests for ApprovalParserShellDesyncGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.approval_parser_shell_desync import ApprovalParserShellDesyncGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_stop_parsing_token_unhandled_fires(tmp_path: Path) -> None:
    (tmp_path / "approval.py").write_text(
        "import subprocess\n\n"
        "def is_safe_command(cmd):\n"
        "    return cmd not in DENY_LIST\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        subprocess.run(['pwsh', '-Command', cmd])\n",
        encoding="utf-8",
    )
    findings = ApprovalParserShellDesyncGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "approval-parser-shell-desync/stop-parsing-token-unhandled")
    assert hit.severity == "high"


def test_stop_parsing_token_rejected_is_safe(tmp_path: Path) -> None:
    (tmp_path / "approval.py").write_text(
        "import subprocess\n\n"
        "def is_safe_command(cmd):\n"
        "    if '--%' in cmd:\n"
        "        return False\n"
        "    return cmd not in DENY_LIST\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        subprocess.run(['pwsh', '-Command', cmd])\n",
        encoding="utf-8",
    )
    findings = ApprovalParserShellDesyncGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_bash_only_gate_is_safe(tmp_path: Path) -> None:
    """FP-bait: a command-safety gate that only ever spawns bash, never PowerShell,
    is out of this guard's stated scope."""
    (tmp_path / "approval.py").write_text(
        "import subprocess\n\n"
        "def is_safe_command(cmd):\n"
        "    return cmd not in DENY_LIST\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        subprocess.run(['bash', '-c', cmd])\n",
        encoding="utf-8",
    )
    findings = ApprovalParserShellDesyncGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_approval_gate_is_safe(tmp_path: Path) -> None:
    """FP-bait: a pwsh spawn with no approval/safety check at all is a different
    problem (or none, if the caller is trusted) -- not this guard's shape."""
    (tmp_path / "runner.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    subprocess.run(['pwsh', '-Command', cmd])\n",
        encoding="utf-8",
    )
    findings = ApprovalParserShellDesyncGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "approval.py").write_text(
        "# security: allow-approval-parser-shell-desync\n"
        "import subprocess\n\n"
        "def is_safe_command(cmd):\n"
        "    return cmd not in DENY_LIST\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        subprocess.run(['pwsh', '-Command', cmd])\n",
        encoding="utf-8",
    )
    findings = ApprovalParserShellDesyncGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_guard_applies_universally(tmp_path: Path) -> None:
    assert ApprovalParserShellDesyncGuard().applies(_prof(tmp_path)) is True


# ── review-round fixes: the approved value must reach the spawn, inside one function ──

def _guard_run(tmp_path: Path, name: str, text: str) -> list:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return ApprovalParserShellDesyncGuard().run(tmp_path, _prof(tmp_path))


_RULE = "approval-parser-shell-desync/stop-parsing-token-unhandled"


def test_unrelated_approval_and_literal_pwsh_spawn_is_silent(tmp_path: Path) -> None:
    """FP-bait (review M5): an unrelated `approval_policy()` plus a fully literal pwsh spawn in a
    different function. No approved value reaches the spawn."""
    findings = _guard_run(
        tmp_path, "tasks.py",
        "import subprocess\n\n"
        "def approval_policy():\n"
        "    return True\n\n"
        "def run_fixed():\n"
        "    subprocess.run(['pwsh', '-File', 'fixed.ps1'])\n",
    )
    assert findings == []


def test_approved_value_in_a_different_function_is_silent(tmp_path: Path) -> None:
    """FP-bait: the gate is applied to `cmd` in one function; the pwsh spawn takes `cmd` in
    another. Not one scope, so no claim that the approved value is the one that runs."""
    findings = _guard_run(
        tmp_path, "approval.py",
        "import subprocess\n\n"
        "def check(cmd):\n"
        "    return is_safe_command(cmd)\n\n"
        "def other(cmd):\n"
        "    subprocess.run(['pwsh', '-Command', cmd])\n",
    )
    assert findings == []


def test_membership_gate_then_pwsh_spawn_fires(tmp_path: Path) -> None:
    findings = _guard_run(
        tmp_path, "approval.py",
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if cmd in ALLOWED_COMMANDS:\n"
        "        subprocess.run(['pwsh', '-Command', cmd])\n",
    )
    assert any(f.rule == _RULE for f in findings)


def test_typescript_gate_and_spawn_in_one_function_fires(tmp_path: Path) -> None:
    findings = _guard_run(
        tmp_path, "approval.ts",
        "import { spawn } from 'child_process';\n\n"
        "export function run(cmd: string) {\n"
        "  if (isSafeCommand(cmd)) {\n"
        "    spawn('pwsh', ['-Command', cmd]);\n"
        "  }\n"
        "}\n",
    )
    assert any(f.rule == _RULE for f in findings)


def test_typescript_gate_and_literal_spawn_in_other_functions_is_silent(tmp_path: Path) -> None:
    findings = _guard_run(
        tmp_path, "approval.ts",
        "import { spawn } from 'child_process';\n\n"
        "export function gate(cmd: string) {\n"
        "  return isSafeCommand(cmd);\n"
        "}\n\n"
        "export function fixed() {\n"
        "  spawn('pwsh', ['-File', 'fixed.ps1']);\n"
        "}\n",
    )
    assert findings == []


def test_typescript_same_name_in_different_functions_is_silent(tmp_path: Path) -> None:
    """FP-bait that only function scoping (not identifier linkage alone) keeps quiet."""
    findings = _guard_run(
        tmp_path, "approval.ts",
        "import { spawn } from 'child_process';\n\n"
        "export function gate(cmd: string) {\n"
        "  return isSafeCommand(cmd);\n"
        "}\n\n"
        "export function other(cmd: string) {\n"
        "  spawn('pwsh', ['-Command', cmd]);\n"
        "}\n",
    )
    assert findings == []


def test_gated_value_not_in_pwsh_argv_is_silent(tmp_path: Path) -> None:
    """FP-bait: the gate and a pwsh spawn share a function, but the spawn argv is fully literal."""
    findings = _guard_run(
        tmp_path, "approval.py",
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        subprocess.run(['pwsh', '-File', 'fixed.ps1'])\n",
    )
    assert findings == []


# ── #424 E6 (#1000): the pragma counts only as a real comment, in the file's own grammar ──

_PY_FIRING = (
    "import subprocess\n\n"
    "def is_safe_command(cmd):\n"
    "    return cmd not in DENY_LIST\n\n"
    "def run(cmd):\n"
    "    if is_safe_command(cmd):\n"
    "        subprocess.run(['pwsh', '-Command', cmd])\n"
)
_TS_FIRING = (
    "import { spawn } from 'child_process';\n\n"
    "export function run(cmd: string) {\n"
    "  if (isSafeCommand(cmd)) {\n"
    "    spawn('pwsh', ['-Command', cmd]);\n"
    "  }\n"
    "}\n"
)
_GO_FIRING = (
    "package main\n\n"
    'import "os/exec"\n\n'
    "func run(cmd string) {\n"
    "\tif isSafeCommand(cmd) {\n"
    '\t\texec.Command("pwsh", "-Command", cmd).Run()\n'
    "\t}\n"
    "}\n"
)


def test_approval_parser_shell_desync_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the comment-only view, so a Python string quoting
    # the pragma is content; only a real `#` comment (`test_pragma_suppresses_finding`) opts out.
    findings = _guard_run(
        tmp_path, "approval.py",
        'HELP = "opt out with # security: allow-approval-parser-shell-desync"\n' + _PY_FIRING,
    )
    assert [f.rule for f in findings] == [_RULE]


@pytest.mark.parametrize("marker", ["//", "#"], ids=["slash-form", "hash-form"])
def test_approval_parser_shell_desync_pragma_quoted_in_a_string_does_not_suppress_ts(
    tmp_path: Path, marker: str
) -> None:
    # #424 E6 (#1000): D2 widened the pragma to `//`, so a TS string quoting either comment form must
    # stay content (the CLAUDE.md rule-1 test for that widening).
    findings = _guard_run(
        tmp_path, "approval.ts",
        f'const help = "opt out with {marker} security: allow-approval-parser-shell-desync";\n' + _TS_FIRING,
    )
    assert [f.rule for f in findings] == [_RULE]


def test_approval_parser_shell_desync_ts_slash_comment_pragma_suppresses(tmp_path: Path) -> None:
    # #424 E6 (#1000) D2: TS comments are `//`, and the old `#`-only regex never saw one, so the
    # documented opt-out could not be written in a .ts file at all.
    assert [f.rule for f in _guard_run(tmp_path, "approval.ts", _TS_FIRING)] == [_RULE]
    findings = _guard_run(
        tmp_path, "approval.ts", "// security: allow-approval-parser-shell-desync\n" + _TS_FIRING,
    )
    assert findings == []


@pytest.mark.parametrize("marker", ["//", "#"], ids=["slash-form", "hash-form"])
def test_approval_parser_shell_desync_pragma_quoted_in_a_string_does_not_suppress_go(
    tmp_path: Path, marker: str
) -> None:
    # #424 E6 (#1000): .go reads under the go dialect, so a Go string quoting the pragma is content.
    findings = _guard_run(
        tmp_path, "approval.go",
        _GO_FIRING.replace(
            "package main\n",
            f'package main\n\nconst help = "opt out with {marker} security: allow-approval-parser-shell-desync"\n',
        ),
    )
    assert [f.rule for f in findings] == [_RULE]


def test_approval_parser_shell_desync_go_slash_comment_pragma_suppresses(tmp_path: Path) -> None:
    # #424 E6 (#1000) D2: a real Go `//` comment opts the file out (the old `#`-only regex missed it).
    assert [f.rule for f in _guard_run(tmp_path, "approval.go", _GO_FIRING)] == [_RULE]
    findings = _guard_run(
        tmp_path, "approval.go", "// security: allow-approval-parser-shell-desync\n" + _GO_FIRING,
    )
    assert findings == []
