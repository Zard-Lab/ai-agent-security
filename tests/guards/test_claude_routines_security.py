"""Tests for ClaudeRoutinesSecurityGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.claude_routines_security import ClaudeRoutinesSecurityGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def _write_routine(root: Path, name: str, content: str) -> None:
    d = root / ".claude" / "routines"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(content, encoding="utf-8")


# ── permission-surface-wider-than-interactive ────────────────────────────────

def test_wildcard_permission_fires(tmp_path: Path) -> None:
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "0 9 * * *", "permissions": ["shell:exec", "network:*"]}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    hit = next(
        f for f in findings
        if f.rule == "claude-routines-security/permission-surface-wider-than-interactive"
    )
    assert hit.severity == "medium"


def test_scoped_permission_is_safe(tmp_path: Path) -> None:
    """FP-bait: a scoped, non-wildcard permission is not flagged."""
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "0 9 * * *", "permissions": ["fs:read:/reports"], '
        '"audit_log": true}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── schedule-from-runtime-state ───────────────────────────────────────────────

def test_schedule_with_template_interpolation_fires(tmp_path: Path) -> None:
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "${CRON_EXPR}", "audit_log": true}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "claude-routines-security/schedule-from-runtime-state" for f in findings)


def test_fixed_schedule_literal_is_safe(tmp_path: Path) -> None:
    """FP-bait: a fixed cron-like literal schedule is the safe form."""
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "0 9 * * *", "audit_log": true}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "claude-routines-security/schedule-from-runtime-state" for f in findings)


# ── no-audit-log-declaration ──────────────────────────────────────────────────

def test_wildcard_permission_with_no_audit_log_fires(tmp_path: Path) -> None:
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "0 9 * * *", "permissions": ["network:*"]}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "claude-routines-security/no-audit-log-declaration" for f in findings)


def test_wildcard_permission_with_audit_log_is_safe(tmp_path: Path) -> None:
    """FP-bait: a wildcard permission WITH an audit-log declaration doesn't fire the audit rule."""
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "0 9 * * *", "permissions": ["network:*"], '
        '"audit_log": true}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "claude-routines-security/no-audit-log-declaration" for f in findings)


def test_no_wildcard_permission_no_audit_rule_regardless(tmp_path: Path) -> None:
    """FP-bait: with no wildcard permission at all, the audit-log rule has nothing to react to."""
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "0 9 * * *"}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── file scoping / YAML / suppression ────────────────────────────────────────

def test_yaml_routine_also_scanned(tmp_path: Path) -> None:
    _write_routine(
        tmp_path, "nightly.yaml",
        "prompt: x\nschedule: \"0 9 * * *\"\npermissions:\n  - shell:exec\n",
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert any(
        f.rule == "claude-routines-security/permission-surface-wider-than-interactive"
        for f in findings
    )


def test_file_outside_routines_dir_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        '{"permissions": ["shell:exec", "network:*"]}\n', encoding="utf-8",
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_all_findings(tmp_path: Path) -> None:
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "${CRON_EXPR}", "permissions": ["shell:exec"], '
        '"//": "security: allow-claude-routines-security"}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_universally(tmp_path: Path) -> None:
    assert ClaudeRoutinesSecurityGuard().applies(_prof(tmp_path)) is True


def test_command_scoped_shell_permission_is_safe(tmp_path: Path) -> None:
    """FP-bait: `shell:exec:git status --short` names ONE command, so it is not the unscoped
    `shell:exec` wildcard (the docstring targets 'shell:exec with no scoped command')."""
    _write_routine(
        tmp_path, "nightly.json",
        '{"prompt": "x", "schedule": "0 9 * * *", "permissions": ["shell:exec:git status --short"], '
        '"audit_log": true}\n',
    )
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_unscoped_shell_exec_still_fires_in_each_spelling(tmp_path: Path) -> None:
    """Still fires (the traded-against direction): bare `shell:exec` at a JSON string end, in a
    YAML list item, and with an explicit `:*` scope."""
    for i, perms in enumerate((
        '{"permissions": ["shell:exec"], "audit_log": true}\n',
        '{"permissions": ["shell:exec:*"], "audit_log": true}\n',
        'permissions:\n  - shell:exec\naudit_log: true\n',
    )):
        _write_routine(tmp_path, f"r{i}.{'yml' if perms.startswith('perm') else 'json'}", perms)
    findings = ClaudeRoutinesSecurityGuard().run(tmp_path, _prof(tmp_path))
    hit_files = {
        f.location.replace("\\", "/").rsplit("/", 1)[-1].split(":")[0] for f in findings
        if f.rule == "claude-routines-security/permission-surface-wider-than-interactive"
    }
    assert hit_files == {"r0.json", "r1.json", "r2.yml"}
