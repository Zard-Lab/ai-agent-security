---
type: Guard
title: "claude-routines-security"
description: "A Claude Code Routine grants an over-broad permission, an unstable schedule, or no audit log."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "claude-routines-security"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM06", "OWASP-ASI:ASI04", "CWE-88", "CWE-778"]
---

# Claude Code Routine grants an over-broad permission, an unstable schedule, or no audit log

_Author — 2026-09-26_

---

## The threat

Claude Code Routines run a saved prompt on a schedule, unattended, with no interactive human in
the loop to catch an over-broad permission grant or a malicious schedule the way a live session
would. This is a structural gap, not a named CVE: Anthropic's own Routines feature (research
preview, 2026-04-14) had no coverage anywhere in agentsec before this guard. Sourced from
`agent-audit-kit`'s `routines.py` (AAK-ROUTINE-001..003), verified against the real repo source.

## Why it's often introduced

A routine is set up quickly to automate a recurring task, and the permission scope granted is
whatever gets the routine working without friction — a wildcard is the path of least resistance
compared to scoping down to exactly what's needed. A schedule built from a config value or
environment variable is convenient when the schedule needs to vary per deployment, and audit
logging is easy to forget for something that "just runs in the background."

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans `.claude/routines/*.{json,yml,yaml}` files. Deliberately TEXT-based, not
   schema-parsed: this is a research-preview feature with no stable, fully-documented schema to
   parse against yet, so raw-text pattern matching is the more honest posture than assuming field
   names that may not survive the feature reaching general availability.
3. **permission-surface-wider-than-interactive** (MEDIUM): a wildcard permission scope
   (`fs:*`, `shell:exec` with no scoped command, `shell:exec:*`, `network:*`) appears anywhere in
   the file. A command-scoped form such as `shell:exec:<one specific command>` names one command
   and is not a wildcard.
4. **schedule-from-runtime-state** (HIGH): the `schedule` field's value contains a
   template/interpolation marker (`${...}`, `{{...}}`, or a bare `$VAR`) rather than a fixed
   cron-like literal.
5. **no-audit-log-declaration** (MEDIUM): the file grants a wildcard permission (rule 3) but no
   `audit_log`/`auditLog`/`audit-log` field is set to a truthy/enabled value (`true`/`enabled`/
   `on`) anywhere in the file.
6. Suppress with `# security: allow-claude-routines-security` (or the pragma text as a string
   value, in a JSON or a YAML routine). Because that string form is documented for YAML too, the
   check stays a raw-text match in both formats (#1040 T5): a YAML comment view would void it.

## When NOT to flag

- Only scoped, non-wildcard permissions (e.g. `fs:read:/reports`).
- A fixed, literal cron-like schedule string.
- A wildcard permission paired with an audit-log field set to a truthy value.
- No wildcard permission at all — the audit-log rule has nothing to react to.
- A file outside `.claude/routines/`.

## Tests

| Test | What it checks |
|---|---|
| `test_wildcard_permission_fires` / `test_scoped_permission_is_safe` | Wildcard vs. scoped permission |
| `test_command_scoped_shell_permission_is_safe` | FP-bait: a command-scoped `shell:exec:...` is not the unscoped wildcard |
| `test_unscoped_shell_exec_still_fires_in_each_spelling` | Still fires: bare `shell:exec` (JSON and YAML) and `shell:exec:*` |
| `test_schedule_with_template_interpolation_fires` / `test_fixed_schedule_literal_is_safe` | Templated vs. fixed schedule |
| `test_wildcard_permission_with_no_audit_log_fires` / `test_wildcard_permission_with_audit_log_is_safe` | Missing vs. present audit-log declaration |
| `test_no_wildcard_permission_no_audit_rule_regardless` | FP-bait: no wildcard permission at all |
| `test_yaml_routine_also_scanned` | `.yaml` routine files are scanned too |
| `test_file_outside_routines_dir_is_ignored` | A file outside `.claude/routines/` is ignored |
| `test_pragma_suppresses_all_findings` | Inline pragma silences every rule |
| `test_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- Text-based pattern matching, not schema-aware: a wildcard permission expressed a syntactically
  different way this guard's fixed vocabulary doesn't name is invisible.
- The schedule check only recognizes `${...}`/`{{...}}`/bare-`$VAR` interpolation markers; a
  schedule built from runtime state through some OTHER mechanism (string concatenation in a
  wrapper script that generates the routine file, for instance) is not visible in the static file.
- The audit-log check is presence-based on a field name/value pair anywhere in the file, not
  scoped to confirm it actually applies to the SAME routine (a multi-routine file with one
  audited and one unaudited entry could under-report).
- This guard was built against a research-preview feature's still-evolving surface, deliberately
  without assuming a stable schema — as the feature matures, a schema-aware rewrite may become
  both possible and more precise than this text-based approach.

## What this guard does NOT prove

Silence does not prove a Claude Code Routine is safe to run unattended — only that these three
specific shapes are absent. Whether the routine's PROMPT itself does something dangerous, or
whether the granted permissions (even if scoped) are appropriate for the task, is outside this
guard's scope.

# Citations

[1] agentsec checklist item `4-claude-routines-security` (§4)
[2] Anthropic Claude Code Routines (research preview, 2026-04-14)
[3] OWASP-LLM:LLM06, OWASP-ASI:ASI04, CWE-88 (Argument Injection), CWE-778 (Insufficient Logging)
[4] agent-audit-kit `routines.py`, rules AAK-ROUTINE-001..003
