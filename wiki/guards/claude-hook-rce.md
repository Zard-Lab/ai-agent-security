---
type: Guard
title: "claude-hook-rce"
description: "A Claude Code hook command interpolates a shell variable with no quoting, or is defined in the personal settings.local.json rather than the reviewed settings.json."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "claude-hook-rce"
checklist_section: ["8"]
standards: ["CWE-78", "CWE-88", "CWE-284", "OWASP:A01"]
---

# Claude Code hook command is exploitable — unquoted variable expansion or a pre-trust local hook

_Author — 2026-09-26_

---

## The threat

Claude Code hooks (`.claude/settings.json`'s `hooks` key: `PreToolUse`/`PostToolUse`/etc, each
mapping to `[{"matcher": ..., "hooks": [{"type": "command", "command": "..."}]}]`) run a shell
command on tool-use events. CVE-2025-59536 disclosed two ways this becomes remote code execution:
a hook command interpolating a shell variable with no quoting at all (subject to word-splitting
and glob expansion if the variable's value is tool-input influenced), and a hook planted in
`.claude/settings.local.json` — the personal, typically-gitignored override file, not the
checked-in `settings.json` a team reviews — which runs on the next tool-use event without going
through the same review path. Sourced from `agent-audit-kit`'s `hook_rce.py`
(AAK-HOOK-RCE-001/003), verified against the real repo source.

**Deliberately not ported: a third AAK rule** (`shell:true`/dynamic-string execution in an
externally-referenced hook SCRIPT's own source) — that requires resolving and reading whatever
file the hook's `command` field points at, a different concern already covered by
`js-command-injection`/`command_injection` wherever that script actually lives, rather than
something specific to the hook JSON wiring this guard focuses on.

## Why it's often introduced

A hook command is written to log or forward tool-call context (`$CLAUDE_TOOL_INPUT` and similar
variables Claude Code exposes to hooks) quickly, and unquoted variable expansion is the path of
least resistance in a one-line shell command — the double-quote requirement for safe expansion is
an easy detail to skip when a hook is written and tested against benign input. `settings.local.json`
is, by design, meant for personal untracked overrides, which is exactly what makes it an appealing
place to plant a hook that skips code review entirely.

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans `settings.json`/`settings.local.json` files sitting directly inside a `.claude/`
   directory (`iter_files_named`, `respect_gitignore=False`).
3. **settings-local-hooks-pre-trust** (HIGH): the file is specifically `settings.local.json` and
   its `hooks` key is a non-empty object.
4. **unquoted-variable-interpolation** (HIGH): for every hook `command` string found under
   `hooks.<event>[*].hooks[*].command`, a real quote-state walk (not a per-character lookaround)
   identifies each `$VAR`/`${VAR}` reference and classifies it as unquoted, double-quoted, or
   single-quoted. An unquoted reference fires; both quoted forms stay silent (a reference in the
   MIDDLE of a longer double-quoted string, not just immediately adjacent to the quote characters,
   is still correctly recognized as quoted).
5. Suppress with a top-level `"//": "security: allow-claude-hook-rce"` string anywhere in the JSON
   document (JSON has no comment syntax, so the pragma is a literal, harmless dict entry).

## When NOT to flag

- No `hooks` key at all, or an empty one.
- Every variable reference in every hook command is double- or single-quoted.
- `hooks` appears only in the checked-in `settings.json`, not `settings.local.json`.

## Tests

| Test | What it checks |
|---|---|
| `test_unquoted_variable_interpolation_fires` / `test_unquoted_braced_variable_fires` | Bare `$VAR` and `${VAR}` both fire |
| `test_double_quoted_variable_is_safe` / `test_variable_in_middle_of_double_quoted_string_is_safe` | Double-quoted forms, including mid-string, stay silent |
| `test_single_quoted_variable_is_safe` | Single-quoted (fully literal) form stays silent |
| `test_no_variable_at_all_is_safe` | A command with no variable reference stays silent |
| `test_settings_local_hooks_fires` | `settings.local.json` defining hooks fires |
| `test_settings_json_hooks_is_not_the_local_rule` | FP-bait: the same hooks in checked-in `settings.json` don't trip the local-file rule |
| `test_settings_local_with_no_hooks_is_safe` / `test_settings_local_with_empty_hooks_is_safe` | No/empty hooks key stays silent |
| `test_pragma_suppresses_all_findings` | The JSON-literal pragma silences every rule |
| `test_applies_universally` | `applies()` is unconditionally `True` |
| `test_deeply_nested_json_file_does_not_hide_other_findings` | A deeply nested JSON file (`RecursionError` in `json.loads`) is skipped like any unparseable file and a real finding in a sibling file survives |

## Known bypasses

- The quote-state walk is a single-pass shell-quoting model; it does not resolve nested command
  substitution (`$(...)`/backticks) inside a double-quoted variable value, which bash still
  expands even when word-splitting is suppressed — double-quoting closes the word-splitting/glob
  bypass this rule targets, not every possible shell-injection vector.
- Only the `hooks.<event>[*].hooks[*].command` shape is walked; a hook wired a structurally
  different way (a future Claude Code schema change) is invisible.
- `settings-local-hooks-pre-trust` fires on ANY non-empty `hooks` key in `settings.local.json`,
  including a hook a developer genuinely added for their own personal workflow — it is a review
  signal ("confirm this was intentional"), not proof of a planted attack.

## What this guard does NOT prove

Silence does not prove a Claude Code hook configuration is safe — only that these two specific
shapes are absent. A hook command with no variable interpolation at all can still run an
inherently dangerous fixed command; this guard proves quoting hygiene and file provenance, not
that the hook's own logic is benign.

# Citations

[1] agentsec checklist item `8-claude-hook-rce` (§8)
[2] CVE-2025-59536
[3] CWE-78 (OS Command Injection), CWE-88 (Argument Injection), CWE-284 (Improper Access Control),
    OWASP:A01
[4] agent-audit-kit `hook_rce.py`, rules AAK-HOOK-RCE-001/003
