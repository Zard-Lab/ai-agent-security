---
type: Guard
title: "approval-parser-shell-desync"
description: "A command-safety approval check parses a command differently than the shell that actually executes it."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "approval-parser-shell-desync"
checklist_section: ["8"]
standards: ["CWE-150", "OWASP-ASI:ASI04"]
---

# Command-safety approval parser disagrees with the shell about what a command means

_Author — 2026-09-26_

---

## The threat

CVE-2026-19591: Codex CLI's safety parser decides whether a command needs human approval,
then hands it to a shell. PowerShell's stop-parsing token `--%` makes `pwsh` re-read the
rest of the line verbatim; Codex's parser didn't implement it, so a command classified as
safe ran a different command — writing a file with no approval prompt, and what it could
write was Codex's own configuration, loaded on the next start. CWE-150 (Improper Neutralization
of Escape, Meta, or Control Sequences), OWASP-ASI:ASI04. The bug is structural: whenever a
security decision is made by parsing text that a DIFFERENT program (the shell) will also
parse, any disagreement between the two parsers is a bypass, and this guard checks the one
disclosed, concrete instance of that class. Sourced from `agent-audit-kit`'s
`approval_parser_desync.py` (AAK-APPROVAL-PARSER-DESYNC-001), verified against the real repo
source.

## Why it's often introduced

A command-safety parser is typically written and tested against `bash`/`sh` syntax (the
default assumption on Linux CI and most examples), and PowerShell support is added later by
just pointing the same approved-command string at `pwsh` — without re-auditing whether the
approval parser's own syntax model still matches what PowerShell will do with that string.

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans `.py`/`.ts`/`.tsx`/`.js`/`.mjs`/`.cjs`/`.rs`/`.go` files (`iter_files`), TS/JS
   comments stripped before matching (Python comments left as-is, matching the source's own
   choice, since `#` comments in Python source rarely collide with the patterns checked).
3. Fires HIGH when, inside ONE function (or the module-level scope), ALL of: an approval or
   safety check is applied to a value (`isSafe(cmd)`/`isAllowed(`/`checkCommand(`/
   `requireApproval(`/`cmd in ALLOWED_LIST`), and that same identifier appears in the argv of
   a spawn sink (`spawn(`/`exec(`/`subprocess.run|Popen|call(`/`Command::new(`/
   `exec.Command(`) that invokes a PowerShell-family interpreter (`pwsh`/`powershell(.exe)`)
   — but no handling of the stop-parsing token `--%` (rejecting it, stripping it, or refusing
   to classify a command containing it) appears anywhere in the file. Function scope is `ast`
   for Python and brace matching for the other languages.
4. Inline opt-out: a `# security: allow-approval-parser-shell-desync` comment (`// …` in JS/TS/Go)
   anywhere in the file silences the file (a string literal quoting the phrase does not count, #424). A `.rs` file has no comment
   dialect here yet, so there the phrase is still matched in the raw text.
5. Rule `approval-parser-shell-desync/stop-parsing-token-unhandled`, standards
   `["CWE-150", "OWASP-ASI:ASI04"]`.

**Scope, stated rather than implied:** this detects the PowerShell stop-parsing token
specifically. It does not enumerate every shell's escaping quirks, and a file that gates
commands for `bash` only is not flagged by it.

## When NOT to flag

- The stop-parsing token is checked for anywhere in the file (rejected, stripped, or used
  to refuse classification).
- No PowerShell interpreter is ever invoked — a `bash`/`sh`-only gate is out of this
  guard's stated scope.
- No approval/safety-check call site at all — an unconditional spawn with no gate is a
  different (and arguably worse, but different) problem.

## Tests

| Test | What it checks |
|---|---|
| `test_stop_parsing_token_unhandled_fires` | The disclosed shape, no `--%` handling — fires |
| `test_stop_parsing_token_rejected_is_safe` | `--%` explicitly checked and rejected — silent |
| `test_bash_only_gate_is_safe` | Only `bash` ever spawned — out of scope |
| `test_no_approval_gate_is_safe` | No safety check at all — different shape |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_approval_parser_shell_desync_pragma_quoted_in_a_string_does_not_suppress`, `test_approval_parser_shell_desync_pragma_quoted_in_a_string_does_not_suppress_ts`, `test_approval_parser_shell_desync_ts_slash_comment_pragma_suppresses`, `test_approval_parser_shell_desync_pragma_quoted_in_a_string_does_not_suppress_go`, `test_approval_parser_shell_desync_go_slash_comment_pragma_suppresses` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `//` comment now opts a JS/TS file out too, and a TS string quoting either form does not |
| `test_unrelated_approval_and_literal_pwsh_spawn_is_silent` | An unrelated `approval_policy()` plus a literal pwsh spawn — silent |
| `test_approved_value_in_a_different_function_is_silent` | Gate and spawn in different functions — silent |
| `test_gated_value_not_in_pwsh_argv_is_silent` | Same function, but the spawn argv is literal — silent |
| `test_typescript_same_name_in_different_functions_is_silent` | Same identifier, different TS functions — silent |
| `test_membership_gate_then_pwsh_spawn_fires` | `cmd in ALLOWED_COMMANDS` then a pwsh spawn of `cmd` — fires |
| `test_typescript_gate_and_spawn_in_one_function_fires` | TS gate plus spawn in one function — fires |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- Only the PowerShell `--%` token is checked; other shell-specific parsing divergences
  (e.g. a different interpreter's own escape quirks) are entirely outside this guard's
  scope by design.
- The approval-check and spawn-sink vocabularies are fixed regexes; a bespoke, differently
  named safety-check function is invisible.
- The gated value is followed by identifier name inside one function. A value that is renamed,
  passed through a helper, or joined into a command string before the spawn, or a gate and a
  spawn split across two functions (`check()` then `run()`), is not linked and stays silent.

## False-positive mechanisms that remain

- Identifier matching is by name, so an unrelated gate on `cmd` and a pwsh spawn that happens
  to take a different value also called `cmd`, in the same function, still match.
- A gate that runs on a different, already-sanitised value than the one spawned (renamed
  before the spawn) is judged by names, not data flow.
- Brace-language function scoping is a text heuristic: a nested block that looks like a
  function header can widen the scope it judges.

## What this guard does NOT prove

Silence does not prove the approval parser correctly agrees with the shell on every other
input — only that this one specific, disclosed desync (the `--%` token) is handled. A
parser with a DIFFERENT desync bug (a different escape sequence, a different shell) stays
silent here.

# Citations

[1] agentsec checklist item `8-approval-parser-shell-desync` (§8)
[2] CVE-2026-19591 (Codex CLI)
[3] CWE-150, OWASP-ASI:ASI04
[4] agent-audit-kit `approval_parser_desync.py`, rule AAK-APPROVAL-PARSER-DESYNC-001
