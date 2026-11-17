---
type: Guard
title: "argv-toctou"
description: "A command/argv buffer is rebuilt after approval, with no re-validation before it spawns."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "argv-toctou"
checklist_section: ["8"]
standards: ["CWE-367", "CWE-78"]
---

# Command argv is rebuilt after approval, with no re-validation before it spawns

_Author — 2026-09-26_

---

## The threat

OpenClaw before 2026.5.18 contained a command-injection vulnerability (CVE-2026-53822, CVSS 8.8)
where a shell-wrapper argv could change between the moment it was approved as safe and the moment
it actually executed — a classic Time-Of-Check-to-Time-Of-Use race on program state, not a
filesystem race. Whatever a safety/approval check reviewed and approved is not necessarily what a
spawn call actually runs, if the argv is rebuilt (re-split, re-joined, appended to, or extended) in
between. Sourced from `agent-audit-kit`'s `argv_toctou.py` (AAK-MCP-ARGV-TOCTOU-001), verified
against the real repo source.

## Why it's often introduced

An approval check is often written against the ORIGINAL command string or argv the caller
supplied, and then, for entirely unrelated reasons (normalizing whitespace, injecting a fixed
flag, adapting to a different spawn API's argv-vs-string expectation), the code re-splits or
appends to that same buffer before the actual spawn call. Nobody re-runs the approval check on the
rebuilt value because the check already "passed" — the TOCTOU gap is invisible unless you're
specifically looking for the reconstruction step between check and use.

## Detection design

1. `applies()` returns `True` when `"python" in profile.features` (Python-only; the AST-scoped
   correlation below requires a real parse tree).
2. `safe_ast_parse` resolves every function (`FunctionDef`/`AsyncFunctionDef`) in the file. All
   three signals below are checked ONLY within one function's own line span — same-file,
   cross-function scope was this guard's first-pass design and produced 12 false positives across
   agentsec's own codebase (unrelated approval/rebuild/spawn-shaped code scattered across
   different, unconnected functions) before it ever shipped; scoping to one function eliminated
   every one of them.
3. **rebuild-after-approval-no-revalidation** (HIGH): within one function, correlated BY VARIABLE
   and in this order — an approval/safety-check call site (`isSafe(`/`isAllowed(`/`checkCommand(`/
   `requireApproval(`/an allow-list/deny-list/command-safety identifier/a real ALL-CAPS `SAFE_*`
   constant) whose line names the variable(s) under review, THEN on a later line one of those
   variables is rebuilt (`x = y.split(...)`, `.join(...)`, `x.append(...)`, `x.extend(...)`,
   `x += [...]`, `x = y + [...]`; the result of a rebuild is itself tracked, so a derived
   `parts = cmd.split()` followed by `parts.append(...)` is followed through), THEN on a later line
   still a spawn sink (`spawn(`/`exec(`/`subprocess.run|Popen|call(`) whose ARGV (first positional
   argument, or an `args=`/`command=`/`cmd=` keyword) uses the rebuilt variable — with no SECOND
   approval-shaped line between the rebuild and the spawn. The function is indexed once and the
   approval check is a bisect, so the work is linear in the function's size.
4. Suppress with a `# security: allow-argv-toctou` comment anywhere in the file, which silences the
   file (a string literal or docstring quoting the phrase does not count, #424).

## When NOT to flag

- No approval/safety-check call site in the function at all (a bare command-injection concern,
  not a TOCTOU-on-approval one — out of this guard's scope).
- Approval immediately followed by spawn, with no rebuild step in between — the safe idiom.
- A rebuild that happens BEFORE the approval call — the approved value IS the final value, no gap.
- A second approval-shaped call between the rebuild and the spawn — genuine re-validation.
- Approval, rebuild, and spawn spread across different, unconnected functions.
- An ordinary snake_case identifier merely starting with `safe_` (a helper function name like
  `safe_parse`/`safe_ast_parse`) — only a real ALL-CAPS `SAFE_*` constant counts as an approval
  marker; the case-insensitive version of that check was the exact bug this guard's own self-audit
  caught (see below).

## Tests

| Test | What it checks |
|---|---|
| `test_rebuild_after_approval_no_revalidation_fires` | Core violation: approve → `.split(` → spawn, no re-check |
| `test_rebuild_via_append_fires` | The `.append(` rebuild shape also fires |
| `test_revalidation_between_rebuild_and_spawn_is_safe` | FP-bait: a second approval call re-validates |
| `test_no_rebuild_between_approval_and_spawn_is_safe` | FP-bait: approve → spawn directly, no rebuild |
| `test_no_approval_at_all_is_safe` | FP-bait: rebuild + spawn with no approval call at all |
| `test_rebuild_and_spawn_in_different_function_is_safe` | FP-bait: cross-function scope must not correlate |
| `test_rebuild_before_approval_is_safe` | FP-bait: rebuild happens before approval — the safe order |
| `test_safe_named_snake_case_identifier_is_not_an_approval_marker` | FP-bait: `safe_parse(`/`safe_ast_parse(` is not a `SAFE_*` constant |
| `test_real_safe_constant_is_an_approval_marker` | The narrowing direction traded against: a real `SAFE_COMMANDS` constant still fires |
| `test_approved_value_spawned_after_unrelated_join_is_safe` | FP-bait: an unrelated `", ".join(parts)` before a spawn of the approved, never-rebuilt value |
| `test_literal_argv_spawn_after_unused_split_is_safe` | FP-bait: a literal argv after an unused, unassigned `cmd.split(" ")` |
| `test_rebuild_into_new_variable_that_spawns_fires` | Still fires: the rebuilt value lands in a new name that spawns |
| `test_scales_linearly_with_function_length` | Many rebuild/approval/spawn lines in one function stay linear (a same-machine ratio) |
| `test_pragma_suppresses` | Inline pragma silences the guard |
| `test_argv_toctou_pragma_quoted_in_a_string_does_not_suppress` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_applies_requires_python` | `applies()` requires the `python` feature |

## Known bypasses

- The correlation is by variable NAME within one function, not a real dataflow trace: names an
  approval line mentions are treated as approved, and an alias created some other way (`b = a`,
  a tuple unpack, a value round-tripped through a helper or an attribute) is not followed, so a
  rebuild through such an alias is invisible. Conversely an approval line that names a variable only
  incidentally makes it count as approved. Rebuild shapes outside the fixed vocabulary
  (`.split(`/`.join(`/`.append(`/`.extend(`/`+= [`/`+ [`) are invisible.
- The approval and spawn vocabularies are fixed name lists; an approval check or spawn sink named
  outside them is invisible (enumeration-based, like several sibling guards in this family).
- A rebuild happening in a HELPER function called between the approval and the spawn (rather than
  inline in the same function) is not traced — the correlation is intra-function only.
- Non-Python languages are out of scope entirely (`applies()` requires `python`); the same class of
  bug in a JS/TS/Rust/Go approval-then-spawn pipeline is invisible to this guard.

## What this guard does NOT prove

Silence does not prove an approval-then-spawn pipeline is TOCTOU-safe — only that this one
line-order, name-based shape was not found in one function. A rebuild reachable through a
non-obvious control-flow path (a loop, an early return skipped, a rebuild inside a called helper)
is outside static single-function analysis.

# Citations

[1] agentsec checklist item `8-argv-toctou` (§8)
[2] CVE-2026-53822 (OpenClaw before 2026.5.18, CVSS 8.8)
[3] CWE-367 (Time-of-check Time-of-use Race Condition), CWE-78 (OS Command Injection)
[4] agent-audit-kit `argv_toctou.py`, rule AAK-MCP-ARGV-TOCTOU-001
