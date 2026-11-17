---
type: Guard
title: "policy-truncation"
description: "A deny/allow policy is evaluated against a truncated command while the full, untruncated command reaches the spawn call."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "policy-truncation"
checklist_section: ["8"]
standards: ["CWE-697", "CWE-78"]
---

# A deny/allow policy checks a truncated command while the full, untruncated command spawns

_Author — 2026-09-26_

---

## The threat

A policy check that only ever sees the first N characters of a command can be defeated by simply
making the command longer than N: pad the front with anything the policy will approve, then place
the real payload past the truncation boundary. The executor runs the FULL string regardless — the
policy's decision was made on a string that is not the string that actually runs. CVE-2026-73614
(disclosed in ClaudeHookBridge, CVSS 8.8) is the named instance, but the primitive itself is
vendor-independent: `x = cmd.slice(0, 500)` (or Python's `cmd[:500]`) tested against a deny/block
check, while the untruncated `cmd` still reaches the executor. Sourced from `agent-audit-kit`'s
`policy_truncation.py` (AAK-POLICY-TRUNCATION-001), verified against the real repo source.

## Why it's often introduced

A length limit on the string a policy check inspects is often added for a completely unrelated
reason — a logging budget, a display truncation, a defensive cap against a pathologically long
input — and the same truncated variable then gets reused for the policy decision because it's
already sitting right there. Nobody re-derives "wait, is this the same string that's about to
execute" once the truncated copy already exists.

## Detection design

1. `applies()` returns `True` when `"python" in profile.features` (Python-only; the AST-scoped
   correlation requires a real parse tree, matching `argv-toctou`'s established approach).
2. `safe_ast_parse` resolves every function. All three signals below are checked ONLY within one
   function's own line span — the same lesson `argv-toctou`'s own self-audit dogfooding already
   established (a same-file, cross-function scope produces false positives on unrelated code).
3. **untruncated-value-reaches-spawn** (HIGH): within one function, in this order —
   (a) a variable is assigned a FIXED-LENGTH PREFIX SLICE of another variable (`truncated =
   original[:N]`, an `ast.Slice` with `lower` absent/zero and a literal integer `upper` — a
   variable-length slice like `cmd[:limit]` is deliberately NOT matched, since the bound isn't
   fixed at the source level); (b) that truncated variable is referenced in a policy/deny-check
   call or membership test on a LATER line (`is_blocked(truncated)`/`check_command(truncated)`/
   `truncated in DENY_LIST`/a real ALL-CAPS `SAFE_*`/`DENY_*`/`ALLOW_*`/`BLOCK_*` constant); (c)
   the ORIGINAL (untruncated) variable is used in the ARGV of a spawn sink (`spawn(`/`exec(`/
   `subprocess.run|Popen|call(`: the first positional argument, or an `args=`/`command=`/`cmd=`
   keyword) on a LATER line still. "Is the full value spawned?" is decided from that argv alone,
   so `subprocess.run(cmd, env=make_env(safe_cmd))` fires (the full `cmd` runs) while
   `subprocess.run(safe_cmd, cwd=os.path.dirname(cmd))` stays silent (the checked value runs).
   The function is indexed once (policy lines per name, spawn calls per argv name), so the work is
   linear in the function's size, not one rescan per slice.
4. Suppress with a `# security: allow-policy-truncation` comment anywhere in the file, which
   silences the file (a string literal or docstring quoting the phrase does not count, #424).

## When NOT to flag

- The TRUNCATED value itself is what reaches the spawn call — the policy check and the executed
  command agree, no bypass exists.
- No policy/deny check references the truncated variable at all (e.g. it's used only for logging).
- No truncation at all — a policy check against the full, untruncated command is exactly the safe
  form.
- The slice's upper bound is a variable, not a fixed literal (`cmd[:limit]`) — not this guard's
  target shape.
- Truncation, the policy check, and the spawn call are spread across different, unconnected
  functions.

## Tests

| Test | What it checks |
|---|---|
| `test_untruncated_value_reaches_spawn_fires` | Core violation: truncate → policy-check the truncated copy → spawn the original |
| `test_denylist_constant_membership_fires` | A membership test against an ALL-CAPS deny-list constant also fires |
| `test_truncated_value_itself_spawned_is_safe` | FP-bait: the truncated value is what spawns — no bypass |
| `test_no_policy_check_on_truncated_value_is_safe` | FP-bait: truncation with no policy check on it |
| `test_no_truncation_at_all_is_safe` | FP-bait: a policy check against the full command — the safe form |
| `test_variable_length_slice_is_safe` | FP-bait: a variable-bound slice (`cmd[:limit]`) is not the target shape |
| `test_truncation_and_spawn_in_different_function_is_safe` | FP-bait: cross-function scope must not correlate |
| `test_full_value_argv_with_truncated_name_elsewhere_in_call_fires` | The full value is the argv and the truncated name is only in `env=`: still fires |
| `test_truncated_argv_with_original_in_other_argument_is_safe` | FP-bait: the argv is the checked value; the original only feeds `cwd=` |
| `test_multiline_spawn_call_with_original_argv_fires` | A spawn call spread over several lines is resolved from its AST |
| `test_scales_linearly_with_slices_per_function` | Thousands of slices in one function stay linear (a same-machine ratio, not an absolute time) |
| `test_pragma_suppresses` | Inline pragma silences the guard |
| `test_policy_truncation_pragma_quoted_in_a_string_does_not_suppress` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_applies_requires_python` | `applies()` requires the `python` feature |

## Known bypasses

- The correlation is line-order-based within a function, not a real variable-name dataflow trace
  across function boundaries — a truncation, policy check, or spawn reachable only through a
  called helper function is not traced.
- The spawn decision looks only at the spawn call's argv. A full value that reaches the executor
  some other way, for instance `subprocess.run(safe_cmd, env={"CMD": cmd})` where the child later
  runs `$CMD`, or a spawn wrapper whose name is outside the fixed list, is not seen. An argv built
  from BOTH names (`run(cmd + safe_cmd)`) is treated as spawning the full value and fires.
- The policy-check and spawn vocabularies are fixed name lists; a check or sink named outside them
  is invisible.
- A truncation shape other than a fixed-length prefix slice (e.g. `original[:len(original)-N]`, a
  `.zfill`/regex-based truncation, or truncation via a helper function) is not recognized —
  intentionally narrow, matching the disclosed `slice(0, N)`/`cmd[:N]` shape.
- Non-Python languages are out of scope entirely; the same class of bug in a JS/TS/Rust/Go
  policy-then-spawn pipeline (the disclosed CVE's own `cmd.slice(0, 500)` example is JS-shaped) is
  invisible to this guard.

## What this guard does NOT prove

Silence does not prove a policy-then-spawn pipeline is truncation-safe — only that this one
line-order, name-based shape was not found in one Python function. A truncation reachable through
a non-obvious control-flow path, or expressed via a helper function rather than an inline slice,
is outside static single-function analysis.

# Citations

[1] agentsec checklist item `8-policy-truncation` (§8)
[2] CVE-2026-73614 (ClaudeHookBridge, CVSS 8.8)
[3] CWE-697 (Incorrect Comparison), CWE-78 (OS Command Injection)
[4] agent-audit-kit `policy_truncation.py`, rule AAK-POLICY-TRUNCATION-001
