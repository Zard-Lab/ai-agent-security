---
type: Guard
title: "ansi-escape-llm-output"
description: "LLM response printed to a terminal without ANSI-escape stripping."
timestamp: "2026-08-24T00:00:00+08:00"
guard_id: "ansi-escape-llm-output"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM05", "CWE-150"]
---

# LLM response printed to a terminal without ANSI-escape stripping

_Author — 2026-08-24_

---

## The threat

Sourced from Garak's `probes/ansiescape.py` + `detectors/ansiescape.py`: a malicious or
hallucinated LLM completion can embed ANSI/VT100 escape sequences in its text output. When
an agentic CLI tool prints that response straight to a terminal — `print(response)`,
`click.echo(response)`, `console.print(response)` — the escape codes are interpreted by the
terminal emulator, not shown as literal text. That gives an attacker who controls (via
prompt injection) or merely influences (via hallucination) the model's output a channel to:

- reposition or hide the cursor, overwrite prior output, or clear the screen/scrollback to
  make earlier (legitimate) output disappear,
- spoof colors/prompts to make injected text look like trusted system output,
- and, on vulnerable terminal emulators, trigger more dangerous behavior (title-bar
  injection, clipboard writes, and historically, code execution in specific emulator bugs).

This is a real, narrow terminal-hijack-via-LLM-output vector, distinct from other output-
handling guards in this codebase:

- `log-injection` is CRLF-only log-forging (newline injection faking log lines) — it never
  considers ANSI control sequences or terminal rendering.
- `claude-code-compromise` covers hook/permission/config abuse inside AI *coding assistant*
  configuration (CLAUDE.md, settings.json, hooks) — a different attack surface from a
  script printing a model's own response text to a terminal.
- `llm-output-to-sink` and `llm-response-logged` cover code-execution sinks and log sinks,
  not terminal print sinks.

## Why it's often introduced

Printing the model's answer directly is the simplest possible integration in an agentic
CLI tool — `print(agent.run_sync(prompt).output)` — and works correctly in every normal
case. ANSI stripping is invisible until someone deliberately (red-team) or accidentally
(a model that has learned to emit box-drawing/color codes from its training data) triggers
it.

## Detection design

1. **applies() gate:** `"llm" in profile.features`.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`, minus `is_nonproduct_path`.

3. **Pattern (`unstripped-print`, MEDIUM):**
   - Gate the whole-file scan on `_LLM_CALL_ANYWHERE` (same LLM-call-detection shape
     `llm-output-to-sink` uses) so files with no LLM call are skipped entirely.
   - Collect LLM-result variable names via `_LLM_ASSIGN` (identical to
     `llm-output-to-sink`'s call-site-tracking shape), scoped to the **enclosing function**
     (`_enclosing_def_span`, copied from `llm-json-output-unvalidated`'s helper of the same
     name) — a same-named variable in a different function does not taint this one.
   - For each line matching a print sink (`print(`, `click.echo(`, or any `<expr>.print(` —
     `\bprint\s*\(` alone covers `console.print(`/`rich.console.print(`/`self.console.print(`
     since the preceding `.` is a non-word character and `\b` fires on that boundary; it
     does NOT match inside `pprint(`, where `print` has no boundary from the preceding `p`),
     check whether the line references one of the tracked LLM-result variable names
     (word-boundary match — covers both `print(response)` and an f-string embedding it,
     `print(f"Answer: {response}")`).
   - If it does, check the WHOLE enclosing function's text for an ANSI-stripping signal:
     `strip_ansi(`, an `ANSI_ESCAPE`-named identifier, or a literal escape-code marker
     (`\x1b`, `\033`, as they appear in source text — this matches whether the
     enclosing string is raw or not, since detection is a text scan, not an executed one).
     Absent → fire.
   - Triple-quoted docstring content is blanked first (`strip_python_strings`) so
     anti-pattern examples in a guard's own module docstring don't self-match.

4. **Inline opt-out pragma:** `# security: allow-ansi-escape-llm-output`.

5. **Severity and rule:** `"medium"`, rule `"ansi-escape-llm-output/unstripped-print"`,
   standards `["OWASP-LLM:LLM05", "CWE-150"]`.

## Deliberate scoping choice

This guard does **not** attempt to structurally prove the printing code path is a CLI tool
writing to a real terminal, as opposed to a web API handler that happens to call `print()`
for local debug output. That distinction is not reliably recoverable from static text —
other guards in this codebase (e.g. auth-dependency guards) distinguish route-handler code
via FastAPI decorators (`@router.get`, `@app.post`), but a bare `print()` call carries no
such structural marker. Any LLM-result variable reaching a print/echo/`.print(` sink,
unstripped, fires — narrower precision was judged not practically achievable and not worth
the false-negative cost of trying.

## When NOT to flag

- The print/echo call's argument doesn't reference any LLM-result variable tracked in the
  enclosing function — an unrelated status message stays silent.
- An ANSI-stripping signal exists anywhere in the same function, even if it doesn't
  provably run before this specific print call (a deliberate widen-to-avoid-noise choice,
  matching this codebase's other function-scoped guards).
- The file contains `# security: allow-ansi-escape-llm-output`.

## Tests

| Test | What it checks |
|---|---|
| `test_applies_when_llm_feature_present` | Guard activates on `llm` feature |
| `test_not_applies_without_llm_feature` | Guard skips non-LLM stacks |
| `test_fires_on_unstripped_print` | Fires: `print(response.output)`, no stripping |
| `test_fires_on_click_echo` | Fires: `click.echo(response.output)` |
| `test_fires_on_rich_console_print` | Fires: `console.print(response.output)` |
| `test_fires_on_fstring_embedding_llm_var` | Fires: `print(f"Answer: {response.output}")` |
| `test_fp_bait_strip_ansi_call_present` | Silent: `print(strip_ansi(response.output))` |
| `test_fp_bait_ansi_escape_pattern_present` | Silent: an `ANSI_ESCAPE` pattern + `.sub()` used before printing |
| `test_fp_bait_non_llm_sourced_print` | Silent: `print(status)` where `status` isn't LLM-derived |
| `test_fp_bait_when_pragma_present` | Silent: file-level pragma |
| `test_fp_bait_print_in_unrelated_function` | Silent: same-named non-LLM variable in a different function |

## Known bypasses

- The LLM-result variable renamed via a plain reassignment before the print call is not
  tracked — same limitation as `llm-json-output-unvalidated`.
- An LLM result returned from one function and printed in another is not tracked
  (per-function scoping only).
- An ANSI-stripping helper under a name other than `strip_ansi`/`ANSI_ESCAPE*` and with no
  literal escape-code marker in its pattern (e.g. a stripping call imported from a third-
  party package under an unrelated alias) is invisible to the signal check, so a genuinely
  safe file can still fire — the price of a name/marker-based heuristic instead of dataflow
  into an actual regex library call.
- The pragma silences the rule for the entire file.

## What this guard does NOT prove

- That the code path is actually a CLI tool writing to a real interactive terminal (see
  "Deliberate scoping choice" above) — it fires on any print/echo/`.print(` reached by
  LLM output, CLI or not.
- That an ANSI-stripping signal present in the function is correctly ordered BEFORE the
  print call, or that it is applied to the exact value being printed (an unrelated
  `strip_ansi()` call elsewhere in the function silences the finding).
- That the terminal emulator receiving the output is actually vulnerable to the escape
  sequences involved — this guard flags the unmitigated *pattern*, not a proven exploit.

# Examples

```python
# Fires — response printed straight to the terminal, no stripping anywhere in main():
def main(prompt: str) -> None:
    response = agent.run_sync(prompt)
    print(response.output)

# Silent — response is stripped before printing:
def main(prompt: str) -> None:
    response = agent.run_sync(prompt)
    print(strip_ansi(response.output))
```

# Citations

[1] Garak `probes/ansiescape.py` + `detectors/ansiescape.py`
[2] agentsec checklist item `4-ansi-escape-llm-output` (§4)
[3] OWASP-LLM:LLM05
[4] CWE-150 (Improper Neutralization of Escape, Meta, or Control Sequences)
