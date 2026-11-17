---
type: Guard
title: "code-injection-eval-exec"
description: "No code injection via a bare eval()/exec() sink fed dynamic content."
timestamp: "2026-09-22T10:00:00+08:00"
guard_id: "code-injection-eval-exec"
checklist_section: ["3b"]
standards: ["ASVS:1.3.2", "OWASP:A03"]
---

# No code injection via a bare eval()/exec() sink fed dynamic content

_Author — 2026-07-01_

---

## The threat

An attacker who can influence the string passed to `eval()`/`exec()` runs arbitrary
Python: `eval(request.args.get("expr"))` lets a caller submit `__import__('os').
system('rm -rf /')` as the "expression." This is CWE-95 (Improper Neutralization of
Directives in Dynamically Evaluated Code), OWASP:A03 (Injection). It's the Python-
interpreter sibling of `command-injection`'s shell-sink check — same class of bug
(dynamic content reaching a code-execution primitive), different sink.

## Why it's often introduced

A developer builds a small formula evaluator, a plugin/config DSL, or a debug endpoint
and reaches for `eval()`/`exec()` as the quick way to "run" user-supplied text:

```python
@app.post("/calculate")
def calculate(expr: str):
    return eval(expr)          # anything Python can do, the caller can do
```

## Why this guard exists alongside llm-output-to-sink

`llm-output-to-sink` already catches `eval`/`exec` fed by an LLM call's result — but
it's gated on `"llm" in profile.features` and only scans files that already contain an
LLM call. A plain FastAPI app with no LLM involvement at all, doing
`eval(request.query_params.get("expr"))`, is caught by neither that guard nor
`command-injection` (which only watches shell sinks like `os.system`/`subprocess`, not
the interpreter's own `eval`/`exec`). This guard is deliberately LLM-independent
(`applies_when: ["python"]`) to close that gap.

## Detection design

1. **applies() gate:** `"python" in profile.features` — runs on any Python codebase,
   not just LLM/agentic stacks.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`dynamic-content`, HIGH):** Same-line check, reusing `command-injection`'s
   `_is_dynamic()` shape: an `eval(`/`exec(` call whose argument is dynamic —
   - an f-string (`_FSTRING`),
   - has no string literal anywhere **once `["key"]`/`['key']` dict/subscript access is
     stripped out first** (`_SUBSCRIPT_KEY`) — a bare variable/expression, or a subscript
     chain like `node["code"]`/`node["a"]["b"]["c"]` (added 2026-07-04, CVE-2026-33017:
     Langflow's real vulnerable code extracts attacker code via `custom_params.pop("code")`,
     the same "pull a value out of a dict" shape — the quoted key previously made this
     read as a static literal even though the extracted value is fully dynamic),
   - uses `.format(`,
   - or uses `%`-formatting or `+` concatenation (`_PCT`/`_CONCAT`).

   A static string literal argument (`eval("2 + 2")`) does NOT fire — including one that
   happens to contain bracket-looking text (`eval('config["debug"] = False')`), since the
   outer quotes survive the subscript-key strip.

4. **Inline opt-out pragma:** `# security: allow-eval-exec`

5. **Severity and rule:** `"high"`, rule `"code-injection-eval-exec/dynamic-content"`,
   standards `["OWASP:A03", "CWE-95"]`.

**2026-09-22: `compile(`/`__import__(`/SymPy `parse_expr(` sinks added.**
Ported from `agent-audit-kit`'s real `AAK-MCP-TOOL-UNSAFE-EVAL-001` (fetched and read in full),
anchored on **CVE-2026-44717** (`mcp-calculate-server`, an MCP tool handler routing a tool
parameter through `sympy.parsing.sympy_parser.parse_expr()` with no `local_dict`/`global_dict`
pinning — SymPy's own docs call unpinned `parse_expr` on untrusted input equivalent to `eval`).
The bare `eval(`/`exec(` case on an MCP-tool-handler parameter was already caught here
regardless of decorator context (this guard has no decorator-awareness at all, by design —
adding one would only narrow an already-working generic check); `compile(`/`__import__(`/
`parse_expr(` were the real, disclosed gap.

- `compile(`/`__import__(` use the SAME dynamic-content check as `eval`/`exec`.
- `parse_expr(` additionally requires BOTH `local_dict=` and `global_dict=` to be absent from
  the same line to fire — present-but-empty pinning (`local_dict={}`) is the documented-safe
  form and must not fire; only one of the two pinned is still unsafe per the source's own
  detection contract, so both must be present to silence it. `parse_expr(` is deliberately NOT
  excluded when preceded by a `.` (unlike `eval`/`exec`'s own exclusion) — the real vulnerable
  shape is the fully-dotted `sympy.parsing.sympy_parser.parse_expr(...)` call, and `parse_expr`
  (unlike `eval`/`exec`) is not a builtin name any other attribute access could be confused with.

**Real bug found and fixed in the same pass, not shipped separately:** the guard's original
argument-extraction (`_arg_after`) returned the WHOLE tail of the line after the sink's opening
paren, not just the first argument. `eval`/`exec` are almost always called with one argument in
practice, so this went unnoticed — but `compile(source, filename, mode)`'s common 3-argument
form broke it: the static `filename`/`mode` string literals made the whole-tail string read as
"has a literal somewhere," masking a genuinely dynamic first argument
(`compile(formula, '<formula>', 'eval')` silently did not fire). Replaced with
`_first_arg_after`, a balanced-bracket-aware first-argument extraction (stops at the first
top-level comma or unbalanced closer) — confirmed via the existing test suite that this does
not change `eval`/`exec` behavior, since the dynamism in every existing test was already in the
first argument specifically.

## When NOT to flag

- A static string literal passed directly (`eval("2 + 2")`, `exec("pass")`) — nothing
  for an attacker to influence.
- A full-line comment mentioning `eval(`/`exec(` (e.g., documenting the risk) — the
  guard skips lines starting with `#`.
- An audited, trusted-constant case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_bare_variable_eval` | Fires: `eval(user_input)` — bare variable, no literal |
| `test_fires_on_fstring_exec` | Fires: `exec(f'x = {formula}')` |
| `test_fires_on_concat` | Fires: `eval('2 + ' + expr)` — string concatenation |
| `test_passes_static_literal` | Silent: `eval('2 + 2')` — static literal only |
| `test_passes_comment_mention` | Silent: full-line comment mentioning `eval(` |
| `test_pragma_opt_out` | Silent: inline `# security: allow-eval-exec` pragma |
| `test_fires_on_dict_subscript_argument` | Fires: `exec(node['code'])` — CVE-2026-33017's own extraction shape |
| `test_fires_on_chained_dict_subscript_argument` | Fires: `exec(node['data']['node']['template']['code']['value'], exec_globals)` |
| `test_passes_static_literal_with_bracket_looking_text` | Silent: `eval('config["debug"] = False')` — bracket-looking text inside a genuine literal |
| `test_fires_on_dynamic_compile` | Fires: `compile(formula, '<formula>', 'eval')` — the 3-arg form that exposed the `_arg_after` bug |
| `test_fires_on_dynamic_dunder_import` | Fires: `__import__(module_name)` |
| `test_compile_static_literal_does_not_fire` | Silent: `compile('1 + 1', '<string>', 'eval')` |
| `test_fires_on_unpinned_sympy_parse_expr` | Fires: `parse_expr(expression)` inside an `@mcp.tool()` handler — CVE-2026-44717's own shape |
| `test_sympy_parse_expr_with_dotted_module_path_fires` | Fires: `sympy_parser.parse_expr(expression)` — confirms no leading-dot exclusion |
| `test_sympy_parse_expr_with_both_dicts_pinned_stays_silent` | Silent: `parse_expr(expression, local_dict={}, global_dict={})` — the documented-safe form |
| `test_sympy_parse_expr_with_only_local_dict_still_fires` | Fires: only `local_dict={}` present — both dicts required to silence |
| `test_sympy_parse_expr_static_literal_does_not_fire` | Silent: `parse_expr('2 + 2')` |

## Known bypasses

- Indirect access that evades the literal `eval`/`exec` regex: `getattr(__builtins__,
  'eval')(user_input)`, a reassigned alias (`e = eval; e(user_input)`), or
  `__import__('builtins').eval(...)`.
- Multi-line argument construction where the dynamic signal (f-string/concat/bare
  variable) doesn't appear on the same physical line as the `eval(`/`exec(` call.
- **A `.get("key")`/`.pop("key")` accessor call (rather than `["key"]` subscript syntax)
  still reads as a static literal** — deliberately not extended to cover this: the
  existing `_arg_after` helper strips ALL trailing `)` characters off the captured
  argument, which over-strips a nested method call like `payload.get("code"))` before
  `_SUBSCRIPT_KEY` would ever see it. Fixing that would require rewriting `_arg_after`'s
  paren handling, not just widening the accessor pattern — deferred as its own change
  rather than risking a fragile fix bundled with the subscript one (2026-07-04).
- **A subscript key that itself contains a quote character** (`node["a\"b"]`, or mixed-quote
  nesting like `node['a"b']`) is not stripped by `_SUBSCRIPT_KEY` — its `[^'"]*` body stops
  at the first embedded quote, so the `['"]...['"]` shape no longer lines up and the match
  fails. The unstripped quote stays in `unsubscripted`, so the line falls back to being read
  as a static literal if there is no other quote-free signal — i.e. the subscript false
  negative this guard otherwise fixes survives for this shape. Narrower than `.get`/`.pop`
  (a dict key holding a literal quote is rare in real code) and fails safe: no worse than the
  pre-`_SUBSCRIPT_KEY` behavior, never a false positive. Same regex-vs-escapes limitation the
  file's other heuristics carry (`_CONCAT`/`_PCT`).
- The pragma `# security: allow-eval-exec` silences the finding for that specific line
  only (unlike some guards' project-wide pragmas) — an audited case elsewhere in the
  same file still needs its own pragma or will still fire.

## What this guard does NOT prove

- That the "dynamic" content is actually attacker-reachable — a bare variable could be
  a hardcoded config value assigned earlier in the function, not user input. The guard
  is intentionally conservative-by-name-shape, not full dataflow analysis.
- That `ast.literal_eval()` (the safe alternative) isn't itself misused for something it
  wasn't designed for — this guard only flags `eval`/`exec` specifically.
- Multi-line or cross-function dataflow: the dynamic signal must appear on the same
  line as the sink call.

# Citations

[1] agentsec checklist item `3b-eval-exec-injection` (§3b)
[2] ASVS:1.3.2
[3] OWASP:A03
[4] CVE-2026-44717 (mcp-calculate-server, unpinned SymPy `parse_expr`)
[5] agent-audit-kit `AAK-MCP-TOOL-UNSAFE-EVAL-001` (sattyamjjain/agent-audit-kit)
