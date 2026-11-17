---
type: Guard
title: "dynamic-import-non-literal"
description: "Dynamic module import with a non-literal, attacker-influenceable name."
timestamp: "2026-07-01T21:23:59+08:00"
guard_id: "dynamic-import-non-literal"
checklist_section: ["3b"]
standards: ["OWASP:A01"]
---

# Dynamic module import with a non-literal, attacker-influenceable name

_Author — 2026-07-01_

---

## The threat

`importlib.import_module(name)` and `__import__(name)` load and execute an arbitrary
Python module by name. When `name` is built from attacker-influenceable content — a
request parameter, an unvalidated config value — the caller effectively chooses which
module gets imported and run. CWE-706 (Use of Incorrectly-Resolved Name or Reference),
OWASP:A01 (Broken Access Control — the caller reaches code paths/modules they shouldn't
be able to select).

## Why it's often introduced

A plugin or extension system loads modules by name, and the name comes straight from a
request or config value without validation:

```python
@app.post("/plugins/{plugin_name}/run")
def run_plugin(plugin_name: str):
    module = importlib.import_module(plugin_name)   # caller picks the module
    return module.run()
```

## Detection design

1. **applies() gate:** `"python" in profile.features` — runs on any Python codebase.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`attacker-influenced-name`, HIGH):** Same-line check. Matches
   `importlib.import_module(`/`__import__(` (`_IMPORT_SINK`), extracts the first
   argument via `_first_arg()` (stops at the first top-level comma or the line's
   trailing close-paren, so a second keyword argument like `package=None` doesn't leak
   into the dynamism check), then applies the same `_is_dynamic()` shape used by
   `command-injection`/`code-injection-eval-exec`: an f-string, `.format(`, `%`-format,
   `+` concatenation, or a bare variable/expression with no string literal at all.

4. **Inline opt-out pragma:** `# security: allow-dynamic-import`

5. **Severity and rule:** `"high"`, rule
   `"dynamic-import-non-literal/attacker-influenced-name"`, standards
   `["OWASP:A01", "CWE-706"]`.

## When NOT to flag

- A static string literal module name (`importlib.import_module("myapp.plugins.
  pdf_export")`) — nothing for a caller to influence.
- A static literal followed by additional keyword arguments (`import_module("x.y",
  package=None)`) — `_first_arg()`'s comma-stop keeps the second argument from being
  misread as part of the module-name check.
- An audited, allowlist-validated plugin loader suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_bare_variable_import_module` | Fires: `import_module(plugin_name)` — bare variable |
| `test_fires_on_fstring_import_module` | Fires: `import_module(f'plugins.{name}')` |
| `test_fires_on_dunder_import` | Fires: `__import__(mod)` — same dynamism check applies |
| `test_passes_static_literal` | Silent: static literal module name |
| `test_passes_static_literal_with_extra_arg` | Silent: static literal + `package=None` kwarg |
| `test_pragma_opt_out` | Silent: inline `# security: allow-dynamic-import` pragma |

## Known bypasses

- Indirect access that evades the literal `importlib.import_module`/`__import__`
  regex: a reassigned alias (`imp = importlib.import_module; imp(name)`), or
  `getattr(importlib, 'import_module')(name)`.
- Multi-line argument construction where the module-name variable is built on a
  different line than the `import_module(`/`__import__(` call itself.
- A dynamic name that's actually validated against an allowlist *before* this line
  (e.g., `if plugin_name in ALLOWED: importlib.import_module(plugin_name)`) still
  fires — the guard has no cross-line allowlist-check awareness, only a same-line
  dynamism check.

## What this guard does NOT prove

- That the module name, even if dynamic, is actually attacker-reachable — it could be
  a value computed from trusted, internal state.
- That an allowlist check exists elsewhere in the function guarding this call — the
  guard cannot distinguish a validated dynamic name from an unvalidated one.
- Multi-line or cross-function dataflow: the dynamic signal must appear on the same
  line as the sink call.

# Citations

[1] agentsec checklist item `3b-dynamic-import-non-literal` (§3b)
[2] OWASP:A01
