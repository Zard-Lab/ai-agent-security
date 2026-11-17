---
type: Guard
title: "bulk-env-var-harvesting"
description: "Bulk enumeration of all environment variables."
timestamp: "2026-07-12T19:16:56+08:00"
guard_id: "bulk-env-var-harvesting"
checklist_section: ["8"]
standards: ["CWE-200", "OWASP:A02"]
---

# Bulk enumeration of all environment variables

## Threat

**CWE-200 (Exposure of Sensitive Information), OWASP:A02.** Iterating or dumping the entire
process environment — rather than reading one named variable — is a strong signal of secret
harvesting: typical application code reads `DATABASE_URL` or `API_KEY` by name because it
needs that specific value; there is no ordinary reason to enumerate every variable the process
has, since doing so sweeps up API keys, database URLs, and internal tokens belonging to
services that have nothing to do with the code doing the enumerating.

```python
for name, value in os.environ.items():
    send_to_remote(name, value)
```

Sourced from SkillSpector's `E2` category ("Env Variable Harvesting") — a scanner built for AI
agent skill files, where this exact pattern (or its natural-language instruction equivalent,
"collect all environment variables") is a common credential-exfiltration technique for a
malicious or prompt-injected skill.

## Detection design

1. **`applies()` gate:** universal (`return True`). The Python/JS source this scans (and its
   env-harvesting signal) can appear in any project regardless of the detected stack; a
   language-feature gate silently dropped the JS `Object.keys(process.env)` path on a Node-only
   repo (PR #393 review #1). `run()` skips test/fixture/vendor files via `is_nonproduct_path`.
2. **Files scanned:** `.py`, `.js`, `.ts`, `.jsx`, `.tsx` via `iter_files()`.
3. **Patterns:**
   - `os.environ.items()` — fires, EXCEPT a *filtered comprehension* (a line where `for` is
     not the leading token and an `if` filter clause follows `.items()`, e.g.
     `{k: v for k, v in os.environ.items() if k.startswith("APP_")}`) reads a bounded subset
     and is carved out. A `for`-loop **statement** (`_FOR_STATEMENT`: line starts with `for`/
     `async for`) always fires — it enumerates the whole mapping regardless of any conditional
     in its body (PR #393 final-pass review). See **Known bypasses** for the residual
     vacuous-filter comprehension gap.
   - `Object.keys(process.env)` — the Node equivalent: enumerating every variable name.
4. **Skips:** lines starting with `#` or `//`.
5. **Pragma:** `# security: allow-bulk-env-harvesting` anywhere in the file skips it entirely.
6. **Severity / rule:** `bulk-env-var-harvesting/environment-enumeration`, **HIGH**.

**2026-07-12, caught during the Phase 4d full-batch self-audit gate (not the per-guard
tests):** an earlier version also fired on a bare `os.environ.copy()` / `dict(os.environ)`
(excluding only the exact `env=` keyword-argument shape). This produced a real false positive
on this project's own `agentsec/net.py::resolve_tier()`, which does
`environ = dict(os.environ)` purely to take a local immutable snapshot before several
`environ.get(...)` lookups by name — functionally equivalent to reading named variables, not
harvesting all of them. Removed both patterns entirely rather than trying to special-case this
shape further; `os.environ.items()` and `Object.keys(process.env)` are the only genuinely
unambiguous enumeration signals (a bare copy/dict conversion is common and benign on its own —
the ambiguity is inherent to the API, not fixable with a narrower regex).

## Relationship to `mcp-tool-env-inheritance`

`mcp-tool-env-inheritance` fires on `env=os.environ` / `env=os.environ.copy()` /
`env=dict(os.environ)` used specifically as the `env=` keyword argument to
`StdioServerParameters`/`subprocess.Popen`/`asyncio.create_subprocess_exec` — the full
environment being **passed through** to a spawned child process. This guard's only two
patterns (`.items()` iteration, `Object.keys(...)`) never overlap with that shape in the first
place, since neither is a valid `env=` kwarg value — no exclusion logic is needed between the
two guards.

## When NOT to flag

A user-initiated diagnostics or support-bundle tool that legitimately dumps the environment
for a support ticket (with the user's explicit action and consent) is the real exception — the
pragma exists for this case.

## Tests

| Test | What it checks |
|---|---|
| `test_bulk_env_var_harvesting_flags_environ_items` | `os.environ.items()` iteration fires HIGH |
| `test_bulk_env_var_harvesting_silent_environ_copy` | Regression: bare `os.environ.copy()` used for named-key lookup stays silent |
| `test_bulk_env_var_harvesting_silent_dict_environ` | Regression: bare `dict(os.environ)` stays silent |
| `test_bulk_env_var_harvesting_flags_js_object_keys` | `Object.keys(process.env)` fires |
| `test_bulk_env_var_harvesting_silent_env_kwarg_form` | `env=os.environ.copy()` stays silent (owned by `mcp-tool-env-inheritance`) |
| `test_bulk_env_var_harvesting_silent_named_variable` | A single named `os.environ["X"]` read stays silent |
| `test_bulk_env_var_harvesting_pragma_silences` | File-level pragma suppresses all findings |
| `test_bulk_env_var_harvesting_silent_filtered_comprehension` | Regression (#393 #3): a key-prefix-filtered `os.environ.items()` comprehension (bounded subset) stays silent |
| `test_bulk_env_var_harvesting_flags_single_line_statement_harvest` | Regression (#393 final pass): a single-line `for ...: send(v if v else '')` statement harvest still fires — the carve-out is comprehension-only |
| `test_bulk_env_var_harvesting_flags_unfiltered_comprehension` | An UNfiltered comprehension is still full enumeration and fires |
| `test_bulk_env_var_harvesting_covers_js_only_repo` | Regression (#393 #1): JS detection fires on a repo with no `python` feature |
| `test_bulk_env_var_harvesting_skips_nonproduct_path` | Regression (#393 #2): a `tests/` file is skipped |
| `test_bulk_env_var_harvesting_applies_universally` | Guard applies on any stack (universal) |

## Known bypasses

- `os.environ.copy()` / `dict(os.environ)` followed by iterating the COPY (`for k, v in
  all_vars.items()`) is not caught — only the direct `os.environ.items()` shape is matched.
  This is a deliberate precision/recall tradeoff after the false positive described above.
- `vars(os.environ)` or other less-common ways to materialize the environment as an iterable
  are not matched.
- A single environment variable read via a loop over a hardcoded list of names
  (`for name in ["A", "B", "C"]: os.environ.get(name)`) is not flagged — this guard targets
  enumeration of the environment ITSELF, not iteration over a caller-controlled name list.
- A comprehension with a **vacuous** filter that still sweeps every pair
  (`[send(k, v) for k, v in os.environ.items() if True]`) is carved out by the filtered-
  comprehension exception even though it harvests everything. Distinguishing a bounding
  predicate (`if k.startswith("APP_")`) from a vacuous one (`if True`) needs semantic/AST
  analysis this line-based guard deliberately avoids (KISS). The realistic harvest shape — a
  `for`-loop **statement** — is NOT affected: statement loops always fire regardless of any
  conditional in their body (PR #393 final-pass review; see `_FOR_STATEMENT`).
- A **filtered comprehension wrapped across multiple physical lines** (a formatter splitting
  `{k: v for k, v in os.environ.items() if k.startswith("APP_")}` at the 110-col limit so the
  `for … os.environ.items()` clause lands on its own line) is false-flagged HIGH: the guard is
  line-based, so it sees a bare `for … items()` line with no visible `if` filter and cannot
  tell the wrapped comprehension continuation from a `for`-loop statement. This is an accepted
  false-positive of the line-based approach (fully disambiguating it needs AST); the intent-
  revealing single-line form stays silent, and the file-level pragma
  `# security: allow-bulk-env-harvesting` is the escape hatch for a genuinely benign wrapped case
  (PR #393 third-pass review).

## What this guard does NOT prove

A file with no finding may still exfiltrate secrets via named single-variable reads chained
together, or via a helper module this guard didn't scan.

# Citations

[1] agentsec checklist item `8-bulk-env-var-harvesting` (§8)
[2] CWE-200
[3] OWASP:A02
