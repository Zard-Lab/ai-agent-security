---
type: Guard
title: "insecure-tempfile-mktemp"
description: "Insecure tempfile.mktemp() usage (race condition)."
timestamp: "2026-07-03T12:29:58+08:00"
guard_id: "insecure-tempfile-mktemp"
checklist_section: ["8"]
---

# Insecure tempfile.mktemp() usage (race condition)

_Author — Marconi, 2026-07-03_

---

## The threat

`tempfile.mktemp()` generates a temporary filename and returns it **without creating
the file**. Between the name being generated and the caller actually opening it, a
race window exists during which another process — or a malicious local user in a
shared/multi-tenant environment — can create a file at that same path first (a classic
TOCTOU, time-of-check-to-time-of-use, race condition — CWE-377). The Python standard
library docs themselves warn plainly: "Use of this function may introduce a security
hole in your program." Named as an explicit in-scope example in LlamaIndex's own
SECURITY.md ("Insecure temporary file creation with world-readable permissions" — the
underlying `mktemp()` mechanism is the classic root cause of that class of bug).

## Why this guard fits the stack

`mktemp()` reads as an obviously-named, innocuous helper — the deprecation isn't
obvious from the function name alone, and it predates `mkstemp()` by enough that older
tutorials, Stack Overflow answers, and AI code generators still occasionally suggest
it:

```python
import tempfile

path = tempfile.mktemp(suffix=".csv")   # name generated, file NOT created yet
with open(path, "w") as f:              # race window: another process could win here
    f.write(export_data)
```

## Detection design

1. `applies()` gate — `"python" in profile.features`.
2. Scans every `.py` file under `python_scan_dirs(root, profile)` (file-wide pragma
   check first).
3. Fires on any `tempfile.mktemp(` call — the function itself is unsafe regardless of
   its arguments, so no dynamic/static argument distinction is needed (unlike most
   other guards in this codebase, which gate on *dynamic* content).
4. Inline opt-out: `# security: allow-insecure-tempfile-mktemp` anywhere in the file.
5. Severity: `high` (a real, unconditional race-condition exposure once the deprecated
   API is called at all). Rule id: `insecure-tempfile-mktemp/mktemp-race-condition`.
   Standards: `["CWE-377"]`.

## When NOT to flag

- `tempfile.mkstemp()` — the safe, atomic alternative (creates the file at generation
  time, returns an open fd + path). Different function name, not matched.
- `tempfile.NamedTemporaryFile()` / `tempfile.TemporaryDirectory()` — also safe,
  atomic, different names.
- A `.mktemp()` call on an unrelated object (not the `tempfile` module) — the regex
  requires the literal `tempfile.` prefix.
- An audited case, suppressed with `# security: allow-insecure-tempfile-mktemp`
  anywhere in the file.

## Tests

| Test | What it checks |
|---|---|
| `test_insecure_tempfile_mktemp_fires` | Positive: `tempfile.mktemp(suffix='.csv')` fires HIGH (**verified_by**). |
| `test_insecure_tempfile_mktemp_fires_no_args` | Positive: the bare no-argument form also fires (the function itself is unsafe, not a specific argument shape). |
| `test_insecure_tempfile_mktemp_silent_on_mkstemp` | FP-bait: `tempfile.mkstemp()` (safe atomic alternative) → silent. |
| `test_insecure_tempfile_mktemp_silent_on_named_temporary_file` | FP-bait: `tempfile.NamedTemporaryFile()` → silent. |
| `test_insecure_tempfile_mktemp_silent_on_unrelated_method` | FP-bait: `.mktemp()` on an unrelated (non-`tempfile`) object → silent. |
| `test_insecure_tempfile_mktemp_pragma_silences` | Suppress pragma (file-wide) → silent. |
| `test_insecure_tempfile_mktemp_not_applies_without_python` | `applies()` gate false without `python`. |

## Known bypasses

- **Aliased import**: `from tempfile import mktemp as make_temp_name; make_temp_name()`
  defeats the `tempfile.mktemp(` literal match entirely.
- **Reassigned module reference**: `tf = tempfile; tf.mktemp()` is not matched — the
  regex requires the literal identifier `tempfile` immediately before `.mktemp(`.

## What this guard does NOT prove

A silent guard does not mean temp-file handling is safe elsewhere — it only means no
literal `tempfile.mktemp(` call was found. It does not check whether `mkstemp()`'s
returned file descriptor is used correctly, whether temp files are cleaned up, or
whether a completely different insecure temp-file pattern (e.g. a hand-rolled
predictable-filename scheme not using the `tempfile` module at all) exists elsewhere in
the code.

## Severity rationale (HIGH over Bandit's MEDIUM)

Bandit's B306 grades `tempfile.mktemp()` MEDIUM. This guard grades it HIGH: the LlamaIndex RC that
motivated it treated the TOCTOU symlink race (CWE-377) as high-severity in a shared-compute / agent
context (an agent writing to a predictable temp path an attacker can pre-create). On a single-tenant
hosted web app the practical risk is lower — suppress with `# security: allow-insecure-tempfile-mktemp`
after confirming the temp dir is not attacker-writable. When both tools run, prefer this guard's grade.

# Citations

[1] agentsec checklist item `8-insecure-tempfile-mktemp` (§8)
