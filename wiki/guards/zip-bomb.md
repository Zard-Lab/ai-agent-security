---
type: Guard
title: "zip-bomb"
description: "Unsafe archive extraction without size/count limit — Zip Bomb (CWE-409)."
timestamp: "2026-06-28T10:36:33+08:00"
guard_id: "zip-bomb"
checklist_section: ["3a"]
standards: ["ASVS:5.2.3", "ASVS:5.3.3", "OWASP:A01", "OWASP:A04"]
---

# Unsafe archive extraction without size/count limit — Zip Bomb (CWE-409)

_Marconi Sim — 2026-06-28_

---

## The threat

A zip bomb (CWE-409, OWASP:A04 Insecure Design / OWASP:ASVS 5.2.3) is a compressed archive
engineered to expand to an enormous uncompressed size — the classic "42.zip" decompresses to
4.5 petabytes from a 42 kB payload. In a FastAPI service with a file-upload endpoint, a single
malicious upload that reaches an unguarded `.extractall()` can exhaust all available disk space
or main memory in seconds, producing a hard denial-of-service with no authentication required
and no error recovery path.

**Who reaches this, with what privilege, to what effect?** Any unauthenticated (or minimally
authenticated) user who can submit a file upload. No special privilege is required. The effect
is immediate disk or memory exhaustion on the host, taking down the entire service.

---

## Why it's often introduced

Python's `zipfile` and `tarfile` stdlib modules enforce no limits by default. The obvious,
working pattern — demonstrated in official docs and countless tutorials — is:

```python
with zipfile.ZipFile(upload_path) as zf:
    zf.extractall(target_dir)   # 42 kB → ∞ GB
```

Developers trust the archive library to be safe and are usually thinking about the path-traversal
(zip-slip) half of the problem, not the size-expansion half. The bomb attack vector is often
omitted entirely from security checklists because no individual file *read* operation raises an
alarm — it's the aggregate that kills.

---

## Detection design

1. **`applies()` gate** — `"python" in profile.features`. The guard is Python-only; JS/TS
   archives are handled by separate toolchain guards.

2. **Files scanned** — `python_scan_dirs(root, profile)` + `iter_files(d, (".py",))`, the same
   walk used by all Python guards. Already-seen files are deduplicated via `seen: set[Path]`.

3. **Two-stage match:**
   - Stage 1 (file-level, cheap): `_ARCHIVE_IMPORT` regex must match — the file must import
     `zipfile` or `tarfile`. This prevents the guard from firing on unrelated `extractall`
     method names (e.g. a DOM tree library).
   - Stage 2 (line-level): for each line matching `_EXTRACTALL` (`\.extractall\(`), look back
     from the extractall call to the START of its enclosing function (
     `enclosing_function_span()` in `guards/base.py`) — not a fixed window. A call with no
     enclosing function (module-level code) falls back to a 12-line look-back window. If
     `_SAFE_PATTERNS` matches anywhere in that scope, the call is considered guarded and the
     line is skipped. The search is look-BACK only, never forward: a size/count check written
     AFTER `.extractall()` has already run is not a mitigation.

4. **Inline opt-out pragma** — a `# security: allow-zip-bomb` comment. Checked at file level before any
   per-line scan. If the comment appears anywhere in the file body (a string literal quoting the phrase
   does not count, #424; typically on the
   extractall line), all findings for that file are suppressed.

5. **Severity and rule:** `HIGH`, rule `zip-bomb/no-size-limit`, standards
   `["OWASP:A04", "OWASP:ASVS", "CWE:409"]`.

Before the enclosing-function search, this guard used a fixed 12-line look-back window (wider than zip-slip's 5,
since the safe pattern — iterating members to accumulate total size — typically precedes the
`extractall` call by a `for` loop, an `if` check, and at least one blank line). That fixed
window is still the fallback for module-level calls with no enclosing function.

---

## When NOT to flag

- Files that check `MAX_SIZE`, `SIZE_LIMIT`, `total_size`, `file_size`, `compress_size`,
  `MAX_FILES`, `max_members`, or similar anywhere from the start of the enclosing function
  through the `extractall` call (or within 12 lines before it, at module level).
- Files that wrap `extractall` in a helper that enforces limits — if the helper is a DIFFERENT
  function the caller invokes (not inlined into the enclosing function's own body), use the
  pragma.
- Files that do not import `zipfile` or `tarfile` (the file-level import check prevents
  false positives on unrelated `extractall` methods).

---

## Tests

| Test | What it checks |
|---|---|
| `test_zip_bomb_flags_zipfile_extractall_no_size_check` | fires on bare `zf.extractall()` in a zipfile context |
| `test_zip_bomb_flags_tarfile_extractall_no_size_check` | fires on bare `tf.extractall()` in a tarfile context |
| `test_zip_bomb_silent_when_file_size_checked` | silent when `file_size` + `MAX_SIZE` checked before extractall |
| `test_zip_bomb_silent_when_max_files_checked` | silent when `MAX_FILES` + member count checked |
| `test_zip_bomb_silent_when_tarfile_size_checked` | silent when `SIZE_LIMIT` + `total_size` loop present |
| `test_zip_bomb_pragma_silences_file` | silent when `# security: allow-zip-bomb` is in the file |
| `test_zip_bomb_silent_when_no_archive_import` | silent on `obj.extractall()` without zipfile/tarfile import |
| `test_zip_bomb_does_not_apply_without_python_feature` | `applies()` returns False without `python` feature |
| `test_zip_bomb_silent_when_size_check_outside_old_fixed_window` | silent when the size check sits past the old 12-line window but is still in the enclosing function |
| `test_zip_bomb_module_level_call_still_uses_window_fallback` | module-level call with no enclosing function still uses the fixed-window fallback |
| `test_zip_bomb_still_fires_when_size_check_is_after_extractall` | directionality: a check written after the call still fires (look-back only, never forward) |

---

## Known bypasses

- **Size check in a separate function:** if the member-size loop lives in a DIFFERENT function
  the caller invokes (not inlined into the enclosing function's own body), the guard sees
  neither the helper call nor the loop — only the same-function case is covered.
- **Aliased modules:** `import zipfile as zf; zf_obj = zf.ZipFile(p); zf_obj.extractall(t)` is
  caught (the import pattern still matches). But `from somewhere import extract_all; extract_all(p, t)`
  is invisible.
- **Dynamic attribute access:** `getattr(archive, 'extractall')(target)` is not detected.
- **Variable re-use after check:** a size check at the top of a long function (> 12 lines above
  the `extractall`) will not be in the window and the guard will fire even though a check exists.

---

## What this guard does NOT prove

- That the size cap is actually enforced at the right layer (e.g. before the archive is written
  to disk at all, via a `Content-Length` header check).
- That the count limit is large enough to prevent inode exhaustion on systems with limited inode
  budgets (e.g. ext4 with default settings).
- That the path-traversal (zip-slip) vector is handled — that is the job of the `zip-slip` guard.
  Together the two guards cover both halves of `3a-decompression-bomb-zip-slip`.
- That a guarded helper used outside the 12-line window actually enforces limits — code review is
  required for suppressed findings.

# Citations

[1] agentsec checklist item `3a-decompression-bomb-zip-slip` (§3a)
[2] ASVS:5.2.3
[3] ASVS:5.3.3
[4] OWASP:A01
[5] OWASP:A04
