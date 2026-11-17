---
type: Guard
title: "zip-slip"
description: "Unsafe .extractall() without path validation — Zip Slip (CWE-22)."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "zip-slip"
checklist_section: ["3a"]
standards: ["ASVS:5.2.3", "ASVS:5.3.3", "OWASP:A01", "OWASP:A04"]
---

# Unsafe .extractall() without path validation — Zip Slip (CWE-22)

## Threat

**Zip Slip** (CWE-22 path traversal via archive extraction) is an attack where a malicious
actor crafts an archive (ZIP, TAR, JAR, WAR, etc.) containing members whose paths include
`../` sequences — for example `../../etc/cron.d/evil`. When a service calls `.extractall()`
without validating that each resolved member path stays within the intended extraction
directory, the attacker's file is written to an arbitrary location on the server.

In a Python web service the impact is typically remote code execution: overwriting a
`.py` file in `site-packages` or the application itself, adding an SSH `authorized_keys`
entry, or writing a cron job. The attack is especially dangerous at file-upload endpoints
that unpack user-supplied archives on behalf of the caller.

References:
- Snyk Zip Slip advisory (2018) — confirmed in Gradle, npm, many OSS libraries
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- OWASP A01:2021 — Broken Access Control

---

## Detection design

**Module:** `agentsec/guards/zip_slip.py`
**Class:** `ZipSlipGuard`
**Rule ID:** `zip-slip/unsafe-extractall`
**Feature gate:** `"python" in profile.features` or `"express" in profile.features`

The guard scans all `.py` files under `python_scan_dirs`. For each file:

1. Skip the file entirely if a `# security: allow-zip-extractall` comment is anywhere
   in the file text (file-level suppression; a string literal quoting the phrase does not count, #424).
2. For each line that matches `\.extractall\(`, look back to the START of the enclosing
   function (`enclosing_function_span()` in `guards/base.py` — not a fixed window).
   A call with no enclosing function (module-level code) falls back to a 5-line look-back
   window. The search is look-BACK only, never forward — a validation check written AFTER
   `.extractall()` has already run is not a mitigation.
3. If **none** of the safe-extraction identifiers appear in that scope, emit one HIGH finding.

**Regex — extractall trigger:**

```
\.extractall\(
```

Matches `.extractall(` on any line — covers `zf.extractall(`, `tf.extractall(`,
`zipfile.ZipFile(...).extractall(`, etc.

**Regex — safe patterns (suppress the finding if any match in the window):**

```
safe_extract|os\.path\.realpath|os\.path\.commonpath|abspath|secure_filename
```

| Identifier | Why it indicates safety |
|---|---|
| `safe_extract` | A named helper that validates member paths before extraction |
| `os.path.realpath` | Used to resolve the full path and compare to the target root |
| `os.path.commonpath` | The `if commonpath([dest, target]) != target: raise` idiom |
| `abspath` | `os.path.abspath` — less strict but commonly used for the same check |
| `secure_filename` | werkzeug sanitizer; also used as a conventional guard name |

---

## Express/Node extension (codeql `js/zipslip`)

Same shape, JS-side: `.extractAllTo(` / `.extractAll(` (adm-zip, node-stream-zip) matched
per-line, with a 5-line safe-pattern window (`safeExtract|isPathInside|path\.resolve|\.startsWith\(`).
Deliberately does NOT flag `tar.extract({file, cwd})` — the `tar` npm package validates member
paths internally since a 2021 CVE fix, so matching its bare call would be a false positive on
already-safe code. Manual per-entry extraction loops (`unzipper`/`yauzl` streaming) are outside
scope for the same reason as the Python side's `namelist()` loop — a multi-step pattern, not a
single bulk-unpack call. JS/TS files are comment-stripped via `strip_js_comments` before matching.
The call and the safe idioms must also be live code (#1055): each match is tested with
`js_code_matches` on the anchor mask (`strip_js_comments(text, strip_strings=True,
keep_substitutions=True)`), on the call's `(` and on the idiom's first character. An idiom named in
a log or error string does not clear the call, a call spelled out in a docs string does not fire,
code inside a `${...}` substitution still counts, and every match is tried, so a quoted copy cannot
hide a real one after it on the same line.
Suppress with `// security: allow-zip-extractall`.

---

## Severity rationale

**HIGH.** Zip Slip is not a theoretical risk — it was confirmed in production in dozens of
major OSS projects. Successful exploitation gives the attacker arbitrary write access on
the server filesystem with the service's user permissions. In a typical FastAPI app running
as a non-root container user this still permits overwriting application source, environment
files, and writable system paths. The path from initial write to code execution is short
and well-documented.

---

## Known bypasses / false negatives

| Scenario | Why missed |
|---|---|
| Member path validation in a DIFFERENT function called before `.extractall()` (not inlined into the enclosing function's own body) | The enclosing-function search does not cross function boundaries |
| Using `zipfile.Path` API instead of `.extractall()` | No `.extractall(` call; not matched |
| Validation using `pathlib.Path.resolve()` without `os.path` APIs | `resolve()` is not in the safe-pattern list |
| Dynamic member filtering via `namelist()` + per-member write | Pattern requires `.extractall(`; manual extraction loop is not matched |
| `tarfile` `filter=` argument (Python 3.12+) | Not in the safe-pattern list; a false negative for modern code |
| JS/TS anchoring (#1055) | The `.extractAllTo(`/`.extractAll(` call and the safe idioms count only when they are live code on the anchor mask, so a `path.resolve(` or `safeExtract` named in a log string no longer silences a real call. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). An idiom there is missed, which errs toward firing; a call there is missed, which errs toward silence |

---

## False positive scenarios

| Scenario | Why it fires (and how to suppress) |
|---|---|
| Test code that intentionally extracts a known-safe fixture archive | No context distinguishes test fixtures from production code; suppress with pragma |
| A custom `_safe_extract` wrapper that calls `.extractall()` internally but spells the surrounding check differently | The 5-line window may not contain a recognized identifier; add `safe_extract` to the function name or suppress |
| An extractall preceded by member-by-member validation in a loop more than 5 lines above | Window is bounded at 5 lines; suppress with pragma if reviewed |

---

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| `3a-decompression-bomb-zip-slip` | not-covered | covered | `ZipSlipGuard` detects unsafe `.extractall()` calls; test `test_zip_slip_flags_extractall` planted-violation validates the detection end-to-end |

---

## Tests

| Test | Validates |
|---|---|
| `test_zip_slip_flags_extractall` | True positive: bare `.extractall(` without any safe idiom fires HIGH finding with rule `zip-slip/unsafe-extractall` |
| `test_zip_slip_flags_tarfile_extractall` | True positive: `tf.extractall(path=output_dir)` without safe idiom also fires |
| `test_zip_slip_silent_when_safe_extract_present` | False-positive bait: `_safe_extract(tar, ...)` on its own (no `.extractall(`) is silent |
| `test_zip_slip_silent_when_realpath_in_window` | False-positive bait: `.extractall(` preceded within 5 lines by `os.path.realpath` is silent |
| `test_zip_slip_pragma_silences_file` | Pragma: file carrying a `# security: allow-zip-extractall` comment produces no findings even with bare `.extractall(` |
| `test_zip_slip_does_not_apply_without_python_feature` | Feature gate: guard returns `False` for `applies()` when `python` is not in `profile.features` |
| `test_zip_slip_applies_on_express` | Feature gate: guard returns `True` for `applies()` when `express` is in `profile.features` |
| `test_zip_slip_js_flags_extractallto` | True positive: `zip.extractAllTo(destDir, true)` without a safe idiom fires HIGH |
| `test_zip_slip_js_silent_when_path_resolve_check_present` | False-positive bait: `path.resolve` + `.startsWith(` validation before `.extractAllTo(` is silent |
| `test_zip_slip_js_silent_on_tar_extract` | False-positive bait: `tar.extract({file, cwd})` (internally validated since 2021) is silent |
| `test_zip_slip_js_pragma_silences_file` | Pragma: `// security: allow-zip-extractall` silences the JS/TS file |
| `test_zip_slip_js_quoted_safe_idiom_no_longer_clears_the_finding` | #1055 FN direction: a safe idiom in a string or template text no longer silences a real call |
| `test_zip_slip_js_real_safe_idiom_still_clears_the_finding` | #1055: a real idiom still clears, including one nested in `${...}` and one after a quoted copy on the same line |
| `test_zip_slip_js_call_spelled_in_a_string_stays_silent` | #1055 FP direction: the call spelled out in a string or template text does not fire |
| `test_zip_slip_js_real_call_still_fires` | #1055: the real call fires, including one nested in `${...}` and one after a quoted copy |
| `test_zip_slip_js_pragma_still_suppresses_a_code_anchored_finding` | The pragma still silences a finding the anchor rule kept |

# Citations

[1] agentsec checklist item `3a-decompression-bomb-zip-slip` (§3a)
[2] ASVS:5.2.3
[3] ASVS:5.3.3
[4] OWASP:A01
[5] OWASP:A04
