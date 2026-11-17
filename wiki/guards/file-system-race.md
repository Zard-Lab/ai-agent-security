---
type: Guard
title: "file-system-race"
description: "File checked then used separately — time-of-check-to-time-of-use race."
timestamp: "2026-08-08T16:33:33+08:00"
guard_id: "file-system-race"
checklist_section: ["8"]
standards: ["CWE-367"]
---

# File checked then used separately — time-of-check-to-time-of-use race

_Author — 2026-08-08_

---

## The threat

**Time-of-check-to-time-of-use (TOCTOU) race, CWE-367.** Checking a file's existence or
stat/permissions and then, in a separate later call, writing to or opening that same path
assumes the filesystem entry the path resolves to has not changed in between. An attacker who
can influence what that path points to — a symlink swap on a shared temp directory, a
concurrent write from another request in a multi-tenant upload path, or a race against a
cleanup process — can make the later call act on a different file than the one that was
checked.

- **Who reaches it:** an attacker (or a competing legitimate process) with write access to
  the filesystem location the checked path lives in — most realistically a shared or
  predictable temp/upload directory.
- **Privilege required:** local filesystem access to the target directory (or the ability to
  create a symlink there), not necessarily the application's own privilege level.
- **Effect:** the write/open call can be redirected to an attacker-chosen destination
  (arbitrary file write via a symlink swap) or read attacker-planted content instead of the
  intended file.

Standards carried by findings: **CWE-367** (Time-of-check Time-of-use Race Condition).

---

## Why it's often introduced / Why this guard fits the stack

Checking a file exists before writing to it reads as defensive, careful code — and for a
purely local, single-process script it usually is. The risk appears specifically in a
network-facing service where the checked path is reachable by concurrent requests or shared
with other processes:

```js
// upload.js — a typical "don't overwrite" check
function saveUpload(uploadPath, data) {
  if (fs.existsSync(uploadPath)) {
    return false;               // "already exists, refuse"
  }
  fs.writeFileSync(uploadPath, data);   // <-- the check proved nothing by this point
  return true;
}
```

Between the `existsSync` check and the `writeFileSync` call, nothing stops another request
(or an attacker who predicted the path) from creating a symlink at `uploadPath` pointing
somewhere sensitive. The write then lands wherever the symlink points, not at the checked
location.

Sourced from GitHub CodeQL's `js/file-system-race` query
(`javascript/ql/src/Security/CWE-367/FileSystemRace.ql`, verified against real fetched
source): a `FileCheck` (`exists`/`existsSync`/`stat`/`statSync`/`lstat`/`lstatSync`/
`access`/`accessSync`) followed by a `FileUse` (`writeFile`/`writeFileSync`/`appendFile`/
`appendFileSync`/`open`/`openSync`/`readFile`/`readFileSync`) on the same path — except an
`exists`/`existsSync` check followed by a `readFile`/`readFileSync`, which CodeQL's own
query explicitly treats as fine ("a read after an exists check is fine").

---

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "express" in profile.features`.
   The `fs` module race is plain Node, not Express-specific, so the gate is the broader
   JS/TS language signal, with `express` kept as a belt-and-braces alternative (mirrors how
   `js-path-traversal` and sibling `fs`-based guards gate).

2. **Files scanned** — all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`
   (`is_nonproduct_path` excluded), comment-stripped via `strip_js_comments` before matching.

3. **Logic (single-file, windowed, same-variable-matched):**

   - Match a check call and capture its path argument, restricted to a bare identifier:
     `\bfs\.(exists(?:Sync)?|stat(?:Sync)?|lstat(?:Sync)?|access(?:Sync)?)\s*\(\s*(\w+)`.
   - Within the next 10 lines, match a use call the same way:
     `\bfs\.(writeFile(?:Sync)?|appendFile(?:Sync)?|open(?:Sync)?|readFile(?:Sync)?)\s*\(\s*(\w+)`.
   - Fire only when the captured identifiers are IDENTICAL — a check on `configPath`
     followed by a use on `logPath` is not a pair.
   - Skip the `exists`/`existsSync` + `readFile`/`readFileSync` combination — CodeQL's own
     documented exemption, since a stale read is not a write-integrity risk the same way a
     stale write or open is.

   Restricted to a bare-identifier path argument (not a property access or call expression)
   because the variable-identity match is the whole precision mechanism here — matching two
   calls on `x.path` vs `y.path` by the literal text `path` would pair unrelated checks and
   uses across different objects.

4. **Inline opt-out pragma** — `// security: allow-file-system-race` on the check line
   (checked against the unstripped source at that line — a file may have several
   check-then-use pairs and only one may need suppression).

5. **Severity / rule / standards:**
   - Severity: `medium` — matches CodeQL's own `problem.severity warning` /
     `precision: medium` framing for this exact query; a real but conditional risk (needs an
     attacker-reachable shared location), not an unconditional sink.
   - Rule: `file-system-race/check-then-use`
   - Standards: `["CWE-367"]`

---

## When NOT to flag

- **`exists`/`existsSync` check followed by `readFile`/`readFileSync`** — CodeQL's own
  documented exemption; a stale read returns stale data, not a corrupted write target.
- **Check and use on different path variables** — no relationship established between them.
- **Use more than 10 lines past the check** — outside the window this guard tracks.
- **Pragma suppressed** — `// security: allow-file-system-race` on the check line.

---

## Tests

| Test | What it checks |
|---|---|
| `test_file_system_race_fires_on_exists_then_write` | True positive: `fs.existsSync(uploadPath)` then `fs.writeFileSync(uploadPath, ...)` on the same variable — fires MEDIUM. |
| `test_file_system_race_fires_on_stat_then_open` | True positive: `fs.stat(targetPath, ...)` then `fs.open(targetPath, ...)` also fires. |
| `test_file_system_race_silent_on_exists_then_read` | False-positive bait: `existsSync` + `readFileSync` on the same path — CodeQL's own exemption, silent. |
| `test_file_system_race_silent_on_different_paths` | False-positive bait: check on `configPath`, use on `logPath` — different variables, silent. |
| `test_file_system_race_silent_beyond_window` | False-positive bait: the use is 12 lines past the check, outside the 10-line window — silent. |
| `test_file_system_race_pragma_silences` | Pragma: `// security: allow-file-system-race` on the check line silences that pair. |
| `test_file_system_race_does_not_apply_without_js` | Feature gate: `applies()` returns `False`, `run()` returns `[]`, for a profile without `javascript`/`express`. |

---

## Known bypasses

- **Non-identifier path arguments**: `fs.existsSync(getPath())` or `fs.existsSync(obj.path)`
  — only a bare identifier is matched on either side of the pair, so a call expression or
  property access as the path argument is not tracked in either direction.
- **Check and use split across functions**: a check in one function whose result is passed
  to a callback that performs the use elsewhere is not tracked — single-file, same-scope
  proximity only.
- **A differently-spelled variable holding the same value**: `const p = uploadPath;
  fs.writeFileSync(p, data)` — the guard matches identifier text, not value identity, so a
  reassignment breaks the pairing (a false negative) just as readily as it would prevent a
  false positive on two variables that happen to share a name but hold different paths.
- **Use more than 10 lines past the check** in a long function — a real race whose write
  happens well after the check (e.g. after significant validation logic) is not caught.

---

## What this guard does NOT prove

- It does not verify the checked path is actually attacker-reachable — a check-then-use pair
  on a fully static, build-time-known path (no shared or predictable location involved) is
  flagged the same as one on a genuinely shared upload directory. The severity is kept at
  MEDIUM specifically because of this conditional-exploitability gap.
- It does not detect the equivalent Python-side pattern (`os.path.exists()` then `open()`) —
  out of scope for this guard; `insecure-tempfile-mktemp` covers the Python side's narrower
  `tempfile.mktemp()` predictable-name race, a different (if related) CWE-367 instance.
- A silent guard does not mean the code is race-free — a check-then-use pair spanning more
  than 10 lines, split across functions, or built from non-identifier path expressions is a
  real, undetected residual.

# Citations

[1] agentsec checklist item `8-file-system-race` (§8)
[2] CWE-367
