---
type: Guard
title: "hidden-executable-dotfile"
description: "No hidden (dotfile) executable script committed to the repo."
timestamp: "2026-07-12T21:23:52+08:00"
guard_id: "hidden-executable-dotfile"
checklist_section: ["8"]
standards: ["OWASP:A08"]
---

# No hidden (dotfile) executable script committed to the repo

_Author — 2026-07-12_

---

## The threat

A file whose name starts with `.` is hidden from a plain `ls`/default directory
listing and easy to overlook during a casual code review, a quick `find *.py`-style
sweep, or a directory browse in a file manager — yet the moment something invokes
it (a build step, a cron entry, a malicious agent-skill bundle's install hook), a
dot-prefixed script executes exactly like any visible one. Naming a planted backdoor
`.update.sh` or `.cache.py` lets it blend into a directory listing full of legitimate
dotfiles (`.env`, `.gitignore`, `.eslintrc`) — a low-effort, high-payoff hiding
technique. CWE-506 (Embedded Malicious Code), OWASP:A08 (Software and Data
Integrity Failures).

## Why this guard fits the stack

This is a filename-hygiene check, not a content-pattern check — it applies
universally (any repo, any language) rather than being gated on a detected stack
feature, matching `svg-embedded-script`/`pdf-embedded-javascript`'s precedent this
session for "property of the file, not the stack" guards. It complements the
content-focused guards (`obfuscated-payload-execution`, `code-injection-eval-exec`)
by catching the *placement* signal even before any content is read.

## Detection design

1. **`applies()` gate** — always `True`.
2. **Files scanned** — `iter_files_named(root, ".*.py", ".*.sh", ".*.bash", ".*.rb",
   ".*.pl")` — a dot-prefixed name ending in one of five script-executable
   extensions. Non-product paths (test fixtures) skipped via `is_nonproduct_path`.
3. **Scope decision — `.js`/`.ts` deliberately excluded.** Hidden JS/TS config files
   (`.eslintrc.js`, `.babelrc.js`, `.prettierrc.js`, `.commitlintrc.js`, ...) are an
   extremely common and entirely legitimate tooling convention. Including them would
   make this guard's findings mostly noise on any real JS/TS repo. `.py`/`.sh`/
   `.bash`/`.rb`/`.pl` have no comparable common legitimate hidden-dotfile
   convention, so the guard is scoped to those five.
4. **Pragma** — a `# security: allow-hidden-executable-dotfile` comment, checked against the
   comment-only view of the file's own content for `.py`, `.sh`, `.bash` and `.rb` (#424; read via the
   shared `read()` helper). `.pl` has no comment dialect yet, so a Perl dotfile is still matched on its raw
   text and a quoted phrase there still suppresses.
5. **Severity / rule id** — MEDIUM (a filename-only signal, not a content-proven
   one), `hidden-executable-dotfile/dotfile-script`, `OWASP:A08` (checklist item
   also carries `CWE-506`).

## When NOT to flag

- An ordinary dotfile with no script-executable extension (`.env`, `.gitignore`,
  `.dockerignore`, `.editorconfig`) stays silent — only the five scoped extensions
  trigger a match at all.
- A hidden `.js`/`.ts` config file (`.eslintrc.js`, `.prettierrc.js`, ...) is out of
  scope by design (see above) — the extension list simply excludes them.
- A visibly-named script (`update.py`, no leading dot) is not hidden and stays
  silent — this guard is about the dot-prefix, not the script content.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_hidden_python_script` | `.update.py` fires `dotfile-script`, MEDIUM |
| `test_fires_on_hidden_shell_script` | `.cache.sh` fires `dotfile-script` |
| `test_passes_visible_python_script` | `update.py` (no leading dot) stays silent |
| `test_passes_common_hidden_js_config` | `.eslintrc.js` stays silent (excluded extension) |
| `test_passes_ordinary_dotfile_no_extension` | `.gitignore`/`.env` stay silent (no scoped extension) |
| `test_pragma_opt_out` | the pragma in the file's own content silences the finding |

## Known bypasses

- Any extension outside the fixed five (`.mjs`, `.cjs`, `.ps1`, `.php`, a
  no-extension script relying on a shebang alone) evades this guard entirely.
- A hidden *directory* containing a visibly-named script (`.tools/update.py`) is not
  caught — only the leaf filename is inspected, not ancestor directory names.
- Renaming the file to drop the leading dot only for the audit, then restoring it
  post-merge, defeats a point-in-time scan (a general limitation of any static
  filename check, not specific to this guard).

## What this guard does NOT prove

A finding here proves nothing about the file's actual content or intent — plenty of
legitimate build/CI tooling genuinely does live in a dot-prefixed script (some
projects hide internal helper scripts this way on purpose). It is a "worth a look"
signal, not a malice determination; the file's actual content should be reviewed
before deciding whether the finding is a real concern or an accepted convention for
that repo (in which case the pragma is the right response, not deletion).

# Citations

[1] agentsec checklist item `8-hidden-executable-dotfile` (§8)
[2] OWASP:A08
