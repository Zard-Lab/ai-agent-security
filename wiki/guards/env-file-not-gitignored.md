---
type: Guard
title: "env-file-not-gitignored"
description: "A real .env* file exists in the repo with no .gitignore exclusion pattern covering it."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "env-file-not-gitignored"
checklist_section: ["8"]
standards: ["CWE-538", "OWASP:A05"]
---

# A .env file exists with no .gitignore exclusion

_Author — 2026-09-26_

---

## The threat

A `.env` file holding real local credentials (DB connection strings, API keys, session
secrets) is a completely normal development artifact. The actual risk this guard targets
is narrower and structural: if nothing in `.gitignore` excludes it, the *next* `git add .`
or `git add -A` commits it — silently, with no confirmation prompt, into a history that
every contributor, CI log, and fork can read forever after. CWE-538 (File and Directory
Information Exposure), OWASP:A05 (Security Misconfiguration). Sourced from
`agent-audit-kit`'s `secret_exposure.py` AAK-SECRET-006 (verified against the real repo
source).

## Why it's often introduced

`.env` is created by copying `.env.example`, or by a framework's own scaffolding (`create-*`
CLI tools routinely write a starter `.env`), often *before* `.gitignore` is set up or
edited. A repo that adds a `.env*` ignore rule later never retroactively checks whether an
earlier `.env` was already sitting there uncovered. Because the file works fine locally
either way, nothing about the development loop surfaces the gap until an accidental commit
already happened.

## Detection design

1. `applies()` — returns `True` unconditionally; a `.env` file is a near-universal local-dev
   artifact independent of the detected stack.
2. Files scanned: every `.env*`-named file in the repo (`iter_files_named(root, ".env*",
   respect_gitignore=False)` — deliberately including gitignored ones, since seeing the full
   population is how the guard tells covered from uncovered), plus every `.gitignore` file
   in the repo (their content is concatenated and searched, not parsed as glob syntax).
3. A `.env*` file is excluded from consideration first if its name ends in `.example`,
   `.sample`, `.template`, or `.dist` (template variants meant to be committed). For every
   remaining file, the guard fires unless the last `.gitignore` line that matches it is an
   ignore. Each whole line is glob-matched (`fnmatch`) against the file's name after dropping a
   leading `**/` or `/`: `.env`, `/.env`, `**/.env`, `.env*`, `*.env` and the file's own name
   all cover it. Comment lines never count, a `!negation` line un-ignores what it matches
   (last match wins, as in git), and a directory-only rule (`.env/`) does not cover a file.
   A substring hit does not count: `.env.local` does not cover `.env`, and `.env.*` does not
   cover a bare `.env`. It is a line-level glob check, not a full gitignore engine: every
   `.gitignore` in the repo is read as one list, so which directory a rule came from is not
   modeled.
4. Inline opt-out: `# security: allow-env-file-not-gitignored` as a comment anywhere in
   `.gitignore` (there is no natural place to put a pragma directly on the `.env` file
   itself for a presence-only check), read through the `hash` comment view: a quoted span
   does not count (#1040). The view also keeps a mid-line ` #`, which git reads as part of
   a pattern, exactly as the raw match did.
5. Severity HIGH, rule `env-file-not-gitignored/no-exclusion`, standards
   `["CWE-538", "OWASP:A05"]`.

## When NOT to flag

- A `.env.example`/`.env.sample`/`.env.template`/`.env.dist` file — these are meant to be
  tracked, and typically hold placeholder values, not real secrets.
- Any `.env*` file already covered by a `.gitignore` pattern, even a narrow one naming only
  that exact file.

## Tests

| Test | What it checks |
|---|---|
| `test_env_file_with_no_gitignore_fires` | No `.gitignore` at all — fires |
| `test_env_file_with_unrelated_gitignore_fires` | `.gitignore` exists but never mentions `.env` — still fires |
| `test_env_covered_by_bare_env_star_pattern_is_safe` | `.env*` line in `.gitignore` — silent |
| `test_env_covered_by_exact_filename_is_safe` | Exact filename line in `.gitignore` — silent |
| `test_env_dot_star_pattern_covers_variant` | `.env.*` covers a `.env.production`-style file |
| `test_env_example_template_is_never_flagged` | `.env.example` never flagged |
| `test_env_sample_and_template_variants_are_never_flagged` | `.sample`/`.template` variants never flagged |
| `test_no_env_file_present_is_silent` | No `.env*` file at all — no finding, no `.gitignore` required |
| `test_pragma_in_gitignore_suppresses_finding` | Pragma comment in `.gitignore` silences it |
| `test_bare_env_not_covered_by_lookalike_gitignore_lines` | `.env.local`, a commented `# .env`, `!.env`, `.env` then `!.env`, `.env.*`, `.env/`, a scoped `config/.env` do not cover a real `.env` (still fires) |
| `test_bare_env_covered_by_equivalent_forms_is_safe` | `.env`, `/.env`, `**/.env`, `.env*`, `*.env`, padded and CRLF lines all still silence it (FP-bait) |
| `test_env_variant_not_covered_by_a_different_variant_line` / `test_env_variant_covered_by_env_dot_star_is_safe` | Same rules for a `.env.local`-style file |
| `test_nonproduct_archive_path_is_skipped` | An opted-in archive-segment directory is skipped |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- A commented-out line, a `!negation`, a different file's name (`.env.local` for a real
  `.env`) and a directory-only rule are NOT coverage (fixed after review: the check used to be
  a substring match, which let all four silence the finding).
- A `.gitignore` scoped to a subdirectory (`/backend/.env`) is treated the same as a
  repo-wide rule, so a `.env` in a *different* directory than the one the pattern actually
  covers can go unflagged.
- A file covered by a *global* gitignore (`core.excludesFile` in the user's git config, not
  committed to the repo) is invisible to this guard entirely — only in-repo `.gitignore`
  files are read.

## What this guard does NOT prove

Silence means only that some `.gitignore` line glob-matches the file — it does not prove
the file was never previously committed (a `.gitignore` entry added after an earlier commit
does not remove the file from git history), and it says nothing about the file's *contents*
(that is `vite-client-secret`, `env-secret-logged`, and the generic secret-content guards'
job, not this one's).

# Citations

[1] agentsec checklist item `8-env-file-not-gitignored` (§8)
[2] CWE-538: File and Directory Information Exposure
[3] OWASP:A05 — Security Misconfiguration
[4] agent-audit-kit `secret_exposure.py`, rule AAK-SECRET-006 (source pattern this guard was ported from)
