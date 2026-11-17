---
type: Guard
title: "<id>"
description: "<one sentence, the guard's title, ending with a period.>"
timestamp: "YYYY-MM-DDTHH:MM:SSZ"
guard_id: "<id>"
checklist_section: ["<section>"]
standards: ["OWASP:A0N"]
status: draft
---

# <the guard's title, as prose>

<!--
Copy this file to wiki/guards/<id>.md (the <id> MUST equal the guard's `id` attribute,
e.g. stripe-payments, not stripe-webhook) and fill in each section. Delete these comments.

FRONTMATTER (OKF v0.1):
  type / title / description / timestamp are the four REQUIRED OKF fields. `description` must be
  exactly ONE sentence ending with a period; it is used verbatim in the wiki/guards/index.md
  bullet. `timestamp` is quoted ISO-8601 (`2026-08-14T09:00:00Z` or with a `+HH:MM` offset).
  guard_id / checklist_section / standards are agentsec extension fields.
  `checklist_section` is ALWAYS a list, even for one section, and every id in it must match a
  section that checklist.json maps this guard to via `check_ids`. The drift test asserts this,
  so it is no longer a `§` in the heading -- do not put one there.
  Drop `status: draft` (it defaults to `active`).

Every guard doc MUST answer the 4 rubric questions -- they map to the sections below. Keep it
honest: a guard that over-claims is worse than one that says plainly what it does not cover.

BODY ORDER is OKF's: prose -> domain sections -> `# Examples` -> `# Citations` LAST.
The `##` sections below are the domain section. `# Citations` must stay the final top-level
heading in the file.
-->

_Author — YYYY-MM-DD_

---

## The threat
<!-- Rubric Q1 — exploitability rationale: WHO reaches this, with WHAT privilege, to WHAT effect?
     Name the concrete attack, not just the category. Cite the OWASP / OWASP-LLM standard the
     guard's findings carry. -->

## Why it's often introduced  /  ## Why this guard fits the stack
<!-- How the bug gets into a FastAPI + React + Postgres + LLM/RAG app (the 9_Agent_SaaS shape).
     A short code snippet of the bad pattern helps. -->

## Detection design
<!-- Numbered, matching the code:
     1. applies() gate — which profile.features turn it on
     2. what files are scanned (helper: iter_files / python_scan_dirs / sql_dir / frontend_dir)
     3. the patterns / regexes / parse and any global-check-vs-per-line logic
     4. the inline opt-out pragma: its COMMENT form in the file's own syntax (`# security: allow-<id>`;
        `// …` in JS/TS/Go/Java; either in PHP and HCL; `-- …` in SQL) and its reach (line / block /
        whole file / repo).
        A pragma counts only as a comment (#424): a string literal, docstring, YAML scalar or SQL
        literal quoting the phrase never suppresses, so never describe it as a bare
        `security: allow-<id>` token or as "the string … anywhere in the file". The guard reads it
        through `pragma_present` / `pragma_line_set` (guards/base.py); a whole-file or repo reach is
        pinned in tests/test_pragma_anchoring.py::_FILE_SCOPED_PRAGMA.
     5. severity(ies) and the rule id(s) emitted, with the standards list
     Pull severity / standards / rule / pragma VERBATIM from the guard's Finding(...) calls. -->

## When NOT to flag
<!-- Rubric Q2 — the legitimate pattern that looks similar but is fine, and what the pragma is for
     (show the pragma as a comment, e.g. `# security: allow-<id>`, never as a bare token). -->

## Tests
<!-- A table of the REAL test function names that cover this guard, and what each asserts.
     | Test | What it checks | -->

| Test | What it checks |
|---|---|
| `test_...` | ... |

## Known bypasses
<!-- Rubric Q3 — honestly list how a determined author could evade detection
     (indirect assignment, aliasing, whitespace, config indirection, dynamic construction, …). -->

## What this guard does NOT prove
<!-- Rubric Q4 — the coverage gap left open even when the guard is silent. -->

# Citations
<!-- Numbered, real sources only. Cite the checklist item(s) that map this guard and the
     standards ids they carry; add external references (OWASP pages, CVEs, advisories) where
     they exist. Do not invent URLs. -->

[1] agentsec checklist item `<section>-<slug>` (§<section>)
[2] OWASP:A0N
