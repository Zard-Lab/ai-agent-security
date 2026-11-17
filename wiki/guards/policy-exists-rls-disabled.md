---
type: Guard
title: "policy-exists-rls-disabled"
description: "RLS policy defined but RLS not enabled — the policy is inert, the table is open."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "policy-exists-rls-disabled"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS policy defined but RLS not enabled — the policy is inert, the table is open

Flags a table that has an RLS **policy** but never `ENABLE ROW LEVEL SECURITY`. Closes checklist item
`7-policy-exists-rls-disabled`. OWASP:A01.

## The threat

A `CREATE POLICY` is inert unless the table also runs `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`.
Postgres simply does not consult policies on a table whose RLS is off, so the table is open to every
role that holds table privileges (on Supabase, that includes the `anon`/`authenticated` keys). The
dashboard still lists the policy, so the table *looks* governed. It is the inverse of the
permissive-policy bug: there the policy is present but useless because it says `true`; here it is
present but useless because the switch is off. CWE-284. Supabase Splinter lints this as
`policy_exists_rls_disabled`.

## Exploitability rationale

The checklist item is CRITICAL (a policy-but-no-RLS table is fully open while appearing protected). The
**finding** is HIGH: it is a near-certain bug, but RLS could in rare cases be enabled by a path the
static scan can't see (a dynamic `EXECUTE`, an ORM migration outside the `.sql` set). High + a pragma
covers that without crying wolf. The companion `public-table-rls` guard catches the no-policy-no-RLS
case; this one specifically catches the "they wrote a policy and thought they were done" mistake.

## What counts as a hit (and what doesn't)

A `CREATE POLICY ... ON <table>` whose target table is never `ENABLE ROW LEVEL SECURITY`'d
and never `DROP`'d anywhere in the migration SQL. The ENABLE/DROP scan is aggregated across **all**
`.sql` files and comment-stripped, so a policy in one migration and the `ENABLE` in another is fine, and
a commented-out `ENABLE` does not count as protection. One finding per dead table (deduped). A table
that is RLS-enabled, or dropped, does not match.

The policy keyword and its `ON <table>` clause may sit on **different lines** — Postgres and the
Supabase docs both write the statement that way, and a line-oriented scan saw a `CREATE POLICY` with
no table and dropped it (#422/#584). Matching is `;`-statement-bounded via `iter_bounded_matches`
(issue #419's linear walker), over a comment-blanked, **policy-name-masked** copy of the file that
preserves length and newlines, so a policy inside a `/* … */` block is not DDL and the reported line
still maps to the source. The name mask (`blank_policy_names`) exists because the `ON` tail is
unanchored: a name like `"foo on bar"` read as `ON bar`, attributed the policy to a table that HAS
RLS, and the unprotected real table went silent (#824 review). The statement bound, the
head-attribution check and the pragma window are all quote-aware (`find_statement_end`, #559): a `;`
inside the name or a `USING` literal is content, so a pragma written at the statement's real end, or
on the head line of a multi-line `;`-named policy, is honoured rather than silently voided.
The `ENABLE` may carry `ALTER TABLE ONLY` (what `pg_dump` emits).

## When NOT to flag (and the pragma)

- The table is `ENABLE ROW LEVEL SECURITY`'d anywhere in the SQL set → silent.
- The table is dropped → silent.
- A deliberately open table with a documentation policy → suppress it with
  `-- security: allow-policy-without-rls`, anywhere in the `CREATE POLICY` statement. The pragma is
  read across the whole statement, not just its first line: on the multi-line form the natural place
  to write it is the end, several lines below the keyword. It stops at the statement's own `;`, so a
  pragma on a following statement cannot reach back and silence this one.
- **A Supabase-owned schema** (`storage`, `auth`, `realtime`, `vault`) → silent, because Supabase
  enables RLS on those itself and an application migration has no `ALTER TABLE` to write; the message
  ("the policy is inert and the table is open") would be false there. Gated on the `supabase`
  feature, so a hand-rolled Postgres app that names its own schema `auth` is unaffected and still
  reported.

## Known bypasses (honest limits)
- **RLS enabled outside the SQL set.** If `ENABLE ROW LEVEL SECURITY` runs from application code or a
  migration tool rather than a scanned `.sql` file, this can false-positive — hence HIGH + pragma.
- **`FORCE ROW LEVEL SECURITY` only.** We key on `ENABLE`; the rare `FORCE`-without-`ENABLE` shape is not
  modeled.
- **Comments (closed in #442 phase 2b).** The per-file structure scan reads the shared `strip_sql_comments(sql, blank=True)`, the length- and newline-preserving lexer the other SQL guards use, so a `--` inside
  a literal no longer blanks a policy on the same line, a `DO`-body comment is a comment, and a `COPY`
  data row is data. The cross-file `protected` set still reads the same lexer in delete mode, where only
  presence matters.

## Postgres `E'…'` escape strings (issue #500)

This guard was the **first consumer** of `blank_block_comments(dialect="sql")`, adopted in #587. That
preset shipped with a known, unfixed hazard: it set `backslash_escapes=False` (correct for a plain
literal under `standard_conforming_strings`, and the fix for a `'C:\'` false positive) but had no notion
of the Postgres `E'…'` prefix, which escapes with a backslash regardless. An `E'it\'s a note /* …'`
literal therefore mis-closed at the escaped quote, resumed code-mode lexing inside itself, and let its
own `/*` blank live SQL through to the next `*/`.

Because this guard had already adopted the preset, that was a **live** false negative on `main`, not
latent surface: measured, a fixture with an unprotected `CREATE POLICY` went from 1 finding to 0 with an
`E'` string present. The same blind spot existed in `strip_sql_comments` (used by 9 guard modules,
including this one's cross-file `protected` aggregation), so `public-table-rls` and `pg-anon-grant` were
measured going 1 → 0 on the same shape.

Both scanners now honor the prefix via `opens_sql_escape_string`, gated per-LITERAL rather than
per-dialect so an ordinary `'C:\'` still closes at its own quote. Tests:
`test_blank_block_comments_sql_honors_pg_escape_strings`,
`test_strip_sql_comments_honors_pg_escape_strings`, and
`test_opens_sql_escape_string_requires_a_bare_prefix` (the `E` must be a bare prefix, not the tail of
`case`/`date`/`value`).

## What this guard does NOT prove

It proves a policy exists without RLS being enabled in the migration SQL; it does not evaluate whether
the policy (once RLS is on) is correctly scoped — that is `rls-permissive-policy` /
`rls-no-user-metadata-claim`. Absence of a finding ≠ RLS is correctly configured. This is the fast,
dep-free, pre-deploy mirror of Splinter's `policy_exists_rls_disabled`.

# Citations

[1] agentsec checklist item `7-policy-exists-rls-disabled` (§7)
[2] OWASP:A01
