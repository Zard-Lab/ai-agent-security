---
type: Guard
title: "rls-permissive-policy"
description: "Permissive RLS policy (USING true) authorizes everyone."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "rls-permissive-policy"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Permissive RLS policy (USING true) authorizes everyone

Flags an "always-true" Row Level Security policy — `USING (true)` / `WITH CHECK (true)` / `USING (1=1)`
— in a `*.sql` file. Closes checklist item `7-rls-policy-always-true`. OWASP:A01.

## The threat

A policy whose expression is a constant `true` authorizes **every** row to **every** role the policy
targets. With RLS enabled the dashboard shows the table as "protected" and the policy looks present, but
it does nothing — "RLS theater." On a Supabase table reachable by the `anon`/`authenticated` key this is
a full data leak that *looks* secure. It is the single most common RLS mistake from AI code generators
(Cursor / Bolt / Lovable emit `CREATE POLICY ... USING (true)` by default). CWE-284.

## Exploitability rationale

The checklist item is CRITICAL (it silently voids the app's main tenant-isolation control). The **finding**
is HIGH: it is a very strong signal but not always a bug — a genuinely public-by-design table (a public
blog, a shared reference table) legitimately uses `USING (true)`. High + a pragma covers the rare
intentional case without crying wolf.

## What counts as a hit (and what doesn't)

Parses whole `CREATE POLICY … ;` **statements** (multiline, case-insensitive) and fires when the statement
contains `using (true)`, `with check (true)`, or `using (1=1)` — **unless** its `TO` clause targets only
`service_role`. A scoped policy (`USING (user_id = auth.uid())`, `USING (tenant_id = ...)`) doesn't match.
Comments are neutralised by a length-preserving blank pass (so commented-out `CREATE POLICY` is ignored
while live statements still report the correct line); the quoted policy name is space-filled too
(`blank_policy_names`), so a name like `"mark as restrictive"` cannot be read as an `AS RESTRICTIVE`
clause and silently downgrade a gating `always-true` HIGH to a non-gating `restrictive-always-true`
MEDIUM (#824 class; PR #893 re-review). The message names the targeted role; `anon` / PUBLIC
(no `TO` clause) are annotated "reachable by unauthenticated callers."

**Why skip `service_role`.** The Supabase `service_role` key **bypasses RLS entirely** — it is never subject
to a policy. A `USING(true) TO service_role` policy therefore authorizes nothing the role didn't already
have; flagging it is a false positive (and it dominates real Supabase schemas — ~half the hits on the
flagship). Skipping it cannot hide a real exposure: a table whose only permissive policy is `TO service_role`
still denies normal users (RLS-on + no matching policy = deny-all). A policy with no `TO` defaults to PUBLIC
(every role, incl. `anon`) and still fires; a mixed `TO service_role, authenticated` still fires.

## Sibling rules

Four more rules share this guard's clause-parsing infrastructure and its own `rls-permissive-
policy` check id, mined from `pgrls`'s SEC008/SEC010/SEC020/SEC031/SEC011:

- **`always-false`** (MEDIUM): `USING (false)` / `WITH CHECK (false)` denies every row/write —
  a deny-all disguised as an RLS-protected table. Suppress with
  `-- security: allow-policy-always-false`.
- **`write-check-open`** (MEDIUM): a scoped `USING` paired with an explicit `WITH CHECK (true)`
  — the read side is scoped but the policy imposes no write-side constraint. Suppress with
  `-- security: allow-write-check-open`.
- **`restrictive-always-true`** (MEDIUM): an `AS RESTRICTIVE` policy's `USING` clause is a
  constant `true` — a no-op floor (RESTRICTIVE policies only narrow, never grant). Suppress with
  `-- security: allow-restrictive-always-true`.
- **Buried `OR true`** (folds into `always-true` itself, no new rule id): `USING (x = 1
  OR true)` is functionally identical to `USING (true)` — this is what the "Known bypasses"
  section below used to call "indirect always-true... not matched." It is now matched: a
  balanced-paren clause-body extraction finds an OR-adjacent bare `true` token anywhere in the
  clause and treats it identically to the literal case for every rule above (always-true,
  write-check-open, restrictive-always-true — whichever applies). A buried `OR true` in a
  RESTRICTIVE policy correctly routes to `restrictive-always-true`, not `always-true`, the same
  exclusion the literal case already gets.

## When NOT to flag (and the pragma)

- A policy scoped to the caller (`auth.uid()`, a tenant column, a role check) → silent.
- A policy targeting **only `service_role`** → silent (RLS-bypassed; see above).
- A genuinely public table (public read-only data) → suppress the statement with
  `-- security: allow-permissive-policy` (recognised on the statement's lines or the line above).
- Commented-out SQL → silent.

## Known bypasses (honest limits)

- **Superseded migrations (the big one).** The scan is per-file and static — it does not reconcile
  cross-file state. A policy created `USING (true)` in an early migration and later `DROP`ped or replaced
  by a scoped one is **still flagged by this guard**. Real example: the flagship's
  `36-documents-multi-dim.sql` "Allow anon RPC access … TO anon USING(true)" is superseded by the
  user-scoped `documents_*_user_access` in `schema-snapshot.sql`, but both are scanned. The reconciliation
  is one layer up, not in the guard: when the repo ships an authoritative dump (`agentsec/sql_state.py`: a
  dump-like name such as `schema-snapshot.sql`, `schema.sql` or `*.dump.sql`, **and** pg_dump's session
  preamble or banner in its head), a SCHEMA-STATE finding in every other `.sql` file of the dump's own
  directory subtree is stamped `superseded` — still rendered and tagged with the dump that governs it, but out
  of the headline tally, deprioritized at every
  severity and non-gating (#800; before that the stamp only re-ranked, so a superseded HIGH still failed
  CI). Scoped to schema state on purpose: the check declares `schema_state` when a dump can speak for it,
  so a homoglyph, an invisible-unicode payload or a committed secret that merely sits in a migration file
  is never demoted — a dump carries none of those (#829). Without a dump, `--exclude` pure-history
  migration files or pragma the audited-historical statement; a `DROP POLICY`-replaying pass is
  deliberately not planned (it would rebuild Splinter at lower fidelity).
- **`;` inside a multi-line literal.** The statement ends at the first `;` outside a single-line quoted
  span (`find_statement_end`, issue #559); a `;` inside a string literal that itself spans lines (very rare)
  still truncates the parse, because a quote closing past a newline is read as stray rather than paired.
- **Indirect always-true.** `USING (coalesce(true, ...))`, `USING (1=1 OR x)` (a non-bare-`true`
  tautology), or a function that returns true is not matched. The one indirect form that IS now
  matched is a bare `OR true` disjunct — see "Sibling rules" above; other tautological
  forms remain out of scope (a real tautology checker is significant infrastructure for marginal
  value, the same trade the literal-only scope already makes).
- **`WITH CHECK` only on writes.** A read policy with a real `USING` but `WITH CHECK (true)` is flagged
  (the write side is open) — kept HIGH on purpose: INSERT-forgery into an `audit_logs`-style table is a
  real integrity risk, not a downgrade candidate.

## Comment blanking (issue #500)

The guard blanks comments before matching so a commented-out `CREATE POLICY` is ignored while live ones
keep valid line numbers. It originally did that with a private, string-unaware
`re.sub(r"/\*.*?\*/", …, re.DOTALL)`. Three shapes made that regex blank **live** policies through to
the next `*/` anywhere later in the file, and each returned 0 findings instead of 2 with no error, no
warning and a green test suite:

| shape | why it fired |
|---|---|
| `/*` inside an ordinary `'…'` literal | the regex has no string awareness — every `/*` is an opener |
| `/* legacy note -- superseded */` | the `--` pass ran FIRST and ate the block comment's own `*/`, orphaning the opener |
| `E'it\'s a note /* …'` | the `E'…'` literal mis-closed at the escaped quote, so its own `/*` was lexed in code context |

The #500 fix was `blank_block_comments(sql, dialect="sql")` — string-aware at the opening marker, capped on an
unmatched opener, length- and newline-preserving — with the `--` pass moved to run **after** it.

**The ordering is load-bearing, not cosmetic.** Adopting the shared helper while keeping the original
line-comments-first order fixes the first and third shapes and leaves the second one live, while passing
every other test in the file. That combination was measured, and it is the reason the sibling
`policy-exists-rls-disabled` ordering (block first, then line) is the one to copy. Regression tests for
all three shapes, plus the two FP-bait controls (a genuinely commented-out policy stays silent; `'C:\'`
in a plain literal still fires), live in `tests/guards/test_rls_permissive_policy.py`.

**Since #442 phase 2b the guard has no private blanker.** It reads the shared `strip_sql_comments(sql, blank=True)`, the length- and newline-preserving lexer the other SQL guards use. That lexer is one
left-to-right scan, so the block-versus-line ordering hazard above cannot occur. It also closes three
residuals the private copy carried:
- A `--` inside a string literal no longer blanks the rest of its line. That was a false negative.
- A policy `/* */`-commented inside a `DO $$ … $$` body is a comment. The copy's dollar-opaque block pass
  left it live, which was a false positive.
- A `COPY … FROM stdin` data row is data, not a statement.

A `/*` inside a dollar-quoted body (`$$See docs/*.md$$`) cannot open a comment past the body's close
(#442 phase 2a), which is the case the private copy already handled. The cross-guard pin for all 15
guards that moved is `tests/test_sql_guard_shared_comment_lexer.py`.

## Canary note (don't reflow)

The canary plant lives in `canary.py`'s `sql/schema.sql` block as a single Python source line —
`"ALTER TABLE ... ENABLE ROW LEVEL SECURITY;\nCREATE POLICY canary_all ... USING (true);\n"`. It is
deliberately one line and not two. `test_self_audit.py`'s baseline (`agentsec-exceptions.json`) keys
suppressions on `canary.py:<line>`, so any added/removed source line above a plant shifts that plant's
number and breaks the baseline. Keeping the two SQL statements on one source line means this guard's
plant cost the baseline only one shifted entry (the api-docs plant below `EXPECTED_RULES`, 290→291).
Splitting it back into two readable lines would shift ~9 entries. Leave it merged.

## What this guard does NOT prove

It catches the literal always-true policy in migration SQL; it does not evaluate the full resolved policy
set, role grants, or whether a table even needs RLS. Absence of a finding ≠ the policies are correctly
scoped — per-caller scoping (and the companion `public-table-rls` / `definer-function-grants` guards)
remain the controls. This is the fast, dep-free, pre-deploy mirror of Supabase Splinter's
`rls_policy_always_true` lint.

## Related

This guard completes the static-mirror trilogy for the production RLS blind spot documented in
the maintainers' blind-spot analysis: `public-table-rls` (RLS off), `definer-function-grants` (definer
over-grant), and this one (RLS on but always-true). Unlike the live Splinter lints, it is a pure pattern
scan with **no `pgrst.db_schemas` GUC dependence**, so it does not inherit that note's gating blind spot.

# Citations

[1] agentsec checklist item `7-rls-policy-always-true` (§7)
[2] OWASP:A01
