---
type: Guard
title: "pg-rls-no-policy"
description: "RLS enabled on table but no CREATE POLICY defined — blocks all access."
timestamp: "2026-10-15T18:54:39Z"
guard_id: "pg-rls-no-policy"
checklist_section: ["7"]
standards: ["CIS:6.3", "OWASP:A01"]
---

# RLS enabled on table but no CREATE POLICY defined — blocks all access

Flags a table that has `ENABLE ROW LEVEL SECURITY` but no `CREATE POLICY` referencing it
anywhere in the scanned SQL. Closes checklist item `7-rls-enabled-no-policy`.
Standards: OWASP:A01, CIS:6.3.

## Threat

`ALTER TABLE t ENABLE ROW LEVEL SECURITY` without any `CREATE POLICY` causes Postgres to
apply its **default-deny** rule: every SELECT, INSERT, UPDATE and DELETE from every non-superuser
role returns zero rows or a permission error. The table is effectively locked out of the
application. This is almost never intentional. The two common causes are:

1. **Incomplete migration** — a developer enabled RLS in one commit and planned to add policies
   in the next, then shipped the first without the second.
2. **Copy-paste from documentation** — tutorials often show `ENABLE ROW LEVEL SECURITY` without
   explaining that the table is locked until a policy is added.

On Supabase the symptom surfaces as the application silently returning empty results for a table
it can reach (because the `authenticated` role is neither a superuser nor covered by a policy),
which can be confused with a data-loading bug rather than an access-control misconfiguration.
CWE-284 (Improper Access Control). CIS Control 6.3 (Access Control).

## Detection design

Cross-file scan over all `.sql` files. Auto-generated dumps (`pg_dump` / `supabase db dump`,
detected by a **structured header comment line** via `_is_generated_sql_dump` — not a substring
anywhere, so prose that merely mentions a dump is not skipped) are handled specially: their ENABLE
and GRANT are ignored (a dump's grants are Supabase's implicit anon/authenticated defaults, and its
un-pragma'd ENABLE would void a pragma in the source migration), but their `CREATE POLICY` is still
read — a policy anywhere means the table is covered, the false-positive-safe direction (issue #802,
#819 review):

**Pass 1 — collect tables covered by a policy:**

```
CREATE POLICY <name> ON [<schema>.]<table> ...
```

The quoted policy **name** is space-filled first (`blank_policy_names`, length- and
newline-preserving): the `ON` tail is unanchored, so a name like `"foo on bar"` otherwise read as
`ON bar`, marked the wrong table covered, and silenced `bar`'s real finding while `documents` drew a
false one (#824 review). The statement bound is quote-aware (`find_statement_end`, #559).

Regex (comment-stripped, name-masked):

```python
re.compile(
    r"create\s+policy\b[^;]*?\bon\s+(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
```

**Pass 2 — collect tables with RLS enabled but no policy:**

```
ALTER TABLE [IF EXISTS] [<schema>.]<table> ENABLE ROW LEVEL SECURITY
```

Regex (comment-stripped):

```python
re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?"
    r"\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
```

**Pass 3 — collect tables a client role can reach (issue #802):**

```
GRANT <privs> ON [TABLE] [<schema>.]<table> TO <roles>
GRANT <privs> ON ALL TABLES IN SCHEMA <schema> TO <roles>
```

A grant counts only if `<roles>` names a role *subject to* RLS — anything other than
`service_role`/`postgres` (the `_RLS_BYPASS_ROLES` set). Both the qualified and bare table
names are indexed (search-path resolution), and a blanket `ON ALL TABLES IN SCHEMA` marks the
whole schema. The priv-run regex is length-bounded (`{1,400}?`) to stay linear on hostile SQL
(issue #419), mirroring `public_table_rls.py`.

Tables in the ENABLE set that are absent from the policy set are reported, one finding per
table (deduplicated). Severity is **HIGH** iff the table (or its schema) is in the client-grant
set, else **INFO**. The pragma `-- security: allow-rls-no-policy` anywhere in the file that
contains the ENABLE statement suppresses it entirely.

## Severity rationale

**Client-reachability aware (issue #802).** "RLS enabled, no policy" is default-deny only for
roles *subject to* RLS. `service_role` (BYPASSRLS) and `postgres` (owner/superuser) are not,
so a table granted only to them — or to nobody — is deny-all for every client, which is the
**fail-closed secure state** and the deliberate design for a service-role-only table (the
flagship's `oauth_authorization_codes`, `eval_results`, …). Severity therefore branches:

- **HIGH** when a **client role** (`anon`/`authenticated`, or any non-`service_role`/`postgres`
  role) holds a GRANT on the table — directly, or via a blanket `GRANT … ON ALL TABLES IN
  SCHEMA`. Then the grant and the missing policy are inconsistent: it is the "leak via stale
  grants" footgun a developer "fixes" by disabling RLS. Not CRITICAL because the immediate
  effect is denial of service to that role, not data exposure.
- **INFO** when no client role holds a grant (service-role-only, or ungranted). No client can
  reach the table, so there is no exposure. Fired at INFO rather than dropped so that an
  *accidental* lockout (an incomplete migration that also forgot the grant) stays visible.

The client-role gate is the "or leak via stale grants" half of checklist item
`7-rls-enabled-no-policy`.

## Known bypasses

- Reference/example SQL (`examples/`, `.agents/examples/`, `fixtures/`, tests) is skipped via `is_reference_sql_path`. `migrations/` is deliberately NOT skipped — for SQL it is the DEPLOYED schema (Supabase `supabase/migrations/*.sql`), so an RLS/extension gap there still fires (round-2 §C.2, PR #484 review).

| Bypass | Description |
|--------|-------------|
| Dynamic ENABLE | `ENABLE ROW LEVEL SECURITY` executed from application code or an ORM migration not in `.sql` files — this guard does not see it. |
| `EXECUTE` / `DO $$ ... $$` | Dynamic PL/pgSQL blocks are not parsed; an ENABLE inside a block is not detected. |
| Multi-line ENABLE | The ENABLE regex requires the statement to be on one or a few lines; an unusual line-wrapped form may be missed. |
| Policy in a non-`.sql` file | A policy defined in a migration tool config or seeding script outside the SQL file set is not counted. |
| Auto-generated dumps: ENABLE/GRANT ignored, policy honoured | A file whose header marks it a `pg_dump` / `supabase db dump` (`_is_generated_sql_dump`, keyed on a structured header comment line) has its ENABLE and GRANT ignored — a dump captures Supabase's *implicit* `GRANT ALL … TO anon/authenticated` default on nearly every public table (RLS-neutralized noise, not intent, issue #802), and its un-pragma'd ENABLE would void a `-- security: allow-rls-no-policy` the author wrote in the source migration (review-doctrine Rule 4). Its `CREATE POLICY` is still read, so a policy that lives only in a dump still suppresses (#819 review). Consequence: a table whose ENABLE exists ONLY in a dump (never in a hand-authored file) is not flagged — dumps mirror the migrations, so this loses no real signal. |
| Implicit client grants | A table reachable only through Supabase's *implicit* default grants that are NOT captured in any scanned hand-authored file reads as "no client grant" → INFO. Static SQL cannot see a privilege that isn't written down; time-bounded, since Supabase is removing implicit grants (flagship migration 147, cutover 2026-10-30) in favour of explicit ones this guard *does* read. |

## FP scenarios

| Scenario | Guard behavior |
|----------|---------------|
| Table is ENABLE'd and has a policy in another file | Silent — policy set is aggregated across all files. |
| Pragma present on the ENABLE line or in the file | Silent — `-- security: allow-rls-no-policy` suppresses the entire file. |
| ENABLE in a SQL comment | Silent — comment-stripped before matching. |
| A `/*` inside a dollar-quoted body (`$$See docs/*.md$$`) with a later `*/` | Nothing below the body is stripped: a comment opened inside a body ends inside it. Until the lexer bounded it (#442 phase 2), a hidden `CREATE POLICY` was a false HIGH and a hidden `ENABLE` a silent miss. A policy commented out inside a `DO $$ … $$` body is still not credited. |
| Service-role-only table (GRANT only to `service_role`, RLS on, 0 policies) | INFO, not HIGH — deny-all is the fail-closed design (issue #802). |
| Auto-generated `supabase db dump` carries implicit `GRANT ALL … TO anon/authenticated` | Dump file skipped whole; its grants never promote a service-role-only table to HIGH (issue #802). |
| No grant at all (RLS on, 0 policies, ungranted) | INFO — no client can reach it; kept visible in case it is an accidental lockout. |
| Client grant present but no policy | HIGH — `anon`/`authenticated` (or a blanket schema grant) can reach it; the missing policy is the stale-grant footgun. |
| Intentional deny-all staging table | INFO by default (no client grant); use the pragma to suppress entirely and document the reason. |

## Checklist items flipped

| Item ID | Title | From | To |
|---------|-------|------|----|
| `7-rls-enabled-no-policy` | RLS enabled but no policy defined — accidental deny-all | manual | covered |

## Tests

| Test function | Purpose |
|---------------|---------|
| `test_pg_rls_no_policy_fires_on_enable_without_policy` | True positive: ENABLE + a client (`authenticated`) grant + no policy emits one HIGH finding. |
| `test_pg_rls_no_policy_info_when_no_grant_at_all` | Narrowing (#802): ENABLE, no policy, no grant → the rule still fires but as INFO. |
| `test_pg_rls_no_policy_info_when_service_role_only` | The reported FP: `GRANT … TO service_role` only + RLS + no policy → INFO, not HIGH. |
| `test_pg_rls_no_policy_high_when_client_grant_in_other_file` | Negative control (#802): a client grant in a *separate* file still yields HIGH. |
| `test_pg_rls_no_policy_high_on_blanket_all_tables_grant` | `GRANT … ON ALL TABLES IN SCHEMA … TO authenticated` makes every table client-reachable → HIGH. |
| `test_pg_rls_no_policy_service_role_grant_is_not_a_client_grant` | Role parsing: `service_role` alone is never read as a client role; a sibling `authenticated` grant is. |
| `test_pg_rls_no_policy_ignores_generated_dump_grants` | The flagship shape: a `supabase db dump`'s implicit `anon`/`authenticated` grants are ignored; a service-role-only table stays INFO and anchors in the hand-authored file. |
| `test_pg_rls_no_policy_dump_skip_is_content_based_not_name` | The dump skip keys on the header, not the filename: a same-named file without the marker still fires HIGH on its client grant. |
| `test_pg_rls_no_policy_dump_mention_in_prose_does_not_skip` | #819: a hand-authored file that merely discusses a dump in a comment (or negates it) is not skipped — its real HIGH survives. |
| `test_pg_rls_no_policy_real_dump_header_still_skips` | #819 other direction: a genuine `pg_dump` / `supabase db dump` header is still detected, so implicit grants don't promote. |
| `test_pg_rls_no_policy_high_on_multiline_role_list` | #819: a client role after a newline in the `TO` list is not dropped → HIGH, not INFO. |
| `test_pg_rls_no_policy_policy_only_in_dump_still_suppresses` | #819: a `CREATE POLICY` that lives only in a dump still suppresses (no new false positive). |
| `test_pg_rls_no_policy_silent_when_policy_same_file` | False positive: ENABLE and CREATE POLICY in the same file is silent. |
| `test_pg_rls_no_policy_silent_when_policy_other_file` | False positive: policy in a different file than the ENABLE is still silent. |
| `test_pg_rls_no_policy_pragma_suppresses` | Pragma anywhere in the ENABLE file suppresses the finding. |
| `test_pg_rls_no_policy_applies_gate` | `applies()` returns True for supabase/postgres features, False for others. |
| `test_pg_rls_no_policy_no_sql_files` | No SQL files → empty findings list, no crash. |
| `test_pg_rls_no_policy_policy_after_a_dollar_quoted_glob_is_credited` | #442 phase 2: a policy between `$$See docs/*.md$$` and a later block comment still covers its table. |
| `test_pg_rls_no_policy_policy_commented_out_inside_a_do_body_is_not_credited` | The same policy commented out inside a `DO $$ … $$` body does not cover it → HIGH. |
| `test_pg_rls_no_policy_enable_after_a_dollar_quoted_glob_is_still_seen` | #442 phase 2: an ENABLE + client grant in the same position still fires HIGH. |

# Citations

[1] agentsec checklist item `7-rls-enabled-no-policy` (§7)
[2] CIS:6.3
[3] OWASP:A01
