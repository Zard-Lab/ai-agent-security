---
type: Guard
title: "public-table-rls"
description: "Exposed-schema table created without RLS."
timestamp: "2026-10-15T18:54:39Z"
guard_id: "public-table-rls"
checklist_section: ["2b", "7"]
standards: ["OWASP-LLM:LLM08", "OWASP:A01"]
---

# Exposed-schema table created without RLS

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

---

## The threat

In a Supabase/PostgREST stack, every table in an **API-exposed** schema is reachable through the
auto-generated REST API using the **anon key** that ships in the browser bundle. Row Level
Security (RLS) is the *only* thing standing between an anonymous client and that table's rows
— and RLS is **off by default**. A `CREATE TABLE documents (...)` with no
`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` means anyone with the public anon key can
`select * from documents` for every tenant. In a multi-tenant SaaS or a RAG app whose
embeddings/conversations live in an exposed schema, that is a full cross-tenant data breach.
Findings carry **OWASP A01 (Broken Access Control)** and **OWASP-LLM:LLM08**; severity **high**.

**Exposed ≠ only `public`.** The Data API serves any schema listed in `pgrst.db_schemas` on the
`authenticator` role, not just `public`. A repo that moves a domain into its own schema (e.g.
`workbook`) and grants it to `anon`/`authenticated` exposes those tables exactly like `public`.
This guard was originally `public`-only and **missed exactly this** on the flagship app
(`workbook.courses/sections/questions` were RLS-off + anon-readable for months — see
the maintainers' exposed-schema RLS blind-spot analysis); it now checks every exposed schema.

## Why it's often introduced

Supabase migrations are hand-written SQL. Adding `ENABLE ROW LEVEL SECURITY` plus policies is
extra, easily-forgotten boilerplate, and a table works perfectly in development (where you use
the service-role key) without it. The gap only manifests as a breach in production under the
anon key.

## Detection design

This guard is **DB-independent and order-independent** — it parses facts out of the SQL rather
than executing it.

1. **`applies()` gate** — `"sql" in profile.features`.
2. **Scan** — every `.sql` file under `profile.sql_dir` (or root), comment-stripped via
   `strip_sql_comments`. A comment opened inside a dollar-quoted body ends inside it, so the `/*`
   of `$$See docs/*.md$$` cannot strip SQL below the body. Until the lexer bounded it (#442
   phase 2), that glob plus any later `*/` cut both ways: a hidden `ENABLE` was a false HIGH and a
   hidden `CREATE TABLE` a silent miss. A comment wholly inside a `DO $$ … $$` body still strips,
   so a commented-out `ENABLE` there is still not credited.
3. **Parse** — regexes extract, per file, the **schema-qualified** tables that are
   `CREATE`d, `ENABLE`d for RLS, `DROP`ped, or moved out via `SET SCHEMA` (keyed `schema.name`;
   a table with no explicit schema is `public`).
4. **Exposed-schema detection** — `detect_exposed_schemas(texts, *, data_api_default_public)` returns
   the schemas reachable by the anon key. `public` is seeded **only when the repo has a PostgREST/
   Supabase Data API surface** (`data_api_default_public`, passed as `"supabase" in profile.features`).
   Without one — a plain-Postgres app behind a privileged `pg`/driver connection, no anon key — `public`
   is NOT anon-reachable, so its tables must not be flagged (round-2 §D.4: an over-broad `db=supabase`
   detection + an unconditional `public` default produced 8 FPs on a `pg`-driver repo). Regardless of
   that default, any schema (including `public`) that is `GRANT`ed (USAGE on the schema, privileges on a
   `schema.table`, or `ALL TABLES IN SCHEMA`) to `anon`/`authenticated`, or named in a literal
   `pgrst.db_schemas='…'` setting, is added — so a self-hosted PostgREST that explicitly grants `public`
   to anon is still caught even without the `supabase` feature. Only tables whose schema is in this set
   can be flagged; tables in a non-exposed schema (an internal `private` schema, `auth`, `storage`) are
   skipped — they aren't API-reachable, so flagging them would be a false positive. `applies()`
   deliberately stays gated on `sql` (not `supabase`) so the explicit-grant path still runs on any stack.
5. **Schema-variant awareness (the subtle part)** — many repos ship *two mutually exclusive*
   install paths: granular per-feature migrations **and** a consolidated bundle
   (`0-all-tables.sql`) that re-creates everything. Naively unioning all files lets an
   `ENABLE` in the bundle excuse a `CREATE` in the granular path — a **false negative**,
   because deploying the granular path actually leaves the table exposed. So the guard splits
   files into *variants* (the granular set as one path, plus each bundle as its own) and flags
   a table that is unprotected in **any** variant. A heuristic (`_BUNDLE_MIN_DUP_TABLES = 3`)
   identifies a file as a bundle when it re-creates ≥3 tables that other files also create.
6. **Finding** — `unprotected = created − rls − dropped − moved_out`, per variant, restricted to
   exposed schemas. Severity **high**, rule `public-table-rls/rls-disabled-in-public`, standards
   `["OWASP:A01", "OWASP-LLM:LLM08"]`. When the same table *is* protected in some other variant,
   the message says so explicitly (the high-value, easy-to-miss case).

**Reusable, public functions** (PR #742 review, Major 2 added the second one): `detect_exposed_schemas(texts, *, data_api_default_public)`
and `rls_gap_tables(root, sql_dir, profile)` (the module-level `_build_variants` plus the
flagging logic above, factored into one callable) are both module-level, not private to this
guard's class. `supabase_anon_key_rls_reachable.py` imports `rls_gap_tables()` directly rather
than reimplementing a simplified, non-variant-aware version of this same analysis — the earlier
reimplementation silently missed the granular-vs-bundle case this guard exists to catch.

## When NOT to flag

A table is clean when, **within the same install path**, it is RLS-enabled, dropped, or moved
to a non-exposed schema — or when its schema is not API-exposed at all (no anon/authenticated
grant, not in `pgrst.db_schemas`). There is no inline pragma; the remediation note mentions
allowlisting with a reason as the escape hatch for an intentionally-public table.

A **plain-Postgres app** (no `supabase` feature, no anon/authenticated grant, no `pgrst.db_schemas`)
is not flagged at all: without a PostgREST Data API, `public` is not anon-reachable and RLS is not the
applicable control (§D.4). The check re-engages the moment there is real exposure evidence — the
`supabase` feature, or an explicit `GRANT … TO anon` on a schema.

**Silence there is DISCLOSED, not a pass.** When RLS-off tables exist but no Data-API surface was
detected, the guard emits one `info` finding
(`public-table-rls/not-analysed-no-data-api`) naming those tables and saying plainly that exposure
could not be determined. `applies()` still returned True, so without this the guard ran, returned
nothing, and the report showed a *passing* check — meaning any miss in Supabase project-shape
detection read as a green light on a repo whose RLS was never assessed (#481 review).

## Tests

| Test | What it checks |
|---|---|
| `test_rls_flags_public_table_without_rls` | public `CREATE` with no `ENABLE RLS` (under `supabase`) → HIGH |
| `test_rls_plain_postgres_public_table_not_flagged` | FP-bait (§D.4): plain-Postgres (no `supabase`, no anon grant) public tables → silent |
| `test_rls_public_flagged_via_explicit_anon_grant_without_supabase` | no `supabase` but an explicit `GRANT … public … TO anon` → still HIGH (self-hosted PostgREST) |
| `test_rls_passes_when_enabled_or_dropped` | table enabled, or dropped, or moved out → silent |
| `test_rls_flags_table_protected_only_in_consolidated_bundle` | granular path leaves it exposed even though the bundle protects it → still HIGH (the variant-split's whole reason for existing) |
| `test_rls_flags_exposed_nonpublic_schema_without_rls` | `workbook.courses` granted to authenticated, no RLS → HIGH (the flagship blind spot) |
| `test_rls_exposed_schema_passes_when_rls_enabled` | same with `ENABLE RLS` → silent |
| `test_rls_non_exposed_schema_not_flagged` | `private.secrets`, service_role-only grant → silent (no FP) |
| `test_rls_plain_postgres_public_table_not_flagged` (assertion) | the no-Data-API case emits the `not-analysed-no-data-api` info disclosure naming both tables |
| `test_rls_exposed_via_pgrst_db_schemas_literal` | schema named in a `pgrst.db_schemas='…'` literal → HIGH |
| `test_rls_enable_after_a_dollar_quoted_glob_is_credited` | an `ENABLE` between `$$See docs/*.md$$` and a later block comment is credited → silent (#442 phase 2) |
| `test_rls_enable_commented_out_inside_a_do_body_is_not_credited` | the same `ENABLE` commented out inside a `DO $$ … $$` body is not credited → HIGH |
| `test_rls_table_after_a_dollar_quoted_glob_is_still_seen` | a `CREATE TABLE` in the same position is still seen → HIGH (#442 phase 2) |

## Known bypasses

- **Dynamic / templated SQL** — tables created by an ORM `create_all()`, a stored procedure,
  or string-built DDL never appear as a literal `CREATE TABLE` and aren't seen.
- **RLS enabled but no policy** — `ENABLE ROW LEVEL SECURITY` with zero `CREATE POLICY`
  counts as protected here, yet (depending on default-deny vs force) can still be misconfigured.
- **Dashboard-only schema exposure** — a schema exposed *only* via the Supabase Dashboard
  "Exposed schemas" setting, with no SQL `GRANT` to anon/authenticated and no literal
  `pgrst.db_schemas` statement, is invisible to a static scan (the flagship documents its
  exposed list in a *comment*, which `strip_sql_comments` removes). The live `agentsec live
  --db-schemas …` Splinter run and the Dashboard Advisor are the backstops.

## What this guard does NOT prove

That RLS *policies* are correct, nor the full set of exposed schemas — only that RLS is enabled
(or the table is dropped/moved) for every table in a schema whose exposure is visible in the SQL.
It reasons about DDL/`GRANT` statements in `.sql` files, not the live database state, and not the
content of the policies that govern access.

# Citations

[1] agentsec checklist item `2b-tenant-isolation` (§2b)
[2] agentsec checklist item `7-rls-per-user-scoping` (§7)
[3] OWASP-LLM:LLM08
[4] OWASP:A01
