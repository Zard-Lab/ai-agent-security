---
type: Guard
title: "matview-exposed"
description: "Public-schema materialized view has no schema-move or REVOKE mitigating its Data API exposure."
timestamp: "2026-10-18T00:00:00Z"
guard_id: "matview-exposed"
checklist_section: ["7"]
standards: ["OWASP:A01", "CIS:6.3"]
---

# Materialized view exposed via the Data API with no mitigation

_Author — 2026-08-23. Built from our research notes (source:
[database-sentinel](https://github.com/Farenhytee/database-sentinel), `MATVIEW_EXPOSED`)._

---

## The threat

PostgreSQL materialized views **cannot carry RLS policies at all** —
`ALTER MATERIALIZED VIEW ... ENABLE ROW LEVEL SECURITY` does not exist in Postgres. This is a
hard engine limitation, not a configuration mistake a migration author forgot to make. A
materialized view left in the `public` schema is therefore fully exposed through Supabase's
auto-generated Data API (PostgREST) — `GET /rest/v1/<view>` — no matter how thoroughly the
underlying base tables' RLS is locked down.

The trap is specifically that it looks like the *opposite* of a mistake: a developer secures
their tables with RLS, then creates a materialized view joining/aggregating that same data for
query performance — an entirely ordinary, well-intentioned thing to do — and the view silently
bypasses every one of those policies for anyone who can reach the API. Findings carry
**OWASP A01 (Broken Access Control)** and **CIS 6.3**; severity **high** — this is a full,
unauthenticated data exposure of whatever the view selects, on par with `public-table-rls.py`'s
finding for an ordinary table.

## Why this guard fits the stack

Materialized views are a common optimization in a Supabase/PostgREST app once a dashboard,
report, or aggregate query gets expensive to compute per-request — exactly the kind of thing a
9_Agent_SaaS-shaped app adds under load, well after the initial RLS design was reviewed and
signed off.

## Detection design

1. **`applies()` gate** — `"supabase" in profile.features`.
2. **Scan** — every `.sql` file under `profile.sql_dir` (or root), skipping reference/example/
   test paths via `is_reference_sql_path` (migrations are the deployed schema, not skipped).
3. **Find** — `CREATE MATERIALIZED VIEW [IF NOT EXISTS] [schema.]name AS ...`. No explicit
   schema defaults to `public` (Postgres's own default).
4. **Mitigation search** — two statement shapes, both found by linear, #419-safe scans
   (`iter_bounded_matches` for the move, `iter_statement_spans` for the ACL statements), not a
   lazy scan-to-`;` regex:
   - `ALTER MATERIALIZED VIEW ... SET SCHEMA <newschema>` — counts only when `<newschema>` is
     not itself `public` (a no-op move to `public` is not a mitigation).
   - `REVOKE <privs> ON [TABLE|MATERIALIZED VIEW] [schema.]<name>[, ...] FROM <roles>`. The
     object keyword is skipped, so `ON TABLE public.v` names `public.v` (before #1096 it captured
     `TABLE` as the name, a false positive on a fully revoked view). `ON SCHEMA`/`ON FUNCTION`/
     `ON ALL TABLES IN SCHEMA` are not relation targets. The **whole** role list is parsed by
     `guards/base.py::sql_role_names`, not just its first role, and roles are unioned per view
     across every such statement in the scanned SQL. Statements are read on
     `guards/base.py::blank_sql_literals_nested`, so a REVOKE quoted in a string
     (`RAISE NOTICE 'revoke …'`) is not one, while a REVOKE in a dollar-quoted `DO` body stays
     visible and a lone apostrophe in a dollar-quoted string (`COMMENT … IS $$Don't$$`) cannot hide
     a later one. The literal an `EXECUTE '…'` / `EXECUTE format('…'` runs is parsed as a statement
     (`guards/base.py::sql_execute_literals`); a `format()` placeholder target such as `public.%I`
     names no relation and credits nothing.
   An unqualified name resolves to `public`, as for the CREATE, and a mitigation is indexed under
   that **qualified** name only, so a revoke on `private.v` no longer covers `public.v`.
5. **Flag** — a `public`-schema materialized view that is not moved out of `public` and whose
   unioned revoked roles miss `anon` or `authenticated` (or `PUBLIC`, when some
   `GRANT ... ON <view> TO PUBLIC` exists). One finding per view, at the file that creates it.
6. **Suppress** — `-- security: allow-matview-exposed` anywhere in the file that creates the
   view. Severity **high**, rule `matview-exposed/public-materialized-view-unmitigated`,
   standards `["OWASP:A01", "CIS:6.3"]`.

### Why both Data API roles (#1096)

Supabase's default privileges (`ALTER DEFAULT PRIVILEGES … GRANT ALL ON TABLES TO "anon"`, the
same for `"authenticated"`) grant both Data API roles **directly** on every new relation in
`public`. So `REVOKE ALL ON public.v FROM PUBLIC`, which removes only an implicit PUBLIC grant that
Postgres does not even make on relations by default, leaves the view readable by both. Until #1096
the guard accepted a REVOKE whose FIRST role was any of the three. `authenticated` is required
(unlike `definer-function-grants`, which lets it keep EXECUTE) because a materialized view cannot
carry RLS: any signed-in user reads every row. `PUBLIC` joins the requirement only when the SQL
grants the view to PUBLIC.

### Deliberate narrowing vs. the source candidate

A `GRANT` statement is deliberately **not** treated as re-exposing the view (only a
`GRANT … TO PUBLIC` changes what must be revoked, above).
Postgres grants `SELECT` on new relations to `PUBLIC` by default in many setups, so an explicit
`GRANT` on a materialized view is not itself evidence that access was widened (it may just
restate the default) or narrowed. Only a `REVOKE` — which unambiguously pulls access back — or
a schema move counts. This keeps the check to the two mitigations the source candidate itself
names, rather than reasoning about the full grant/role graph, which would need live-database
state (effective privileges after role inheritance) to get right and is exactly the kind of
"prove a mitigation is absent" surface most prone to false positives from static text alone.

## When NOT to flag

* The view is created outside `public` (an explicit non-`public` schema).
* An `ALTER MATERIALIZED VIEW ... SET SCHEMA` moves it to any schema other than `public`,
  anywhere in the scanned SQL (order-independent, same file or a different one).
* REVOKEs targeting the view remove it from both `anon` and `authenticated` (plus `PUBLIC` when
  it was granted to PUBLIC), in one statement or split across statements and files.
* The pragma is present in the file that creates the view.

## Tests

| Test | What it checks |
|---|---|
| `test_matview_exposed_fires_on_public_matview_no_mitigation` | `CREATE MATERIALIZED VIEW public.x`, no mitigation → HIGH |
| `test_matview_exposed_fires_with_no_schema_prefix` | no schema prefix defaults to `public` → HIGH |
| `test_matview_exposed_silent_with_revoke` | FP-bait: explicit `REVOKE ALL ... FROM PUBLIC, anon, authenticated` → silent |
| `test_matview_exposed_silent_with_schema_move` | FP-bait: `ALTER MATERIALIZED VIEW ... SET SCHEMA private` → silent |
| `test_matview_exposed_silent_for_nonpublic_schema` | `CREATE MATERIALIZED VIEW private.x` → silent |
| `test_matview_exposed_revoke_on_different_view_still_fires` | a REVOKE naming a different view does not silence this one |
| `test_matview_exposed_set_schema_to_public_is_a_noop` | `SET SCHEMA public` (no-op) does not silence |
| `test_matview_exposed_pragma_suppresses` | `-- security: allow-matview-exposed` → silent |
| `test_matview_exposed_applies_gate` | fires only when `supabase` is a detected feature |
| `test_matview_exposed_no_sql_files` | no `.sql` files → empty, no crash |
| `test_matview_exposed_skips_examples_dir` | a matview under `examples/` → silent (reference SQL) |
| `test_matview_exposed_hostile_headless_sql_is_linear` | 30k head-repeats, no `;` → completes in well under 5s (issue #419 DoS class) |
| `test_issue_1096_matview_revoke_from_public_only_still_fires` | the #1096 repro: `REVOKE ALL ON public.v FROM PUBLIC` → fires |
| `test_issue_1096_matview_revoke_missing_authenticated_fires` | `FROM PUBLIC, anon` → fires (authenticated required) |
| `test_issue_1096_matview_roles_split_across_statements_stay_silent` | FP-bait: the flagship split shape, `FROM anon` + `ON TABLE v FROM "authenticated"` → silent |
| `test_issue_1096_matview_on_table_keyword_is_skipped` | FP-bait: `ON TABLE public.v FROM PUBLIC, anon, authenticated` → silent |
| `test_issue_1096_matview_on_table_other_view_still_fires` | `ON TABLE public.other` does not cover `public.v` |
| `test_issue_1096_matview_multi_target_revoke_covers_each_view` | FP-bait: `ON public.a, public.b` covers both |
| `test_issue_1096_matview_revoke_on_other_schema_does_not_cover_public` | `private.v` revoked beside `public.v` → fires |
| `test_issue_1096_matview_granted_to_public_needs_public_revoked` | `GRANT … TO PUBLIC` + revoke from anon/authenticated only → fires |
| `test_issue_1096_matview_granted_to_public_and_fully_revoked_stays_silent` | the same with PUBLIC revoked too → silent |
| `test_issue_1096_matview_schema_revoke_is_not_a_view_revoke` | `REVOKE … ON SCHEMA public` is not a view revoke |
| `test_issue_1096_matview_pragma_still_silences_partial_revoke` | the file pragma silences the newly-firing PUBLIC-only shape |
| `test_issue_1096_matview_execute_literal_revoke_counts` | FP-bait: `EXECUTE 'REVOKE … FROM anon, authenticated'` in a DO block → silent |
| `test_issue_1096_matview_execute_format_literal_revoke_counts` | FP-bait: the same via `EXECUTE format('…')` with `ON TABLE` → silent |
| `test_issue_1096_matview_execute_literal_missing_a_role_still_fires` | an `EXECUTE` literal revoking anon only → fires |
| `test_issue_1096_matview_revoke_quoted_in_a_notice_is_not_a_revoke` | a REVOKE inside a `RAISE NOTICE` literal → fires |
| `test_issue_1096_matview_static_revokes_in_do_block_and_quoted_names_still_count` | FP-bait: a REVOKE in a `DO $$ … $$` body plus `"public"."v"` / `"authenticated"` → silent |
| `test_issue_1096_matview_apostrophe_in_a_dollar_quoted_comment_keeps_a_later_revoke` | FP-bait: `COMMENT … IS $$Don't …$$` before the REVOKE → silent |
| `test_issue_1096_matview_placeholder_target_does_not_credit_a_view_named_like_its_schema` | `ON public.%I` does not cover a view named `public` → fires |

## Known bypasses

* **Dynamic / templated DDL** — a materialized view created via a stored procedure or
  string-built DDL never appears as a literal `CREATE MATERIALIZED VIEW` and isn't seen.
* **REVOKE targeting a role this guard doesn't check** — a custom role name other than
  `PUBLIC`/`anon`/`authenticated` (e.g. a bespoke `webapp_readonly` role that is itself
  over-granted) is not recognized as a mitigation signal, and the guard would then wrongly
  flag an already-secured view; conversely a genuinely narrow custom-role grant elsewhere is
  invisible to this guard either way.
* **Grant-then-revoke ordering** — revokes are unioned without regard to order, so a later
  `GRANT SELECT ... TO anon` that re-exposes the view is not seen.
* **Privilege-blind REVOKE** — a `REVOKE INSERT ON v FROM anon, authenticated` counts although it
  leaves `SELECT` in place; the privilege list is not read.
* **Dump-only repos** — a pg_dump writes no `REVOKE … FROM anon` for a locked-down view (it just
  omits the grant), so a matview in a dump-only repo keeps firing even when it is safe.
* **Column-level exposure nuance** — the guard does not check whether the view's own `SELECT`
  pulls in sensitive columns; it treats "exposed via the Data API at all" as the flag, not what
  specifically is exposed.

## What this guard does NOT prove

That the underlying base tables' RLS is even correctly configured — this guard only reasons
about the materialized view's own schema placement and the presence of a REVOKE, independent
of everything upstream. It also does not confirm the mitigation is *sufficient* (e.g. that a
non-`public` target schema is itself unreachable via `pgrst.db_schemas`) — only that a
schema-move or REVOKE statement referencing the view exists somewhere in the scanned SQL.

# Citations

[1] agentsec checklist item `7-materialized-view-exposed` (§7)
[2] research notes (private, not in this repo)
[3] OWASP:A01
[4] CIS:6.3
