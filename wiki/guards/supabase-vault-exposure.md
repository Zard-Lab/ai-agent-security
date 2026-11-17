---
type: Guard
title: "supabase-vault-exposure"
description: "Supabase Vault material is reachable by anon or authenticated through a vault-reading SECURITY DEFINER function, a decrypted view, or a DROP and re-CREATE that resets an ACL."
timestamp: "2026-10-19T12:00:00Z"
guard_id: "supabase-vault-exposure"
checklist_section: ["7"]
standards: ["OWASP:A01", "OWASP:A02", "CWE-200", "CWE-732"]
---

# Supabase Vault material reachable by the Data API roles

_Author: 2026-10-18. Designed against the flagship (`ai-agent-mastery`): its live dev project's
catalog (`has_function_privilege` / `has_table_privilege` / `pg_default_acl`), a rolled-back probe of
the vault 0.3.1 decrypt gate, and its `sql/` migrations plus its `supabase db dump` snapshot._

---

## The threat

Supabase Vault (`supabase_vault`) stores secrets encrypted in `vault.secrets` and decrypts them at
query time in the `vault.decrypted_secrets` view. The key never lives in the database. The
`vault` schema itself is not exposed: on a stock project only `service_role` holds `USAGE` on it.
Apps then build three things in `public`, which IS exposed through PostgREST:

1. a reference table holding the vault id (`public.api_keys(secret_id uuid)`), which is safe:
   a vault UUID decrypts nothing (`sensitive-columns` treats it as the recommended pattern);
2. a view joining `vault.decrypted_secrets` (`public.api_keys_with_secrets`);
3. `SECURITY DEFINER` RPCs that read or write the vault (`public.read_secret_logged(uuid, text)`,
   `public.create_secret(text, ...)`).

In `public`, the grants on (2) and (3) are the only thing between `anon` / `authenticated` and every
plaintext secret. Supabase's docs say it plainly: "anyone that has access to the view has access to
decrypted secrets" [1].

Two facts make this easy to get wrong:

- **Supabase's default privileges re-expose every new object.** `pg_default_acl` in `public` grants
  `anon` and `authenticated` all privileges on new tables and views, and `EXECUTE` on new functions.
  Postgres also grants `EXECUTE` to `PUBLIC` on every new function [5]. So `REVOKE ... FROM PUBLIC`
  alone leaves anon and authenticated their **direct** grant, and a `DROP` + `CREATE` resets the
  object's ACL to those defaults (`CREATE OR REPLACE` keeps it). Supabase's 2026-10-30 change stops
  the default for new tables and sequences in existing projects [3]. It does not mention functions,
  so the function risk outlives that date.
- **A definer function is the crown jewel; a definer view is defence in depth.** On vault 0.3.x the
  decrypt step calls `vault._crypto_aead_det_decrypt(...)`, and Postgres checks a function's
  `EXECUTE` against the role running the query, even inside an owner-rights view [4]. Measured on a
  live project: granting `anon` `SELECT` on the definer view and selecting as `anon` fails with
  `permission denied for function _crypto_aead_det_decrypt`. A `SECURITY DEFINER` function runs as
  its owner, who holds that `EXECUTE`, so one anon-executable vault-reading RPC returns every secret.
  The older pgsodium-based vault (0.2.x) has no decrypt-function gate, which is why a readable view
  is still HIGH.

Findings carry **OWASP A01** (broken access control), **OWASP A02** (cryptographic failure: the
encryption is bypassed, not broken), **CWE-200** and **CWE-732**.

## Why this guard fits the stack

The flagship hit every precondition: 11 vault-touching definer functions, two decrypted views and a
weekly `supabase db dump` snapshot. Its migrations needed **four** separate shapes to lock the
functions down:

- a full `REVOKE ... FROM PUBLIC, anon, authenticated` (`sql/137`);
- a dynamic DO loop, `EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon,
  authenticated', r.sig)` over `ARRAY['read_secret_logged', ...]` (`sql/169`);
- a static REVOKE inside an `IF EXISTS` DO block (`sql/245`);
- a `DROP FUNCTION` + `CREATE OR REPLACE` + REVOKE in one file (`sql/190`).

The original exposure (9 anon-executable vault functions) sat for months, because the name-based
`definer-function-grants` accepted the `REVOKE ALL ... FROM PUBLIC` the functions shipped with.

## Detection design

1. **Gate.** `applies()` is true for `supabase` or `sql` in `profile.features`. `run()` returns `[]`
   (N/A) unless some `.sql` file, outside comments, mentions `vault.`, a `search_path` or
   `pgrst.db_schemas` including `vault`, or the schema by name (`ON SCHEMA vault`,
   `IN SCHEMA public, vault`, quoted or not). The last form matters: a repo whose only vault SQL
   is `GRANT USAGE ON SCHEMA vault TO anon` is the clearest exposure, not "no Vault".
2. **Files.** Every `.sql` under the repo root except reference paths (`is_reference_sql_path`;
   `migrations/` counts as product).
3. **Views of each file.** Each file is read under four same-length views:
   - `code`: comments blanked;
   - `struct`: literal and dollar-body contents blanked too;
   - `acl`: `struct` with DO-block bodies restored, because REVOKEs there run with the migration;
   - `deep`: every top-level dollar body restored.

   Offsets mean the same character in all four.
4. **Classification is by body, never by name.**
   - A view is *decrypted* when its definition references `vault.decrypted_secrets`, or a view
     already classified as decrypted (transitively).
   - A function is *vault material* when its dollar-quoted body (with its own literals blanked)
     references `vault.decrypted_secrets`, `vault.secrets`, `vault.create_secret`,
     `vault.update_secret` or `vault._crypto_aead_det_decrypt`, a decrypted view, or calls another
     vault-material function.
   - Quoted spellings (`"vault"."decrypted_secrets"`) count, and an unqualified name resolves
     through the function's pinned `search_path` (`public, vault` makes a bare `decrypted_secrets`
     vault's). A mention inside a string literal or a comment does not.
5. **Function keys are overload-aware:** `(schema, name, input arg types)`.
   - Types are normalised: names, modes, `DEFAULT`s and quotes are dropped, OUT parameters are
     excluded, and `int4`/`varchar`-style aliases are mapped.
   - So `"public"."f"("p_caller" "text")` (pg_dump) and `public.f(p_caller text)` are one key.
   - A REVOKE/GRANT with an argument list covers that overload. One without, or the sql/169 dynamic
     loop, covers every overload of the name.
6. **Two modes.**
   - **Dump mode.** A file `sql_state.find_dumps` recognises (dump-like name AND pg_dump preamble)
     spells out the real ACL. A function there is exposed iff its `REVOKE ALL ... FROM PUBLIC` is
     ABSENT or a GRANT to `anon`/`authenticated`/`PUBLIC` is present. A view is exposed iff such a
     GRANT is present.
   - **Migration mode.** Every other file assumes Supabase's defaults. The object is exposed unless
     REVOKEs found anywhere in the migrations cover each required role, and no migration GRANTs one
     back. Required roles are `PUBLIC`, `anon` and `authenticated` for functions, and `anon` and
     `authenticated` for views.
   - The cross-file union is deliberate (no ordered replay; the resulting state is the live
     Splinter lint's job). Two things do look at order: R3, and
     bulk statements (below).
   - **A GRANT or REVOKE counts only for the privileges it names.** It reaches a function when it
     names `EXECUTE` or `ALL`, and a view when it names `SELECT` or `ALL`. So `GRANT INSERT ON v
     TO anon` does not make the view readable, `REVOKE INSERT, UPDATE, DELETE ON v` (the "make it
     read-only" idiom) does not stop it being read, and `REVOKE GRANT OPTION FOR ...` removes only
     the grant option. Column-level privileges are asymmetric on purpose: a granted
     `SELECT (col)` (spaced or not: `SELECT(col)`) exposes that column, so it counts; a revoked one
     leaves the table-level grant, so it does not.
   - **Bulk statements** (`GRANT`/`REVOKE ... ON ALL FUNCTIONS|ROUTINES|TABLES IN SCHEMA s`)
     reach only the objects that exist when they run, so one counts for an object only when it
     sits after that object's FIRST CREATE in the migrations (later in the file, or in a file
     sorting after it). `CREATE OR REPLACE` keeps the ACL, so a later replace does not move that
     point; a DROP + re-CREATE does reset it, and R3 checks that from the re-CREATE. The stock
     `GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated, service_role` after a
     REVOKE re-exposes the function; the same line in Supabase's init migration, before the
     CREATE, does nothing to it. A bulk REVOKE after the first CREATE covers the roles it names.
     Bulk statements are NOT ordered against each other or against per-object ones: once past
     the first CREATE they join the cross-file union like every other ACL.
7. **Fail closed.**
   - An unterminated dollar body runs to EOF.
   - Unbalanced parens make the signature unknown, so it is matched name-level.
   - A dump-named file without the pg_dump preamble is judged as a migration.
8. **Pragma.** `-- security: allow-supabase-vault-exposure <reason>` as a SQL comment on a line of
   the flagged statement (its CREATE / GRANT line through its `;`), read via `pragma_line_set`.
   - For a function, put it on a header line (the CREATE through the opening `$$`, or after the
     closing `$$`). A `--` inside the dollar-quoted body is part of the body's text, not a SQL
     comment, so it does not suppress.
   - It is line-scoped: a comment above the statement, or at the top of the file, does not reach it.
   - The phrase inside a string literal never suppresses.
9. **Linear on hostile input.** Each head-driven scan (CREATE FUNCTION, GRANT/REVOKE, ALTER DEFAULT
   PRIVILEGES, DROP) is bounded at the next head of
   its kind, so the windows tile the file (#419). ACLs and later fixes are indexed once, not
   rescanned per object.

| Rule | Severity | Fires when |
|---|---|---|
| `supabase-vault-exposure/definer-function-executable` | critical | A vault-material `SECURITY DEFINER` function in an exposed schema is executable by `PUBLIC`, `anon` or `authenticated` (per mode above). |
| `supabase-vault-exposure/decrypted-view-readable` | high | A decrypted view or matview in an exposed schema, not `security_invoker` (inline, or a later `ALTER VIEW ... SET (security_invoker = true)`), is readable by `anon` or `authenticated`. |
| `supabase-vault-exposure/recreated-without-revoke` | critical (function) / high (view) | A file DROPs one of the above and re-CREATEs it, and neither that file after the CREATE nor any file sorting after it (natural order) revokes the required roles again. Migration files only. |
| `supabase-vault-exposure/definer-search-path-writable` | low | A vault-material definer function pins `search_path` to anything beyond empty / `pg_catalog` / `pg_temp` (e.g. `public, vault`), with no later safe `ALTER FUNCTION ... SET search_path`. Unpinned is `pg-function-search-path`'s job. |

### Scope against neighbouring checks

- **[`supabase-vault-plaintext-leak`](supabase-vault-plaintext-leak.md)** holds the vault rules a
  schema dump cannot vouch for: a literal secret committed in SQL, `log_statement` on, `vault` in
  `pgrst.db_schemas` / `config.toml`, and GRANTs on the `vault` schema itself (a dump carries no
  data rows, server settings or role settings [2], and a `supabase db dump` of the app schema need
  not carry the Supabase-managed `vault` schema's ACL). They were split out because this guard's
  `schema_state = True` let a dump demote them to non-gating history (PR #1095 reviews: H1, then
  re-review item 2 for the vault GRANTs).
- **`definer-function-grants`** flags every unrevoked definer function, by NAME (critical when the
  name looks secret-ish), and accepts a REVOKE from any one role. This guard is body-proven and
  role-complete, so it catches a benign-named vault reader and the `FROM PUBLIC`-only trap. A
  secret-named vulnerable function fires both, by design: different rules, different evidence.
- **`pg-security-definer-view`** flags every view without `security_invoker`, grant-blind. This
  guard fires only when a decrypted view is also readable, so a service_role-only decrypted view is
  silent here and remains that guard's question.
- **Splinter** lints `security_definer_view` (0010), `anon/authenticated_security_definer_function_executable`
  (0028/0029) and `function_search_path_mutable` (0011) on a LIVE database [6], but only for
  schemas in `pgrst.db_schemas`, and with no vault awareness. This guard reads the repo, needs no
  database. The vault-schema grants Splinter has no lint for are covered by the sibling
  [`supabase-vault-plaintext-leak`](supabase-vault-plaintext-leak.md).

## When NOT to flag

- A decrypted view with `security_invoker = true`: `anon` has no `USAGE` on `vault`, so the view
  cannot decrypt for it. The real exposure would then be a vault grant, which
  `supabase-vault-plaintext-leak` covers.
- Any object granted only to `service_role` (or `postgres`): the backend's own path.
- A vault definer function locked down by a REVOKE split across files, by a dynamic DO loop, or by
  a REVOKE inside a DO block (all silent, all tested).
- `CREATE OR REPLACE` with no DROP before it: the ACL is preserved.
- A placeholder or a variable passed to `create_secret(...)` (`'REPLACE_ME'`,
  `current_setting('app.key')`, `v_key`).

For a deliberate exception (e.g. an RPC that returns a non-secret vault field to `authenticated` by
design), annotate the statement:

```sql
CREATE OR REPLACE FUNCTION public.secret_names() RETURNS SETOF text -- security: allow-supabase-vault-exposure names only, no values
```

## Tests

| Test | What it checks |
|---|---|
| `test_r1_definer_reads_vault_unrevoked_fires` | The planted vault-reading definer RPC fires critical, all three roles named (the `verified_by` test) |
| `test_r1_revoke_from_public_alone_still_fires` | The Supabase trap: `FROM PUBLIC` alone leaves anon/authenticated |
| `test_r1_full_revoke_same_file_is_silent` / `test_r1_revoke_split_across_files_is_silent` | Role-complete REVOKE, in one file or split across two (flagship 0-all-tables + 137) |
| `test_r1_grant_back_in_another_file_fires` | Any GRANT to a Data API role wins (no ordering) |
| `test_r1_revoke_of_a_different_overload_does_not_cover` / `test_r1_name_level_revoke_covers_every_overload` | Overload-aware keys |
| `test_r1_dynamic_do_loop_revoke_is_silent` / `test_r1_static_revoke_inside_a_do_block_is_silent` | Flagship sql/169 and sql/245 shapes |
| `test_r1_writer_function_calling_vault_create_secret_fires` / `test_r1_quoted_vault_reference_fires` / `test_r1_transitive_through_a_decrypted_view_and_a_vault_function_fires` | Body-based classification, quoted identifiers, transitivity |
| `test_r1_unqualified_vault_object_resolves_through_the_pinned_search_path` | A bare `decrypted_secrets` counts when the pinned `search_path` includes `vault` (flagship sql/141), not when it is `''` |
| `test_r1_invoker_function_is_silent` / `test_r1_vault_only_in_a_string_or_comment_of_the_body_is_silent` / `test_r1_function_in_a_private_schema_is_silent` | FP-bait |
| `test_r1_revoke_in_a_comment_string_or_function_body_does_not_count` | A REVOKE that never runs (in a `--` or `/* */` comment, a string, a non-DO function body) does not cover the function |
| `test_r1_bulk_function_grant_after_the_revoke_fires` / `test_r1_bulk_grants_that_do_not_reach_the_function_are_silent` | A bulk `GRANT ... ON ALL FUNCTIONS` after the REVOKE re-exposes it; one before the CREATE, to `service_role`, on `TABLES`, or in another schema does not |
| `test_r1_bulk_revoke_after_the_create_covers_it` / `test_r1_bulk_revoke_before_the_create_or_partial_still_fires` | A bulk REVOKE after the CREATE covers; one before it, or one skipping a role, still fires |
| `test_r1_create_or_replace_after_a_bulk_revoke_is_still_covered` / `test_r1_bulk_revoke_before_the_first_create_still_fires_after_a_replace` | Bulk ordering is against the FIRST CREATE: a later `CREATE OR REPLACE` stays covered by a bulk REVOKE in between, and a bulk REVOKE before the first CREATE covers neither |
| `test_r1_pragma_inside_the_statement_suppresses` / `test_r1_pragma_inside_a_string_does_not_suppress` / `test_r1_pragma_above_the_statement_does_not_suppress` | Comment-only, statement-scoped pragma |
| `test_dump_locked_acl_is_silent_for_r1_and_r2` / `test_dump_missing_revoke_from_public_fires_r1` / `test_dump_grant_to_anon_fires_r1_and_r2` / `test_dump_named_file_without_pg_dump_head_uses_migration_semantics` / `test_dump_column_grant_without_space_fires_r2` / `test_first_create_ordering_ignores_a_dump` | Dump mode (flagship snapshot ACL shape), an unspaced column grant in a dump, a dump's CREATE never counting as the first CREATE, and the fail-closed fallback |
| `test_r2_*` (15 tests) | Decrypted view: unrevoked fires; anon-only revoke fires; a REVOKE leaving SELECT (writes only, `GRANT OPTION FOR`, column-level, a bulk revoke of writes) fires; a GRANT naming no read (`INSERT`, `UPDATE, DELETE`, bulk `UPDATE`) stays silent while `SELECT`, `ALL PRIVILEGES`, a mixed list, a column-level `SELECT` (spaced, unspaced and quoted) and a bulk `SELECT` still expose; a CREATE OR REPLACE VIEW after a bulk REVOKE that followed the first CREATE stays covered, and a bulk REVOKE before the first view CREATE fires; flagship revoke block, `REVOKE SELECT` / `ALL PRIVILEGES`, `security_invoker` and a later `ALTER VIEW` stay silent; a bulk `ON ALL TABLES` grant fires; matview fires; a non-decrypted view is silent |
| `test_r3_*` (8 tests) | DROP + re-CREATE without REVOKE fires (view and function); same-file REVOKE, later-file REVOKE, a later bulk REVOKE, `CREATE OR REPLACE` and a DROP of another overload stay silent; a bulk REVOKE before the DROP, or a REVOKE of only non-reading privileges after it, still fires |
| `test_r7_*` (4 tests) | `public, vault` fires in both spellings; `''`, unpinned, a non-vault definer, and a later safe `ALTER FUNCTION` stay silent |
| `test_norm_type_*`, `test_bulk_acl_targets_are_keyed_by_object_kind`, `test_dump_and_migration_signatures_normalise_to_the_same_key`, `test_function_body_is_bounded_by_its_dollar_quote_not_the_first_semicolon`, `test_unterminated_body_runs_to_eof_fail_closed`, `test_search_path_parses_every_spelling`, `test_acl_roles_and_targets_parse`, `test_dynamic_do_loop_revoke_is_name_level_and_scoped_to_its_block` | Parser helpers |
| `test_each_rule_carries_its_own_title` | Each rule reports its own title, so a low search-path finding never reads as an exposed secret |
| `test_applies_gate` / `test_repo_without_vault_is_na` / `test_reference_sql_paths_are_skipped` / `test_migrations_dir_is_product` / `test_supabase_vault_exposure_hostile_headless_sql_is_linear` | Gates, N/A, scan roots, linearity |

## Known bypasses

- **Dynamic SQL.** A function body that reaches vault only through `EXECUTE 'SELECT ... FROM
  vault.decrypted_secrets'` (or `format(...)`) is not classified: nested literals are blanked. The
  same goes for a REVOKE or GRANT built dynamically other than the sql/169 `%s` loop shape.
- **`ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated`** is not
  credited as a REVOKE. This errs safe (it can only add findings), but a repo that fixed the default
  systemically needs the pragma.
- **A GRANT fixed by a later REVOKE still fires (known FP).** Per-object ACLs are a cross-file
  union with no replay, so `GRANT EXECUTE ... TO anon` in an old migration followed by a full
  `REVOKE` in a newer one (the normal remediation) keeps a critical. The fix is to delete or
  rewrite the old GRANT, or annotate the CREATE with the pragma. Bulk statements behave the same
  once past the object's first CREATE: a bulk GRANT followed by a per-object or bulk REVOKE
  still fires. Only their position relative to the first CREATE is ordered.
- **A bulk REVOKE before the CREATE does not cover it.** This is correct Postgres behaviour (the
  function did not exist yet), but a repo that runs a bulk lockdown first and creates functions
  afterwards, relying on `ALTER DEFAULT PRIVILEGES` it does not ship, needs a per-function REVOKE.
- **A DROP and its re-CREATE in different files.** R3 pairs a DROP with a CREATE in the same file
  only, so `DROP` in `002.sql` and `CREATE` in `003.sql` after a full REVOKE in `001.sql` is
  missed. The ACL reset is real; R1 then reads the old REVOKE as still covering.
- **Definer status set later, or plaintext copied out.** `ALTER FUNCTION ... SECURITY DEFINER`
  applied after an invoker CREATE is not tracked, and neither is
  `CREATE TABLE ... AS SELECT ... FROM vault.decrypted_secrets`, which materialises plaintext into
  an ordinary table.
- **SQL-standard bodies** (`BEGIN ATOMIC ... END`) are not bounded as a body, so their vault
  references are missed.
- **Objects created outside `.sql` files** (an ORM migration, the dashboard SQL editor) are
  invisible; so is a vault function defined in a schema the repo later exposes only through
  config this guard does not read.
- **Cross-file union.** A REVOKE in one migration and a GRANT-free re-CREATE (`CREATE OR REPLACE`
  after a manual `DROP` run outside the repo) leave the live ACL different from what the files say.

## What this guard does NOT prove

- **The live ACL.** It reads files, so it proves nothing about the database you deploy to (a
  manual grant in the SQL editor, a skipped migration). Run Splinter via `agentsec live`, or the
  catalog query in the flagship plan, for that.
- **That `public` is not CREATE-able by an untrusted role** (R7's low severity assumes Supabase's
  PG15 default).
- **Which vault version runs**, so it cannot tell whether a readable decrypted view is merely
  defence in depth (0.3.x decrypt gate) or a full leak (0.2.x).
- **That the backend's own `service_role` path is safe**, or that `service_role` keys are not
  exposed (see `service-role-key`).

# Examples

Fires (`definer-function-executable`, critical): `REVOKE ... FROM PUBLIC` is not enough on Supabase.

```sql
CREATE OR REPLACE FUNCTION public.read_secret(p_id uuid) RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id = p_id;
$$;
REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC;
```

Silent: every Data API role revoked, `service_role` granted back.

```sql
REVOKE EXECUTE ON FUNCTION public.read_secret(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.read_secret(uuid) TO service_role;
```

Fires (`recreated-without-revoke`, high): the DROP resets the view's ACL to Supabase's defaults.

```sql
DROP VIEW IF EXISTS api_keys_with_secrets;
CREATE VIEW api_keys_with_secrets AS
  SELECT ak.key_name, vs.decrypted_secret FROM api_keys ak
  LEFT JOIN vault.decrypted_secrets vs ON ak.secret_id = vs.id;
```

# Citations

[1] Supabase docs, Vault: https://supabase.com/docs/guides/database/vault ("You should ensure that
you protect access to this view with the appropriate SQL privilege settings at all times, as anyone
that has access to the view has access to decrypted secrets.")

[2] supabase/vault README: https://github.com/supabase/vault/blob/main/README.md (statement logging
"will contain the _unencrypted_ secrets"; secrets stay encrypted in dumps and replication streams)

[3] Supabase changelog #45329, tables not exposed to the Data API automatically:
https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically

[4] PostgreSQL, CREATE VIEW (`security_invoker`; functions called in a view are checked as if called
directly by the query's user): https://www.postgresql.org/docs/current/sql-createview.html

[5] PostgreSQL, Privileges (EXECUTE granted to PUBLIC by default on functions):
https://www.postgresql.org/docs/current/ddl-priv.html

[6] Supabase database linter (Splinter): https://supabase.com/docs/guides/database/database-linter

[7] agentsec checklist item `7-supabase-vault-material-exposed` (§7), OWASP:A01, OWASP:A02
