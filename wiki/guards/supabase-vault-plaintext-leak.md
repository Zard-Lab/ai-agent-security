---
type: Guard
title: "supabase-vault-plaintext-leak"
description: "Supabase Vault exposure a schema dump cannot vouch for: a literal secret committed in SQL, statement logging on in a vault repo, the vault schema in the Data API's exposed-schema list, or a grant on the vault schema itself."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "supabase-vault-plaintext-leak"
checklist_section: ["7"]
standards: ["OWASP:A02", "OWASP:A01", "CWE-312", "CWE-798", "CWE-532", "CWE-732"]
---

# Supabase Vault exposure a schema dump cannot vouch for

_Author: 2026-10-18. Split out of [`supabase-vault-exposure`](supabase-vault-exposure.md) in
answer to the PR #1095 review (finding H1); the vault-schema GRANT rule followed in the re-review
(item 2)._

---

## The threat

Supabase Vault keeps secrets encrypted at rest and decrypts them only in `vault.decrypted_secrets`.
[`supabase-vault-exposure`](supabase-vault-exposure.md) covers who can reach that view through
grants, views and `SECURITY DEFINER` functions. Four other paths, which a schema dump cannot vouch
for, put the plaintext where that guard does not look:

- **A literal secret in a migration.** `SELECT vault.create_secret('sk-live-...', 'openai')` in a
  seed file puts the plaintext in git history for everyone with read access to the repo, forever.
  Vault's encryption protects the database copy, not the source.
- **Statement logging.** With `log_statement = 'all'` (or `'mod'`), Postgres writes every
  statement's text to the server log, including the plaintext argument of each
  `vault.create_secret(...)` call. The vault README says so directly: the logs "will contain the
  _unencrypted_ secrets" [1].
- **`vault` in the exposed-schema list.** PostgREST serves every schema in `pgrst.db_schemas`
  (`[api] schemas` in the Supabase CLI's `config.toml`). With `vault` there, `vault.decrypted_secrets`
  is one REST call away for any API key holder whose role can read it.
- **A grant on the `vault` schema itself.** `GRANT USAGE ON SCHEMA vault TO anon` (or a grant on
  `vault.decrypted_secrets`, `ALL ... IN SCHEMA vault`, or default privileges there) hands the
  decrypting view straight to the Data API roles.

Findings carry **OWASP A02** (the encryption is bypassed, not broken) and **CWE-312** (cleartext
storage). The literal-secret rule adds **CWE-798**, the logging rule **CWE-532**, the
exposed-schema rule **OWASP A01**, and the vault-grant rule **OWASP A01** and **CWE-732**.

## Why this guard fits the stack

These rules started inside `supabase-vault-exposure`. That guard declares `schema_state = True`,
because its grants, views and functions are exactly what a `supabase db dump` snapshot reproduces,
so the snapshot rightly supersedes a stale migration copy of them. But `schema_state` is per
check, not per rule. Measured on the PR #1095 review: with a pg_dump snapshot in `supabase/`, a
migration committing a literal secret, `log_statement = 'all'` and `pgrst.db_schemas = 'public,
vault'` produced three findings that were all marked superseded history, so `--fail-on high`
passed with a live key committed.

A dump carries none of these. It has no data rows (the secret), no server or database settings
(the logging), and no role settings (`ALTER ROLE authenticator SET pgrst.db_schemas`, which only
`pg_dumpall` emits). So they live in a check that leaves `schema_state` at its default `False`,
which is the rule `sql_state.py` states for "a committed secret" (#829).

The vault-schema GRANT rule joined on the re-review, for a related reason. `sql_state` demotes a
migration finding because a dump exists in its directory, not because the dump re-flags it. `vault`
is a Supabase-managed schema, and a `supabase db dump` of the app schema need not carry its ACL,
so a dump's silence about a vault grant proves nothing. A stale vault grant that a later migration
revoked may keep gating; that is the safe direction, and the pragma covers it.

## Detection design

1. **Gate.** `applies()` is true for `supabase` or `sql` in `profile.features`. The SQL rules
   share `supabase-vault-exposure`'s N/A gate: a product `.sql` file outside comments must mention
   `vault.`, a `search_path` or `pgrst.db_schemas` including `vault`, or the schema by name
   (`ON SCHEMA vault`, `IN SCHEMA public, vault`). The `config.toml` rule needs no SQL at all: a
   config listing `vault` is the repo's vault usage.
2. **Files.** Every `.sql` file outside reference paths (`is_reference_sql_path`), prepared under
   the same four same-length views as `supabase-vault-exposure` (`code`, `struct`, `acl`, `deep`),
   plus every `supabase/config.toml` at any depth, so a monorepo's `apps/x/supabase/config.toml`
   counts.
3. **`literal-secret-in-sql`.** In the `deep` view (DO and function bodies restored, so a seed
   inside a DO block counts), each `create_secret(` / `update_secret(` call (any schema
   qualifier), `INSERT INTO vault.secrets (..., secret, ...) VALUES (...)` and
   `UPDATE vault.secrets SET secret = ...`. The secret argument is the positional one
   (first for `create_secret`, second for `update_secret`) or a `secret =>` named argument. It
   fires when that argument is a string literal (`'...'`, `E'...'`, `$tag$...$tag$`, with an
   optional `::type`) that is not a placeholder. A `FUNCTION`/`ROUTINE` word just before the name
   marks a definition or a GRANT head, not a call. The value is never echoed: the message gives
   its length only.
4. **`statement-logging-enabled`.** `log_statement` set to `all` or `mod` through
   `ALTER SYSTEM/DATABASE/ROLE/USER ... SET` or a plain `SET`, outside a string literal.
5. **`vault-schema-exposed`.** `pgrst.db_schemas` set to a list containing `vault` outside a
   string literal; or a `config.toml` `schemas = [...]` array containing `vault`, single- or
   multi-line, matched on the `#`-comment-stripped text (so a `]` inside a comment does not close
   the array) and only inside the `[api]` table (the same key under another table, or before any
   table header, is not the API's list). The header may be quoted with either quote kind, spaced,
   upper-case, followed by a comment, or preceded by a UTF-8 BOM.
6. **`vault-schema-granted`.** Every GRANT (top-level, or inside a DO block, which runs with the
   migration) whose target is in the `vault` schema, to `PUBLIC`, `anon` or `authenticated`:
   `ON SCHEMA vault`, `ON vault.<object>`, `ON ALL ... IN SCHEMA vault`, and
   `ALTER DEFAULT PRIVILEGES IN SCHEMA vault ... GRANT`. Any privilege counts: `INSERT` on
   `vault.secrets` is as bad as `SELECT` on `vault.decrypted_secrets`.
7. **Dump files.** The literal-secret rule skips a file `sql_state.find_dumps` recognises: a dump
   has no seed rows. Every other rule reads dump files too (a `pg_dump -C` or `pg_dumpall` file can
   carry `ALTER DATABASE ... SET log_statement`, and a dump that does carry a vault grant should
   fire).
8. **Pragma.** `-- security: allow-supabase-vault-plaintext-leak <reason>` as a SQL comment on a
   line of the flagged statement, or `# security: allow-supabase-vault-plaintext-leak <reason>`
   on the `schemas = [...]` lines of a `config.toml`. It is read through `pragma_line_set`, so the
   phrase inside a string literal never suppresses, and it is line-scoped: a comment above the
   statement, or trailing the previous one, does not reach it.
   - For a finding inside a DO block or a function body, the statement is the enclosing `DO` /
     `CREATE FUNCTION`, from its keyword through the `;` after the closing `$$`, and a comment on any
     of those lines counts: a header line, a line inside the body (the SQL comment view reads a `$$`
     body as code, #1040), or the closing `END $$; -- reason` line.
   - `supabase-vault-exposure`'s pragma does not reach this guard.
9. **Linear on hostile input.** Every head-driven scan is bounded at the next head of its kind
   (the shared `_bounded`, #419), and a pragma-scope lookup bisects an index of the file's
   statement ends (as `find_statement_end` reports them, so a `;` inside a `"..."` identifier
   is not one) instead of scanning on from a `;`-less dollar body.

| Rule | Severity | Fires when |
|---|---|---|
| `supabase-vault-plaintext-leak/literal-secret-in-sql` | high | A non-placeholder literal is the secret of `create_secret(...)` / `update_secret(...)`, or is written by `INSERT INTO vault.secrets` / `UPDATE vault.secrets SET secret = ...`, in executed migration SQL. |
| `supabase-vault-plaintext-leak/statement-logging-enabled` | medium | `log_statement` is set to `all` or `mod` in a repo that uses vault [1]. |
| `supabase-vault-plaintext-leak/vault-schema-exposed` | critical | `vault` is in `pgrst.db_schemas`, or in `[api] schemas` of a `supabase/config.toml`. |
| `supabase-vault-plaintext-leak/vault-schema-granted` | critical | A GRANT to `anon`/`authenticated`/`PUBLIC` on `SCHEMA vault`, a `vault.<object>`, `ALL ... IN SCHEMA vault`, or `ALTER DEFAULT PRIVILEGES IN SCHEMA vault`. |

Placeholders the literal rule ignores: empty or whitespace values, and any value containing
`REPLACE_ME`, `CHANGE_ME`, `<...>`, `your-`, `placeholder`, `example`, `dummy`, `xxx`, `...`, a
`%s`/`%L` format slot, or a `{{` / `${` template.

### Scope against neighbouring checks

- **`supabase-vault-exposure`** owns the vault rules on the app's own objects, which a schema dump
  of the app reproduces: definer functions, decrypted views, DROP + re-CREATE, a writable
  `search_path`.
- **gitleaks** and the generic secret guards match known key formats anywhere. This guard matches
  any non-placeholder value, but only where it is stored into vault, so a random-looking token
  with no known prefix is still caught.

## When NOT to flag

- A secret passed in from outside the SQL: `vault.create_secret(current_setting('app.openai_key'))`,
  a `psql -v` variable, or a PL/pgSQL variable.
- A placeholder in a template seed file (`'REPLACE_ME'`, `'<your-key>'`).
- `log_statement` at `none` or `ddl`.
- `vault` in `extra_search_path`, which changes name resolution, not what PostgREST serves.

For a deliberate exception (a throwaway key in a local-only seed), annotate the statement:

```sql
SELECT vault.create_secret('local-dev-only', 'stub'); -- security: allow-supabase-vault-plaintext-leak local seed, never deployed
```

## Tests

| Test | What it checks |
|---|---|
| `test_dump_in_the_repo_does_not_demote_secret_logging_or_exposed_schema_findings` | Through `audit()`: with a pg_dump snapshot present, all four rules (each by its exact rule id) stay live and gating, while `supabase-vault-exposure`'s definer finding in the same migration is still demoted (the H1 regression, plus re-review item 2) |
| `test_literal_secret_fires_and_never_echoes_the_value` | Every literal sink fires high with CWE-798, and the value appears in no message, remediation or title |
| `test_literal_inside_a_do_block_or_function_body_fires` | A seed inside a DO block counts |
| `test_placeholders_comments_and_variables_are_silent` / `test_function_definition_head_is_not_a_call` / `test_literal_in_a_dump_file_is_not_read` | FP-bait: comments, placeholders, variables, string mentions, definition heads, dump files |
| `test_pragma_inside_the_statement_suppresses_and_in_a_string_does_not` / `test_the_exposure_guard_pragma_does_not_reach_this_guard` | Comment-only, line-scoped pragma, owned by this guard |
| `test_pragma_on_the_enclosing_do_block_reaches_a_secret_inside_it` / `test_pragma_outside_the_enclosing_do_block_or_inside_its_body_does_not_reach` | A DO-wrapped seed is suppressed from the `DO` header line or the `END $$;` line, and not from the previous or next statement, a line above the DO, the `DO $$ BEGIN` line after the `$$`, or the body |
| `test_pragma_reach_ignores_a_semicolon_inside_a_quoted_identifier` / `test_a_pragma_trailing_a_previous_statement_with_a_quoted_semicolon_does_not_reach` | A `;` inside a `"x;y"` identifier neither cuts the statement short of a trailer pragma nor moves its head past a CREATE-line pragma; a previous statement's trailing pragma still does not reach |
| `test_pragma_scope_end_is_the_statement_end_find_statement_end_reports` | Invariant over 3000 generated statements (spaced and unspaced, well-formed one-line quoting): every dollar span's statement end equals a fresh `find_statement_end` from its tail. Multi-line quoting is excluded on purpose: the walk differs there (#1111) |
| `test_log_statement_in_a_dump_file_fires` | A dump can carry `ALTER DATABASE ... SET log_statement`, and it is read there |
| `test_log_statement_*` (3 tests) | `all`/`mod` fire; `ddl`/`none`, a quoted mention, and a vault-free repo stay silent |
| `test_vault_in_pgrst_db_schemas_fires_with_no_other_vault_sql` | The setting alone opens the gate and fires critical |
| `test_vault_in_supabase_config_toml_fires` / `test_config_toml_alone_fires_multiline_and_nested` | Single-line, multi-line with a comment, and a nested monorepo config, with no SQL at all |
| `test_config_toml_bracket_inside_a_comment_does_not_close_the_array` / `test_config_toml_schemas_counts_only_in_the_api_table` | A `]` in a `#` comment does not hide `vault`; `schemas` counts only under `[api]` (not top-level, not `[db]`), even after another table |
| `test_config_toml_api_table_header_spellings_fire` / `test_config_toml_other_tables_stay_silent_in_every_spelling` | `['api']`, `["api"]`, `[ API ]`, `[api] # c` and a BOM-prefixed `[api]` fire; `['db']`, a BOM before `[db]` and `["apis"]` stay silent |
| `test_config_toml_without_vault_is_silent` / `test_config_toml_pragma_suppresses` | FP-bait: a comment naming vault, `extra_search_path`, a commented-out line, a non-Supabase `config.toml`, a reference path; the `#` pragma |
| `test_vault_grants_to_data_api_roles_fire` / `test_vault_grants_to_service_role_are_silent` / `test_vault_grant_is_the_repo_s_only_vault_sql_still_fires` / `test_grants_on_other_schemas_stay_na` | Schema / object / `ALL IN SCHEMA` / default-privileges grants fire, including when the grant is the repo's only vault SQL; `service_role` grants and schemas named like vault stay silent |
| `test_vault_grant_inside_a_do_block_fires_and_the_trailer_pragma_suppresses` | A vault grant inside a DO block fires and the `END $$;` pragma suppresses it |
| `test_vault_grant_in_a_dump_file_fires` / `test_log_statement_ddl_or_none_in_a_dump_file_is_silent` | A dump's own vault grant fires; a dump's `ddl`/`none` logging setting stays silent |
| `test_applies_gate` / `test_reference_sql_paths_are_skipped` / `test_supabase_vault_plaintext_leak_hostile_headless_sql_is_linear` / `test_supabase_vault_plaintext_leak_semicolonless_dollar_bodies_are_linear` / `test_each_rule_carries_its_own_title` | Gates, scan roots, linearity (head scans and `;`-less dollar bodies), titles |
| `test_identifier_pattern_matches_the_exposure_guard_s` | The local copy of the identifier pattern (kept local so the ReDoS linter resolves `_SECRET_CALL`) equals `supabase-vault-exposure`'s |

## Known bypasses

- **Literal secrets through a variable or a SELECT.** `v_key := 'sk-...'; PERFORM
  vault.create_secret(v_key)` is not traced (no data flow), and neither is
  `INSERT INTO vault.secrets (...) SELECT 'sk-...', ...`.
- **Secrets in non-SQL seeds.** A literal passed to `create_secret` from a Python or JS seed
  script is out of scope here; generic secret scanners cover known key formats there.
- **Logging set outside the repo.** `log_statement` set in the dashboard or in a
  `postgresql.conf` the repo does not ship is invisible, as is `log_min_duration_statement = 0`,
  which also logs statement text.
- **An exposed-schema list built elsewhere.** `PGRST_DB_SCHEMAS` in a compose file, a hosting
  dashboard setting, or a dotted `api.schemas = [...]` key outside an `[api]` table is not read.
- **A vault grant revoked later still fires (known FP).** As in `supabase-vault-exposure`, GRANTs
  are not replayed against later REVOKEs. Delete the old grant, or annotate it with the pragma.

## What this guard does NOT prove

- **That a committed secret is still valid.** It cannot tell a rotated key from a live one; the
  remediation says to rotate either way.
- **The live server settings or exposed schemas.** It reads files. Run `agentsec live` for the
  deployed database.

# Examples

Fires (`literal-secret-in-sql`, high), even with a schema snapshot in the repo:

```sql
SELECT vault.create_secret('sk-live-4f9a2b7c1d8e3f60', 'openai_key');
```

Silent: the value comes from the environment at deploy time.

```sql
SELECT vault.create_secret(current_setting('app.openai_key'), 'openai_key');
```

Fires (`vault-schema-exposed`, critical):

```toml
[api]
schemas = [
  "public",
  "vault",
]
```

# Citations

[1] supabase/vault README: https://github.com/supabase/vault/blob/main/README.md (statement logging
"will contain the _unencrypted_ secrets")

[2] Supabase docs, Vault: https://supabase.com/docs/guides/database/vault

[3] Supabase CLI config reference (`[api] schemas`): https://supabase.com/docs/guides/local-development/cli/config

[4] PostgreSQL, Error Reporting and Logging (`log_statement`): https://www.postgresql.org/docs/current/runtime-config-logging.html

[5] agentsec checklist item `7-supabase-vault-material-exposed` (§7), OWASP:A01, OWASP:A02
