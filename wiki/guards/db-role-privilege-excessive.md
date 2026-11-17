---
type: Guard
title: "db-role-privilege-excessive"
description: "Application DB role holds excessive privilege (SUPERUSER/CREATEDB/CREATEROLE/schema ownership/broad DDL grant)."
timestamp: "2026-08-14T12:33:25+08:00"
guard_id: "db-role-privilege-excessive"
checklist_section: ["7"]
standards: ["OWASP:A01", "SOC2:CC6.3"]
---

# Application DB role holds excessive privilege (SUPERUSER/CREATEDB/CREATEROLE/schema ownership/broad DDL grant)

_Author — 2026-08-13_

---

## The threat

**JadePuffer (Sysdig, securityaffairs.com/194713)** — the first documented end-to-end
AI-driven ransomware operation. An LLM agent chained initial access (Langflow CVE-2025-3248,
unauth RCE), credential harvesting, and default-credential lateral movement, then reached its
most destructive stage: **encrypting and dropping the victim's Postgres tables through the
compromised application's own DB connection.**

That final stage only worked because the app's runtime role could `DROP TABLE`. Postgres has
no standalone "DROP" privilege — a role can drop an object only if it is `SUPERUSER`, or it
**owns** the object (directly, via owning the schema, or via having `CREATE`d it itself). So
the blast radius of *any* app-layer RCE — this one, or a SQL-injection, or a compromised
dependency — is bounded entirely by how privileged the app's own DB role is. WHO reaches
this: anyone who compromises the running application (the exact reach an RCE, an SSRF-to-
internal-admin-endpoint, or a supply-chain compromise already gives). WHAT privilege: none
beyond "run application code" — the excessive privilege lives in the DB role, not in any
additional access the attacker needs. WHAT effect: full destructive capability over the
schema/database (`DROP TABLE`, `TRUNCATE`, arbitrary `ALTER`), i.e. exactly the ransomware
end-state. Findings carry `OWASP:A01` (Broken Access Control — the app operates outside its
least-privilege boundary) and `SOC2:CC6.3` (least-privilege logical access controls).

This guard is the static-tool answer to "ransomware encrypted the DB": flag the concrete SQL/
compose patterns that hand an app's runtime role the same blast radius a DB-owning attacker
would want, before the app is ever exposed.

## Why it's often introduced

The path of least resistance in early development is to point the app straight at the
Postgres bootstrap superuser (`postgres`/`postgres` in a docker-compose `DATABASE_URL`), or to
let an ORM's `create_all()`/auto-migrate feature run as the app's own connection — which
requires `CREATE` on the schema and leaves the app owning every table it created (and
therefore able to drop them). Neither choice is malicious; both are simply never revisited
once the app works. A `CREATE ROLE app_user WITH SUPERUSER` in a bootstrap migration, or a
`GRANT ALL ON SCHEMA app TO app_user` "just to get CI green," are the same shortcut in SQL
form:

```sql
-- what looks like "give the app what it needs" is actually "give the app everything"
CREATE ROLE app_user WITH LOGIN PASSWORD 'x' SUPERUSER;
GRANT ALL PRIVILEGES ON DATABASE appdb TO app_user;
```

## Detection design

1. **`applies()` gate** — `"sql" in profile.features` (matches the checklist item's own
   `applies_when: ["sql"]`).
2. **Files scanned** — SQL: every `.sql` file under `profile.sql_dir` (falling back to `root`),
   filtered through `is_reference_sql_path` (keeps `migrations/`/`alembic/` in scope — the
   deployed schema for SQL guards — while dropping `examples/`/`fixtures/`/`tests/` noise).
   Compose: every `docker-compose*.yml`/`*.yaml` under `root` via `iter_files_named`, skipping
   local-dev compose files (`is_dev_compose_file`) — see "When NOT to flag".
3. **Patterns** (four independent detectors, comment-stripped via `strip_sql_comments` /
   `strip_hash_comments`):
   - `CREATE|ALTER ROLE|USER <name> ... SUPERUSER|CREATEDB|CREATEROLE` — attribute keywords
     matched with `\b` boundaries so the negated one-word forms (`NOSUPERUSER` etc., which
     Postgres writes with no space) never match.
   - `ALTER SCHEMA <schema> OWNER TO <role>` — explicit ownership transfer.
   - `GRANT ALL [PRIVILEGES] ON SCHEMA|DATABASE <obj> TO <roles...>` — matched against a
     comma-separated role list so a multi-role `TO` clause is evaluated per-role.
   - Compose: a connection-string value matching `postgres(ql)?(+driver)?://postgres:` —
     the app's own DSN authenticating as the literal `postgres` superuser account.
   All four exempt a role via `_is_exempt_role`: Postgres/Supabase built-in roles (`postgres`,
   `anon`, `public`, `authenticated`, `service_role`, the `supabase_*` platform roles) and any
   role name containing `migrat` (best-effort migration-tool-role naming heuristic).
4. **Inline opt-out pragma** — `-- security: allow-db-role-privilege-excessive` (file-level,
   `.sql`), `# security: allow-db-role-privilege-excessive` (file-level, compose).
5. **Severity/rule/standards** — all findings are `high`, `standards=["OWASP:A01",
   "SOC2:CC6.3"]`, with rule ids `db-role-privilege-excessive/role-<attrs>`,
   `db-role-privilege-excessive/schema-owner`, `db-role-privilege-excessive/broad-grant`,
   `db-role-privilege-excessive/superuser-connection-string`.

## When NOT to flag

- **`NOSUPERUSER`/`NOCREATEDB`/`NOCREATEROLE`** (the negated forms) are the safe default and
  never match — see the `\b`-boundary reasoning above.
- **A scoped grant** — `GRANT SELECT, INSERT, UPDATE, DELETE ON <specific_table> TO
  <role>;` — is exactly the intended shape of an app's runtime privileges and stays silent.
  This is the guard's own contrast case for "broad" (test:
  `test_scoped_grant_stays_silent`).
- **`anon`/`public`/`authenticated`/`service_role` grants** are `pg-anon-grant`'s territory (a
  different threat model: unauthenticated RLS bypass, not an app-runtime-role blast radius) —
  duplicating that guard's findings under a different id would misdirect triage.
- **The `postgres` bootstrap role and Supabase platform roles** (`supabase_admin` etc.) are
  exempt from schema-ownership and broad-grant findings — `ALTER SCHEMA public OWNER TO
  postgres;` is routine `pg_dump` boilerplate, not an app-layer decision.
- **A role name containing `migrat`** (`migrator`, `db_migrator`, `admin_migration`) is exempt
  from all three SQL-side findings — a migration-only role legitimately needs elevated rights
  precisely because it is documented as NOT the app's runtime connection.
- **Local-dev compose files** (`docker-compose.dev.yml` etc., via `is_dev_compose_file`) are
  skipped for the superuser-connection-string check: `postgres`/`postgres` is the
  overwhelmingly common, low-signal convention for a throwaway local database, and flagging it
  buries the production-relevant finding in dev-file noise (mirrors `compose-db-port-exposed`'s
  scoping of the same file class).

## Tests

| Test | What it checks |
|---|---|
| `test_db_role_privilege_excessive_applies_on_sql_feature` | `applies()` gates on the `sql` feature |
| `test_db_role_privilege_excessive_not_applies_without_sql_feature` | `applies()` is False without it |
| `test_flags_alter_role_superuser` / `test_flags_create_role_superuser` | SUPERUSER fires on both CREATE and ALTER ROLE |
| `test_flags_alter_role_createdb` / `test_flags_alter_role_createrole` | CREATEDB/CREATEROLE independently fire (not just SUPERUSER) |
| `test_flags_create_user_alias` | `CREATE USER` (the Postgres ROLE alias) is also scanned |
| `test_two_separate_alter_role_statements_each_fire` | adversarial: splitting an excessive grant across two statements doesn't evade detection |
| `test_negated_attributes_stay_silent` | FP-bait: `NOSUPERUSER`/`NOCREATEDB`/`NOCREATEROLE` never match |
| `test_migration_role_name_is_exempt` | FP-bait: a role named as a migration-tool role is exempt |
| `test_pragma_silences_role_attrs` | the SQL pragma silences the role-attribute finding |
| `test_flags_schema_owner_transfer_to_app_role` | `ALTER SCHEMA ... OWNER TO` fires on a non-exempt role |
| `test_schema_owner_postgres_bootstrap_role_is_silent` | FP-bait: `OWNER TO postgres` (pg_dump boilerplate) is silent |
| `test_schema_owner_migration_role_is_silent` | FP-bait: a migration-role owner is silent |
| `test_flags_grant_all_on_schema` / `test_flags_grant_all_privileges_on_database` | both `GRANT ALL` object types fire |
| `test_scoped_grant_stays_silent` | FP-bait: the guard's own scoped-grant contrast case never fires |
| `test_grant_all_to_anon_public_is_pg_anon_grant_territory` | FP-bait: anon/public/service_role grants are exempt (own guard's territory) |
| `test_grant_all_keyword_split_across_lines` | adversarial: `ALL`/`PRIVILEGES` split across physical lines still fires |
| `test_grant_all_multi_role_list_flags_each_non_exempt_role` | adversarial: a multi-role `TO` list is evaluated per-role, exempt roles filtered out |
| `test_grant_all_pragma_silences` | the SQL pragma silences the broad-grant finding |
| `test_fixtures_dir_is_out_of_scope` | `is_reference_sql_path` drops `fixtures/` |
| `test_migrations_dir_stays_in_scope` | `is_reference_sql_path` keeps `migrations/` (the deployed schema) |
| `test_flags_compose_superuser_connection_string` | compose leg fires on a `postgres://postgres:...` DSN |
| `test_flags_compose_superuser_connection_string_sqlalchemy_dialect` | adversarial: the `+asyncpg`/dialect-suffixed DSN form still matches |
| `test_compose_scoped_app_role_connection_string_silent` | FP-bait: a dedicated app-role DSN stays silent |
| `test_dev_compose_superuser_connection_string_is_out_of_scope` | dev compose files are out of scope for this check |
| `test_compose_pragma_silences` | the compose pragma silences the connection-string finding |

## Known bypasses

- **The migration-role exemption is a naming heuristic, not a structural one.** Nothing stops
  an attacker (or a careless author) from naming the app's actual runtime role `migrator` to
  evade every SQL-side check. Nothing confirms an exempted role is genuinely never used for
  runtime traffic — the guard cannot see which role a running app's connection string actually
  uses unless that string is itself in a scanned compose file.
- **The compose connection-string check is a literal-string match on `postgres:` as the
  username.** A superuser account under any OTHER name (`root`, `admin`, a role that happens
  to hold SUPERUSER but isn't spelled `postgres`) is invisible to this leg — it relies entirely
  on the SQL-side role-attribute check to catch that shape instead, and only if the role's
  `CREATE`/`ALTER ROLE` statement is itself in the scanned repo.
- **Role-membership-based escalation is not checked.** `GRANT rds_superuser TO app_user;` (or
  the Azure/Cloud SQL equivalents) grants superuser-equivalent privilege via role membership
  rather than a `SUPERUSER` attribute, and is not matched by any pattern here.
- **`GRANT CREATE ON SCHEMA ... TO <role>`** (without `ALL`) is not flagged. `CREATE` alone
  lets a role create (and therefore own, and therefore later drop) its own objects — a real,
  narrower version of the same risk — but was deliberately left out to keep the "broad DDL"
  signal to the `GRANT ALL` shape the B4 spec names explicitly; see "What this guard does NOT
  prove" for the honest scope statement.
- **Environment files (`.env`, `.env.production`) and non-compose IaC (Terraform, Ansible,
  Kubernetes manifests) are not scanned** for the superuser-connection-string pattern — only
  docker-compose files. A DSN set any other way is invisible to this guard.

## What this guard does NOT prove

- **It never confirms which role the running application actually connects as.** It flags
  *statements that grant excessive privilege to a role*, and a compose DSN using the literal
  `postgres` username — it has no way to correlate a `CREATE ROLE app_user ... SUPERUSER`
  statement with proof that `app_user` is (or is not) the app's live runtime credential. A
  silent guard does not mean the deployed app connects least-privileged; a firing guard does
  not guarantee the flagged role is the one actually in use (it might be a genuinely
  unused/legacy statement left in an old migration).
- **The B4 spec's "absence of a separate migration-only role" softer half is deliberately NOT
  implemented.** Proving that no separate migration role exists from a partial static view of
  one repo is unsound: the role may be provisioned entirely outside what agentsec scans
  (Terraform, a cloud console, an out-of-band bootstrap script, a managed-Postgres provider's
  default setup). A tool asserting "no migration role exists" when one exists elsewhere is a
  **false claim from absence of evidence** — a worse failure mode than saying nothing, per the
  guard's own design brief. This guard only ever flags a POSITIVE signal (a statement/DSN it
  can see), never a negative one.
- **A silent result does not certify the app is least-privileged in production.** Runtime
  privilege can be reassigned after deploy (`ALTER ROLE` run manually against the live DB,
  never committed to SQL/compose), a managed-Postgres provider (RDS, Cloud SQL, Supabase) can
  hand out privilege through its own console/API entirely outside the repo, and role membership
  grants (`GRANT rds_superuser TO ...`) are not checked at all (see "Known bypasses"). This
  guard is a **repo-static** check on committed intent, not a live database audit — that half
  is `agentsec live`'s Supabase Splinter integration, which reads the actual deployed grants.

# Citations

[1] agentsec checklist item `7-least-privilege-db-role` (§7)
[2] OWASP:A01
[3] SOC2:CC6.3
