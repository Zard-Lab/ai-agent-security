---
type: Guard
title: "node-db-driver-hardcoded-password"
description: "Node DB driver configured with a hardcoded password."
timestamp: "2026-11-21T00:00:00Z"
guard_id: "node-db-driver-hardcoded-password"
checklist_section: ["8"]
standards: ["OWASP:A02", "CWE-798"]
---

# Node DB driver configured with a hardcoded password

Flags a literal database password in the config object of a Node SQL driver (`new Pool/Client`,
`createConnection`, `createPool`, `new ConnectionPool`) and a `postgres://user:password@host` style
URL literal, in files that import `pg`, `pg-promise`, `mysql`, `mysql2` or `mssql`. Mined from
eslint-plugin-security-rules' `no-hardcoded-credentials` rules for pg and mysql.

_Author — 2026-11-21_

---

## The threat

A database password committed as a string literal is readable by everyone with repository access,
every fork, every CI log that echoes the source and every shipped bundle. Rotating it needs a code
change and a redeploy, so in practice it is never rotated. Anyone who reaches the source, with no
other privilege, gets direct database access with whatever rights the app account has (CWE-798,
OWASP:A02). The existing secret guards are provider-prefix based (`hardcoded-llm-provider-key`,
`client-side-secret-literal`) and `mcp-hardcoded-credential` only runs on MCP servers, so an ordinary
Express or Next.js service with `new Pool({ password: 'Sup3rS3cretPw!' })` was not reported.

## Why this guard fits the stack

Node services reach Postgres and MySQL through a small set of drivers whose connection config is a
plain object literal, so the shape is statically visible without dataflow. The import gate keeps the
`Client`/`Pool` names of unrelated SDKs out of scope, the same trade `js-sql-injection` makes.

## Detection design

1. `applies()` gates on the `javascript` or `typescript` feature.
2. Scans `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, skipping test, fixture, example and mock paths via
   `is_nonproduct_path(..., credential_scan=True)`. `migrations/` and `alembic/` trees stay in
   scope: a password in a migration runner is a real committed credential.
3. Skips a file with no `require`/`import` of `pg`, `pg-promise`, `mysql`, `mysql2` (including
   `mysql2/promise`) or `mssql`.
4. Comments are blanked (`strip_js_comments`) and a string-blanked anchor mask is used so a call or a
   key spelled out inside a string is not code (`js_code_matches`).
5. `driver-config-literal-password`: for each live `new [x.]Pool|Client|ConnectionPool({` or
   `createConnection|createPool({`, the brace-balanced object body is searched for a `password`
   key (bare or quoted) whose value is a quoted string or template literal.
6. `connection-url-embedded-password`: a `postgres(ql)|mysql(2)|mssql|sqlserver://user:password@`
   literal anywhere in a driver-importing file.
7. A value counts as a secret only if it is at least four characters, has no `${` / `%s` / `{{`
   substitution and is not a placeholder or stock dev password: `test*`, `changeme*`, `your-*`,
   `<...>`, `[...]`, `{...}`, `xxx*`, `example*`, `dummy*`, `fake*`, `todo*`, `placeholder*`,
   `redacted*`, `password`, `passwd`, `pass`, `secret`, `postgres`, `root`, `admin`, `mysql`.
8. Pragma: `// security: allow-node-db-driver-hardcoded-password`, read as a comment (`pragma_present`),
   whole file.
9. Severity HIGH, standards `["OWASP:A02", "CWE-798"]`, rules
   `node-db-driver-hardcoded-password/driver-config-literal-password` and
   `node-db-driver-hardcoded-password/connection-url-embedded-password`.

## When NOT to flag

`password: process.env.DB_PASSWORD`, any non-literal expression, an empty or very short value, a
template with a `${}` hole, a documented placeholder, and the stock local-dev passwords above stay
silent. A `password` key in an object that is not a driver config (`const form = { password: '...' }`)
is not read. Test, fixture, example and mock paths are skipped. A reviewed case (a throwaway local
container) is suppressed with `// security: allow-node-db-driver-hardcoded-password`.

## Tests

| Test | What it checks |
|---|---|
| `test_literal_password_in_driver_config_fires` | pg `Pool`/`Client`, mysql `createConnection`, mysql2 `createPool` with a quoted key, mssql `ConnectionPool` with a template, and a password after nested options each fire once |
| `test_config_finding_reports_the_password_line` | the finding carries the password line, not the constructor line |
| `test_connection_url_with_password_fires` | a `postgres://` URL in a `connectionString` and a `mysql://` template URL fire the URL rule |
| `test_safe_or_placeholder_values_silent` | env/config values, empty, short, `test`, `changeme`, `your-...`, `<...>`, `postgres`, `${}` templates, a commented password, a quoted example, a URL without a password, a `${}` URL and a non-driver object stay silent |
| `test_needs_a_driver_import` | an unrelated SDK `Client` is not read |
| `test_test_and_fixture_paths_silent` | `__tests__`, `tests`, `fixtures`, `examples` and `__mocks__` paths are skipped |
| `test_pragma_suppresses` | the file pragma silences the guard |
| `test_pragma_quoted_in_a_string_does_not_suppress` | a string quoting the pragma is not an opt-out |
| `test_typescript_file_and_aliased_constructor_fires` | `.ts` files and the `pg.Pool` member form fire |
| `test_migrations_tree_is_still_scanned` | a `migrations/` runner is not treated as non-product |
| `test_not_applies_without_js_or_ts` | the feature gate |

## Known bypasses

| Bypass | Description |
|--------|-------------|
| Indirection | `const PW = 'Sup3rS3cret'; new Pool({ password: PW })` is not followed; only a literal in the config object is read. |
| Shared driver wrapper | A repo that imports the driver only in a `db.js` wrapper has no import in the other files, which stay unread. |
| Stock dev passwords | `postgres`, `root`, `admin`, `mysql` are treated as local-dev defaults and stay silent, so a real service using one is missed. |
| Other factories | `pgp({...})`, `sql.connect({...})`, Knex and ORM configs are not recognized as driver configs. |
| Split URL | A URL assembled by concatenation (`'postgres://app:' + pw + '@db'`) is not matched, which is also the safe form when `pw` is not a literal. |

## What this guard does NOT prove

A silent run does not prove the app keeps its credentials out of source. It shows only that no driver
config object or database URL literal in a driver-importing, non-test file carries a password
literal. Secrets in `.env` files, compose files and CI config are other guards' concern.

# Citations

[1] agentsec checklist item `8-js-db-driver-hardcoded-password` (§8)
[2] OWASP:A02, CWE-798
