---
type: Guard
title: "empty-password-in-config"
description: "Empty password field in checked-in config file."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "empty-password-in-config"
checklist_section: ["8"]
standards: ["CWE-862", "OWASP:A02"]
---

# Empty password field in checked-in config file

_Author — 2026-08-09_

---

## The threat

A key literally named `password` (case-insensitive) whose value is the empty string `""`,
committed inside a checked-in JSON or YAML config file, is CWE-862 (Missing Authorization) by
omission: many services and libraries treat a blank/empty password field as "authentication
disabled" rather than "not yet filled in" — an empty password is frequently a *valid*, silently
accepted credential, not a parse error. Whoever deploys that config verbatim (a fresh
environment, a forked repo, a default `docker-compose up`) inherits an authentication bypass
with no error, no warning, and no obvious signal that anything is wrong — the service simply
starts and accepts connections. This reaches anyone who can read the config (every contributor,
every CI log, every fork) and, transitively, anyone who can reach the service the empty password
was meant to gate. Standard: OWASP:A02 (Cryptographic/credential handling failures), CWE-862.

Ported from CodeQL's `javascript/ql/src/Security/CWE-862/EmptyPasswordInConfigurationFile.ql`
(and its shared `PasswordInConfigurationFileQuery.qll` library).

## Why this guard fits the stack

Every layer of the flagship 9_Agent_SaaS shape carries JSON/YAML config: a Supabase/Postgres
connection block in a `config.json`, a Docker Compose override, a CI-adjacent settings file, a
seed/bootstrap config checked in for local dev. A common failure mode is a developer scaffolding
a config file with the shape filled in and the secret fields left blank, intending to fill them
via environment override later — and then committing that file before the override is wired up:

```json
{
  "database": {
    "host": "db.internal",
    "user": "app",
    "password": ""
  }
}
```

If the deploy path reads this file directly (rather than requiring the env var to be set,
erroring on a blank), the database now accepts unauthenticated (or empty-password) connections
in every environment that deploys this file as committed.

## Detection design

1. **`applies()` gate** — none; `applies_when: []`. A blank password field in a checked-in
   config is bad on any stack, so this guard runs unconditionally (mirrors how the sibling
   manual item `12-db-password-strong` is also `applies_when: []`).
2. **Files scanned** — `iter_files(root, (".json",))` and `iter_files(root, (".yaml", ".yml"))`,
   scanned separately since the parsing approach differs per format. NOT `.env`/`.ini`/
   `.properties` — CodeQL's own `config()` predicate excludes those despite the CWE-862 tag, and
   this guard mirrors that scope deliberately (see "Known bypasses").
3. **The pattern**:
   - **JSON**: `json.loads()` each file, then an iterative (never natively recursive — a
     deeply-nested untrusted file must not `RecursionError` the guard) walk of the parsed
     structure through dicts and arrays-of-dicts at any depth, looking for a key whose name is
     exactly `password` (case-insensitive, `key.lower() == "password"`, never a substring
     match) with value `== ""`.
   - **YAML**: no PyYAML runtime dependency (agentsec is stdlib-only by design; the same
     precedent as `npm_ignore_scripts.py` scanning workflow YAML by regex line), so matched
     per-line: `^\s*password\s*:\s*(?:""|''|)\s*$` case-insensitive — a `password:` key
     followed by nothing, or an explicit empty-string value.
4. **Exclusions**:
   - `is_nonproduct_path()` — test/example/fixture/migration paths.
   - A locally-added locale/i18n/translation exclusion (`is_nonproduct_path` does not cover
     this bucket): any path segment `lang(uage)?s?/`, `locale?s?/`, `i18n/`, or a filename
     whose stem is `translation`/`translations`.
   - Any file literally named `package.json`, for the JSON case — dependency blocks are version
     strings, never password fields, but excluded defensively regardless of content.
5. **Inline opt-out pragma** — the string `security: allow-empty-password-in-config` anywhere
   in the file: a `#` comment on any line for YAML; since JSON has no comment syntax, any JSON
   string value (e.g. `"_note": "security: allow-empty-password-in-config"`) for JSON. Checked
   before parsing, so it works even against a file that wouldn't otherwise parse. In YAML only a
   comment counts: the check reads the `yaml` comment view, so a scalar quoting the phrase does not
   suppress (#1040 T5). JSON has no comment syntax, so there it is a raw-text substring.
6. **Severity / rule** — HIGH, `empty-password-in-config/empty-password`, standards
   `["OWASP:A02", "CWE-862"]`.

## When NOT to flag

- A `password` field holding ANY non-empty value (a real secret, a placeholder token like
  `"CHANGE_ME"`, or an environment-variable reference like `"${DB_PASSWORD}"`) is not empty and
  must not fire — this guard only ever asserts the literal empty string, not "looks like a weak
  or placeholder password" (that's a different, broader check this guard deliberately does not
  attempt).
- A key that merely *contains* "password" as a substring (`password_hint`, `password_placeholder`,
  `has_password`) must not fire — only the exact key name.
- Test/fixture/example/migration paths, and locale/i18n/translation files, are excluded — a
  planted blank password in a test fixture is fake by construction, and a translation file is
  not a config file at all (a string like `"password:"` could appear as a UI label to translate).
- `package.json` is excluded outright for the JSON case, regardless of content.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_empty_password_json_top_level` | Planted violation: top-level `"password": ""` in JSON fires HIGH. |
| `test_fires_on_empty_password_json_deeply_nested` | Bypass check: `{"database": {"credentials": {"password": ""}}}` still fires — the JSON walk is not shallow. |
| `test_fires_on_empty_password_json_inside_array_of_objects` | An empty password nested inside an array-of-objects (`services: [...]`) still fires. |
| `test_fires_on_empty_password_yaml_no_value` | Planted violation: `password:` with nothing after it in YAML fires HIGH at the correct line. |
| `test_fires_on_empty_password_yaml_explicit_empty_string` | Planted violation: `password: ""` in YAML fires. |
| `test_silent_on_nonempty_password_json` | FP-bait: a real (non-empty) password value in JSON stays silent. |
| `test_silent_on_nonempty_password_yaml` | FP-bait: a real (non-empty) password value in YAML stays silent. |
| `test_silent_on_nonproduct_path` | FP-bait: a planted violation under `tests/fixtures/` stays silent (`is_nonproduct_path`). |
| `test_silent_on_package_json_even_with_empty_string_value` | FP-bait: `package.json` is excluded outright, even with an unrelated empty-string value and a literal `password` key. |
| `test_silent_on_key_name_password_placeholder` | Bypass check: `password_placeholder`/`password_hint` keys (substrings, not exact matches) stay silent. |
| `test_silent_on_locale_path_yaml` | FP-bait: a file under `locales/` stays silent. |
| `test_pragma_suppresses_yaml` | The inline opt-out pragma suppresses a real planted violation. |

## Known bypasses

- **Any key name other than the literal `password`** evades this guard entirely — `pwd`,
  `pass`, `db_password`, `secret`, `passwd`, `pwd_hash`. This is a **deliberate, narrow-but-precise
  scoping choice**, not an oversight: it mirrors CodeQL's own upstream predicate exactly (which
  also matches only the literal name), and a broader stem match would need to distinguish a real
  password-shaped key from an unrelated one (`password_policy`, `password_reset_url`) without a
  reliable signal, trading precision for recall in a direction this guard does not take. A future,
  separately-designed guard could extend the key-name vocabulary deliberately, with its own FP
  analysis — this guard does not attempt it.
- **A non-empty placeholder that means "empty"** — `"password": "CHANGE_ME"`, `"password": "TODO"`,
  `"password": null` — does not match the literal empty-string check and is not flagged. Only a
  genuinely empty string is in scope.
- **`.env`/`.ini`/`.properties` files** are entirely out of scope, by design, mirroring the
  CodeQL predicate this guard is ported from — a blank `DB_PASSWORD=` in a `.env` file is not
  detected by this guard (a separate class of guard already exists for `.env` secret handling
  in this codebase).
- **Indirection**: a config that loads its password from a separate, non-empty-looking file or
  a templated value resolved at deploy time (`"password": "{{ vault_password }}"`) is a non-empty
  string and does not fire, even if the template resolves to empty at runtime — this is a static
  guard over the literal committed text, not a deploy-time check.

## What this guard does NOT prove

- It does not prove the config file is ever actually deployed or read by a running service — it
  flags the committed text, not runtime behavior.
- It does not validate password *strength* — a non-empty, weak, or default password
  (`"password": "admin"`) is entirely out of scope for this guard (see `12-db-password-strong`,
  a manual/ops item, for the deployed-value question this guard does not and cannot answer
  statically).
- It does not detect the same class of bug under any other key name — see "Known bypasses".
- It does not detect an empty password expressed in `.env`/`.ini`/`.properties` format, or in a
  format this guard doesn't parse (TOML, XML, a custom DSL).

# Citations

[1] agentsec checklist item `8-empty-password-in-config` (§8)
[2] CWE-862
[3] OWASP:A02
