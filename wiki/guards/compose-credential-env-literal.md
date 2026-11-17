---
type: Guard
title: "compose-credential-env-literal"
description: "Docker-compose credential-shaped env key with a literal value."
timestamp: "2026-09-22T20:14:52+00:00"
guard_id: "compose-credential-env-literal"
checklist_section: ["6c"]
standards: ["CWE-798", "OWASP:A02"]
---

# Docker-compose credential-shaped env key with a literal value

_Author — Marconi, 2026-08-16_

---

## The threat

An environment variable whose key name matches a credential convention (`PASSWORD`,
`TOKEN`, `SECRET`, `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`, `CREDENTIAL`, `_PASS`, `_PWD`,
`_DSN`, …) and whose value is a non-empty literal string is exposed via `docker inspect`,
`/proc/<pid>/environ`, `docker compose config`, process listings, and CI logs — any
process or operator with daemon access can read it. Compose's `secrets:` primitive
materializes credentials as files under `/run/secrets/` instead, which appears in none of
those surfaces. CWE-798 (Use of Hard-coded Credentials), OWASP:A02.

## Why this guard fits the stack

`environment:` is the default way a compose-defined FastAPI/LLM stack passes a DB
password or LLM provider key to a service — this project already has guards for
env-secret-in-source/logging/prompt-exposure, but nothing that inspects the compose file
itself for a literal credential sitting in plain YAML:

```yaml
services:
  app:
    environment:
      DB_PASSWORD: hunter2
```

Sourced from compose-lint's `CredentialEnvKeysRule` (`CL-0020`), simplified: the real
source's quantity-knob exemption list is more extensive (a fuller `TTL`/size/policy-word
family, corpus-tuned) than the representative subset reproduced here.

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()`, then walks each service's `environment:` block in
   either dict form (`KEY: value`) or list form (`- KEY=value` / `- KEY: value`).
4. A key is credential-shaped if it contains a substring from `_SUBSTRING_PATTERNS`
   (`PASSWORD`, `SECRET`, `API_KEY`, …) or ends in a suffix from `_SUFFIX_PATTERNS`
   (`_PASS`, `_PWD`, `_DSN`, …). Exempt if the key ends `_FILE` (the documented
   file-path opt-out) or contains `ALLOW_EMPTY_`/`RANDOM_` (a boolean toggle, not a
   credential). Exempt if the value is a flag word (`yes`/`no`/`true`/`false`/`0`/`1`/
   `on`/`off`), a Compose interpolation that ships no literal (`${VAR}`, the empty-default
   `${VAR:-}`/`${VAR-}`, the error form `${VAR:?msg}` — a NON-empty default such as
   `${VAR:-hunter2}` still fires, #663), a **userinfo-free `scheme://` URL** (a locator,
   not a secret: `GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_URI: pg-functions://postgres/public/hook`,
   `OAUTH_TOKEN_URL: https://auth.example.com/oauth/token` — the `build_secret.py` #447
   rule applied here for #898; ANY `@` in the authority keeps the value a credential, so
   `postgresql://admin:hunter2@db` and the user-only `https://ghp_x@github.com` still
   fire), or the key names a quantity/lifetime knob (`TTL`, `TIMEOUT`, `_SECONDS`,
   `_LIMIT`, …) whose value is a bare number.
5. Inline opt-out: `# security: allow-compose-credential-env-literal` anywhere in the file.
6. Severity: `high`. Rule id: `compose-credential-env-literal/literal-credential`.
   Standards: `["OWASP:A02", "CWE-798"]`.

## When NOT to flag

- The key ends `_FILE` or contains a boolean-toggle fragment.
- The value is a boolean/numeric flag, a pure environment-variable reference, or a bare
  quantity on a lifetime/size-shaped key.
- The value is a userinfo-free `scheme://` URL — a GoTrue hook locator (`pg-functions://…`),
  an OAuth/OIDC token endpoint (`*_TOKEN_URL`, `*_TOKEN_ENDPOINT`), any `https://host/path`
  with no `user[:pass]@` in the authority (#898).
- A non-credential-shaped key.
- An audited case, suppressed with `# security: allow-compose-credential-env-literal`.

## Tests

| Test | What it checks |
|---|---|
| `test_dict_form_password_fires` | Positive: dict-form `DB_PASSWORD: hunter2` fires (**verified_by**). |
| `test_list_form_password_fires` | Positive: list-form `- DB_PASSWORD=hunter2` fires. |
| `test_api_key_fires` | Positive: `STRIPE_API_KEY` fires. |
| `test_file_suffix_exempt` | FP-bait: `DB_PASSWORD_FILE` → silent. |
| `test_var_reference_exempt` | FP-bait: `${DB_PASSWORD}` → silent. |
| `test_flag_value_exempt` | FP-bait: `ALLOW_EMPTY_PASSWORD: 'yes'` → silent. |
| `test_quantity_knob_exempt` | FP-bait: `TOKEN_TTL_MINUTES: 30` → silent. |
| `test_var_reference_with_empty_default_exempt` / `…_bare_dash_empty_default_exempt` / `…_error_message_exempt` | FP-bait (#663): `${VAR:-}`, `${VAR-}`, `${VAR:?msg}` → silent. |
| `test_var_reference_with_non_empty_default_still_fires` / `…_bare_dash_non_empty_default_still_fires` | Narrowing check (#663): `${POSTGRES_PASSWORD:-postgres}`, `${VAR-hunter2}` still fire. |
| `test_userinfo_free_url_exempt` | FP-bait (#898): `GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_URI: pg-functions://postgres/public/custom_access_token_hook` → silent. |
| `test_oauth_token_endpoint_url_exempt` | FP-bait (#898): `OAUTH_TOKEN_URL: https://…/oauth/token` (dict form) and `- KEYCLOAK_TOKEN_ENDPOINT=https://…` (list form) → silent. |
| `test_quoted_userinfo_free_url_exempt` | FP-bait: a quoted `'pg-functions://…'` locator → silent (the URL arm runs after the quote-strip). |
| `test_url_with_userinfo_still_fires` | Narrowing check (the #447 rule): `DB_DSN: postgresql://admin:hunter2@db:5432/app` still fires HIGH. |
| `test_url_with_user_only_userinfo_still_fires` | Narrowing check: `GIT_TOKEN_URL: https://ghp_abc123@github.com/org/repo` still fires — the sibling guard needs `:password@`, so this guard is the only coverage for user-only userinfo. |
| `test_non_credential_key_does_not_fire` | FP-bait: `LOG_LEVEL` → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **A secret embedded in the path or query of a userinfo-free URL** under a
  credential-shaped key — `DISCORD_WEBHOOK_TOKEN: https://discord.com/api/webhooks/123/<secret>`,
  `MAPS_API_KEY: https://maps.example.com/v1?key=<secret>` — is not flagged since #898: the
  userinfo check (`user[:pass]@` in the authority) is the only value-shape signal, the same
  trade `build_secret.py` accepted for Dockerfile `ENV` under #447. The `gitleaks` runner
  catches only SOME of these by content — measured for #898 on its default ruleset (which
  the shipped `.gitleaks.toml` extends): a Slack `hooks.slack.com/services/…` URL and a
  Google `AIza…` key in a query fire, a Discord webhook URL does **not** — so the Discord
  example above is a real gap, not a hand-off. (A defaulted interpolation
  `${DB_PASSWORD:-hunter2}` is NOT a bypass — it has fired since #663; an earlier revision
  of this doc said otherwise.)
- **An indirect key naming convention** not covered by the substring/suffix lists (e.g. a
  project-specific `SIGNING_MATERIAL`) is invisible — this is a naming-convention check,
  not a content/entropy scanner.

## What this guard does NOT prove

A silent guard does not confirm no credential is present under an unrecognized key name,
or that a value routed through `${VAR}` doesn't resolve to a hardcoded secret elsewhere
(a `.env` file, a CI variable). This is a presence-based, naming-convention check only.

# Citations

[1] agentsec checklist item `6c-compose-credential-env-literal` (§6c)
[2] CWE-798
[3] OWASP:A02
