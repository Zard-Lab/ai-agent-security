---
type: Guard
title: "compose-connection-string-credential"
description: "Docker-compose env value with an inline connection-string credential."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-connection-string-credential"
checklist_section: ["6c"]
standards: ["CWE-798", "OWASP:A02"]
---

# Docker-compose env value with an inline connection-string credential

_Author — Marconi, 2026-08-16_

---

## The threat

A `scheme://user:password@host` userinfo embedded in an environment value leaks a
credential regardless of the key's own name — `DATABASE_URL`, `MONGO_URL`, `REDIS_URL`,
and similar connection-string variables routinely carry one. The exposure surface is
identical to `compose-credential-env-literal`: `docker inspect`, `/proc/<pid>/environ`,
`docker compose config`, process listings, and CI logs. CWE-798 (Use of Hard-coded
Credentials), OWASP:A02.

## Why this guard fits the stack

Where `compose-credential-env-literal` matches credential-shaped *keys*, this guard
matches credential-shaped *values*, regardless of key name — the two are deliberately
separate guards, mirroring compose-lint's own split into two rules:

```yaml
services:
  app:
    environment:
      DATABASE_URL: postgresql://admin:hunter2@db:5432/app
```

Sourced from compose-lint's `ConnectionStringCredentialsRule` (`CL-0021`), simplified to a
single bounded regex rather than the real source's manual, ReDoS-hardened userinfo
character-by-character scan.

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()`, walks each service's `environment:` block (dict or
   list form, same value-extraction as `compose-credential-env-literal`).
4. `_CONN_STRING` matches `scheme://user:password@` with bounded scheme/user/password
   character classes (`{0,63}`/`{0,512}`/`{1,512}`) — the length caps keep worst-case cost
   linear in the value's length rather than open to backtracking on an attacker-controlled
   string, the same concern the real source's own docstring documents measuring (an
   unbounded scan on a 40 KB adversarial value took 4.1s; this guard bounds the match
   width directly instead).
5. A password that is a pure `${VAR}` reference (no default) is exempt — parameterized,
   ships no literal. A defaulted interpolation is NOT resolved by this simplified port
   (documented as a known gap below, unlike the real source which resolves it correctly).
6. Inline opt-out: `# security: allow-compose-connection-string-credential` anywhere in
   the file.
7. Severity: `high`. Rule id:
   `compose-connection-string-credential/embedded-credential`.
   Standards: `["OWASP:A02", "CWE-798"]`.

## When NOT to flag

- The password segment is a pure `${VAR}` reference.
- No `@` in the value at all (the cheap pre-check the regex engine never even reaches).
- A URL with no userinfo (`https://api.example.com/v1`).
- An audited case, suppressed with `# security: allow-compose-connection-string-credential`.

## Tests

| Test | What it checks |
|---|---|
| `test_postgres_url_with_literal_password_fires` | Positive: `postgresql://admin:hunter2@db/app` fires (**verified_by**). |
| `test_redis_url_empty_username_fires` | Positive: `redis://:hunter2@cache` (empty username, standard Redis form) fires. |
| `test_key_name_irrelevant_to_detection` | Positive: an arbitrary key name (`CUSTOM_DSN`) still fires — key-name-independent by design. |
| `test_parameterized_password_does_not_fire` | FP-bait: `${DB_PASSWORD}` password → silent. |
| `test_no_credential_url_does_not_fire` | FP-bait: a URL with no userinfo → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **A defaulted interpolation** (`${DB_PASSWORD:-hunter2}`) as the password half is not
  resolved to its literal fallback here — the real source does resolve it, this
  simplified port treats it as opaque and may under- or over-fire depending on the exact
  shape (documented divergence from upstream).
- **A connection string split across two separate env vars** (host in one, credentials
  assembled at runtime) is invisible — this is a single-value pattern match.

## What this guard does NOT prove

A silent guard does not confirm no credential is embedded in a shape this regex doesn't
match, or that a value sourced from `${VAR}` doesn't resolve to a hardcoded secret
elsewhere. This is a presence-based, single-value pattern check only.

# Citations

[1] agentsec checklist item `6c-compose-connection-string-credential` (§6c)
[2] CWE-798
[3] OWASP:A02
