---
type: Guard
title: "default-service-credential"
description: "Deployed service left on a well-known factory-default credential."
timestamp: "2026-08-14T12:33:25+08:00"
guard_id: "default-service-credential"
checklist_section: ["12"]
standards: ["CWE-1392", "OWASP:A07"]
---

# Deployed service left on a well-known factory-default credential

_Author — 2026-08-13_

---

## The threat

Sysdig documented **JadePuffer**, the first end-to-end AI-driven ransomware operation
(securityaffairs.com/194713): an LLM agent autonomously chained initial access via
**CVE-2025-3248** (Langflow missing-auth RCE), credential harvesting, **lateral movement via
well-known default service credentials**, persistence via a beaconing crontab, and finally
encryption/destruction of the backing Postgres database. The lateral-movement stage required no
exploit at all — the agent logged into MinIO with `minioadmin`/`minioadmin`, into Postgres with
`postgres`/`postgres`, and (in the closely related Nacos attack surface this guard also covers)
could forge a valid Nacos admin JWT using the service's publicly documented default signing
secret. WHO: anyone (human or, as JadePuffer proved, an autonomous agent) who can reach the
service's network port. WITH WHAT privilege: none beyond network reachability — the credential is
public knowledge, published in the vendor's own docs. TO WHAT effect: full admin access to an
object store, a database, a service-discovery/config plane, or an observability stack — the exact
blast radius that turned one compromised Langflow instance into an encrypted, exfiltrated,
data-destroyed victim. Findings carry `OWASP:A07` (Identification and Authentication Failures) +
`CWE-1392` (Use of Default Credentials) for the three login-credential checks, and `OWASP:A02`
(Cryptographic Failures) + `CWE-321` (Use of Hard-coded Cryptographic Key) for the Nacos JWT
signing-key check — a different failure class (forgeable tokens, not a login).

## Why it's often introduced / Why this guard fits the stack

A 9_Agent_SaaS-shaped app routinely reaches for MinIO (S3-compatible object storage for
agent-generated files), Postgres (already the core datastore), and — in larger deployments —
Nacos (service discovery/config for a microservice-ish agent architecture) or Grafana
(observability). Every one of these images **ships fully functional with a well-known credential
baked in**, and none of them force a change on first login the way, say, a cloud IAM console
does:

```yaml
services:
  minio:
    image: minio/minio
    environment:
      MINIO_ROOT_USER: minioadmin        # copied straight from the image's own Quick Start docs
      MINIO_ROOT_PASSWORD: minioadmin     # and never revisited once the stack "just works"
```

The docker-compose Quick Start snippet on the vendor's own homepage is frequently the value that
ships to production unchanged — this is a config-copied-verbatim mistake, not a code bug, so no
SAST/dependency scanner catches it. It is exactly the axis a dependency-free static guard is
suited for: no code execution, no live probe, just recognizing a small, well-known set of literal
values in compose/env config.

## Detection design

1. **applies()** — `"docker" in profile.features` (same gate as `compose-db-port-exposed` and
   `datastore-auth-absent` — the JadePuffer shape is specifically a docker-compose deployment).
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`
   (skipping `is_dev_compose_file` and `is_nonproduct_path`) for the compose path, plus
   `iter_files_named(root, ".env", ".env.*", respect_gitignore=False)` (still `is_nonproduct_path`
   gated) for the env path — MinIO/Nacos/Grafana credentials routinely live in an `.env` consumed
   via compose's `env_file:`. Postgres detection is compose-file-only (see below).
3. **Parse / pattern** — a single shared `_var_pattern(name)` helper: `\bNAME\b\s*[:=]\s*<value>`,
   where `<value>` is a double-quoted, single-quoted, or bare token. This one pattern matches
   compose YAML map syntax (`KEY: value`), compose YAML list syntax (`- KEY=value`), and flat
   `.env` lines (`KEY=value`) uniformly — no YAML parsing needed, because every var this guard
   cares about is looked up by an exact, well-known name. `#`-comments are stripped
   (`strip_hash_comments`, quote-aware) before matching. Detection is **file-scoped, not
   per-service-block** — see "Detection: file-scoped pairing" in the guard's module docstring for
   the full rationale and its tested tradeoff.
   - **MinIO** (`minio-default-credential`, HIGH): `MINIO_ROOT_USER`/`MINIO_ACCESS_KEY` found AND
     equal (case-insensitive) to `minioadmin`, PAIRED with `MINIO_ROOT_PASSWORD`/`MINIO_SECRET_KEY`
     also `minioadmin`.
   - **Nacos** (`nacos-default-jwt-secret`, HIGH): `NACOS_AUTH_TOKEN` (or the pre-/post-2.1.0
     property spellings `nacos.core.auth.default.token.secret.key` /
     `nacos.core.auth.plugin.nacos.token.secret.key`) equal to the exact literal
     `SecretKey012345678901234567890123456789012345678901234567890123456789` — Nacos's own
     documented example value prior to 2.2.0.1. No username/password pair is detected for Nacos:
     researched and confirmed the `nacos`/`nacos` admin login is seeded into the backing
     database (embedded Derby or an external MySQL schema's init SQL), not set via a
     compose/env-file literal — there is no static config surface to match, so that half of the
     plan's B3 spec is a documented, deliberate non-implementation (see "Known bypasses").
   - **Postgres** (`postgres-default-credential-exposed`, CRITICAL): gated behind
     `_has_exposed_postgres_port()` — a trimmed, short-syntax-only adaptation of
     `compose-db-port-exposed`'s own `ports:` parser (5432/5433/6543 published to a non-loopback
     host). Only when that gate is true: `POSTGRES_USER=postgres` PAIRED with
     `POSTGRES_PASSWORD=postgres`, OR the same pair as a literal
     `postgres://postgres:postgres@`/`postgresql://postgres:postgres@` DSN anywhere in the file
     (covers a `DATABASE_URL`-style connection string even when discrete USER/PASSWORD vars are
     absent).
   - **Grafana explicit** (`grafana-default-credential`, HIGH): `GF_SECURITY_ADMIN_USER=admin`
     PAIRED with `GF_SECURITY_ADMIN_PASSWORD=admin`.
   - **Grafana implicit** (`grafana-implicit-default-credential`, MEDIUM, compose only): a service
     block whose `image:` matches `grafana/grafana[-oss|-enterprise]` with **neither**
     `GF_SECURITY_ADMIN_USER` **nor** `GF_SECURITY_ADMIN_PASSWORD` present anywhere in the file. A
     **partial** config (one var set, one not) is deliberately left silent — see "When NOT to
     flag."
4. **Pragma** — file-level `# security: allow-default-service-credential`, checked against the
   comment-only view of the text (#424), same convention as `compose-db-port-exposed` / `datastore-auth-absent`.
5. **Severity / rule / standards** — see the table above; `default-service-credential` is the
   shared `check_id` for all five rule ids. `["OWASP:A07", "CWE-1392"]` for the three
   login-credential rules (`minio-default-credential`, `grafana-default-credential`,
   `grafana-implicit-default-credential`, `postgres-default-credential-exposed`);
   `["OWASP:A02", "CWE-321"]` for `nacos-default-jwt-secret` (a signing-key axis, not a login).

## When NOT to flag

- **A value that isn't the exact known-default literal.** `_matches()` is an exact,
  case-insensitive string comparison — never a substring, prefix, or entropy heuristic. A random
  or merely-similar-looking value never fires (`test_minio_real_password_stays_silent`,
  `test_nacos_custom_secret_stays_silent`, `test_grafana_custom_credential_stays_silent`,
  `test_postgres_real_password_exposed_stays_silent`).
- **An env-var indirection** (`MINIO_ROOT_PASSWORD=${MINIO_PASS}`). The bare-token capture takes
  the literal text `${MINIO_PASS}`, which can never equal the known default — a reference to an
  external secret is correctly not itself a finding
  (`test_minio_env_var_reference_stays_silent`, `test_nacos_secret_via_env_reference_stays_silent`).
- **Only one half of a pair present.** MinIO/Grafana/Postgres all require BOTH the user-shaped and
  password-shaped var to be found AND match, else silent — a custom username with the stock
  password (or vice versa) is not this guard's signal (arguably still worth flagging by a
  different, narrower check; out of scope here to keep the false-positive rate near zero on the
  exact multi-var pairing this guard targets).
- **A local-only Postgres default** (no `ports:` publish in the same file). Scoped out rather than
  demoted — see the module docstring's "Why Postgres is scoped to exposure."
- **A `*.dev.yml`/`*.local.yml` compose file** (`is_dev_compose_file`) or a test/fixture/example
  path (`is_nonproduct_path`) — a deliberately-fake default in a fixture is not a live
  misconfiguration.
- **The file-level pragma** `# security: allow-default-service-credential`, for an audited
  air-gapped/demo deployment.

## Tests

| Test | What it checks |
|---|---|
| `test_minio_default_pair_fires_in_compose` | canonical MinIO pair fires HIGH in a compose file |
| `test_minio_default_pair_fires_in_env_file` | same pair fires when it lives in a `.env` |
| `test_minio_deprecated_alias_vars_fire` | the deprecated `MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY` spelling is also matched |
| `test_minio_real_password_stays_silent` | FP-bait: a real password never fires |
| `test_minio_env_var_reference_stays_silent` | FP-bait: `${MINIO_PASS}` indirection never fires |
| `test_nacos_default_jwt_secret_fires` | the exact known-default JWT secret literal fires HIGH |
| `test_nacos_property_style_key_fires` | the legacy `nacos.core.auth.plugin...` property spelling also matches |
| `test_nacos_custom_secret_stays_silent` | FP-bait: a rotated secret never fires |
| `test_nacos_secret_via_env_reference_stays_silent` | FP-bait: `${NACOS_TOKEN}` indirection never fires |
| `test_nacos_jvm_dash_d_system_property_form_fires` | KNOWN GAP fix: `-Dnacos.core.auth...=...` abutting the `-D` flag now fires |
| `test_nacos_dash_lowercase_d_system_property_form_stays_silent` | FP-bait: a coincidental lowercase `-d` immediately before the name does not relax the boundary |
| `test_postgres_default_credential_exposed_fires_critical` | exposed port + default pair fires CRITICAL |
| `test_postgres_default_credential_via_dsn_exposed_fires` | the DSN form (`postgres://postgres:postgres@`) also fires when exposed |
| `test_postgres_default_credential_not_exposed_stays_silent` | the exposure-scoping decision: no `ports:` publish, no finding |
| `test_postgres_loopback_bound_default_stays_silent` | FP-bait: a `127.0.0.1:5432:5432` loopback bind (the correct pattern) never fires |
| `test_postgres_real_password_exposed_stays_silent` | FP-bait: exposed + a real password never fires |
| `test_grafana_default_credential_explicit_fires` | explicit `admin`/`admin` pair fires HIGH |
| `test_grafana_absent_admin_vars_fires_medium` | neither admin var set on a Grafana image fires MEDIUM (the implicit-default case) |
| `test_grafana_custom_credential_stays_silent` | FP-bait: a real admin credential never fires |
| `test_grafana_partial_config_stays_silent` | FP-bait: only one of the two admin vars set stays silent (ambiguous, not guessed at) |
| `test_non_grafana_service_with_no_admin_vars_stays_silent` | FP-bait: absent admin vars mean nothing without a Grafana image present |
| `test_pragma_silences_compose` | file-level pragma silences a compose finding |
| `test_pragma_silences_env_file` | file-level pragma silences an `.env` finding |
| `test_dev_compose_file_stays_silent` | `is_dev_compose_file` honored |
| `test_nonproduct_path_stays_silent` | `is_nonproduct_path` honored (hard constraint #4) |
| `test_not_applies_without_docker_feature` | `applies()` gate |
| `test_fires_when_pair_split_across_two_compose_services` | adversarial: file-scoped (not block-scoped) pairing still fires when the pair is split across two DIFFERENT service blocks in the SAME file — documented, accepted tradeoff |
| `test_pair_split_across_two_files_stays_silent` | adversarial, opposite direction: no cross-FILE pairing — a pair split across two separate files never fires |

## Known bypasses

- **A value supplied via an external mechanism** this guard doesn't read: a Kubernetes
  `Secret`/`ConfigMap`, a secrets-manager injection at container start, an `env_file:` pointing at
  a file outside the scanned set, or a `.properties`/`.conf` file mounted as a volume. The Grafana
  implicit-default check exists specifically because the MOST common real case of this
  (`env_file:` never actually setting the admin vars) is indistinguishable from "genuinely unset,"
  so it is disclosed as a MEDIUM finding rather than silently missed; the other four checks stay
  silent on this class entirely (a documented false negative).
- **Nacos `nacos`/`nacos` username/password** — NOT detected at all, by design: researched and
  confirmed there is no compose/env-file literal to match (it's a database-seeded default), so
  implementing a match here would require reading/parsing an init-SQL file, which is out of scope.
  Only the JWT signing-key axis of the Nacos default-credential surface is covered.
- **Fixed (#685 fix-commit round batch B):** a `-D` JVM system property with no
  delimiter (`-Dnacos.core.auth.plugin.nacos.token.secret.key=...`) was a documented known gap —
  the bare `\b` word-boundary anchor required a non-word character immediately before the property
  name, and `-D` immediately abutting it (both word characters, "D" then "n") never satisfied that
  boundary. `_var_pattern`'s left boundary now also accepts a literal, case-sensitive `-D`
  immediately before the name (`(?:\b|(?<=(?-i:-D)))`), scoped narrowly via a lookbehind: a
  lowercase `-d` coincidentally abutting the name does NOT relax the boundary, only the exact
  capital `-D` JVM-flag spelling does. A property spelling preceded by any other delimiter (space,
  line start, quote) was already matched before this fix and still is.
- **File-scoped, not per-service-block, pairing** (see "Detection: file-scoped pairing" in the
  module docstring) — a pair coincidentally split across two unrelated services in the SAME file
  is treated as a match (a narrow, accepted false-positive surface); a pair split across two
  DIFFERENT files is never matched (a false negative, since no cross-file state is kept).
- **Postgres compose long-syntax `ports:`** (`- target: 5432` / `host_ip:` keys) — the exposure
  gate only recognizes the short-syntax list form, the same documented conservative seed
  `compose-db-port-exposed` itself ships with.
- **Terraform/Kubernetes/other IaC** — this guard only scans docker-compose YAML and `.env` files.
  The same default-credential pattern expressed as a Kubernetes `Deployment` env var, a Terraform
  `aws_db_instance` attribute, or a Helm `values.yaml` is not detected — a deliberate scope
  narrowing to keep the first pass tractable, documented as a natural follow-up extension rather
  than attempted here.
- **A credential-shaped var name this guard doesn't enumerate** (a Redis/Mongo/RabbitMQ/other
  service's own well-known default) is simply outside this guard's four-service list; MongoDB/Redis
  no-auth is already covered by the sibling `datastore-auth-absent` guard (a different axis: no
  password at all, not a specific default value).

## What this guard does NOT prove

Silence means only that *the four known-literal patterns this guard enumerates were not found, in
the files it scans, in the shapes it parses*. It does NOT prove any of these services are actually
hardened: a credential could be a DIFFERENT weak value (`"password123"`) that isn't the specific
factory default; TLS could be off; network ACLs could still allow lateral movement even with a
strong credential; or the credential could be correct in the scanned file but overridden to the
weak default by a runtime injection this guard never sees. It is a single, high-value tripwire
against the exact "the operator never changed day-one defaults" mistake JadePuffer's
lateral-movement stage exploited — not a service-hardening audit for any of the four products it
names.

# Citations

[1] agentsec checklist item `12-default-service-credential` (§12)
[2] CWE-1392
[3] OWASP:A07
