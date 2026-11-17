---
type: Guard
title: "datastore-auth-absent"
description: "Datastore (Redis/MongoDB) running without authentication."
timestamp: "2026-07-07T04:37:50Z"
guard_id: "datastore-auth-absent"
checklist_section: ["7"]
standards: ["CIS:Docker", "OWASP:A05"]
---

# Datastore (Redis/MongoDB) running without authentication

_Author — 2026-07-07_

---

## The threat

A Redis or MongoDB container run **without a password** is a one-request data-loss target. If the
port ever becomes reachable from an untrusted network — and Docker makes that alarmingly easy, since a
published port's DNAT rule bypasses the host's UFW `INPUT` chain — an unauthenticated bot can connect,
read every key/collection, and `FLUSHALL` / drop the database in seconds. This is not theoretical: it
is the standard mass-scan ransom pattern (the `READ_ME_TO_RECOVER_YOUR_DATA` wipe). WHO: any host that
can route a packet to the port. WITH WHAT privilege: none — the datastore accepts unauthenticated
commands. TO WHAT effect: full read + destruction. The findings carry `OWASP:A05` (Security
Misconfiguration) and `CIS:Docker`.

This guard is the **defense-in-depth partner** to `compose-db-port-exposed`: that guard catches the
*exposure* (a datastore port published off-loopback); this one catches the *missing auth*, so a leak
by any other path (docker-compose long-syntax `ports:` #356, a `userland-proxy: false` host #357, a
cloud-firewall slip) is survivable rather than instant.

## Why it's often introduced  /  ## Why this guard fits the stack

The default `redis`/`mongo` images start with **no auth at all** — a developer who writes the obvious
compose service gets a passwordless datastore and never sees a warning:

```yaml
services:
  redis:
    image: redis:7        # no requirepass -> anyone who reaches :6379 is root
```

A 9_Agent_SaaS-shaped app routinely adds Redis (rate-limit / session / agent-memory store) or Mongo
(document store) alongside the Postgres/Supabase core, in the same `docker-compose.yml`. The
"authenticate the datastore" step is easy to skip because on the compose network it "just works."

## Detection design

1. **applies()** — `"docker" in profile.features` (there is no `redis`/`mongo` feature in `detect.py`;
   `docker` is the same gate `compose-db-port-exposed` uses).
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`.
3. **Parse** — `_iter_services()` is a stdlib line parser (PyYAML is dev-only). It finds the top-level
   `services:` key, takes the first service header's indent as the service-indent, and groups each
   `name:` header with the lines beneath it until the next same-indent header or a dedent out of
   `services:`. Per service block: `_engine()` classifies it via the `image:` value
   (`(?:^|/)(redis|valkey)(?::|/|@|$)` and `(?:^|/)(mongo(db)?|mongodb-community-server|mongod)(?::|/|@|$)`
   — matches `redis:7`, `bitnami/redis`, `valkey/valkey`, `redis@sha256:...`, `mongo:6`, `bitnami/mongodb`,
   a name-only `someorg/mongodb-community-server` (#359 Gap 2), and deliberately NOT the `mongo-express` /
   `redis-commander` / `mongodb-exporter` sidecars — the char after the name is `-`, not `:`/`/`/`@`/end),
   falling back to the service name only when there is no `image:`. It then checks the block
   for an auth signal and fires when none is present:
   - Redis authed: `--requirepass` / `requirepass <value>` / `REDIS_ARGS…requirepass` /
     `--aclfile` / `REDIS_ACLFILE`. `REDIS_PASSWORD` counts ONLY on a Bitnami image (the official
     `redis`/`valkey` images never read it; `REDISCLI_AUTH` is a client-side var and is not a signal).
   - Mongo authed: `MONGO_INITDB_ROOT_USERNAME`/`_PASSWORD` (official) / `--auth` / `--keyFile` /
     `security.authorization`; `MONGODB_ROOT_PASSWORD` only on a Bitnami image.
   - Env-var signals require a NON-EMPTY value (so `MONGO_INITDB_ROOT_PASSWORD:` with no value fires),
     and `#`-comments are stripped before matching (so a commented-out token is not a signal).
   - Bitnami `ALLOW_EMPTY_PASSWORD=yes` is an explicit auth-OFF switch and forces a fire regardless of
     any password env.
4. **Pragma** — file-level `# security: allow-unauthenticated-datastore`.
5. **Severity / rule / standards** — `high`, `datastore-auth-absent/no-authentication`,
   `["OWASP:A05", "CIS:Docker"]`. One rule id for both engines (the title/message differ by engine).

## When NOT to flag

- A local-development compose file is an environment where an unauthenticated loopback datastore is
  conventional — skipped (guard-local; round-2 §H.2). The prod/base compose still fires. Recognized by
  the shared `base.is_dev_compose_file`, which covers `*.dev.yml`, `*.local.yml`, the hyphen spellings
  (`docker-compose-dev.yml`) and any case. The mirror guard `compose-db-port-exposed` uses the SAME
  helper: the two previously disagreed, so a `*.dev.yml` was reported as publishing the Redis port
  while this guard suppressed that it had no password — a more reassuring report than either answer
  alone (#484 review).

An intentionally-internal cache — Redis on an internal-only compose network, never published, treated
as ephemeral — may legitimately run without a password. That is the main false-positive source, and
the reason this fires **HIGH, not CRITICAL**, and offers the pragma. The design position (stated in the
finding remediation) is that a password is still recommended even internally, because the "internal"
boundary is exactly what the Docker-bypasses-UFW footgun erodes. Postgres/MySQL are intentionally out
of scope: their official images refuse to start without a password, so "no auth" is not reachable the
same way.

## Tests

| Test | What it checks |
|---|---|
| `test_redis_no_auth_fires` | passwordless Redis fires HIGH with the right check_id/standards |
| `test_mongo_no_auth_fires` | passwordless Mongo fires (MongoDB title) |
| `test_bitnami_allow_empty_password_fires_even_with_password_env` | `ALLOW_EMPTY_PASSWORD=yes` forces a fire |
| `test_valkey_no_auth_fires` | valkey (redis fork) is classified as redis |
| `test_service_name_fallback_when_no_image_fires` | a `build:` service named `redis` is classified by name |
| `test_two_services_only_the_unauthed_one_fires` | service-block isolation: authed sibling is silent, location points at the unauthed header |
| `test_redis_requirepass_command_silent` | `--requirepass` in `command:` silences |
| `test_redis_password_env_silent` | `REDIS_PASSWORD` env silences |
| `test_mongo_root_creds_silent` | `MONGO_INITDB_ROOT_*` env silences |
| `test_mongo_auth_flag_silent` | `mongod --auth` silences |
| `test_postgres_out_of_scope_silent` | Postgres is not flagged |
| `test_mongo_express_ui_not_flagged` | the `mongo-express` UI is not mis-classified as the DB |
| `test_redis_commander_ui_not_flagged` | the `redis-commander` UI is not mis-classified as the DB |
| `test_pragma_silences` | the file-level pragma silences |
| `test_not_applies_without_docker_feature` | applies() gate |
| `test_redis_password_env_ignored_on_official_image_fires` | `REDIS_PASSWORD` on an official image is not auth (#358) |
| `test_rediscli_auth_is_not_a_server_auth_signal_fires` | `REDISCLI_AUTH` (client-side) is not a signal (#358) |
| `test_commented_out_auth_token_still_fires` | a commented-out token is not a signal (#358) |
| `test_empty_password_value_still_fires` | an empty-valued password still fires (#358) |
| `test_digest_pinned_image_classified_fires` | a digest-pinned datastore is classified (#358) |
| `test_quoted_empty_password_still_fires` | a quoted-empty password (`""`) is still no password (#358) |
| `test_hash_in_quoted_password_value_not_clipped` | a `#` inside a quoted password is not clipped to empty (#358) |
| `test_flow_mapping_redis_no_auth_fires` | a one-line flow-mapping `redis: {image: ...}` fires (#359 Gap 1) |
| `test_flow_mapping_classified_by_image_not_name_fires` | a flow service is classified by its inline `image:`, not the name (#359 Gap 1) |
| `test_flow_mapping_with_requirepass_silent` | an auth token inside the flow mapping silences (#359 Gap 1) |
| `test_flow_mapping_service_alongside_block_service` | a flow service and an adjacent block service both resolve (#359 Gap 1) |
| `test_mongodb_community_server_name_without_mongo_segment_fires` | `mongodb-community-server` (name, not `mongo` segment) is classified (#359 Gap 2) |
| `test_mongodb_exporter_not_flagged` | `mongodb-exporter` is not mis-classified as the datastore (#359 Gap 2 FP boundary) |
| `test_flow_mapping_mongodb_community_server_fires` | Gap 1 x Gap 2: a name-only mongo image in flow-mapping style is classified (#359) |

## Known bypasses

- A password supplied via an **externally-mounted `redis.conf`/`mongod.conf`** (`requirepass` lives in
  a file the guard never reads) — a false-negative (the guard would fire on an actually-authed
  datastore; the pragma is the escape hatch).
- Auth injected **at runtime** by a secrets manager or an entrypoint script rather than in compose.
- Auth hidden inside a **YAML anchor / `extends:`** the flat line parser does not resolve.
- A **multi-line flow-mapping service** (`redis: {` opened on the header line, `}` on a following
  line) — the flat parser cannot assemble a flow body spread across physical lines, so it is left
  **unscanned** (a false-NEGATIVE miss). The flow branch fires only when the header line's braces
  balance (`_flow_is_closed`); an unbalanced `redis: {` falls through to a dead zone instead of
  being emitted with an empty body. That empty-body emission was an **active false positive** on the
  canonical `redis`/`mongo` names (it fired "no auth" while a real token sat on a later line) until
  the #375 review; requiring a closing brace demotes it to the disclosed unscanned miss. One-line
  flow mappings (the common form) are covered; multi-line flow is near-nonexistent in real compose.
- A datastore defined **outside docker-compose** (a raw `docker run`, a Helm chart, a managed service)
  is not seen at all.

One-line flow-mapping services (`redis: {image: "redis:7"}`) and MongoDB images whose name lacks a
`mongo` path segment (`someorg/mongodb-community-server`) were both former false-negatives, closed
in #359 — the parser now discovers flow-mapping headers, and the image match includes the
`mongodb-community-server` / `mongod` names, not only a `mongo` path segment.

## What this guard does NOT prove

Silence means only that *a compose service the parser could classify carried an auth signal*. It does
NOT prove the password is strong (`12-db-password-strong` covers strength), that TLS is on, that the
credential is not a hard-coded default, that network ACLs are correct, or that a datastore configured
outside compose is authenticated. It is a single, high-value tripwire against the most common and most
destructive datastore misconfiguration, not a datastore-hardening audit.

# Citations

[1] agentsec checklist item `7-datastore-auth-enabled` (§7)
[2] CIS:Docker
[3] OWASP:A05
