---
type: Guard
title: "compose-db-port-exposed"
description: "Datastore or admin/broker port published to the host in docker-compose."
timestamp: "2026-06-30T14:01:46Z"
guard_id: "compose-db-port-exposed"
checklist_section: ["12", "6c"]
standards: ["CIS:Docker", "OWASP:A05", "SOC2:CC6.6"]
---

# Datastore port published to the host in docker-compose

_Author — 2026-06-30_

---

## The threat

An operator stands up a VPS, enables `ufw default deny incoming`, and believes every port
except 22/80/443 is closed. But the app runs in Docker, and a `docker-compose.yml` publishes the
database: `ports: ["5432:5432"]`. Docker programs its own iptables rules in the DOCKER chain,
which is traversed BEFORE UFW's INPUT chain and is not subject to UFW's default-deny. The result:
PostgreSQL is reachable from the entire internet on `<host-ip>:5432`, despite the firewall. Any
attacker who can reach the host IP can attempt auth against the database directly — brute-force,
known-CVE exploitation, or connecting with leaked credentials — bypassing the application entirely.

This is the single most damaging form of the "Docker bypasses the host firewall" trap (documented
in the HWH `ai-agent-mastery` server-hardening toolkit, which mitigates it with explicit DOCKER-USER
DROP rules). Findings carry `OWASP:A05` (security misconfiguration) and `CIS:Docker`.

## Why it's often introduced  /  Why this guard fits the stack

Exposing `5432:5432` is the default copy-paste in nearly every "run Postgres in Docker" tutorial,
because it lets you connect with a local `psql`/GUI during development. The same compose file is
then shipped to production unchanged. In the 9_Agent_SaaS shape the correct pattern is what the
flagship does: app containers reach Postgres/Redis over the compose network by service name, and any
host publish is bound to loopback (`127.0.0.1:5432:5432`) for local probes only.

```yaml
services:
  db:
    image: postgres:16
    ports:
      - "5432:5432"      # <-- world-exposed despite `ufw default deny incoming`
```

## Detection design

1. **applies() gate** — `"docker" in profile.features` (set by `detect.py` when a Dockerfile or
   `docker-compose*` file is present).
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`,
   filtered by `_is_docker_compose()`.
3. **Parse** — a `ports:`-block state machine (mirrors `ai_docker._check_mcp_port_exposed`): track
   the `ports:` key indent; for each list-item entry, handle both forms:
   - **Short syntax** (scalar) — split `host:hostport:container` / `host:container` / bare `container`.
     The CONTAINER (right-most) port is the service identity, so a remap like `15432:5432` still fires.
   - **Long syntax** (mapping, #356) — accumulate a `- target:` entry across its `published:`/`host_ip:`
     continuation lines (or a one-line `{...}` flow map), flushed at the next list item / block end / EOF.
     `target` is the container port; an omitted `host_ip` defaults to `0.0.0.0` (exposed).
   Fire when the container port is in `_DB_PORTS` (5432/5433/6543/3306/6379/27017/9200/11211) OR
   `_ADMIN_BROKER_PORTS` (15672/9092/2379/2380/8500/5601 — the DockSec candidate #4 extension,
   below) AND the host bind is not loopback (`127.0.0.1`/`::1`/`localhost`).
4. **Pragma opt-out** — `# security: allow-exposed-db-port` anywhere in the file suppresses it
   (shared by both tiers).
5. **Severity / rule / standards** — two tiers, checked in this order (`_emit`):
   - **Datastore tier** — `critical` (matches the two CRITICAL checklist items it flips, §6c/§12),
     rule `compose-db-port-exposed/datastore-port-published`.
   - **Admin/broker tier** (extension) — `high` (one rank below the datastore tier: exploiting
     an exposed admin console into full compromise commonly needs one more step than a raw
     database connection does), rule `compose-db-port-exposed/admin-broker-port-published`.
   Both tiers carry standards `["OWASP:A05", "CIS:Docker"]`.

### Admin/broker port extension (#4, DockSec batch, 2026-09-05)

Sourced from OWASP DockSec's `compose_scanner.py::_check_port_bound_all_interfaces` /
`SENSITIVE_PORTS` (source-verified; see the project's private `docksec.md` research digest,
candidate #4). Extends this guard's existing datastore-only port list with a curated set of
admin consoles and message-broker ports — RabbitMQ management (15672), Kafka broker (9092),
etcd client/peer (2379/2380), Consul HTTP API/UI (8500), Kibana dashboard (5601). Verified against
`_DB_PORTS` before adding: zero overlap between the 8 existing datastore ports and these 6.
Reuses this guard's identical `ports:`-block parser, loopback check, dev-compose skip, and pragma
— only the port->name lookup and the resulting severity/rule differ (`_emit_one`, factored out of
`_emit` for this extension).

## When NOT to flag
- A local-development compose file (`base.is_dev_compose_file`: `*.dev.yml`, `*-dev.yml`,
  `*.local.yml`, any case) is out of scope, exactly as in the mirror guard `datastore-auth-absent`
  and via the SAME helper so the two cannot drift. They previously disagreed, and reporting the
  published port while suppressing the missing password reads as more reassuring than either
  answer alone (#484 review). The base/prod compose still fires.

- A loopback bind `127.0.0.1:5432:5432` is the correct, on-host-only pattern — silent.
- A non-datastore container port (a web app `8080:8080`, or `5432:80` where the container is a web
  server merely mapped onto host port 5432) — silent; the container port is the identity.
- An intentional exposure (a dev-only compose, or a publish that IS protected by a DOCKER-USER DROP
  the guard can't see) — suppress with the pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_compose_db_port_postgres_exposed_fires` | `5432:5432` fires; severity/check_id/standards correct |
| `test_compose_db_port_0000_fires` | explicit `0.0.0.0:5432:5432` fires |
| `test_compose_db_port_remap_fires` | `15432:5432` fires on the container port |
| `test_compose_db_port_redis_fires` | Redis `6379:6379` fires |
| `test_compose_db_port_bare_form_fires` | bare `'5432'` (all-interfaces) fires |
| `test_compose_db_port_localhost_silent` | `127.0.0.1:5432:5432` stays silent |
| `test_compose_db_port_non_db_silent` | web port `8080:8080` stays silent |
| `test_compose_db_nondb_container_silent` | `5432:80` (web container) stays silent |
| `test_compose_db_port_outside_ports_block_silent` | a `5432:5432` in `environment:` stays silent |
| `test_compose_db_port_pragma_silences` | the pragma suppresses the finding |
| `test_compose_db_port_applies_gate` | gated on the `docker` feature |
| `test_compose_db_no_compose_silent` | no compose file -> no findings |
| `test_rabbitmq_management_port_exposed_fires_high` | RabbitMQ 15672 fires HIGH (admin/broker tier, not CRITICAL) |
| `test_kafka_broker_port_exposed_fires` | Kafka 9092 fires |
| `test_etcd_client_and_peer_ports_fire` | etcd 2379 AND 2380 each fire independently |
| `test_consul_http_api_port_fires` | Consul 8500 fires |
| `test_kibana_dashboard_port_fires` | Kibana 5601 fires |
| `test_admin_broker_port_loopback_silent` | a loopback bind on an admin/broker port stays silent |
| `test_admin_broker_port_pragma_silences` | the shared pragma suppresses the admin/broker tier too |
| `test_admin_broker_ports_do_not_overlap_datastore_ports` | structural guardrail: the two port maps never collide |

## Known bypasses

- **Protocol suffix** (`5432:5432/tcp`) is not matched by the short-syntax entry regex.
- **Bracketed IPv6 host bind** (`[::]:5432:5432`, `[2001:db8::1]:5432:5432`) is not parsed — `split(":")`
  yields more than three parts, so the entry is skipped (covered by a `*_known_fn` test).
- **Variable indirection** (`${DB_PORT}:5432`, or a port set via `.env` interpolation) is not resolved.
- **A non-standard datastore port** not in `_DB_PORTS` is missed (the set is intentionally tight to
  keep false positives near zero).

## What this guard does NOT prove

Silence means no datastore host-publish (short- or long-syntax) was found in a committed compose file.
It does NOT prove the host firewall is correct, that DOCKER-USER drops exist, that the database isn't
exposed some other way (`network_mode: host`, a raw `docker run -p`, a cloud security group), or that
loopback-bound services are themselves authenticated. The live-host counterpart (`agentsec harden-host`,
Phase B) verifies the running listener set with `ss`.

# Citations

[1] agentsec checklist item `12-pg-port-not-exposed` (§12)
[2] agentsec checklist item `6c-pg-port-not-bound` (§6c)
[3] CIS:Docker
[4] OWASP:A05
[5] SOC2:CC6.6
[6] OWASP DockSec `compose_scanner.py::_check_port_bound_all_interfaces` / `SENSITIVE_PORTS`
    (source-verified; see the project's private `docksec.md` research digest, candidate #4 —
    the admin/broker port extension)
