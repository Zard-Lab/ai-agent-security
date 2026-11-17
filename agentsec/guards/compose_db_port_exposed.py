"""Guard: sensitive port (datastore or admin/broker) published to the host in
docker-compose (§6c, §12).

The "Docker bypasses UFW" trap. Docker publishes container ports by writing its
own iptables rules into the DOCKER chain, which sits ahead of (and is not
governed by) UFW's INPUT chain. So a host with `ufw default deny incoming`
STILL exposes any port a container `ports:`-publishes to a non-loopback
interface. The highest-impact case is a datastore: a `5432:5432` entry on a
Postgres service makes the database reachable from the whole internet even
though the operator believes the host firewall closed it.

Fires CRITICAL on a docker-compose `ports:` entry whose CONTAINER port is a known
datastore port (Postgres / MySQL / Redis / Mongo / Elasticsearch / Memcached /
Supabase pooler) and whose host binding is NOT loopback (127.0.0.1 / ::1 /
localhost). A `127.0.0.1:5432:5432` loopback bind is silent (reachable only
on-host — the correct pattern). The container (right-most) port identifies the
service, so a remap like `15432:5432` still fires. Suppress an intentional
exposure with `# security: allow-exposed-db-port`.

**Admin/broker port extension (DockSec candidate #4, `_check_port_bound_all_interfaces`'s
`SENSITIVE_PORTS` list — source-verified, see the project's private `docksec.md` research
digest):** the same non-loopback-exposure check also covers a curated set of admin
consoles and message-broker ports — RabbitMQ's management UI (15672), Kafka's broker
port (9092), etcd's client/peer ports (2379/2380), Consul's HTTP API/UI (8500), and
Kibana's dashboard (5601). These carry the identical "reachable from the whole internet
despite `ufw default deny incoming`" mechanics as a database port, but the impact is
unauthenticated admin/management access or direct broker access rather than a datastore
connection — verified against this guard's existing list before adding: none of the
prior 8 datastore ports overlap with these 6. Fires HIGH for this admin/broker tier
(one rank below the CRITICAL datastore tier, since exploiting an exposed admin console
into full compromise commonly needs one more step than a raw database connection does).

Conservative seed (mirrors `ai_docker`'s port parser): it tracks the compose
short-syntax `ports:` list only. The long-syntax mapping (`- target:` /
`published:` / `host_ip:` keys) is a known false-negative, documented in the
design doc.

**Checklist items:** §6c `6c-pg-port-not-bound`, §12 `12-pg-port-not-exposed`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    is_dev_compose_file,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_PRAGMA = "# security: allow-exposed-db-port"

# Publishing a datastore to the internet is a deploy misconfiguration (A05); the
# Docker-bypasses-host-firewall mechanics are a container-network hardening concern (CIS Docker).
_STANDARDS = ["OWASP:A05", "CIS:Docker"]

# Datastore CONTAINER ports -> human name for the message. The container (right-most)
# port identifies the service; the host port may be remapped (e.g. `15432:5432`).
_DB_PORTS: dict[str, str] = {
    "5432": "PostgreSQL",
    "5433": "PostgreSQL",
    "6543": "PostgreSQL (Supabase / PgBouncer pooler)",
    "3306": "MySQL / MariaDB",
    "6379": "Redis",
    "27017": "MongoDB",
    "9200": "Elasticsearch",
    "11211": "Memcached",
}

# Admin-console / message-broker CONTAINER ports (DockSec candidate #4 extension) -> human
# name. Same non-loopback-exposure mechanics as a datastore port, but the impact is
# unauthenticated admin/management access or direct broker access rather than a datastore
# connection, so this tier fires one rank lower (HIGH, not CRITICAL). Verified against
# `_DB_PORTS` above before adding: no overlap between the two port sets.
_ADMIN_BROKER_PORTS: dict[str, str] = {
    "15672": "RabbitMQ management UI",
    "9092": "Kafka broker",
    "2379": "etcd client API",
    "2380": "etcd peer API",
    "8500": "Consul HTTP API/UI",
    "5601": "Kibana dashboard",
}

_LOCALHOST_HOSTS = re.compile(r"^(?:127\.0\.0\.1|::1|localhost)$", re.IGNORECASE)

# A docker-compose `ports:` list entry value: optional host prefix, then host:container.
#   "5432:5432" | "0.0.0.0:5432:5432" | "127.0.0.1:5432:5432" | "15432:5432" | "5432"
_PORTS_ENTRY = re.compile(r"^['\"]?([0-9a-zA-Z.:_-]+)['\"]?$")

# Long-syntax `ports:` mapping keys — `target:`/`published:`/`host_ip:` on their own lines (block form)
# or inside a `{ ... }` (flow form). `target` is the container port; `host_ip` is the host interface
# (omitted => 0.0.0.0, i.e. exposed). `protocol`/`mode` are ignored (not a host-interface signal).
_LONG_KV = re.compile(r"^(target|published|host_ip)\s*:\s*(.+?)\s*$", re.IGNORECASE)
_FLOW_MAP = re.compile(r"^\{.*\}$")
_FLOW_KV = re.compile(r"(target|published|host_ip)\s*:\s*([^\s,}]+)", re.IGNORECASE)


class ComposeDbPortExposedGuard(Guard):
    id = "compose-db-port-exposed"
    title = "Datastore port published to the host in docker-compose"
    area = "Containers"

    # docker-compose.db.yml: Postgres 5432 published to the host (non-loopback) ->
    # fires compose-db-port-exposed/datastore-port-published (CRITICAL).
    # Must NOT contain: 127.0.0.1 (loopback bind silences), # security: allow-exposed-db-port.
    # Container port 5432 is a datastore port; no MCP indicator + no AI volume so ai-docker stays silent.
    #
    # docker-compose.admin-broker-port.yml: RabbitMQ management port 15672 published to the
    # host (non-loopback) -> fires compose-db-port-exposed/admin-broker-port-published (HIGH).
    # Must NOT contain: 127.0.0.1, # security: allow-exposed-db-port.
    canary_plant = CanaryPlant(
        files={
            "docker-compose.db.yml": (
                "version: '3'\n"
                "services:\n"
                "  db:\n"
                "    image: postgres:16\n"
                "    ports:\n"
                "      - '5432:5432'\n"
            ),
            "docker-compose.admin-broker-port.yml": (
                "version: '3'\n"
                "services:\n"
                "  mq:\n"
                "    image: rabbitmq:3-management\n"
                "    ports:\n"
                "      - '15672:15672'\n"
            ),
        },
        expects=frozenset({
            "compose-db-port-exposed/datastore-port-published",
            "compose-db-port-exposed/admin-broker-port-published",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            # A local-development compose file is out of scope, exactly as in the mirror guard
            # `datastore-auth-absent` — via the SAME shared helper, so the two cannot drift. They
            # previously disagreed: this guard reported "the Redis port is published" on a
            # `*.dev.yml` while the mirror suppressed "and it has no password" on the same file,
            # which reads as a more reassuring report than either answer alone (#484 review).
            if is_dev_compose_file(f.name):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            out.extend(self._scan(text, rel(root, f)))
        return out

    def _emit(self, container: str, host: str | None, location: str, line_no: int,
              out: list[Finding]) -> None:
        """Emit a finding if `container` is a datastore OR admin/broker port published on a
        non-loopback host interface. `host` is the host bind (short-syntax prefix or
        long-syntax `host_ip`); None means no explicit host (short `5432:5432` / an omitted
        `host_ip`) which docker publishes on 0.0.0.0. The datastore tier fires CRITICAL with
        rule `datastore-port-published`; the admin/broker tier (#4 extension) fires HIGH with
        rule `admin-broker-port-published` — checked second so a port that somehow appeared
        in both maps would resolve to the more severe datastore finding."""
        if host and _LOCALHOST_HOSTS.match(host):
            return  # loopback bind is safe (reachable only on-host)
        if container in _DB_PORTS:
            self._emit_one(
                container, _DB_PORTS[container], "critical", "datastore-port-published",
                "the datastore", location, line_no, out,
            )
            return
        if container in _ADMIN_BROKER_PORTS:
            self._emit_one(
                container, _ADMIN_BROKER_PORTS[container], "high", "admin-broker-port-published",
                "this admin/broker service", location, line_no, out,
            )

    def _emit_one(
        self, container: str, name: str, severity: Severity, rule_slug: str, referent: str,
        location: str, line_no: int, out: list[Finding],
    ) -> None:
        out.append(Finding(
            check_id=self.id,
            severity=severity,
            title=f"{name} port published to the host network in docker-compose",
            location=f"{location}:{line_no}",
            message=(
                f"This docker-compose `ports:` entry publishes the {name} container port "
                f"({container}) on a non-loopback interface. Docker writes its own iptables "
                "rules ahead of UFW's INPUT chain, so `ufw default deny incoming` does NOT "
                f"close a container-published port — {referent} is reachable from the whole "
                "internet despite the host firewall."
            ),
            remediation=(
                f"Bind it to loopback only: '127.0.0.1:{container}:{container}'. App "
                "containers reach it over the compose network by service name and do not "
                "need a host publish. If a host publish is genuinely required, add a "
                "DOCKER-USER iptables DROP for the external interface, or suppress with "
                "`# security: allow-exposed-db-port`."
            ),
            rule=f"compose-db-port-exposed/{rule_slug}",
            standards=list(_STANDARDS),
        ))

    def _flush(self, pending: dict[str, str] | None, location: str, out: list[Finding]) -> None:
        """Evaluate an accumulated long-syntax entry (`target`/`host_ip`) and emit if exposed."""
        if not pending or "target" not in pending:
            return
        self._emit(pending["target"], pending.get("host_ip"), location, int(pending["line_no"]), out)

    def _scan(self, text: str, location: str) -> list[Finding]:
        """Scan only inside a `ports:` block; fire when an entry publishes a datastore CONTAINER port
        on a non-loopback host interface. Handles both the short-syntax scalar (`- "5432:5432"`) and
        the long-syntax mapping (`- target: 5432` + `host_ip:` lines, or a `{...}` flow map)."""
        out: list[Finding] = []
        in_ports = False
        ports_indent = -1
        pending: dict[str, str] | None = None  # a long-syntax entry being accumulated
        pending_indent = -1
        field_indent = -1  # indent of the entry's direct fields (set on the first continuation line)
        for line_no, raw in enumerate(text.splitlines(), 1):
            if not raw.strip():
                continue
            indent = len(raw) - len(raw.lstrip())
            key = re.match(r"(\s*)ports\s*:", raw)
            if key:
                self._flush(pending, location, out)
                pending, field_indent = None, -1
                in_ports, ports_indent = True, len(key.group(1))
                continue
            if not in_ports:
                continue
            stripped = raw.strip()
            if not stripped.startswith("-"):
                # A non-list line at or above the `ports:` indent ends the block.
                if indent <= ports_indent:
                    self._flush(pending, location, out)
                    pending, field_indent = None, -1
                    in_ports = False
                    continue
                # A continuation line of a long-syntax mapping entry (target/published/host_ip).
                # Anchor to the entry's OWN field indent (the first continuation line): a key nested
                # deeper (e.g. `host_ip:` under a `labels:` map) is not one of this entry's fields.
                if pending is not None and indent > pending_indent:
                    if field_indent == -1:
                        field_indent = indent
                    if indent == field_indent:
                        # Strip an inline comment first, else `host_ip: 127.0.0.1  # note` captures the
                        # comment and fails the anchored loopback match (a spurious CRITICAL).
                        lm = _LONG_KV.match(strip_hash_comments(stripped).strip())
                        if lm:
                            pending[lm.group(1).lower()] = lm.group(2).strip("'\"")
                continue
            # A new list item begins — flush any long-syntax entry accumulated so far.
            self._flush(pending, location, out)
            pending, field_indent = None, -1
            # Drop any inline YAML comment before matching (no valid port char is `#`), else a
            # `- "5432:5432"  # dev only` entry fails the whole-value regex and is silently missed.
            entry = strip_hash_comments(stripped.lstrip("-").strip()).strip()
            # Short-syntax scalar: "host:container" | "container".
            m = _PORTS_ENTRY.match(entry)
            if m:
                parts = m.group(1).split(":")
                if len(parts) == 3:
                    self._emit(parts[2], parts[0], location, line_no, out)
                elif len(parts) in (1, 2):
                    self._emit(parts[-1], None, location, line_no, out)
                continue
            # Long-syntax flow map on one line: `- {target: 5432, host_ip: 0.0.0.0}`.
            if _FLOW_MAP.match(entry):
                flow = {k.lower(): v.strip("'\"") for k, v in _FLOW_KV.findall(entry)}
                flow["line_no"] = str(line_no)
                self._flush(flow, location, out)
                continue
            # Long-syntax block map: `- target: 5432` starts a multi-line entry.
            lm = _LONG_KV.match(entry)
            if lm:
                pending = {lm.group(1).lower(): lm.group(2).strip("'\""), "line_no": str(line_no)}
                pending_indent = indent
        self._flush(pending, location, out)  # a trailing long-syntax entry at EOF
        return out
