"""Guard: a docker-compose service bypasses the DNS-egress-allowlist resolver (§4/§6d/§12).

The **wiring** complement to `dns-egress-allowlist`. A default-deny resolver only constrains
egress for the containers that actually resolve THROUGH it. In the HWH `ai-agent-mastery` model
every app container pins `dns: [<resolver-ip>]` in `docker-compose.yml` so all name resolution
goes through the allowlist resolver (Unbound at a fixed compose-network IP). A service that omits
`dns:` (or points it elsewhere) silently falls back to Docker's embedded resolver and can resolve
any domain — a compromised dependency or a prompt-injected agent in THAT container has an open DNS
exfiltration path, defeating the allowlist for it.

Fires MEDIUM, once per bypassing service, when a compose file shows the shared-resolver pattern in
use — a **private** `ipv4_address` that **two or more** services route `dns:` through (an in-compose
egress-allowlist resolver its peers share) — and another (non-resolver) service does not route DNS
through it. Requiring two routers keeps a single incidental `dns:` pointer (e.g. one service using an
internal service-discovery sidecar) from designating a "resolver" and flooding the file with false
positives. Silent when every service routes through it (the correct HWH shape), when no shared-resolver
pattern is present (nothing to bypass), or under `# security: allow-dns-bypass`.

This verifies compose DNS **wiring** only; the sibling `dns-egress-allowlist` verifies the resolver
is actually default-deny. Together they cover the egress-allowlist control end to end.

**Checklist item:** §6d `6d-egress-dns-wiring` (partial — DNS wiring is one leg of egress control).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files_named, pragma_present, read, rel, strip_hash_comments

_PRAGMA = "# security: allow-dns-bypass"
_STANDARDS = ["OWASP:A05", "OWASP-LLM:LLM02"]

# A dotted-quad IPv4 literal (loose — range-validated by `_is_private` where it matters).
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# A YAML mapping key that opens a nested block: `<name>:` with nothing (or only a comment) after it.
_BLOCK_KEY = re.compile(r"([A-Za-z0-9._-]+)\s*:\s*$")
_SERVICES_KEY = re.compile(r"services\s*:\s*$")
_DNS_KEY = re.compile(r"dns\s*:\s*(.*)$")
_IMAGE_KEY = re.compile(r"image\s*:\s*(.*)$")
_IPV4_ADDRESS = re.compile(r"ipv4_address\s*:\s*['\"]?(\d{1,3}(?:\.\d{1,3}){3})")


@dataclass
class _Service:
    """One service block's DNS-relevant facts (name + line for the finding, the rest for wiring)."""

    name: str
    line_no: int
    has_dns: bool = False
    dns_ips: set[str] = field(default_factory=set)   # IPv4s listed in this service's `dns:`
    ipv4: set[str] = field(default_factory=set)       # this service's `ipv4_address` pins
    image: str = ""


def _is_private(ip: str) -> bool:
    """RFC1918 private IPv4 (10/8, 172.16/12, 192.168/16). The internal resolver lives on the
    compose network, so only a private shared IP counts as an in-compose egress resolver — two
    services both pointing `dns:` at a PUBLIC IP (e.g. 8.8.8.8) is not an allowlist to bypass."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def _parse_services(text: str) -> list[_Service]:
    """Indentation-aware scan of a compose `services:` map (no PyYAML — the house pattern, mirrors
    `compose_db_port_exposed._scan`). Per service, collect `dns:` presence + IPs, `ipv4_address`
    pins, and the image. Inline `#` comments are stripped first (`strip_hash_comments`) so an IP in
    a comment can't leak into the wiring set."""
    services: list[_Service] = []
    cur: _Service | None = None
    in_services = False
    services_indent = -1
    svc_indent = -1        # indent of the service-name keys (set by the first child of `services:`)
    field_indent = -1      # indent of the current service's direct fields (set by its first field)
    dns_key_indent = -1    # indent of the current service's `dns:` key (for its block-list items)
    collecting_dns = False
    for line_no, raw in enumerate(strip_hash_comments(text).splitlines(), 1):
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()

        if not in_services:
            if _SERVICES_KEY.match(stripped):
                in_services, services_indent, svc_indent = True, indent, -1
            continue

        if indent <= services_indent:  # dedented out of the services: map
            in_services, collecting_dns, cur = False, False, None
            continue

        if svc_indent == -1:
            svc_indent = indent

        if indent == svc_indent:  # a new service key (or a stray non-mapping line at that level)
            collecting_dns = False
            m = _BLOCK_KEY.match(stripped)
            if m:
                cur = _Service(name=m.group(1), line_no=line_no)
                services.append(cur)
                field_indent = -1
            else:
                cur = None
            continue

        if cur is None:  # inside services: but no current service (e.g. a scalar list) — ignore
            continue

        if field_indent == -1:
            field_indent = indent

        if collecting_dns:
            if stripped.startswith("-") and indent > dns_key_indent:
                cur.dns_ips.update(_IPV4.findall(stripped))
                continue
            collecting_dns = False  # block list ended — fall through to parse this line normally

        if indent == field_indent:
            mdns = _DNS_KEY.match(stripped)
            if mdns:
                cur.has_dns = True
                rest = mdns.group(1).strip()
                if rest:  # inline flow list `dns: [ip, ...]` or scalar `dns: ip`
                    cur.dns_ips.update(_IPV4.findall(rest))
                else:  # bare `dns:` opens a block list of `- ip` items below
                    collecting_dns, dns_key_indent = True, indent
                continue
            mimg = _IMAGE_KEY.match(stripped)
            if mimg:
                cur.image = mimg.group(1).strip().strip("'\"")
                continue

        mip = _IPV4_ADDRESS.search(stripped)  # `ipv4_address:` sits deeper, under networks:
        if mip:
            cur.ipv4.add(mip.group(1))

    return services


class ComposeDnsBypassGuard(Guard):
    id = "compose-dns-bypass"
    title = "docker-compose service bypasses the DNS-egress-allowlist resolver"
    area = "Containers"

    # docker-compose.egress.yml: an in-compose Unbound resolver at 172.20.0.53 that agent-api +
    # rag-pipeline route DNS through, while `worker` sets no dns: -> fires
    # compose-dns-bypass/service-skips-resolver (MEDIUM) for `worker` only. No ports: (so
    # compose-db-port-exposed stays silent) and no volumes/MCP (so ai-docker stays silent).
    # Must NOT contain: a dns: on worker, or # security: allow-dns-bypass (both silence the guard).
    canary_plant = CanaryPlant(
        files={
            "docker-compose.egress.yml": (
                "version: '3'\n"
                "services:\n"
                "  unbound:\n"
                "    image: mvance/unbound:1.22.0\n"
                "    networks:\n"
                "      appnet:\n"
                "        ipv4_address: 172.20.0.53\n"
                "  agent-api:\n"
                "    image: agent-api:latest\n"
                "    dns:\n"
                "      - 172.20.0.53\n"
                "    networks:\n"
                "      appnet:\n"
                "        ipv4_address: 172.20.0.10\n"
                "  rag-pipeline:\n"
                "    image: rag-pipeline:latest\n"
                "    dns:\n"
                "      - 172.20.0.53\n"
                "    networks:\n"
                "      appnet:\n"
                "        ipv4_address: 172.20.0.11\n"
                "  worker:\n"
                "    image: worker:latest\n"
                "    networks:\n"
                "      appnet:\n"
                "        ipv4_address: 172.20.0.12\n"
                "networks:\n"
                "  appnet:\n"
                "    ipam:\n"
                "      config:\n"
                "        - subnet: 172.20.0.0/16\n"
            ),
        },
        expects=frozenset({"compose-dns-bypass/service-skips-resolver"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            out.extend(self._scan(text, rel(root, f)))
        return out

    def _scan(self, text: str, location: str) -> list[Finding]:
        services = _parse_services(text)
        # Candidate resolvers: private IPs pinned as some service's `ipv4_address`.
        candidates = {ip for s in services for ip in s.ipv4 if _is_private(ip)}
        # Count DISTINCT services routing `dns:` at each candidate. A shared egress-allowlist resolver
        # is one that MULTIPLE services deliberately route through — requiring >=2 routers keeps a
        # single incidental pointer (e.g. one service using an internal service-discovery sidecar)
        # from designating a "resolver" and flooding the rest of the file with false positives.
        route_counts: dict[str, int] = {}
        for s in services:
            # Exclude a service's OWN pinned IP from its vote: a resolver that self-lists its `dns:`
            # (common when a shared dns: fragment is applied to every service) must not supply one of
            # its own quorum votes, else a single genuine router re-establishes the "resolver".
            for ip in (s.dns_ips & candidates) - s.ipv4:
                route_counts[ip] = route_counts.get(ip, 0) + 1
        resolver_ips = {ip for ip, n in route_counts.items() if n >= 2}
        if not resolver_ips:
            return []  # no in-compose shared-resolver pattern — nothing to bypass

        resolver_list = ", ".join(sorted(resolver_ips))
        add_ip = sorted(resolver_ips)[0]  # a concrete resolver IP for the remediation
        out: list[Finding] = []
        for s in services:
            if s.ipv4 & resolver_ips:      # this service IS a resolver — skip
                continue
            if s.dns_ips & resolver_ips:   # routes DNS through the allowlist resolver — correct
                continue
            if s.has_dns:  # has a `dns:` key, but pointing away from the allowlist resolver
                message = (
                    f"Other services route DNS through the internal allowlist resolver "
                    f"({resolver_list}), but '{s.name}' sets `dns:` to a different address, so its "
                    "lookups skip the allowlist and it can resolve any domain that resolver answers. "
                    "A compromised dependency or a prompt-injected agent in this container has an "
                    "open DNS exfiltration path, bypassing the egress allowlist."
                )
                remediation = (
                    f"Change the '{s.name}' service's `dns:` to the allowlist resolver ([{add_ip}]), "
                    "matching the other services. If this service legitimately uses a different "
                    "resolver by design, suppress with `# security: allow-dns-bypass`."
                )
            else:  # no `dns:` key at all — falls back to Docker's embedded resolver
                message = (
                    f"Other services route DNS through the internal allowlist resolver "
                    f"({resolver_list}), but '{s.name}' sets no `dns:`, so it falls back to Docker's "
                    "embedded resolver and can resolve any domain. A compromised dependency or a "
                    "prompt-injected agent in this container has an open DNS exfiltration path, "
                    "bypassing the egress allowlist."
                )
                remediation = (
                    f"Add `dns: [{add_ip}]` to the '{s.name}' service so its name resolution goes "
                    "through the allowlist resolver, matching the other services. If this service "
                    "legitimately needs no external egress, suppress with `# security: allow-dns-bypass`."
                )
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=f"Service '{s.name}' bypasses the DNS-egress-allowlist resolver",
                location=f"{location}:{s.line_no}",
                message=message,
                remediation=remediation,
                rule="compose-dns-bypass/service-skips-resolver",
                standards=list(_STANDARDS),
            ))
        return out
