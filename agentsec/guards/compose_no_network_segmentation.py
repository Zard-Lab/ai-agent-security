"""Guard: no compose service declares an explicit network — all sit on the implicit
default bridge (checklist §6c).

    services:
      web:
        image: myapp:1.0
      worker:
        image: myapp-worker:1.0
      db:
        image: postgres:16
    # no service anywhere declares its own `networks:` -> ALL THREE share one flat
    # default bridge network and can reach each other on every port.

Unlike the other DockSec-sourced guards in this batch, this is a CROSS-SERVICE,
WHOLE-FILE check, not a per-service one: a single service block can never answer
"is this compose file segmented", because segmentation is a property of the file's
service TOPOLOGY as a whole. `run()` therefore collects every service in one pass
before deciding on a single finding for the file, rather than emitting per-service.

When a compose file declares no `networks:` anywhere, every service is attached to one
implicit default bridge network and can reach every other service on any port —
Postgres, an internal admin API, a message broker, all flat. A compromised low-value
service (the public web frontend) can then pivot laterally straight to the database or
an internal-only service with no network boundary to cross. The fix is standard compose
segmentation: put the DB on an internal-only network, and only the services that
genuinely need it on a shared one.

Sourced from OWASP DockSec's `compose_scanner.py`'s `_check_port_bound_all_interfaces`
sibling top-level check, `compose-no-network-segmentation` (read in full; id reused
verbatim from the source), reproduced as a dependency-free check (see `docksec.md`
research digest, DockSec candidate #5). This is a SURFACING check: an unsegmented
compose file is an architecture worth confirming by hand (is this genuinely a
single-trust-boundary app, or does it need segmentation?), not a proven exploit in
itself — flagged via `surfacing = True`.

Fires MEDIUM once per compose file with 2+ services where NOT A SINGLE service declares
its own `networks:` key. A file merely declaring custom networks at the TOP LEVEL
(`networks:` alongside `services:`) without any service actually joining one via its own
per-service `networks:` key still fires — defining a network nobody attaches to changes
nothing about the default-bridge blast radius. A single-service compose file is skipped
(no lateral-movement peer to reach). If AT LEAST ONE service declares its own
`networks:`, the file is treated as segmented and stays silent — the given candidate's
own FP-bait case.

Suppress an audited case (e.g. a genuinely single-trust-boundary app where every service
is meant to reach every other one) with `# security: allow-no-network-segmentation`
anywhere in the compose file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_dev_compose_file,
    iter_compose_services,
    iter_files_named,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "# security: allow-no-network-segmentation"

_STANDARDS = ["OWASP:A05", "CIS:Docker"]

# A per-SERVICE `networks:` field — block-list form or a one-line `[...]`/`{...}` form.
_NETWORKS_KEY = re.compile(r"^\s*networks\s*:\s*(?:#.*)?$", re.IGNORECASE)
_NETWORKS_INLINE = re.compile(r"^\s*networks\s*:\s*(?:\[|\{)", re.IGNORECASE)


def _service_declares_networks(body: list[tuple[int, str]]) -> bool:
    """True if this service's own block sets a `networks:` field (block-list or inline
    `[...]`/`{...}` form). A commented-out `# networks:` does not count as present."""
    for _line_no, raw in body:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        uncommented = stripped.partition("#")[0].rstrip()
        if not uncommented:
            continue
        if _NETWORKS_KEY.match(uncommented) or _NETWORKS_INLINE.match(uncommented):
            return True
    return False


class ComposeNoNetworkSegmentationGuard(Guard):
    id = "compose-no-network-segmentation"
    title = "All compose services share the implicit default network with no segmentation"
    area = "Containers"
    # Per-RULE surfacing (matches `actions_script_injection.py`'s established pattern for a
    # guard added after the #617/BB4 migration), not a flat `surfacing = True`: this guard has
    # exactly one rule, and pinning the prefix to that rule's own full string keeps it inert
    # against `tests/test_checkmeta.py`'s frozen pre-migration equivalence snapshot (which only
    # knows about the 5 guards that existed at migration time) while still classifying every
    # REAL finding this guard ever emits as a review signal, since it never emits any other rule.
    surfacing_rule_prefixes = ("compose-no-network-segmentation/default-network-only",)

    # docker-compose.no-network-segmentation.yml: 3 services, none declares its own
    # `networks:` -> fires compose-no-network-segmentation/default-network-only (MEDIUM).
    # Must NOT contain: a per-service `networks:` key, # security: allow-no-network-segmentation.
    canary_plant = CanaryPlant(
        files={
            "docker-compose.no-network-segmentation.yml": (
                "services:\n"
                "  web:\n"
                "    image: alpine:3\n"
                "  worker:\n"
                "    image: alpine:3\n"
                "  db:\n"
                "    image: postgres:16\n"
            ),
        },
        expects=frozenset({"compose-no-network-segmentation/default-network-only"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            if is_dev_compose_file(f.name):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            finding = self._scan(text, rel(root, f))
            if finding is not None:
                out.append(finding)
        return out

    def _scan(self, text: str, location: str) -> Finding | None:
        services = iter_compose_services(text)
        if len(services) < 2:
            return None  # no peer to laterally move to
        if any(_service_declares_networks(body) for _name, _start, body in services):
            return None  # at least one service segments -> file is not flat by default
        first_start = services[0][1]
        names = ", ".join(name for name, _start, _body in services)
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{location}:{first_start}",
            message=(
                f"None of this compose file's {len(services)} services ({names}) "
                "declares an explicit `networks:` key, so all of them share one "
                "implicit default bridge network and can reach each other on every "
                "port. A compromise of any one service (e.g. the public-facing "
                "frontend) has an unobstructed network path to every other service, "
                "including a database or internal-only API."
            ),
            remediation=(
                "Declare explicit networks and place services on only the ones they "
                "genuinely need to reach — e.g. an internal-only network for the "
                "database, shared only with the services that talk to it directly:\n"
                "  networks:\n"
                "    internal:\n"
                "  services:\n"
                "    db:\n"
                "      networks: [internal]\n"
                f"Suppress an audited exception with `{_PRAGMA}` anywhere in the "
                "compose file."
            ),
            rule="compose-no-network-segmentation/default-network-only",
            standards=list(_STANDARDS),
        )
