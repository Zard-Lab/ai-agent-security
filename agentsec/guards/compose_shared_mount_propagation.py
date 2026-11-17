"""Guard: docker-compose volume using shared mount propagation (checklist §6c).

    services:
      app:
        volumes:
          - /host/path:/container/path:shared

Shared mount propagation lets a mount created inside a container appear on the host
filesystem and vice versa, breaking mount-namespace isolation between the container and
the host (and between sibling containers sharing the same propagated tree). `slave`/
`rslave` propagate host-to-container only and are not flagged — the risk is specifically a
container's own mount events reaching the host. CWE-668 (Exposure of Resource to Wrong
Sphere), CIS Docker Benchmark 5.20.

Sourced from compose-lint's `SharedMountRule` (`CL-0017`). Handles the short-syntax
`:shared`/`:rshared` option suffix and the long-syntax `bind.propagation:` key.

Fires LOW on a `volumes:` entry using `shared` or `rshared` propagation, either syntax.

Suppress an audited case with `# security: allow-compose-shared-mount-propagation`
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

_PRAGMA = "# security: allow-compose-shared-mount-propagation"

_STANDARDS = ["CWE-668", "CIS:Docker"]

_SHARED_PROPAGATION = frozenset({"shared", "rshared"})

_PROPAGATION_KEY = re.compile(r"^\s*propagation\s*:\s*(?:['\"])?(?P<value>[a-zA-Z]+)")


class ComposeSharedMountPropagationGuard(Guard):
    id = "compose-shared-mount-propagation"
    title = "Docker-compose volume using shared mount propagation"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.propagation.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    volumes:\n"
                "      - /host/path:/container/path:shared\n"
            ),
        },
        expects=frozenset({"compose-shared-mount-propagation/shared-propagation"}),
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
            out.extend(self._scan(text, rel(root, f)))
        return out

    def _emit(self, service_name: str, line_no: int, location: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="low",
            title=self.title,
            location=f"{location}:{line_no}",
            message=(
                f"Service '{service_name}' uses shared mount propagation. Mounts "
                "created inside the container will appear on the host and vice versa, "
                "breaking mount-namespace isolation."
            ),
            remediation=(
                "Remove ':shared'/':rshared' from the volume mount, or set "
                "`bind.propagation: rprivate` (the default). Suppress an audited "
                f"exception with `{_PRAGMA}` anywhere in the compose file."
            ),
            rule="compose-shared-mount-propagation/shared-propagation",
            standards=list(_STANDARDS),
        )

    def _scan(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for service_name, _start, body in iter_compose_services(text):
            in_volumes = False
            volumes_indent = -1
            entry_indent = -1
            in_bind = False
            for line_no, raw in body:
                if not raw.strip():
                    continue
                indent = len(raw) - len(raw.lstrip())
                if raw.lstrip().startswith("#"):
                    continue
                key = re.match(r"(\s*)volumes\s*:\s*(?:#.*)?$", raw)
                if key:
                    in_volumes, volumes_indent, in_bind = True, len(key.group(1)), False
                    continue
                if not in_volumes:
                    continue
                stripped = raw.strip()
                if indent <= volumes_indent:
                    in_volumes = False
                    continue
                if stripped.startswith("-"):
                    entry_indent, in_bind = indent, False
                    entry = stripped.lstrip("-").strip().strip("'\"")
                    # Short syntax: .../opts,shared or ...:shared
                    if ":" in entry:
                        opts = entry.split(":")[-1].split(",")
                        if any(o.strip().lower() in _SHARED_PROPAGATION for o in opts):
                            out.append(self._emit(service_name, line_no, location))
                    continue
                if entry_indent == -1:
                    continue
                if re.match(r"^\s*bind\s*:\s*(?:#.*)?$", raw):
                    in_bind = True
                    continue
                if in_bind:
                    m = _PROPAGATION_KEY.match(raw)
                    if m and m.group("value").lower() in _SHARED_PROPAGATION:
                        out.append(self._emit(service_name, line_no, location))
        return out
