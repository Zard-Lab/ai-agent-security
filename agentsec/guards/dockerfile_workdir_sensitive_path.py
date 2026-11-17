"""Guard: Dockerfile WORKDIR points to a sensitive system directory
(dockerfile-workdir-sensitive-path).

Mined from `cr0hn/dockerfile-security`'s declarative rule catalog (`security.yaml` sec-002),
cross-checked against agentsec's real guard source before building: no existing
guard inspects a Dockerfile `WORKDIR` target at all — `docker-socket-access` is scoped
narrowly to the Docker socket's own special-file path, a different (though related) surface.

Fires MEDIUM when a `WORKDIR` instruction's target is exactly `/`, `/root`, `/bin`, `/sbin`,
`/usr`, `/etc`, `/sys`, or `/proc` — a host-adjacent or system-critical path with no reason to
be an application's working directory. Setting the container's default CWD there raises the
blast radius of anything that writes a RELATIVE path afterward (a build step, an entrypoint
script, an attacker who achieves code execution) by aiming it at a system directory instead of
an isolated application tree. A subdirectory of these (`/etc/myapp`) is NOT flagged — only the
bare system root itself, mirroring the source rule's own anchoring. The bare path also matches
quoted or with a trailing slash (`"/root"`, `/etc/`).

**Suppress:** add `# security: allow-dockerfile-workdir-sensitive-path` to the Dockerfile to
silence this check (e.g. a documented base-image-maintenance stage that legitimately operates
at `/`).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_dockerfiles,
    join_dockerfile_continuations,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-dockerfile-workdir-sensitive-path"

# Exactly the bare system directory - a subdirectory (`/etc/myapp`) is NOT flagged, mirroring
# cr0hn/dockerfile-security's sec-002 rule, verified against the real catalog. Beyond the
# source rule, the same directory written with a trailing slash (`/root/`) or quoted
# (`"/root"`, `'/etc/'`) also matches: Docker resolves all of those to the same path.
_SENSITIVE_WORKDIR = re.compile(
    r"^[^\S\n]*WORKDIR\s+([\"']?)(?:/|/root|/bin|/sbin|/usr|/etc|/sys|/proc)/?\1[^\S\n]*$",
    re.MULTILINE | re.IGNORECASE,
)

_STANDARDS = ["OWASP:A05", "CWE-668"]


class DockerfileWorkdirSensitivePathGuard(Guard):
    id = "dockerfile-workdir-sensitive-path"
    title = "Dockerfile WORKDIR points to a sensitive system directory"
    area = "Containers"

    # Canary plant: own file.
    canary_plant = CanaryPlant(
        files={
            "Dockerfile.workdir-sensitive-path": (
                "FROM debian:bookworm-slim\n"
                "WORKDIR /root\n"
            ),
        },
        expects=frozenset({"dockerfile-workdir-sensitive-path/sensitive-workdir"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            text = join_dockerfile_continuations(read(f))
            if not text.strip() or pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            rel_path = rel(root, f)
            for m in _SENSITIVE_WORKDIR.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel_path}:{line_no}",
                        message=(
                            "This `WORKDIR` targets a system-critical or host-adjacent "
                            "directory. Any later instruction, entrypoint script, or "
                            "attacker-controlled process that writes a relative path now "
                            "lands in a system directory instead of an isolated "
                            "application tree."
                        ),
                        remediation=(
                            "Set `WORKDIR` to a dedicated application directory (e.g. "
                            "`/app` or `/opt/<app>`) instead of a bare system path. "
                            "Suppress an audited case (e.g. a base-image-maintenance "
                            "stage) with `# security: allow-dockerfile-workdir-sensitive-path`."
                        ),
                        rule="dockerfile-workdir-sensitive-path/sensitive-workdir",
                        standards=list(_STANDARDS),
                    )
                )
        return out
