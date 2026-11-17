"""Guard: docker-compose service missing `read_only: true` (checklist §6c).

    services:
      app:
        image: myapp:1.0
        # no `read_only: true` -> the CONTAINER'S OWN root filesystem is writable, so
        # any code-execution primitive can drop a webshell, tamper with the app's own
        # binaries, or persist a backdoor for the container's lifetime.

**This is a different concern from `compose_writable_host_root_mount.py`, not a
duplicate.** `compose_writable_host_root_mount.py` (read in full before writing this
guard) fires on a `volumes:` bind mount of a specific root-equivalent HOST path
(`/etc`, `/root`, `/var/lib/docker`, …) into the container — a host-escape primitive
reached through a named host directory. This guard has nothing to do with host paths at
all: it fires on the ABSENCE of the compose `read_only:` service field, which governs
whether the CONTAINER'S OWN root filesystem (the image's layers, mounted at `/`) is
writable at runtime — independent of whether any host path is bind-mounted anywhere. A
compose file can have zero volume mounts and still leave a fully writable container
filesystem; conversely a container can be `read_only: true` and still separately have a
dangerous host bind mount, which is `compose_writable_host_root_mount.py`'s finding, not
this one. The two guards' fired lines never overlap by construction: this one only ever
looks at `read_only:`, that one only ever looks at `volumes:`.

Sourced from OWASP DockSec's `compose_scanner.py::_check_writable_root_fs` (read in
full), reproduced as a dependency-free regex check (see `docksec.md` research digest,
DockSec candidate #3).

Fires MEDIUM per docker-compose SERVICE whose `read_only:` field is absent, or present
but not `true` (covers an explicit `read_only: false`, which is the same runtime outcome
as leaving it unset). A commented-out `# read_only: true` does not count as present.
`read_only: true` (any case, quoted or bare) silences the finding for that service.

Suppress an audited case with `# security: allow-writable-container-rootfs` anywhere in
the compose file.
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

_PRAGMA = "# security: allow-writable-container-rootfs"

_STANDARDS = ["OWASP:A05", "CIS:Docker"]

# A `read_only:` service field with a boolean value (bare or quoted, any case).
_READ_ONLY_KEY = re.compile(r"^\s*read_only\s*:\s*['\"]?(?P<value>true|false)['\"]?\s*$", re.IGNORECASE)


def _service_read_only_true(body: list[tuple[int, str]]) -> bool:
    """True only if this service's own block sets `read_only: true`. Comments are
    stripped first, so a commented-out `# read_only: true` does not count, and an
    explicit `read_only: false` is treated the same as absence (both return False)."""
    for _line_no, raw in body:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _READ_ONLY_KEY.match(stripped.partition("#")[0])
        if m:
            return m.group("value").lower() == "true"
    return False


class ComposeWritableRootFilesystemGuard(Guard):
    id = "compose-writable-root-filesystem"
    title = "Docker-compose service missing read_only: true (writable container root filesystem)"
    area = "Containers"

    # docker-compose.writable-rootfs.yml: service has no `read_only:` field at all ->
    # fires compose-writable-root-filesystem/read-only-missing (MEDIUM).
    # Must NOT contain: read_only: true, # security: allow-writable-container-rootfs.
    canary_plant = CanaryPlant(
        files={
            "docker-compose.writable-rootfs.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
            ),
        },
        expects=frozenset({"compose-writable-root-filesystem/read-only-missing"}),
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

    def _scan(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for service_name, start_line, body in iter_compose_services(text):
            if _service_read_only_true(body):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{location}:{start_line}",
                message=(
                    f"Service '{service_name}' does not set `read_only: true`, so its "
                    "own root filesystem is writable at runtime. Any code-execution "
                    "primitive inside the container (a dependency RCE, an unsafe "
                    "deserialization, a prompt-injected shell-out) can drop a "
                    "webshell, overwrite the app's own binaries, or persist a "
                    "backdoor for the container's lifetime."
                ),
                remediation=(
                    "Add `read_only: true` to the service. If it needs to write "
                    "somewhere at runtime (logs, cache, tmp), pair it with a scoped "
                    "`tmpfs:` or named volume for just that path rather than leaving "
                    f"the whole root filesystem writable. Suppress an audited "
                    f"exception with `{_PRAGMA}` anywhere in the compose file."
                ),
                rule="compose-writable-root-filesystem/read-only-missing",
                standards=list(_STANDARDS),
            ))
        return out
