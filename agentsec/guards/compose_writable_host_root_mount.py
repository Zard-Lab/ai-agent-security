"""Guard: docker-compose bind mount of a root-equivalent host path, writable (checklist §6c).

    services:
      app:
        volumes:
          - /etc:/host-etc          # writable bind of a root-equivalent path

A writable bind mount of `/etc`, `/root`, `/boot`, `/proc`, the container store
(`/var/lib/docker`, `/var/lib/containerd`), or `/var/lib` itself gives the container host
root through ordinary file writes — no exploit or escape technique required. Writing
`/etc/cron.d` schedules a root job on the host's next tick; writing `authorized_keys`
under `/root` grants host SSH access; writing into `/var/lib/docker` tampers with another
container's image layers, escaping on that container's next start. CWE-269 (Improper
Privilege Management), OWASP:A05.

Sourced from compose-lint's `WritableHostRootMountRule` (`CL-0025`), whose grant table and
`/var/lib` exact-vs-descent distinction (a bare `-v /var/lib` bind is CRITICAL; a bind of
`/var/lib/mysql` — an application's own state dir, not a container-store path — is not) are
reproduced verbatim from the real fetched source, including the citation this project's
own review found: `/var/lib/mysql`-shaped binds accounted for 24 of 25 corpus hits on a
naive descent match, with the one genuine `/var/lib` bind being the actual finding.

Fires CRITICAL on a short-syntax bind mount (`- <host>:<container>[:opts]`) whose host
path is `/etc`, `/root`, `/boot`, `/proc`, `/var/lib/docker`, or `/var/lib/containerd`
(matched by descent — the path itself or anything under it) or is exactly `/var/lib`
(NOT by descent — `/var/lib/mysql` is a normal application data directory, not a
container-store path), and the mount is NOT suffixed `:ro`/`:ro,...`. A whole-root mount
(`-v /:/host`) is deliberately out of scope — it is `docker-socket-access`'s territory in
either mode, since it exposes the daemon control socket regardless of read/write.

Suppress an audited case with `# security: allow-writable-host-root-mount` anywhere in
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

_PRAGMA = "# security: allow-writable-host-root-mount"

_STANDARDS = ["OWASP:A05", "CWE-269", "CIS:Docker"]

# Descent match: the path itself, or anything under it.
ROOT_EQUIVALENT_PATHS: tuple[str, ...] = (
    "/etc",
    "/root",
    "/boot",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/proc",
)
# Exact match only — /var/lib/mysql etc. are ordinary application data dirs, not the
# container store; only a bare /var/lib bind grants what this member describes.
ROOT_EQUIVALENT_EXACT_PATHS: tuple[str, ...] = ("/var/lib",)

_GRANTS: dict[str, str] = {
    "/etc": "cron.d, ld.so.preload, sudoers and shadow — host root on the next scheduled job or login",
    "/root": "authorized_keys — host root over SSH",
    "/boot": "the kernel and initramfs — a persistent rootkit surviving reboot",
    "/var/lib/docker": "every other container's filesystem and image layers — tamper with one and it escapes on next start",
    "/var/lib/containerd": "the containerd snapshot trees holding every container's filesystem",
    "/var/lib": "/var/lib/docker and /var/lib/containerd inside it, and with them every other container's filesystem",
    "/proc": "core_pattern — the host's core-dump handler runs a program of the attacker's choosing, as root, on the next crash",
}

# Short-syntax volume list entry: "- <host>:<container>[:opts]". Only a HOST path (absolute
# or `./`-relative) is a real bind mount; a bare name (`pgdata:/var/lib/postgresql/data`) is
# a named volume, which has no host path to protect.
_VOLUME_ENTRY = re.compile(r"^-\s*(?P<value>.+)$")


def normalize_host_path(path: str) -> str:
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path


def match_root_equivalent(host_path: str) -> str | None:
    normalized = normalize_host_path(host_path)
    for prefix in ROOT_EQUIVALENT_PATHS:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return prefix
    if normalized in ROOT_EQUIVALENT_EXACT_PATHS:
        return normalized
    return None


def _split_short_volume(entry: str) -> tuple[str, str] | None:
    """Return (host_path, options) for a short-syntax bind mount, else None.

    A bare `container_path` (no colon) or `name:container_path` (named volume, no leading
    `/`/`./`) is not a bind mount. A Windows drive letter (`C:\\...`) is out of scope —
    compose bind sources on the platforms this project targets are POSIX paths.
    """
    parts = entry.strip("'\"").split(":")
    if len(parts) < 2:
        return None
    host = parts[0]
    if not (host.startswith("/") or host.startswith("./") or host.startswith("../")):
        return None
    opts = parts[2] if len(parts) >= 3 else ""
    return host, opts


class ComposeWritableHostRootMountGuard(Guard):
    id = "compose-writable-host-root-mount"
    title = "Docker-compose bind mount of a root-equivalent host path, writable"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.host-root-mount.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    volumes:\n"
                "      - /etc:/host-etc\n"
            ),
        },
        expects=frozenset({"compose-writable-host-root-mount/host-root-equivalent"}),
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
        for service_name, _start, body in iter_compose_services(text):
            in_volumes = False
            volumes_indent = -1
            for line_no, raw in body:
                if not raw.strip():
                    continue
                indent = len(raw) - len(raw.lstrip())
                key = re.match(r"(\s*)volumes\s*:\s*(?:#.*)?$", raw)
                if key:
                    in_volumes, volumes_indent = True, len(key.group(1))
                    continue
                if not in_volumes:
                    continue
                stripped = raw.strip()
                if not stripped.startswith("-"):
                    if indent <= volumes_indent:
                        in_volumes = False
                    continue
                entry = stripped.partition("#")[0].strip()
                m = _VOLUME_ENTRY.match(entry)
                if not m:
                    continue
                split = _split_short_volume(m.group("value"))
                if split is None:
                    continue
                host, opts = split
                if re.search(r"(?:^|,)ro(?:,|$)", opts):
                    continue  # read-only — a disclosure, not a writable takeover
                matched = match_root_equivalent(host)
                if matched is None:
                    continue
                out.append(Finding(
                    check_id=self.id,
                    severity="critical",
                    title=self.title,
                    location=f"{location}:{line_no}",
                    message=(
                        f"Service '{service_name}' mounts host path '{host}' writable "
                        f"(under {matched}). Writing there is host root: {_GRANTS[matched]}."
                    ),
                    remediation=(
                        f"Remove the bind mount for {host}, or make it read-only (`:ro`) "
                        "if the service only needs to read. Where specific files are "
                        "needed, copy them into the image at build time or use a named "
                        "volume holding only that data. Suppress an audited exception "
                        f"with `{_PRAGMA}` anywhere in the compose file."
                    ),
                    rule="compose-writable-host-root-mount/host-root-equivalent",
                    standards=list(_STANDARDS),
                ))
        return out
