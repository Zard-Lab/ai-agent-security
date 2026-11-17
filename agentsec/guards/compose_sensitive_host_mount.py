"""Guard: docker-compose bind mount of a sensitive host path (checklist §6c).

    services:
      app:
        volumes:
          - /home:/host-home      # exposes every user's home directory

Mounting `/sys`, `/dev`, a whole home-directory tree, or a known credential directory
inside a user's home (`.ssh`, `.docker`, `.aws`, `.kube`, `.gnupg`) into a container
discloses host configuration, kernel interfaces, or credentials to it — without the
host-root write access `compose-writable-host-root-mount` covers. A read-only mount of a
root-equivalent path (`/etc`, `/root`, `/boot`, `/var/lib/docker`, `/var/lib/containerd`,
`/var/lib`, `/proc`) is disclosure rather than takeover and is also this guard's, not the
writable-mount guard's. CWE-200 (Exposure of Sensitive Information), OWASP:A05.

Sourced from compose-lint's `SensitiveMountRule` (`CL-0013`), simplified: real compose-lint
also excludes a handful of inert `/dev/*` bit-bucket devices (`/dev/null`, `/dev/zero`,
`/dev/full`, `/dev/random`, `/dev/urandom`) and a `/run`/`/var/run` runtime-directory
descent tier this guard does not reproduce (documented as a known gap below).

Fires HIGH on a short-syntax bind mount whose host path is `/sys` or `/dev` (excluding the
inert bit-bucket devices), is `/home` itself or a whole user's home directory
(`/home/<user>`), is a known credential directory under a home directory
(`/home/<user>/.ssh`, `.docker`, `.aws`, `.kube`, `.gnupg`), or is a root-equivalent path
(see `compose_writable_host_root_mount.py`) mounted `:ro`.

Suppress an audited case with `# security: allow-sensitive-host-mount` anywhere in the
compose file.
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
from .compose_writable_host_root_mount import match_root_equivalent, normalize_host_path

_PRAGMA = "# security: allow-sensitive-host-mount"

_STANDARDS = ["OWASP:A05", "CWE-200", "CIS:Docker"]

_EXPOSED_PREFIXES: tuple[str, ...] = ("/sys", "/dev")

_INERT_DEVICES = frozenset({"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"})

_HOME_ROOT = "/home"
_HOME_CREDENTIAL_DIRS = frozenset({".ssh", ".docker", ".aws", ".kube", ".gnupg"})

_VOLUME_ENTRY = re.compile(r"^-\s*(?P<value>.+)$")


def _match_exposed(normalized: str) -> str | None:
    if normalized in _INERT_DEVICES:
        return None
    for prefix in _EXPOSED_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return prefix
    return None


def _match_home_tree(normalized: str) -> str | None:
    if normalized == _HOME_ROOT:
        return _HOME_ROOT
    if not normalized.startswith(_HOME_ROOT + "/"):
        return None
    parts = normalized.split("/")  # ["", "home", <user>, ...]
    if len(parts) == 3:
        return normalized  # a whole user's home directory
    if len(parts) > 3 and parts[3] in _HOME_CREDENTIAL_DIRS:
        return "/".join(parts[:4])
    return None


def _split_short_volume(entry: str) -> tuple[str, str] | None:
    parts = entry.strip("'\"").split(":")
    if len(parts) < 2:
        return None
    host = parts[0]
    if not (host.startswith("/") or host.startswith("./") or host.startswith("../")):
        return None
    opts = parts[2] if len(parts) >= 3 else ""
    return host, opts


class ComposeSensitiveHostMountGuard(Guard):
    id = "compose-sensitive-host-mount"
    title = "Docker-compose bind mount of a sensitive host path"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.sensitive-mount.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    volumes:\n"
                "      - /home:/host-home\n"
            ),
        },
        expects=frozenset({"compose-sensitive-host-mount/sensitive-path"}),
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
                read_only = bool(re.search(r"(?:^|,)ro(?:,|$)", opts))
                normalized = normalize_host_path(host)

                matched = _match_exposed(normalized) or _match_home_tree(normalized)
                reason = "exposes host kernel interfaces, devices, or user data"
                if matched is None and read_only:
                    root_equiv = match_root_equivalent(host)
                    if root_equiv is not None:
                        matched = root_equiv
                        reason = "is read-only, disclosing host configuration and credentials"
                if matched is None:
                    continue

                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{location}:{line_no}",
                    message=(
                        f"Service '{service_name}' mounts sensitive host path '{host}' "
                        f"(under {matched}). The mount {reason}."
                    ),
                    remediation=(
                        f"Remove the bind mount for {host}. If the service needs specific "
                        "files, copy them into the image at build time or use a named "
                        "volume with only the required data. Suppress an audited "
                        f"exception with `{_PRAGMA}` anywhere in the compose file."
                    ),
                    rule="compose-sensitive-host-mount/sensitive-path",
                    standards=list(_STANDARDS),
                ))
        return out
