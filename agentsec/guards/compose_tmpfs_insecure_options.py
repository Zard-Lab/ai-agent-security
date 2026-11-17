"""Guard: docker-compose tmpfs mount re-enables exec/suid/dev (checklist §6c).

    services:
      app:
        tmpfs:
          - /tmp:exec

Docker mounts every tmpfs with `noexec,nosuid,nodev` by default. Passing `exec`, `suid`,
or `dev` removes that protection — a deliberate weakening of a secure default that turns a
writable in-memory mount into a place to stage and run dropped payloads, especially under
a `read_only: true` root filesystem where `/tmp` is otherwise the only writable path.
CWE-732 (Incorrect Permission Assignment), OWASP:A05.

Sourced from compose-lint's `TmpfsInsecureOptionsRule` (`CL-0022`). Only the short `tmpfs:`
form (string or list of strings) carries per-entry options; the long `volumes:` form
(`- type: tmpfs`) keeps the secure defaults and cannot express these tokens, so it is out
of scope, matching the real source.

Fires LOW when a `tmpfs:` entry's comma-separated option list (after the `:`) contains
`exec`, `suid`, or `dev`.

Suppress an audited case with `# security: allow-compose-tmpfs-insecure-options` anywhere
in the compose file.
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

_PRAGMA = "# security: allow-compose-tmpfs-insecure-options"

_STANDARDS = ["OWASP:A05", "CWE-732"]

_INSECURE_OPTIONS: dict[str, str] = {
    "exec": "execution of binaries from the mount (default noexec)",
    "suid": "setuid/setgid bits on the mount (default nosuid)",
    "dev": "device nodes on the mount (default nodev)",
}


def _insecure_options(entry: str) -> list[str]:
    opts = entry.partition(":")[2].split(",")
    opts = [o.strip() for o in opts]
    return [token for token in _INSECURE_OPTIONS if token in opts]


class ComposeTmpfsInsecureOptionsGuard(Guard):
    id = "compose-tmpfs-insecure-options"
    title = "Docker-compose tmpfs mount re-enables exec/suid/dev"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.tmpfs.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    tmpfs:\n"
                "      - /tmp:exec\n"
            ),
        },
        expects=frozenset({"compose-tmpfs-insecure-options/secure-default-removed"}),
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

    def _emit(self, service_name: str, entry: str, insecure: list[str], line_no: int, location: str) -> Finding:
        path = entry.partition(":")[0].strip("'\" ")
        opts = ", ".join(insecure)
        return Finding(
            check_id=self.id,
            severity="low",
            title=self.title,
            location=f"{location}:{line_no}",
            message=(
                f"Service '{service_name}' tmpfs mount '{path}' re-enables {opts}. "
                "Docker mounts tmpfs noexec,nosuid,nodev by default; this turns that "
                "off, making a writable in-memory mount a place to stage and run "
                "dropped payloads."
            ),
            remediation=(
                f"Remove the {opts} option to restore Docker's secure default "
                f"(noexec,nosuid,nodev). Suppress an audited exception with "
                f"`{_PRAGMA}` anywhere in the compose file."
            ),
            rule="compose-tmpfs-insecure-options/secure-default-removed",
            standards=list(_STANDARDS),
        )

    def _scan(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for service_name, _start, body in iter_compose_services(text):
            in_tmpfs = False
            tmpfs_indent = -1
            for line_no, raw in body:
                if not raw.strip():
                    continue
                indent = len(raw) - len(raw.lstrip())
                if raw.lstrip().startswith("#"):
                    continue
                key = re.match(r"(\s*)tmpfs\s*:\s*(?P<inline>\S.*)?$", raw)
                if key and not (in_tmpfs and indent > tmpfs_indent):
                    inline = key.group("inline")
                    if inline and inline.strip() and not inline.strip().startswith("#"):
                        # Scalar single-line form: `tmpfs: /tmp:exec`.
                        entry = inline.strip().strip("'\"")
                        insecure = _insecure_options(entry)
                        if insecure:
                            out.append(self._emit(service_name, entry, insecure, line_no, location))
                        continue
                    in_tmpfs, tmpfs_indent = True, len(key.group(1))
                    continue
                if not in_tmpfs:
                    continue
                stripped = raw.strip()
                if not stripped.startswith("-"):
                    if indent <= tmpfs_indent:
                        in_tmpfs = False
                    continue
                entry = stripped.lstrip("-").strip().strip("'\"")
                insecure = _insecure_options(entry)
                if insecure:
                    out.append(self._emit(service_name, entry, insecure, line_no, location))
        return out
