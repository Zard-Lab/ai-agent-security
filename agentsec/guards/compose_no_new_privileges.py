"""Guard: docker-compose service missing `no-new-privileges:true` in `security_opt` (checklist §6c).

    services:
      app:
        image: myapp:1.0
        # no security_opt: at all -> setuid/setgid binaries in the image can still
        # escalate privilege on exec, even without any of the other privileged flags.

The `no-new-privileges` security option (backed by the kernel's `PR_SET_NO_NEW_PRIVS`
prctl) blocks a process from gaining additional privileges via `execve()` — most
concretely, it neutralizes setuid/setgid binaries and file capabilities baked into the
image (a stray `sudo`, `ping`, or a package's setuid helper). It is Docker's own
recommended additive hardening flag (`docker run --security-opt=no-new-privileges`,
`security_opt: ["no-new-privileges:true"]` in compose) and is a distinct concern from
`docker-privileged-flags`, which already flags the OPPOSITE misconfiguration — a
`security_opt` entry naming an `*:unconfined` profile (actively DISABLING a protection
like AppArmor/SELinux). This guard flags the absence of an ADDITIVE protection that is
never on by default; `docker-privileged-flags` flags the presence of a flag that removes
one that is normally on. Neither guard's `run()` overlaps the other's fired lines.

Sourced from OWASP DockSec's `compose_scanner.py::_check_no_new_privileges` (read in full),
reproduced here as a dependency-free regex/state-machine check rather than a real YAML
parse, per this project's zero-runtime-dependency architecture (see `docksec.md` research
digest, DockSec candidate #1).

Fires MEDIUM per docker-compose SERVICE whose `security_opt:` list (short block-list form
or `[...]` flow form) does not contain a `no-new-privileges:true`/`no-new-privileges=true`
entry — including a service with NO `security_opt:` key at all (the common case), and one
whose `security_opt:` exists but only sets something else (e.g. `apparmor:unconfined`,
`seccomp:unconfined` — already flagged separately and more severely by
`docker-privileged-flags`, but that guard has nothing to say about THIS flag's absence).

Suppress an audited case with `# security: allow-no-new-privileges` anywhere in the
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

_PRAGMA = "# security: allow-no-new-privileges"

_STANDARDS = ["OWASP:A05", "CIS:Docker"]

# `no-new-privileges:true` (or the CLI-style `=true`), quote- and case-insensitive.
_NO_NEW_PRIVS = re.compile(r"no-new-privileges\s*[:=]\s*['\"]?true['\"]?", re.IGNORECASE)

_SECURITY_OPT_KEY = re.compile(r"^(?P<indent>\s*)security_opt\s*:\s*(?:#.*)?$", re.IGNORECASE)
_SECURITY_OPT_FLOW = re.compile(r"^\s*security_opt\s*:\s*(?P<body>\[[^\]]*\])", re.IGNORECASE)


def _service_has_no_new_privileges(body: list[tuple[int, str]]) -> bool:
    """True if this service's `security_opt:` list contains `no-new-privileges:true`,
    in either block-list or single-line flow-list form. Comments are stripped before
    matching, so `# no-new-privileges:true` (mentioned but not set) does not count."""
    in_opt = False
    opt_indent = -1
    for _line_no, raw in body:
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if not in_opt:
            flow = _SECURITY_OPT_FLOW.match(stripped.partition("#")[0])
            if flow:
                if _NO_NEW_PRIVS.search(flow.group("body")):
                    return True
                continue
            key = _SECURITY_OPT_KEY.match(raw)
            if key:
                in_opt, opt_indent = True, len(key.group("indent"))
            continue
        if not stripped.startswith("-"):
            if indent <= opt_indent:
                in_opt = False
            continue
        entry = stripped.partition("#")[0].strip()
        if _NO_NEW_PRIVS.search(entry):
            return True
    return False


class ComposeNoNewPrivilegesGuard(Guard):
    id = "compose-no-new-privileges"
    title = "Docker-compose service missing no-new-privileges:true in security_opt"
    area = "Containers"

    # docker-compose.no-new-privileges.yml: service has no security_opt: at all ->
    # fires compose-no-new-privileges/missing (MEDIUM).
    # Must NOT contain: no-new-privileges:true, # security: allow-no-new-privileges.
    canary_plant = CanaryPlant(
        files={
            "docker-compose.no-new-privileges.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
            ),
        },
        expects=frozenset({"compose-no-new-privileges/missing"}),
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
            if _service_has_no_new_privileges(body):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{location}:{start_line}",
                message=(
                    f"Service '{service_name}' does not set `no-new-privileges:true` in "
                    "`security_opt`. Without it, any setuid/setgid binary or file "
                    "capability baked into the image (a stray `sudo`, `ping`, or a "
                    "package's setuid helper) can still escalate privilege on exec, "
                    "even though this is a free, additive protection with no "
                    "application-behavior cost."
                ),
                remediation=(
                    "Add to the service:\n"
                    "  security_opt:\n"
                    "    - no-new-privileges:true\n"
                    f"Suppress an audited exception with `{_PRAGMA}` anywhere in the "
                    "compose file."
                ),
                rule="compose-no-new-privileges/missing",
                standards=list(_STANDARDS),
            ))
        return out
