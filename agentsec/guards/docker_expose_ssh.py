"""Guard: Dockerfile EXPOSEs the SSH port (docker-expose-ssh).

Terrascan source: ``pkg/policies/opa/rego/docker/docker_expose/exposeport.rego`` (rule
``AC_DOCKER_0011`` family) flags an `EXPOSE` instruction whose config contains the
substring `"22"`:

    checkPort(config) { contains(config, "22") }

That is a naive substring match — it also fires on `EXPOSE 2200`, `EXPOSE 8220`, or
`EXPOSE 32200` (any port literally containing the digits "22"), none of which is SSH. This
guard reproduces the underlying concept (containers should not run/expose an SSH server)
but with an exact-port parse instead of a substring match, so `EXPOSE 2200` does not fire
while `EXPOSE 22`, `EXPOSE 22/tcp`, and `EXPOSE 2222 22` (the port 22 anywhere in a
multi-port EXPOSE line) correctly do.

**Threat:** a container that runs (and exposes) its own SSH daemon reintroduces a class of
attack surface containers are specifically designed to avoid — a long-lived, independently
patched network service with its own auth/credential surface, running inside a supposedly
minimal, single-process image. Standard container operational access (`docker exec`,
`kubectl exec`) already covers the legitimate "get a shell in the container" need without
a listening service; an exposed SSH port instead gives any network-reachable attacker a
second, often less-monitored login surface with its own brute-force/credential-stuffing/
CVE exposure independent of the application.

**Detection:** every `EXPOSE` instruction's port list is parsed (space-separated tokens,
each optionally suffixed `/tcp` or `/udp`) and each port number is compared for an EXACT
match against `22` — not a substring match, to avoid the terrascan source rule's own false
positive on ports like `2200`/`8220`.

**Suppress:** add `# security: allow-ssh-expose` to the Dockerfile to silence this check
(e.g. a bastion/jump-host image where SSH access is the intended function).

**Checklist item:** no existing item covers SSH exposure inside application container
images specifically — new item recommended (lower priority than the other docker gaps
here, since a FastAPI/React app Dockerfile rarely has a legitimate reason to touch this
path at all — it is a cheap, high-precision check rather than a commonly-hit one).
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

_PRAGMA = "security: allow-ssh-expose"

_STANDARDS = ["OWASP:A05", "CWE-1327"]

_EXPOSE_INSTRUCTION = re.compile(r"^[^\S\n]*EXPOSE\s+(.+)$", re.MULTILINE | re.IGNORECASE)

# One EXPOSE token: a port number, optionally with a /tcp or /udp protocol suffix.
_PORT_TOKEN = re.compile(r"^(\d+)(?:/(?:tcp|udp))?$", re.IGNORECASE)

_SSH_PORT = "22"


def _exposes_ssh(config: str) -> bool:
    for token in config.split():
        m = _PORT_TOKEN.match(token.strip())
        if m and m.group(1) == _SSH_PORT:
            return True
    return False


class DockerExposeSshGuard(Guard):
    id = "docker-expose-ssh"
    title = "Dockerfile EXPOSEs the SSH port"
    area = "Containers"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `Dockerfile.hardening-canary`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # Dockerfile.hardening-canary carries all 5 docker-* violations at once.
    canary_plant = CanaryPlant(expects=frozenset({"docker-expose-ssh/ssh-port-exposed"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            text = join_dockerfile_continuations(read(f))
            if not text.strip() or pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            rel_path = rel(root, f)
            for m in _EXPOSE_INSTRUCTION.finditer(text):
                if not _exposes_ssh(m.group(1)):
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel_path}:{line_no}",
                        message=(
                            "This Dockerfile EXPOSEs port 22 (SSH). Running an SSH server "
                            "inside an application container reintroduces a persistent, "
                            "independently-attackable network service that standard "
                            "container operational access (`docker exec`) already makes "
                            "unnecessary."
                        ),
                        remediation=(
                            "Remove the SSH server and the `EXPOSE 22` line; use `docker "
                            "exec` (or your orchestrator's exec equivalent) for interactive "
                            "access instead."
                        ),
                        rule="docker-expose-ssh/ssh-port-exposed",
                        standards=list(_STANDARDS),
                    )
                )
        return out
