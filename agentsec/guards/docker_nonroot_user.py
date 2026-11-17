"""Guard: Dockerfile runs the container as root (docker-nonroot-user).

Terrascan source: ``pkg/policies/opa/rego/docker/docker_run/lastUserRoot.rego`` (rule
``AC_DOCKER_0053`` family) fires when the LAST ``USER`` instruction in a Dockerfile
resolves to ``root``:

    cmd := input.docker_user[count(input.docker_user) - 1]
    cmd.config == "root"

i.e. it only looks at the final `USER` directive (an earlier `USER appuser` followed by a
later `USER root` still fires — the last one wins at runtime). This guard reproduces that
concept for agentsec's own Python/regex style and extends it one step further: a Dockerfile
that never sets `USER` at all also runs as root (Docker's implicit default), which is the
same runtime outcome and arguably the more common real-world gap — so it is flagged too,
distinctly, as a missing-USER finding.

**Threat:** a container that runs its main process as root has no privilege boundary between
"code execution inside the container" (e.g. via a dependency RCE, a deserialization bug, or an
LLM agent that shells out under prompt injection) and "root inside that container's namespace" —
which materially raises the blast radius of any container breakout primitive (a misconfigured
volume mount, a kernel CVE, a Docker socket mount) from "attacker-controlled user" to
"attacker-controlled root".

Two distinct findings, same rule family:
- ``docker-nonroot-user/last-user-root`` (HIGH) — Dockerfile has at least one `USER`
  instruction, but the LAST one sets `root` (or UID `0`), so the image still runs as root.
- ``docker-nonroot-user/no-user-instruction`` (MEDIUM — lower confidence than an explicit
  `USER root`, since some base images already drop privilege via their own entrypoint) —
  Dockerfile has no `USER` instruction anywhere, so it inherits the base image's default
  user, which is root unless the base image itself sets one.

**Suppress:** add `# security: allow-root-container` to the Dockerfile to silence both
findings for that file (e.g. a local dev-only Dockerfile, or a base image that legitimately
must run privileged setup as root and drops privilege via a runtime entrypoint script the
guard cannot see).

**Checklist item:** `6c-nonroot-container-user` (currently `partial`).
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

_PRAGMA = "security: allow-root-container"

_STANDARDS = ["OWASP:A05", "CWE-250"]

# A `USER <name-or-uid>` instruction. Captures the argument (first whitespace-delimited
# token — a later `:group` suffix, e.g. `USER app:app`, is part of the same token and
# handled by `_is_root_user`).
_USER_INSTRUCTION = re.compile(r"^[^\S\n]*USER\s+(\S+)\s*$", re.MULTILINE | re.IGNORECASE)

# Root identities: the literal name "root", uid 0, or "root:<anything>" / "0:<anything>"
# (a USER can carry a group after a colon — only the user part matters for privilege).
_ROOT_TOKEN = re.compile(r"^(root|0)(?::.*)?$", re.IGNORECASE)


def _is_root_user(token: str) -> bool:
    return bool(_ROOT_TOKEN.match(token.strip()))


class DockerNonrootUserGuard(Guard):
    id = "docker-nonroot-user"
    title = "Container does not drop privilege to a non-root user"
    area = "Containers"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's six shared
    # Dockerfile plants, each of which more than one guard trips at once, so those files stay in
    # `canary.py`'s base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # Dockerfile.hardening-canary carries all 5 docker-* violations at once.
    canary_plant = CanaryPlant(expects=frozenset({"docker-nonroot-user/no-user-instruction"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            text = join_dockerfile_continuations(read(f))
            if not text.strip():
                continue
            if pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            rel_path = rel(root, f)

            users = list(_USER_INSTRUCTION.finditer(text))
            if not users:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=rel_path,
                        message=(
                            "This Dockerfile has no `USER` instruction, so the container "
                            "runs as whatever user the base image defaults to — root for "
                            "the overwhelming majority of public base images. Code "
                            "execution inside the container (a dependency RCE, an unsafe "
                            "deserialization, a prompt-injected shell-out) then runs as root."
                        ),
                        remediation=(
                            "Add a non-root `USER` instruction before the entrypoint, e.g.:\n"
                            "  RUN useradd --create-home appuser\n"
                            "  USER appuser"
                        ),
                        rule="docker-nonroot-user/no-user-instruction",
                        standards=list(_STANDARDS),
                    )
                )
                continue

            last = users[-1]
            if _is_root_user(last.group(1)):
                line_no = text.count("\n", 0, last.start()) + 1
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel_path}:{line_no}",
                        message=(
                            "The last `USER` instruction in this Dockerfile sets `root` "
                            "(or UID 0), so the built image runs as root regardless of any "
                            "earlier non-root `USER` line. Docker uses only the final "
                            "`USER` in effect at runtime."
                        ),
                        remediation=(
                            "Ensure the LAST `USER` instruction in the Dockerfile (the one "
                            "closest to the entrypoint) is a non-root user, e.g. `USER "
                            "appuser`. If root is needed for setup steps, switch back to a "
                            "non-root user afterward with a final `USER appuser` line."
                        ),
                        rule="docker-nonroot-user/last-user-root",
                        standards=list(_STANDARDS),
                    )
                )
        return out
