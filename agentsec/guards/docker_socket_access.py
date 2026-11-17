"""Guard: code references the Docker socket, a container-escape vector (checklist §6c).

    client = docker.from_env()
    client.containers.run("alpine", "sh", privileged=True, volumes={"/": {"bind": "/host"}})

Access to `/var/run/docker.sock` from inside a container is equivalent to root on the
host: the socket is the Docker daemon's own control API, and the daemon runs as root.
Code (application code, or an AI agent skill/tool) that can talk to this socket can
spawn a new, arbitrarily-privileged container with the host filesystem bind-mounted in
— a well-documented, reliable container-escape technique. This is the SkillSpector
project's PE4 category ("Docker Socket Access"), applied to application/agent-tool code
generally rather than only agent skill files. CWE-269 (Improper Privilege Management),
OWASP:A05.

Fires HIGH on any of:

  * a literal reference to `/var/run/docker.sock` (a bind-mount source, a `docker -H
    unix:///var/run/docker.sock` invocation, an `http+unix://` URL through it);
  * `docker.from_env()` — the Python Docker SDK's default client, which connects to
    the local daemon socket;
  * `DockerClient(` — the Docker SDK's explicit client constructor (Python or the
    equivalent `Docker.getInstance`/`new Docker(` shape in Node's `dockerode`).

A false-positive-prone context (a `# example:`/`**note**`-style documentation comment,
or a fenced code block inside a Markdown file) is common for a security tool's own
README explaining what NOT to do — this guard does not attempt that filtering, since
agentsec's own scan targets are application/deployment code, not documentation.

Suppress an audited case (e.g. a legitimate CI runner or a Docker-in-Docker build
pipeline that genuinely needs socket access) with `# security: allow-docker-socket`
anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_DOCKER_SOCK_PATH = re.compile(r"/var/run/docker\.sock")
_DOCKER_FROM_ENV = re.compile(r"\bdocker\s*\.\s*from_env\s*\(")
_DOCKER_CLIENT_CTOR = re.compile(r"\bDockerClient\s*\(")
_PRAGMA = re.compile(r"#\s*security:\s*allow-docker-socket")

_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".yml", ".yaml")
_STANDARDS = ["OWASP:A05", "CWE-269"]


class DockerSocketAccessGuard(Guard):
    id = "docker-socket-access"
    title = "Code references the Docker socket (container-escape vector)"
    area = "Containers"

    # docker_escape.py: docker.from_env() -> fires docker-socket-access.
    # Must NOT contain: allow-docker-socket pragma.
    # docker_escape.py: docker.from_env() -> fires socket-reference.
    canary_plant = CanaryPlant(
        files={
            "docker_escape.py": (
                "client = docker.from_env()\n"
            ),
        },
        expects=frozenset({"docker-socket-access/socket-reference"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Universal: the source/compose files this scans (and the Docker-socket signal)
        # can appear in any project regardless of the detected stack — a `"python"` gate
        # would silently drop the YAML/JS/shell socket references on a compose-only or
        # Node-only repo.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            m = (
                _DOCKER_SOCK_PATH.search(line)
                or _DOCKER_FROM_ENV.search(line)
                or _DOCKER_CLIENT_CTOR.search(line)
            )
            if not m:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"This line references `{m.group(0)}` — the Docker daemon's "
                        "control socket. Access to it from inside a container is "
                        "equivalent to root on the host: it can be used to spawn a new, "
                        "arbitrarily-privileged container with the host filesystem "
                        "bind-mounted in, a well-documented container-escape technique."
                    ),
                    remediation=(
                        "Remove the Docker socket dependency if it isn't genuinely "
                        "needed. If a build pipeline or CI runner requires it, isolate "
                        "that job specifically and never bind-mount the socket into an "
                        "application/serving container. Suppress an audited case with "
                        "`# security: allow-docker-socket` anywhere in the file."
                    ),
                    rule="docker-socket-access/socket-reference",
                    standards=list(_STANDARDS),
                )
            )
        return out
