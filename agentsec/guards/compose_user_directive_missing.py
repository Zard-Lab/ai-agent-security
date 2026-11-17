"""Guard: docker-compose service has no `user:` directive (checklist §6c).

    services:
      app:
        image: myapp:1.0
        # no `user:` -> the container runs as whatever the IMAGE's own default is,
        # which the compose file gives no evidence either way about.

**This is the docker-compose-format sibling of `docker_nonroot_user.py`, not a
duplicate.** `docker_nonroot_user.py` (read in full before writing this guard) parses a
Dockerfile's `USER` INSTRUCTION — a build-time directive baked into the image itself.
This guard parses a compose file's `user:` SERVICE FIELD — a run-time override compose
applies on top of whatever the image already does, and the two are governed by entirely
different files, syntaxes and authors (an app's own Dockerfile vs. a deploy/ops-owned
compose file, frequently written by different people at different times).

**Build-context resolution (#804).** When a service builds from a local Dockerfile
(`build: ./ctx`, or a `build:` block with `context:`/`dockerfile:`), this guard resolves
that one referenced Dockerfile relative to the compose file's own directory and reads its
FINAL build stage (from the last `FROM` onward). If the final stage ends on a non-root
`USER`, the container provably does not run as root, so the finding is suppressed. It
keeps firing when the service is `image:`-only (no build context to inspect), when the
Dockerfile cannot be resolved or read, when the final stage has no `USER` at all, or when
the final-stage `USER` is `root`/`0` — uncertainty stays a finding. A compose file setting
`user: "1000:1000"` still suppresses independently, and can still override a Dockerfile
that never dropped privilege. Between this guard and `docker_nonroot_user.py`, both places
that decide "does this container actually run as non-root" are covered.

Sourced from OWASP DockSec's `compose_scanner.py::_check_no_non_root_user` (read in
full), reproduced as a dependency-free regex check (see `docksec.md` research digest,
DockSec candidate #2).

Fires MEDIUM (lower confidence than an explicit root grant — for an `image:`-only service
the referenced image may still default to non-root via its own Dockerfile `USER`, which
this guard cannot see) per docker-compose SERVICE that has no `user:` key anywhere in its
own service block and is not otherwise confirmed non-root via its resolved build Dockerfile.
A commented-out `# user: appuser` does not count as present. An explicit `user: root` /
`user: "0"` is a known non-finding here (see "What this guard does NOT prove" — that is
an explicit grant, a different and arguably worse case this guard does not attempt to
detect, since the given candidate scope is specifically the MISSING-directive case).

Suppress an audited case with `# security: allow-compose-root-user` anywhere in the
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
    join_dockerfile_continuations,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "# security: allow-compose-root-user"

_STANDARDS = ["OWASP:A05", "CWE-250", "CIS:Docker"]

# A `user:` service field with a real value. Anchored to whitespace-then-"user" so it
# never matches a differently-named key ending in "user" (e.g. `postgres_user:`) and
# never matches a list entry (`- USER=root` in `environment:`, which starts with `-`).
_USER_KEY = re.compile(r"^\s*user\s*:\s*\S", re.IGNORECASE)


def _service_has_user_directive(body: list[tuple[int, str]]) -> bool:
    """True if this service's own block sets a `user:` field anywhere. Comments are
    stripped first, so a commented-out `# user: appuser` does not count as present."""
    for _line_no, raw in body:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _USER_KEY.match(stripped.partition("#")[0]):
            return True
    return False


# A service's `build:` key: short form (`build: ./ctx`) captures the value; long form
# (`build:` on its own line, sub-keys below) captures nothing and is detected by the empty value.
_BUILD_KEY = re.compile(r"^(?P<indent>\s*)build\s*:\s*(?P<val>.*)$")
# `context:` / `dockerfile:` sub-keys inside a long-form `build:` block.
_CONTEXT_KEY = re.compile(r"^\s*context\s*:\s*(?P<val>.+)$")
_DOCKERFILE_KEY = re.compile(r"^\s*dockerfile\s*:\s*(?P<val>.+)$")
# A Dockerfile stage boundary and its `USER` instruction. `_USER_INSTRUCTION`/`_ROOT_TOKEN` are
# deliberately byte-identical to docker_nonroot_user.py's (last USER in the FINAL stage wins, and
# root/uid-0 does not count as dropping privilege): guards own their own patterns here rather than
# import across sibling modules. If a THIRD consumer appears, extract a shared base.py helper
# (`dockerfile_final_stage_runs_nonroot`) instead of copying a third time (#804 review note).
_DOCKER_FROM = re.compile(r"^\s*FROM\s", re.IGNORECASE)
_USER_INSTRUCTION = re.compile(r"^[^\S\n]*USER\s+(\S+)\s*$", re.MULTILINE | re.IGNORECASE)
_ROOT_TOKEN = re.compile(r"^(root|0)(?::.*)?$", re.IGNORECASE)


def _scalar(s: str) -> str:
    """A compose scalar value: trailing inline comment dropped, surrounding quotes stripped.
    Matches the comment-stripping style of `_service_has_user_directive` (partition on `#`)."""
    s = s.partition("#")[0].strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]
    return s.strip()


def _build_dockerfile(compose_file: Path, root: Path, body: list[tuple[int, str]]) -> Path | None:
    """Resolve the Dockerfile a service's `build:` context references, relative to the compose
    file's own directory, or `None` when the service has no build context, uses the inline
    flow form (`build: {...}`, not parsed), points outside `root`, or the file does not exist.
    Returning `None` keeps the guard firing (the safe, cannot-confirm direction)."""
    context: str | None = None
    dockerfile = "Dockerfile"
    build_indent: int | None = None
    in_build_block = False
    for _line_no, raw in body:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if in_build_block:
            if build_indent is not None and indent <= build_indent:
                in_build_block = False  # left the build: block; fall through to re-test the line
            else:
                mc = _CONTEXT_KEY.match(raw)
                if mc:
                    context = _scalar(mc.group("val"))
                    continue
                md = _DOCKERFILE_KEY.match(raw)
                if md:
                    dockerfile = _scalar(md.group("val"))
                continue
        mb = _BUILD_KEY.match(raw)
        if mb:
            build_indent = len(mb.group("indent"))
            val = _scalar(mb.group("val"))
            if val.startswith("{"):
                # Inline flow-mapping (`build: {context: ., dockerfile: X}`): the sub-keys live on
                # this one line and the indent-based reader does not parse them, so the service
                # stays unresolved (context is None -> the guard keeps firing).
                pass
            elif val:
                context = val  # short form: `build: ./ctx`
            else:
                # Long-form block (`build:` on its own line, sub-keys below). Default the context to
                # `.` per the compose spec, overridden by an explicit `context:` sub-key — so a
                # block that sets only `dockerfile:` still resolves against the compose dir (#804).
                context = "."
                in_build_block = True
    if context is None:
        return None
    candidate = compose_file.parent / context / dockerfile
    try:
        resolved = candidate.resolve()
        if not resolved.is_file():
            return None
        if not resolved.is_relative_to(root.resolve()):
            return None
    except (OSError, ValueError):
        # ValueError: an embedded NUL byte in a compose path makes `resolve()`/`stat` raise a
        # non-OSError; a guard's run() must stay total, so treat it as unresolvable (keep firing).
        return None
    return resolved


def _final_stage_is_nonroot(dockerfile_text: str) -> bool:
    """True only if the Dockerfile's FINAL build stage (from the last `FROM` onward) ends on a
    non-root `USER`. A `USER` in an earlier, discarded stage does not count — that is exactly
    the negative control (#804) where only a non-final stage drops privilege. No `USER` in the
    final stage, or a final-stage `USER root`/`0`, returns False so the guard still fires."""
    text = join_dockerfile_continuations(dockerfile_text)
    lines = text.splitlines()
    from_idxs = [i for i, ln in enumerate(lines) if _DOCKER_FROM.match(ln)]
    final_start = from_idxs[-1] if from_idxs else 0
    final_stage = "\n".join(lines[final_start:])
    users = _USER_INSTRUCTION.findall(final_stage)
    if not users:
        return False
    return _ROOT_TOKEN.match(users[-1].strip()) is None


class ComposeUserDirectiveMissingGuard(Guard):
    id = "compose-user-directive-missing"
    title = "Docker-compose service has no user: directive (image likely runs as root)"
    area = "Containers"

    # docker-compose.no-user.yml: service has no `user:` field at all ->
    # fires compose-user-directive-missing/no-user-directive (MEDIUM).
    # Must NOT contain: a `user:` line, # security: allow-compose-root-user.
    canary_plant = CanaryPlant(
        files={
            "docker-compose.no-user.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
            ),
        },
        expects=frozenset({"compose-user-directive-missing/no-user-directive"}),
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
            out.extend(self._scan(text, rel(root, f), f, root))
        return out

    def _scan(self, text: str, location: str, compose_file: Path, root: Path) -> list[Finding]:
        out: list[Finding] = []
        for service_name, start_line, body in iter_compose_services(text):
            if _service_has_user_directive(body):
                continue
            dockerfile = _build_dockerfile(compose_file, root, body)
            if dockerfile is not None and _final_stage_is_nonroot(read(dockerfile)):
                continue  # build Dockerfile's final stage confirms a non-root USER (#804)
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{location}:{start_line}",
                message=(
                    f"Service '{service_name}' has no `user:` directive, so the "
                    "container runs as whatever user the referenced image defaults "
                    "to — root for the overwhelming majority of public base images. "
                    "This is the compose-level counterpart to a missing Dockerfile "
                    "`USER` instruction: even a non-root-built image can be forced "
                    "back to root by a compose override elsewhere, and this file "
                    "gives no evidence either way."
                ),
                remediation=(
                    'Add a non-root `user:` to the service, e.g. `user: "1000:1000"` '
                    "or `user: appuser` (matching a user created in the image's "
                    f"Dockerfile). Suppress an audited exception with `{_PRAGMA}` "
                    "anywhere in the compose file."
                ),
                rule="compose-user-directive-missing/no-user-directive",
                standards=list(_STANDARDS),
            ))
        return out
