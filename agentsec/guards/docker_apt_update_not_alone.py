"""Guard: Dockerfile RUN updates the package index without installing in the same layer
(checklist §5, CIS Docker Benchmark 4.9-adjacent).

    RUN apt-get update
    RUN apt-get install -y curl

Each `RUN` instruction becomes its own Docker image layer, and layers are cached
independently. If `apt-get update` runs in one layer and `apt-get install` runs in a
LATER, separate layer, a rebuild that only invalidates the install layer (a common
result of Docker's layer-caching rules — e.g. a change earlier in the Dockerfile that
doesn't touch the update line) reuses the OLD cached update layer's stale package
index. The install layer then installs whatever version was available at the time the
update layer was last actually rebuilt — which may be missing security patches
released since. Combining `update` and `install` in the same `RUN` instruction forces
both to invalidate together, so the package index is always fresh when packages are
actually installed. checkov's own `CKV_DOCKER_5` check exists for this exact pattern.

Fires MEDIUM when a `RUN` instruction's command (backslash line continuations joined)
contains an update keyword (`apt-get update`, `apt update`, `yum update`, `dnf update`,
`apk update`) but no install-family keyword (`install`, `upgrade`, `add`, `dist-upgrade`,
`reinstall`, `groupinstall`, `localinstall`) anywhere in that same instruction.

Suppress an audited case (e.g. a deliberately separate update-only layer for image-build
tooling that never installs anything) with `# security: allow-docker-update-not-alone`
on the RUN line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_dockerfiles, pragma_present, read, rel

_RUN_LINE = re.compile(r"^\s*RUN\s+(?P<cmd>.+)$", re.IGNORECASE)
_UPDATE_CMD = re.compile(
    r"\b(?:apt-get|apt|yum|dnf|apk)\s+(?:-\S+\s+)*update\b", re.IGNORECASE
)
# Anchor the install verb to an actual package-manager invocation (mirroring _UPDATE_CMD)
# rather than a bare word — otherwise a stray "install"/"add" in an echo string or a path
# (`RUN apt-get update && echo "will install later"`) masks a genuine update-only layer (FN).
_INSTALL_CMD = re.compile(
    r"\b(?:apt-get|apt|yum|dnf|apk)\s+(?:-\S+\s+)*"
    r"(?:install|upgrade|add|dist-upgrade|reinstall|groupinstall|localinstall)\b",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-docker-update-not-alone")

_STANDARDS = ["OWASP:A06", "CIS:Docker"]


def _join_continuations(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued Dockerfile lines into logical lines. Returns
    `(start_lineno, joined_text)` pairs, 1-indexed."""
    raw_lines = text.splitlines()
    out: list[tuple[int, str]] = []
    i = 0
    n = len(raw_lines)
    while i < n:
        start = i + 1
        parts = [raw_lines[i]]
        while parts[-1].rstrip().endswith("\\") and i + 1 < n:
            i += 1
            parts.append(raw_lines[i])
        joined = " ".join(p.rstrip().rstrip("\\").rstrip() for p in parts)
        out.append((start, joined))
        i += 1
    return out


class DockerAptUpdateNotAloneGuard(Guard):
    id = "docker-apt-update-not-alone"
    title = "Dockerfile updates package index in a layer separate from install"
    area = "Containers"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `Dockerfile.apt-update`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # Dockerfile.apt-update: RUN apt-get update alone -> fires update-without-install.
    canary_plant = CanaryPlant(expects=frozenset({"docker-apt-update-not-alone/update-without-install"}))

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for lineno, joined in _join_continuations(text):
            m = _RUN_LINE.match(joined)
            if not m:
                continue
            cmd = m.group("cmd")
            if cmd.lstrip().startswith("#"):
                continue
            if not _UPDATE_CMD.search(cmd):
                continue
            if _INSTALL_CMD.search(cmd):
                continue
            # The joined logical line is the text the shell runs, so its view pairs quotes across
            # the continuations: the same slice as before, only a comment counts now.
            if pragma_present(_PRAGMA, joined, dialect="hash"):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "This RUN instruction updates the package index but does not "
                        "install anything in the same layer. Docker caches each RUN "
                        "instruction as an independent layer — a rebuild that reuses "
                        "this cached update layer while rebuilding a later install "
                        "layer installs packages against a stale index, which can "
                        "silently install versions missing security patches released "
                        "since the update layer was last actually rebuilt."
                    ),
                    remediation=(
                        "Combine the update and install into the same RUN instruction "
                        "with `&&`, e.g. `RUN apt-get update && apt-get install -y "
                        "curl`, so both invalidate together and the package index is "
                        "always fresh when packages are installed. Suppress an "
                        "audited exception with `# security: allow-docker-update-not-"
                        "alone` on the RUN line."
                    ),
                    rule="docker-apt-update-not-alone/update-without-install",
                    standards=list(_STANDARDS),
                )
            )
        return out
