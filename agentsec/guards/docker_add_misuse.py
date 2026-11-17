"""Guard: Dockerfile `ADD` used where `COPY`/`RUN curl` would be safer (docker-add-misuse).

Two real, verified terrascan patterns, both from the same policy family
(``pkg/policies/opa/rego/docker/docker_add/``), combined here because they're the same
underlying anti-pattern — `ADD` doing more than the author asked for:

**Pattern 1 — `addinsteadofcopy.rego`:** `ADD` used to place a local archive
(`.tar`/`.tar.gz`/`.tgz`/`.tar.bz2`/`.tar.xz`) into the image. Unlike `COPY`, `ADD`
**auto-extracts** a recognized local archive at the destination — a behavior that is easy
to not realize is happening. A build step that means "put this file in the image" instead
silently unpacks its contents, which can plant unexpected files at unexpected paths
(including, in the worst case, overwriting something security-relevant if the destination
already exists) with no line in the Dockerfile that says "extract".

**Pattern 2 — `CurlWgetinsteadofAdd.rego`:** `ADD` used with a remote `http://`/`https://`
URL as the source. `ADD <url> <dest>` fetches and writes the remote content with **no
integrity verification** available in the instruction itself (no checksum, no TLS pinning
control) and the result isn't removable in the same layer even if discarded later — it's
baked in. Docker's own documentation recommends `RUN curl -fsSL <url> -o x && ...` (or
`wget`) instead, specifically so the fetch can be checksum-verified and cache-busted
deliberately, in the same `RUN` layer as any cleanup.

Both are a supply-chain / build-integrity concern: an `ADD` line that silently extracts an
archive or fetches unverified remote content is exactly the kind of implicit behavior that
lets a compromised or tampered artifact slip into an image layer unnoticed at review time.

**Suppress:** add `# security: allow-docker-add` to the Dockerfile to silence both patterns
for that file (e.g. a build stage where the auto-extraction is intentional and reviewed).

**Checklist item:** no existing item covers `ADD` misuse specifically — new item needed
under the docker/container-hardening section.
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

_PRAGMA = "security: allow-docker-add"

_STANDARDS = ["OWASP:A08", "CWE-494"]

# `ADD <src> ... <dest>` (also matches `ADD ["src", "dest"]` JSON-array form — the archive/URL
# tokens land at the front either way, so a simple word split after the instruction works for
# both forms once we drop brackets/quotes).
_ADD_INSTRUCTION = re.compile(r"^[^\S\n]*ADD\s+(.+)$", re.MULTILINE | re.IGNORECASE)

_ARCHIVE_EXT = re.compile(r"\.(?:tar(?:\.(?:gz|bz2|xz))?|tgz|tbz2?)$", re.IGNORECASE)
_URL_SRC = re.compile(r"^https?://", re.IGNORECASE)


def _add_sources(args: str) -> list[str]:
    """Every source token in an ADD instruction's argument list (all but the last -- the
    last token is always the destination). Handles both the shell form
    (`ADD a.tar.gz b.tar.gz /dest`) and the JSON-array form (`ADD ["a.tar.gz", "/dest"]`)."""
    stripped = args.strip()
    if stripped.startswith("["):
        # JSON-array form: split on commas, strip brackets/quotes/whitespace.
        inner = stripped.strip("[]")
        tokens = [t.strip().strip("'\"") for t in inner.split(",") if t.strip()]
    else:
        # Shell form: drop any `--chown=`/`--chmod=`/`--checksum=` flags first.
        tokens = [t for t in stripped.split() if not t.startswith("--")]
    return tokens[:-1] if len(tokens) > 1 else []


class DockerAddMisuseGuard(Guard):
    id = "docker-add-misuse"
    title = "Dockerfile ADD used instead of COPY/RUN curl"
    area = "Containers"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `Dockerfile.hardening-canary`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # Dockerfile.hardening-canary carries all 5 docker-* violations at once.
    canary_plant = CanaryPlant(expects=frozenset({"docker-add-misuse/add-local-archive"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            text = join_dockerfile_continuations(read(f))
            if not text.strip() or pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            rel_path = rel(root, f)
            for m in _ADD_INSTRUCTION.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                sources = _add_sources(m.group(1))
                for src in sources:
                    if _URL_SRC.match(src):
                        out.append(self._url_finding(rel_path, line_no, src))
                        break  # one finding per ADD line is enough signal
                    if _ARCHIVE_EXT.search(src):
                        out.append(self._archive_finding(rel_path, line_no, src))
                        break
        return out

    def _archive_finding(self, location: str, line_no: int, src: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{location}:{line_no}",
            message=(
                f"`ADD {src} ...` copies a local archive — ADD auto-extracts recognized "
                "archives at the destination, which is easy to not realize is happening and "
                "can plant unexpected files at unexpected paths."
            ),
            remediation=(
                "Use `COPY` instead if you only want the archive file placed in the image "
                "(no extraction). If extraction IS intended, prefer an explicit "
                "`RUN tar -xzf ... && rm ...` so the behavior is visible in the Dockerfile."
            ),
            rule="docker-add-misuse/add-local-archive",
            standards=list(_STANDARDS),
        )

    def _url_finding(self, location: str, line_no: int, src: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{location}:{line_no}",
            message=(
                f"`ADD {src} ...` fetches a remote URL directly — the instruction has no "
                "way to verify the content's integrity (no checksum), unlike an explicit "
                "download step."
            ),
            remediation=(
                "Use `RUN curl -fsSL <url> -o <file> && ...` (or `wget`) so the fetch can be "
                "checksum-verified and any cleanup happens in the same layer."
            ),
            rule="docker-add-misuse/add-remote-url",
            standards=list(_STANDARDS),
        )
