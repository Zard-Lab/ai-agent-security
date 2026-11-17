"""Guard: Dockerfile FROM uses the `:latest` tag or no tag at all (docker-latest-base-tag).

Terrascan source: ``pkg/policies/opa/rego/docker/docker_from/imageVersionnotusinglatest.rego``
(rule ``AC_DOCKER_0001`` family) fires on either of:

    contains(config, ":latest")     # explicit :latest
    not contains(config, ":")       # no tag at all -> Docker defaults to :latest

**Threat:** `:latest` (explicit or implicit) is a mutable, unpinned pointer — the exact
bytes it resolves to can change between any two builds with no diff in the Dockerfile
itself. A build today and a build next week can silently pull a different base image: a
new OS patch level is usually harmless, but the maintainer can also ship a compromised or
malicious image under the same `:latest` tag (or the tag can point at an entirely different,
unrelated image after a registry migration), and there is no way to tell from the Dockerfile
that anything changed. This is the base-image analog of an unpinned dependency in a lockfile
— reproducibility and supply-chain integrity both suffer. A version tag (`python:3.12-slim`)
is already a meaningful improvement; a content digest (`python@sha256:...`) is the strongest
form — this guard flags the weakest form (no tag discipline at all), which is a distinct,
more severe case than "tagged but not digest-pinned".

**Detection:** every `FROM` instruction's image reference is checked. The final path
segment (after the last `/`, so a registry host or namespace with its own colon — e.g.
`registry:5000/app` — isn't mistaken for a tag) is inspected for a `:tag` suffix. Missing
entirely, or literally `:latest`, both fire. A `FROM ... AS <stage>` alias is stripped
before parsing. `FROM scratch` and multi-stage `FROM <previous-stage-name>` references
(no registry-resolvable image, nothing to pin) are excluded.

**Suppress:** add `# security: allow-latest-tag` to the Dockerfile to silence this check
(e.g. a local dev-only Dockerfile that intentionally tracks upstream `latest`).

**Checklist item:** `5-base-image-digest-pinned` (currently `partial`) — this guard covers
the "no tag / `:latest`" end of that spectrum; a tagged-but-non-digest image is a separate,
narrower gap this guard does not flag.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_example_template_file,
    iter_dockerfiles,
    join_dockerfile_continuations,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-latest-tag"

_STANDARDS = ["OWASP:A06", "CWE-1104"]

# `FROM [--platform=...] <image>[:<tag>|@<digest>] [AS <stage>]`
# Anchored `^[^\S\n]*`, NOT `^\s*`: under re.MULTILINE a `\s*` after `^` also matches at every
# BLANK line and then scans forward across the whole blank run — quadratic on a long run of
# blank lines, which `join_dockerfile_continuations` manufactures (one per folded
# `\`-continuation, to keep line numbers stable). `[^\S\n]` is every whitespace EXCEPT the
# newline: same-line indentation keeps the full `\s` vocabulary (tab, form feed, NBSP — Docker's
# parser trims leading whitespace with Go's unicode.IsSpace, so an NBSP-indented Dockerfile
# builds, and `[ \t]*` was measured to silently miss it, #696 round 2), while the one character
# that crosses lines is excluded. See the fuller note on `_stage_names` below (#676 / #696
# review rounds). This also makes the reported line number exact: the match can no longer start
# on a blank line above the instruction.
_FROM_INSTRUCTION = re.compile(
    r"^[^\S\n]*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def _stage_names(text: str) -> set[str]:
    """Names introduced by `FROM ... AS <name>` — a later `FROM <name>` references a build
    stage, not a pullable image, so it can't be pinned and must be excluded."""
    # Three constraints, each closing a measured blow-up (#676, then the #696 review round):
    #
    # 1. The image span starts on `[^\s]`, disjoint from the leading `\s+` — the original #676
    #    fix. `FROM\s+.+\s+AS` partitioned an in-line whitespace run cubically:
    #    non-terminating at ~1,000 continuation lines folded ahead of the image token.
    # 2. The span is bounded, `.{0,300}?` — the disjoint first char alone leaves the span
    #    ambiguous against the TRAILING `\s+AS` when no ` AS <stage>` exists (quadratic:
    #    47.5s at a 128KB single line, #696 review). An image span longer than 301 chars
    #    stops registering its alias, so a later `FROM <alias>` reads as an unpinned image: a
    #    deliberate, disclosed trade, pinned at the boundary by its tests.
    # 3. Anchored `^[^\S\n]*`, not `^\s*` — under re.MULTILINE, `^\s*FROM` also anchors at every
    #    BLANK line and rescans the remainder of the blank run from each one (quadratic:
    #    measured 1.24s at 20,000 blank lines even with 1+2 in place). The joiner manufactures
    #    exactly that run — one blank line per folded `\`-continuation, kept for stable line
    #    numbers — so both whitespace shapes come from ordinary benign formatting. The class
    #    excludes ONLY the newline: same-line indentation keeps the full `\s` vocabulary (see
    #    `_FROM_INSTRUCTION` above for the NBSP case that rules out `[ \t]*`).
    #
    # Captures are identical on every valid `FROM ... AS <stage>` form at or under the bound
    # (equivalence sweeps on #676 and the #696 review round).
    return {
        m.group(1)
        for m in re.finditer(
            r"^[^\S\n]*FROM\s+[^\s].{0,300}?\s+AS\s+(\S+)\s*$", text, re.MULTILINE | re.IGNORECASE
        )
    }


def _is_unpinned(image_ref: str, stage_names: set[str]) -> bool:
    if image_ref.lower() == "scratch":
        return False
    if image_ref in stage_names:
        return False  # references an earlier build stage, not a registry image
    if "@" in image_ref:
        return False  # digest-pinned (sha256:...) — the strongest form, out of scope here
    # Only the final path segment can carry a tag; a registry host:port (`registry:5000/x`)
    # must not be mistaken for `image:tag`.
    last_segment = image_ref.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return True  # no tag at all -> implicit :latest
    tag = last_segment.rsplit(":", 1)[-1]
    return tag.lower() == "latest"


class DockerLatestBaseTagGuard(Guard):
    id = "docker-latest-base-tag"
    title = "Docker base image not pinned to a version tag"
    area = "Containers"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `Dockerfile.hardening-canary`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # Dockerfile.hardening-canary carries all 5 docker-* violations at once.
    canary_plant = CanaryPlant(expects=frozenset({"docker-latest-base-tag/unpinned-from"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            # A `*.example` / `*.user.example` Dockerfile is a user-customization TEMPLATE, not a
            # built image — an unpinned `FROM` there is not a deployed risk (round-2 §D.7). This is
            # a guard-local skip: `*.example` is a guard-relative non-product surface, deliberately
            # not in the shared `is_nonproduct_path` list (a `.env.example` is a real attack surface
            # for other guards). Matched case-INSENSITIVELY: the original `str.endswith` missed
            # `Dockerfile.EXAMPLE` while the dev-compose pattern beside it was already
            # case-insensitive (#484 review).
            if is_example_template_file(f.name):
                continue
            text = join_dockerfile_continuations(read(f))
            if not text.strip() or pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            rel_path = rel(root, f)
            stages = _stage_names(text)
            for m in _FROM_INSTRUCTION.finditer(text):
                image_ref = m.group(1)
                if not _is_unpinned(image_ref, stages):
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel_path}:{line_no}",
                        message=(
                            f"`FROM {image_ref}` has no version tag (or uses `:latest`), a "
                            "mutable pointer that can resolve to different bytes on every "
                            "build with no visible change to the Dockerfile — a supply-chain "
                            "and reproducibility risk."
                        ),
                        remediation=(
                            "Pin to a specific version tag at minimum (e.g. "
                            f"`FROM {image_ref.split(':')[0]}:3.12-slim`), or a content "
                            "digest for the strongest guarantee "
                            f"(`FROM {image_ref.split(':')[0]}@sha256:<digest>`)."
                        ),
                        rule="docker-latest-base-tag/unpinned-from",
                        standards=list(_STANDARDS),
                    )
                )
        return out
