"""Guard: docker-compose service image pinned to a tag but not a digest (checklist §5).

    services:
      app:
        image: myapp:1.4.2      # a tag can be silently overwritten on the registry

A version tag can be overwritten on the registry at any time — a pull today and a pull
next week are not guaranteed to return the same bytes. `docker-latest-base-tag` already
flags a Dockerfile `FROM` with no tag or an explicit `:latest` (the weakest end of this
spectrum); this guard covers the adjacent, narrower gap that guard's own docstring names
as out of its scope: a compose service pinned to a REAL version tag (`myapp:1.4.2`, not
`:latest`) still isn't immutable without a `@sha256:` digest. CWE-1104 (Use of Unmaintained
Third Party Components), OWASP:A08.

Sourced from compose-lint's `ImageNoDigestRule` (`CL-0019`). Extends checklist item
`5-base-image-digest-pinned` (already `partial` via `hadolint`/`docker-latest-base-tag`)
rather than opening a new item — same coverage gap, a different file type and a narrower
tag-vs-digest slice of it.

Fires MEDIUM on a service `image:` value that has an explicit tag (not `:latest`/`:edge`/
`:stable`/`:main`/`:master`/`:nightly` — those mutable-by-convention tags are
`docker-latest-base-tag`'s territory, not this guard's, to avoid double-reporting the
same line) and no `@sha256:` digest.

Suppress an audited case with `# security: allow-compose-image-digest` anywhere in the
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

_PRAGMA = "# security: allow-compose-image-digest"

_STANDARDS = ["OWASP:A08", "CWE-1104", "CIS:Docker"]

_MUTABLE_TAGS = frozenset({"latest", "edge", "stable", "main", "master", "nightly"})

_IMAGE_LINE = re.compile(r"^\s*image\s*:\s*(?:['\"])?(?P<ref>[^'\"#\s]+)")


def _split_image_ref(image: str) -> tuple[str, str | None]:
    """(repo, tag) — the tag is the part after the LAST colon past the last slash, so a
    registry host with its own port (`registry:5000/app`) isn't mistaken for a tag."""
    last_slash = image.rfind("/")
    tag_region = image[last_slash + 1 :]
    if ":" not in tag_region:
        return image, None
    repo_part, _, tag = image.rpartition(":")
    return repo_part, tag


class ComposeImageDigestMissingGuard(Guard):
    id = "compose-image-digest-missing"
    title = "Docker-compose service image pinned to a tag but not a digest"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.digest.yml": (
                "services:\n"
                "  canary:\n"
                "    image: myapp:1.4.2\n"
            ),
        },
        expects=frozenset({"compose-image-digest-missing/tag-not-digest"}),
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
            for line_no, raw in body:
                if raw.lstrip().startswith("#"):
                    continue
                m = _IMAGE_LINE.match(raw)
                if not m:
                    continue
                image = m.group("ref")
                if "@sha256:" in image:
                    break
                _repo, tag = _split_image_ref(image)
                if tag is None or tag.lower() in _MUTABLE_TAGS:
                    break
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{location}:{line_no}",
                    message=(
                        f"Service '{service_name}' image '{image}' is pinned to a tag "
                        "but not a digest. Tags can be overwritten on the registry, so "
                        "this does not guarantee image immutability."
                    ),
                    remediation=(
                        f"Add a digest pin: `image: {image}@sha256:<digest>`. Use "
                        "Dependabot or Renovate to keep digests current. Suppress an "
                        f"audited exception with `{_PRAGMA}` anywhere in the compose "
                        "file."
                    ),
                    rule="compose-image-digest-missing/tag-not-digest",
                    standards=list(_STANDARDS),
                ))
                break
        return out
