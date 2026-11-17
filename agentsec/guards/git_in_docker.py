"""Guard: .git directory included in Docker image (OWASP:A05 — Security Misconfiguration).

When a Docker image is built without a `.dockerignore` that excludes `.git`, the entire
git history is copied into the image layer. This exposes:

  - Full commit history including deleted files and old content
  - Author names and email addresses from every commit
  - Commit messages that may reference internal systems, tickets, or sensitive decisions
  - Secrets accidentally committed and later removed (they remain in history)
  - Branch names, tags, and internal workflow patterns

The `.git` directory is invisible in a running container unless an attacker achieves
arbitrary file read or command execution — but at that point, it dramatically raises
the impact: a credential found in a removed file may still be valid; email addresses
enable targeted phishing; history reveals the application's internal architecture.

Two detection patterns:

  **`git-not-in-dockerignore`** (MEDIUM): A `Dockerfile` exists at the root and the
  `.dockerignore` is either missing or does not contain `.git` on its own line. One
  finding is emitted per project (not per Dockerfile), because the `.dockerignore` is
  a single project-level control.

  Same rule also fires for explicit `COPY .git` lines in any Dockerfile (direct evidence
  of intentional inclusion — probably a developer computing the build version from git
  metadata without realizing the full `.git` directory is copied).

**Why MEDIUM?** The exposure is real — secrets and PII in git history — but exploitability
requires prior access (the attacker must be inside the container, or the image must be
leaked). A standalone credential exposure would be HIGH; this is a defence-in-depth miss.

**Suppress:** add `# security: allow-git-in-docker` to the Dockerfile (or `.dockerignore`)
to silence this check when git metadata is intentionally included (e.g., a build-tools
image where the full repo history is needed by a build step and the image is never
deployed to a customer-facing environment).

**Checklist item:** `6a-git-metadata-not-deployed` (§6a — Frontend Security).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_dockerfiles, pragma_present, read, rel

_PRAGMA = "security: allow-git-in-docker"

_STANDARDS = ["OWASP:A05"]

# Matches an explicit "COPY .git" instruction in a Dockerfile (with optional trailing
# content like "COPY .git /app/.git" or "COPY .git .").
_COPY_GIT = re.compile(r"^[^\S\n]*COPY\s+\.git\b", re.MULTILINE | re.IGNORECASE)

def _has_broad_context_copy(text: str) -> bool:
    """True if any `COPY . <dest>` / `ADD . <dest>` (a whole-build-context copy, optionally with
    `--flags`) appears — that pulls `.git` into the image. A Dockerfile that only does scoped copies
    (`COPY backend /app`) cannot include the repo's `.git`, so a missing `.dockerignore` is harmless
    there (the dominant false positive: nested-service Dockerfiles that never `COPY .`). Plain string
    ops, not a regex — avoids a (linear-but-) nested-quantifier ReDoS match."""
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].upper() in ("COPY", "ADD"):
            args = [a for a in parts[1:] if not a.startswith("--")]
            if args and args[0] == ".":
                return True
    return False


def _dockerignore_has_git_entry(text: str) -> bool:
    """Return True if the .dockerignore text contains '.git' or '.git/' on its own line.

    Both forms are functionally equivalent — Docker normalizes trailing slashes — so
    a '.git/' entry (the trailing-slash style some editors/tools generate) correctly
    suppresses this finding.
    """
    for line in text.splitlines():
        stripped = line.strip().rstrip("/")
        if stripped == ".git":
            return True
    return False


class GitInDockerGuard(Guard):
    id = "git-in-docker"
    title = ".git directory not excluded from Docker image"
    area = "Containers"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `Dockerfile`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # Dockerfile: no .dockerignore with .git -> git-not-in-dockerignore (file-absence guard).
    canary_plant = CanaryPlant(expects=frozenset({"git-in-docker/git-not-in-dockerignore"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        # All Dockerfile spellings (Dockerfile, Dockerfile.<x>, *.dockerfile), matching the
        # discovery every other docker guard uses (#422 S12).
        dockerfiles = iter_dockerfiles(root)
        if not dockerfiles:
            return []

        # Read all relevant texts up front.
        di_path = root / ".dockerignore"
        di_text = read(di_path) if di_path.exists() else ""
        df_texts = [(df, read(df)) for df in dockerfiles]

        # If the pragma appears in any Dockerfile or in .dockerignore, suppress all findings.
        if pragma_present(_PRAGMA, di_text, dialect="hash") or any(
            pragma_present(_PRAGMA, text, dialect="hash") for _, text in df_texts
        ):
            return []

        out: list[Finding] = []

        # Pattern 1: explicit COPY .git lines in any Dockerfile.
        for df, text in df_texts:
            if _COPY_GIT.search(text):
                for i, line in enumerate(text.splitlines(), 1):
                    if _COPY_GIT.match(line):
                        out.append(Finding(
                            check_id=self.id,
                            severity="medium",
                            title=self.title,
                            location=f"{rel(root, df)}:{i}",
                            message=(
                                "An explicit `COPY .git` instruction copies the entire git history "
                                "into the image. This exposes commit messages, author emails, branch "
                                "names, and any secrets that were committed and later removed."
                            ),
                            remediation=(
                                "Remove the `COPY .git` line. If you need the git commit SHA for "
                                "version metadata, pass it as a build argument instead: "
                                "`ARG GIT_SHA` and set it at build time with "
                                "`docker build --build-arg GIT_SHA=$(git rev-parse --short HEAD)`."
                            ),
                            rule="git-in-docker/git-not-in-dockerignore",
                            standards=list(_STANDARDS),
                        ))

        # Pattern 2: a Dockerfile is covered when a `.dockerignore` with a `.git` entry sits **next to
        # it** OR at the repo root (a Dockerfile in a subdir keeps its own `.dockerignore` — checking
        # only the root one was a false positive on monorepos / nested services).
        root_covered = _dockerignore_has_git_entry(di_text)
        for df, text in df_texts:
            # Only a broad `COPY .`/`ADD .` can pull `.git` in; a scoped-copy Dockerfile is safe.
            if not _has_broad_context_copy(text):
                continue
            sib = df.parent / ".dockerignore"
            sib_exists = sib.exists()
            if root_covered or (sib_exists and _dockerignore_has_git_entry(read(sib))):
                continue
            if sib_exists:
                location = rel(root, sib)
                message = (
                    "The `.dockerignore` beside this Dockerfile exists but does not contain a `.git` "
                    "entry. Without it, `docker build` copies the entire git history into the image, "
                    "exposing commit messages, author emails, and secrets removed from source but "
                    "still present in history."
                )
                remediation = "Add `.git` on its own line in this `.dockerignore`."
            else:
                location = rel(root, df)
                message = (
                    "This Dockerfile has no `.dockerignore` (beside it or at the repo root) containing "
                    "`.git`, so the entire git history can be copied into the image — exposing commit "
                    "messages, author emails, and secrets removed from source but still in history."
                )
                remediation = (
                    "Create a `.dockerignore` next to this Dockerfile (or at the repo root) and add "
                    "`.git` as an entry, so git history is never included in the image."
                )
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=location,
                message=message,
                remediation=remediation,
                rule="git-in-docker/git-not-in-dockerignore",
                standards=list(_STANDARDS),
            ))

        return out
