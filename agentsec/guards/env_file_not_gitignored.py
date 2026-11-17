"""Guard: a real `.env*` file exists in the repo with no `.gitignore` exclusion covering it
(checklist §8 — Secrets, new item; agent-audit-kit's `secret_exposure.py` AAK-SECRET-006).

A `.env` file holding real local credentials is a normal, expected artifact of local
development — the actual risk is not that it exists, but that nothing stops the NEXT
`git add .` from committing it. This is a hygiene/exposure-surface check, distinct from
every other secret guard in this codebase: it does not read the file's CONTENT for a
credential shape at all (that is `vite-client-secret`'s, `env-secret-logged`'s, and the
generic secret guards' job) — it only asks whether the file is structurally protected from
an accidental commit.

Fires HIGH when a real `.env*` file (not a `.example`/`.sample`/`.template`/`.dist`
template variant, which are meant to be committed) is found and either:

  1. no `.gitignore` exists anywhere in the repo at all, or
  2. a `.gitignore` exists but no whole, active line of it matches the file: the line is
     glob-matched (`fnmatch`) against the file's name, so `.env`, `/.env`, `**/.env`, `.env*`,
     `*.env` and the file's own exact name all count. A `#` comment line never counts, a
     `!negation` line un-ignores whatever it matches (last matching line wins, as in git), and
     a substring hit does not count: `.env.local` does NOT cover `.env`, and `.env.*` does not
     cover a bare `.env` (it needs a dot after the name).

This is a line-level glob check against `.gitignore`'s content, not a full gitignore engine:
the `.gitignore` files of the whole repo are read as one list (which directory a rule came
from is not modeled), a trailing-slash directory rule is treated as not covering a file, and
character-class edge cases follow Python's `fnmatch` rather than git's wildmatch.

Does NOT re-detect: any secret VALUE inside the `.env` file — that is every other
secret-content guard's job. This guard fires even on a `.env` containing no real secrets at
all, because the exposure risk (an accidental future commit) exists independent of what is
in the file today.

Suppress an audited/intentional case with `# security: allow-env-file-not-gitignored`
anywhere in the `.gitignore` file (or, if none exists, this guard has no file to place a
pragma in — add an empty `.gitignore` with the pragma as a comment to suppress).
"""
from __future__ import annotations

import re
from fnmatch import fnmatchcase
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

_PRAGMA = re.compile(r"#\s*security:\s*allow-env-file-not-gitignored")

# Template/example .env variants are meant to be committed — never real secrets, never
# flagged regardless of gitignore coverage.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

_STANDARDS = ["CWE-538", "OWASP:A05"]


def _is_real_env_file(name: str) -> bool:
    if name == ".env":
        return True
    if not name.startswith(".env."):
        return False
    return not name.endswith(_TEMPLATE_SUFFIXES)


def _gitignore_covers(gitignore_text: str, filename: str, rel_path: str | None = None) -> bool:
    """True when the last `.gitignore` line matching `filename` is an ignore (not a `!`
    negation). Only whole, non-comment lines count: a substring hit (`.env` inside `.env.local`,
    inside `# .env`, inside `!.env`) is not coverage."""
    covered = False
    for raw in gitignore_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
        pattern = line
        if pattern.startswith("**/"):
            pattern = pattern[3:]
        pattern = pattern.lstrip("/")
        if not pattern or pattern.endswith("/"):
            continue  # a directory-only rule never covers a file
        target = rel_path if ("/" in pattern and rel_path is not None) else filename
        if fnmatchcase(target, pattern):
            covered = not negated
    return covered


class EnvFileNotGitignoredGuard(Guard):
    id = "env-file-not-gitignored"
    title = "A .env file exists with no .gitignore exclusion"
    area = "Secrets"

    # .env: a real env file at repo root, no .gitignore anywhere -> fires
    # env-file-not-gitignored. Must NOT contain: a .gitignore covering .env*, or the pragma.
    canary_plant = CanaryPlant(
        files={
            ".env": "DATABASE_URL=postgres://canary:canary@localhost/canarydb\n",
        },
        expects=frozenset({
            "env-file-not-gitignored/no-exclusion",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # A .env file is a near-universal local-dev artifact, independent of stack.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        env_files = [
            f for f in iter_files_named(root, ".env*", respect_gitignore=False)
            if _is_real_env_file(f.name)
        ]
        if not env_files:
            return out

        gitignore_files = iter_files_named(root, ".gitignore", respect_gitignore=False)
        gitignore_text = "\n".join(read(g) for g in gitignore_files)
        # `hash`: a `.gitignore` comment is a `#` line. The view keeps a mid-line ` #` too, where git
        # reads a pattern (more view, as the raw match was), and drops only a quoted span.
        if pragma_present(_PRAGMA, gitignore_text, dialect="hash"):
            return out

        for f in env_files:
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments, credential_scan=True):
                continue
            if _gitignore_covers(gitignore_text, f.name, r):
                continue
            out.append(self._finding(root, f, r))
        return out

    def _finding(self, root: Path, f: Path, r: str) -> Finding:  # noqa: ARG002
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=r,
            message=(
                f"`{f.name}` exists in the repo, but no `.gitignore` pattern covers it "
                "(`.env`/`.env*`/`.env.*`/`*.env`, or the file's own name) as an active, "
                "non-negated line. Nothing stops "
                "a future `git add .` from committing this file's contents — whatever "
                "real local credentials it holds today, or holds later."
            ),
            remediation=(
                "Add `.env*` to `.gitignore` (or the file's exact name, if only specific "
                "variants should be excluded). If this file is a committed TEMPLATE with "
                "no real secrets, rename it with a `.example`/`.sample`/`.template` suffix "
                "so this check recognizes it as intentionally tracked."
            ),
            rule="env-file-not-gitignored/no-exclusion",
            standards=list(_STANDARDS),
        )
