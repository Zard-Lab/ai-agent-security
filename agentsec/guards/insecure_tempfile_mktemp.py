"""Guard: insecure tempfile.mktemp() usage (§8, new item).

`tempfile.mktemp()` generates a temporary filename and returns it **without creating
the file** — there is a window between the name being generated and the caller opening
it during which another process (or a malicious local user) can create a file at that
same path first, a classic TOCTOU race condition (CWE-377, Insecure Temporary File).
The Python docs themselves say plainly: "Use of this function may introduce a security
hole in your program." It has been effectively deprecated in favor of `mkstemp()` since
Python 2.3.

Unlike `mktemp()`, the safe alternatives create the file **atomically** at generation
time: `tempfile.mkstemp()` (returns an open fd), `tempfile.NamedTemporaryFile()`, and
`tempfile.TemporaryDirectory()` are not flagged — this guard targets the deprecated
function by name only.

Fires HIGH on any `tempfile.mktemp(` call (the function itself is unsafe regardless of
its arguments — there's no "safe" way to call it).

Suppress an audited case with `# security: allow-insecure-tempfile-mktemp`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = re.compile(r"#\s*security:\s*allow-insecure-tempfile-mktemp")

_STANDARDS = ["CWE-377"]

# `(?<!\.)` guards against a rare `.mktemp(` on an unrelated object; the leading
# `tempfile.` requirement already does most of the work.
_MKTEMP = re.compile(r"\btempfile\s*\.\s*mktemp\s*\(")


class InsecureTempfileMktempGuard(Guard):
    id = "insecure-tempfile-mktemp"
    title = "Insecure tempfile.mktemp() usage (race condition)"
    area = "Files"

    # tempfile.mktemp() -> insecure-tempfile-mktemp.
    canary_plant = CanaryPlant(
        files={
            "exporter.py": "import tempfile\n\npath = tempfile.mktemp(suffix='.csv')\n",
        },
        expects=frozenset({"insecure-tempfile-mktemp/mktemp-race-condition"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect="python"):
            return out
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            if not _MKTEMP.search(line):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "`tempfile.mktemp()` returns a filename without creating the "
                    "file — a race window exists between name generation and the "
                    "caller opening it, during which another process or a malicious "
                    "local user can create a file at that path first (CWE-377). The "
                    "Python docs describe this function as a potential security hole."
                ),
                remediation=(
                    "Use `tempfile.mkstemp()` (creates the file atomically, returns "
                    "an open fd + path), `tempfile.NamedTemporaryFile()`, or "
                    "`tempfile.TemporaryDirectory()` instead. Suppress with "
                    "`# security: allow-insecure-tempfile-mktemp` only after "
                    "confirming the environment has no other local users."
                ),
                rule="insecure-tempfile-mktemp/mktemp-race-condition",
                standards=list(_STANDARDS),
            ))
        return out
