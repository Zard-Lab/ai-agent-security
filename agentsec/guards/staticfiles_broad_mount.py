"""Guard: StaticFiles mounted at root or parent directory (OWASP:A05 / CWE-552).

Mounting FastAPI's `StaticFiles` at "." (current dir), "/" (filesystem root), or ".."
(parent dir) serves the entire project tree — including source code, `.env` files,
private keys, and internal modules — as static HTTP assets. An attacker who discovers
the mount point can download any file the process can read.

The two detectable patterns are:

  **`root-or-parent-dir-mounted`** (HIGH): A `StaticFiles(directory=".")`,
  `StaticFiles(directory="/")`, or `StaticFiles(directory="..")` argument appearing in
  a `mount()` call or a direct constructor call. The "/" case exposes the full filesystem;
  "." and ".." expose the project tree (source, secrets, config). Both are exploitable
  without authentication once the HTTP server starts serving the route.

**Why HIGH?** A single GET request retrieves `.env` (API keys, database passwords), the
application source (proprietary logic, hardcoded tokens), or any file the process user
can read. The impact is complete credential exposure + intellectual property loss. No
authentication or rate-limit protects a static-file mount.

**Checklist item:** `6a-staticfiles-safe-mount` (§6a — Frontend Security, partial —
catches direct literal directory paths; indirect paths through variables are not detected).

**Suppress:** Add `# security: allow-staticfiles-mount` anywhere in the file to silence
this check for that file. Use only when you have confirmed the directory argument has been
validated to a safe, scoped subdirectory at runtime.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-staticfiles-mount"

_STANDARDS = ["OWASP:A05", "CWE-552"]

# Matches StaticFiles(directory=".") / StaticFiles(directory="/") / StaticFiles(directory="..")
# also catches the html= keyword variant and optional whitespace around the argument.
_STATICFILES_DIRECT = re.compile(
    r"""StaticFiles\s*\(\s*(?:directory|html)\s*=\s*['"](?:\.|/|\.\.)['"]""",
)

# Matches mount("/route", StaticFiles(directory=".")) — the app.mount pattern.
_STATICFILES_MOUNT = re.compile(
    r"""mount\s*\(\s*['"][^'"]*['"]\s*,\s*StaticFiles\s*\(\s*directory\s*=\s*['"](?:\.|/)['"]""",
)


class StaticfilesBroadMountGuard(Guard):
    id = "staticfiles-broad-mount"
    title = "StaticFiles mounted at project root or filesystem root — exposes source code and secrets"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `static_mount.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # static_mount.py: StaticFiles(directory=".") -> root-or-parent-dir-mounted.
    canary_plant = CanaryPlant(expects=frozenset({"staticfiles-broad-mount/root-or-parent-dir-mounted"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features or "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[Path] = set()

        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)

                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue

                # Blank triple-quoted docstring/template CONTENT so the StaticFiles-root
                # EXAMPLES in a docstring (this guard's own module docstring self-matches, issue
                # #424) don't fire. Single-line calls in real code are unaffected.
                for lineno, line in enumerate(strip_python_strings(text, filename=f).splitlines(), 1):
                    if _STATICFILES_DIRECT.search(line) or _STATICFILES_MOUNT.search(line):
                        findings.append(Finding(
                            check_id=self.id,
                            severity="high",
                            title="StaticFiles mounted at project root or filesystem root",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "A FastAPI `StaticFiles` mount uses \".\" (current directory), "
                                "\"/\" (filesystem root), or \"..\" (parent directory) as its "
                                "directory argument. This serves the entire project tree — "
                                "including source code, `.env` files with API keys and database "
                                "passwords, private keys, and internal configuration — as "
                                "publicly readable HTTP assets. An attacker who discovers the "
                                "mount point can retrieve any file the process user can read "
                                "with a single GET request."
                            ),
                            remediation=(
                                "Point `StaticFiles` at a purpose-built, content-only directory "
                                "(e.g. `StaticFiles(directory=\"static\")` or "
                                "`StaticFiles(directory=\"frontend/build\")`). "
                                "That directory should contain only files intended for public "
                                "access: built JS/CSS/images, never source files or "
                                "environment configuration. If this mount is intentional and "
                                "scoped safely at runtime, suppress with "
                                "`# security: allow-staticfiles-mount`."
                            ),
                            rule="staticfiles-broad-mount/root-or-parent-dir-mounted",
                            standards=list(_STANDARDS),
                        ))
                        break  # one finding per file is sufficient

        return findings
