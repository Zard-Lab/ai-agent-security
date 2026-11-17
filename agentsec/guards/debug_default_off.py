"""Guard: DEBUG must default to False (checklist §6a).

A web app left with `DEBUG = True` (or `FastAPI(debug=True)`, or a settings class
whose `DEBUG` default is `True`) leaks stack traces, file paths, and configuration
to anyone who triggers an error — and in some frameworks exposes an interactive
debugger that is straight RCE. The fail-safe default is False, with debug enabled
only via an explicit dev-only env toggle.

Fires HIGH on a literal `debug = True` assignment (any case; with or without a type
annotation). Reading from the environment (`DEBUG = os.getenv(...)`) does not match
— only a hardcoded `True` does. Suppress an intentional case with:

    DEBUG = True  # security: allow-debug-true
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
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

# `DEBUG = True`, `debug=True`, `DEBUG: bool = True` — RHS must be the literal True.
_DEBUG_TRUE = re.compile(r"\bdebug\b\s*(?::\s*\w+\s*)?=\s*True\b", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-debug-true")


class DebugDefaultOffGuard(Guard):
    id = "debug-default-off"
    title = "DEBUG defaults to False"
    area = "Web setup"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # hardcoded DEBUG = True (fires debug-default-off)
    canary_plant = CanaryPlant(
        files={
            "config.py": "DEBUG = True\n",
        },
        expects=frozenset({"debug-default-off/debug-enabled"}),
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
                raw = read(f)
                text = strip_python_strings(raw, filename=f)
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040), numbered on the text walked below (a form feed in a docstring
                # shifts the raw count, #1132).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, line in enumerate(text.splitlines(), start=1):
                    if line.lstrip().startswith("#"):
                        continue  # commented-out line
                    if not _DEBUG_TRUE.search(line):
                        continue
                    if i in pragmas:
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="DEBUG enabled (should default to False)",
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "`debug = True` is hardcoded. In production this leaks stack "
                                "traces / config on error, and some frameworks expose an "
                                "interactive debugger (RCE). DEBUG should default to False."
                            ),
                            remediation=(
                                "Default to False and enable debug only via an explicit dev "
                                "env toggle, e.g. `DEBUG = os.getenv(\"DEBUG\", \"\") == \"1\"`. "
                                "If intentional, suppress with `# security: allow-debug-true`."
                            ),
                            rule="debug-default-off/debug-enabled",
                            standards=["OWASP:A05"],
                        )
                    )
        return out
