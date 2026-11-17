"""Guard: fire-and-forget background tasks must handle their own exceptions.

Ported from donor `scripts/security/check_background_tasks.py`. An exception in a
coroutine scheduled with `asyncio.create_task(...)`/`ensure_future(...)` and never
awaited is silently dropped. A *bare* fire-and-forget call (the scheduling call
starts the statement — not assigned/returned/awaited/stored) must carry a
`background-safe` marker asserting its body guards its own exceptions.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, python_scan_dirs, read, rel

_BARE_SPAWN = re.compile(
    r"^\s*(?:asyncio|loop|self\._loop|self\.loop)\.(?:create_task|ensure_future)\("
)
_MARKER = "background-safe"


class BackgroundTasksGuard(Guard):
    id = "background-tasks"
    title = "Fire-and-forget task without exception handling"
    area = "Reliability"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `app.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"background-tasks/unguarded-create-task"}))

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
                # Skip test/offline tooling (+ the repo's opt-in archive trees) — offline scripts
                # aren't a served surface. Honors `.agentsec/config.json` archive_paths.
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                for i, line in enumerate(read(f).splitlines(), start=1):
                    if _BARE_SPAWN.match(line) and _MARKER not in line:
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="low",
                                title=self.title,
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "Bare fire-and-forget task; an unhandled exception in its "
                                    "body is silently dropped."
                                ),
                                remediation=(
                                    "Wrap the coroutine body in try/except with logging (or a safe "
                                    f"wrapper) and add a `# {_MARKER}` marker, or store/await the task."
                                ),
                                rule="background-tasks/unguarded-create-task",
                                standards=["OWASP:A09"],
                            )
                        )
        return out
