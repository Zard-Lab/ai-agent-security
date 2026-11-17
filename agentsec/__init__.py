"""agentsec — stack-aware security audit tool for FastAPI + React + Postgres + LLM/RAG apps."""
from __future__ import annotations

import json
from pathlib import Path


def _checklist_version() -> str:
    """The package version IS the checklist registry version (single source of truth —
    see pyproject `[tool.hatch.version]`). Read straight from the shipped JSON so
    `__version__` always reflects the on-disk checklist, even in an editable checkout."""
    try:
        data = json.loads(
            (Path(__file__).parent / "checklist" / "checklist.json").read_text(encoding="utf-8")
        )
        return str(data["version"])
    except (OSError, ValueError, KeyError):
        return "0+unknown"


__version__ = _checklist_version()

# ---------------------------------------------------------------------------
# Canonical repo identity: the public repository users install from, pin in CI and file issues
# on. The ONE place to change if it ever moves; Python code imports these (including
# scripts/cut-release.py and scripts/regen-versions-json.py).
#
# Non-Python files can't import this, so they are separate switch points. When
# you flip the slug below, also update (`git grep -i "<old owner>/ai-agent-security"`):
#   - README.md                       (the "Run it in CI" `uses:` snippet, the dev-install line,
#                                      and every absolute doc link)
#   - pyproject.toml                  (`[project.urls]`, shown on the PyPI project page)
#   - docs/user-guide.md §16          (the action's `uses:` line and the pre-commit `repo:` line;
#                                      action.yml itself names no slug: it reads
#                                      `github.action_repository` for its feedback links)
#   - BREAKING_CHANGES.md, docs/infographic/*.html, wiki/  (migration recipes, install hints, links)
#   - .github/ISSUE_TEMPLATE/config.yml  (`contact_links` — GitHub requires ABSOLUTE urls
#                                        here, so the Discussions/SECURITY.md links cannot
#                                        be made relative and are a real switch point)
# tests/test_ci_library.py pins the expected URL, and tests/test_packaging.py checks every public
# text file's repo pointers against this constant: your switch-point tripwires.
# ---------------------------------------------------------------------------
AGENTSEC_REPO_SLUG = "Zard-Lab/ai-agent-security"
AGENTSEC_REPO_URL = f"https://github.com/{AGENTSEC_REPO_SLUG}"
