"""Phase 1 gap-reporting — local gap-memory + `agentsec report-gap` command.

The gap-memory (~/.agentsec/gaps.json) is a local-only write recording the
first-seen date for each uncovered stack detected during an audit or detect run.
No network access. The report-gap command opens a pre-filled GitHub issue in the
browser so the user can file a gap report with one click.
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from urllib.parse import quote

from agentsec import AGENTSEC_REPO_SLUG

# The one repo-identity switch point lives in `agentsec/__init__.py`; never a second literal here.
_REPO = AGENTSEC_REPO_SLUG


def _gaps_file() -> Path:
    """Return the local gap-memory file path (~/.agentsec/gaps.json)."""
    return Path.home() / ".agentsec" / "gaps.json"


def record_gaps(stacks: set[str], today: date | None = None) -> None:
    """Silently record uncovered stacks to the local gap-memory file. No network.

    First-seen date is preserved — a stack recorded once is never updated.
    Skips the write entirely if no new stacks are found (cheap hot-path).
    Never raises: any I/O or parse error is silently swallowed so a gap-memory
    hiccup cannot abort an audit.
    """
    if not stacks:
        return
    try:
        path = _gaps_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        seen: dict[str, str] = {}
        if path.exists():
            try:
                seen = json.loads(path.read_text(encoding="utf-8")).get("seen", {})
            except (OSError, json.JSONDecodeError):
                seen = {}  # corrupt gap file — treat as empty and overwrite
        day = str(today or date.today())
        if all(s in seen for s in stacks):
            return  # nothing new — skip the write
        for s in stacks:
            seen.setdefault(s, day)
        path.write_text(
            json.dumps({"seen": seen}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001  # nosec B110
        pass  # gap-memory is best-effort; never block an audit


def list_gaps() -> dict[str, str]:
    """Return {stack: first_seen_date} from the local gap-memory file."""
    try:
        path = _gaps_file()
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        seen = data.get("seen", {}) if isinstance(data, dict) else {}
        return seen if isinstance(seen, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _issue_url(stack: str) -> str:
    title = f"feat: add {stack} guards"
    body = (
        f"## Stack gap report\n\n"
        f"**Stack:** `{stack}`\n\n"
        f"I ran `agentsec audit` on a `{stack}` project and agentsec has no guards "
        f"for this stack yet. The baseline checks ran, but `{stack}`-specific "
        f"security patterns were not inspected.\n\n"
        f"**What I am building:** (describe your app briefly)\n\n"
        f"**agentsec version:** (run `agentsec --version`)\n\n"
        f"---\n_Filed via `agentsec report-gap {stack}`_"
    )
    return (
        f"https://github.com/{_REPO}/issues/new"
        f"?title={quote(title)}&body={quote(body)}&labels={quote('gap-report')}"
    )


def issue_url(stack: str) -> str:
    """The pre-filled GitHub issue URL for a stack gap. Pure: no network, no browser."""
    return _issue_url(stack)


def open_in_browser(url: str) -> None:
    """Open `url` in the user's browser — invoked ONLY on explicit `--open`. agentsec
    itself sends nothing; the browser navigates to a prefilled issue the user reviews.
    `webbrowser` is imported lazily so this module's top-level imports stay network-free
    (the G5 guardrail; asserted by tests/test_gap_report.py)."""
    import webbrowser  # noqa: PLC0415  # lazy on purpose — keep module imports network-free

    webbrowser.open(url)
