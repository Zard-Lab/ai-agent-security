"""Guard: SQLAlchemy text()/raw execute() must use bound params, not string-built SQL (checklist 3a-sqlalchemy-text-parameterized).

The classic SQL-injection sink in a SQLAlchemy/FastAPI app is an f-string (or
`.format()` / `+`) built straight into `text(...)` or a raw `.execute(...)`:

    db.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))   # injectable

You cannot parameterize an f-string — it interpolates at runtime, before the
driver ever sees it. The fix is bound parameters: `text("... WHERE email = :email")`
plus an params dict. This is one of the most common AI-generated DB bugs.

Fires HIGH on a line where `text(...)` / `execute(...)` wraps an interpolated string
(an `f"..."`, a `.format(...)`, or `"..." + var`) AND the line carries a SQL
keyword (so a non-SQL `execute()` does not trip it). Safe parameterized calls
(`text("... :id")`, `execute("... %s", (v,))`) do NOT fire. A reviewed case can
suppress the line with `# security: allow-raw-sql`.

OWASP:A03 (Injection). Gated on `python`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
    strip_python_strings,
)

# The opening of a text()/execute()/executemany() call — we then extract only its FIRST
# argument (the SQL), so an interpolation on a LATER argument (a benign `"x" + y` / `.format()`
# after the call's real `)`) cannot trigger a false positive.
_CALL = re.compile(r"\b(?:text|execute|executemany)\s*\(", re.I)
# Within that first argument, an interpolated string:
#   f"..."            (f-string — cannot be parameterized)
#   "...".format(...) (str.format)
#   "..." + var       (concatenation with an identifier; "..." + "lit" is NOT matched)
# `["'].*?["']` requires the string to CLOSE before the marker so an in-string `)` (e.g.
# COUNT(*)) is spanned while a bare `)` alone is not; the arg boundary already bars siblings.
_INTERP_IN_ARG = re.compile(r'f["\']|["\'].*?["\']\s*(?:\.format\b|\+\s*\w)', re.I)
# A SQL keyword on the line — precision backstop so a non-SQL execute() is silent.
_SQL_KW = re.compile(r"\b(?:select|insert|update|delete|where|from|join|values|union)\b", re.I)
_PRAGMA = re.compile(r"#\s*security:\s*allow-raw-sql")


def _first_arg(line: str, open_paren: int) -> str:
    """The first positional argument of the call whose `(` is at `open_paren`.

    Bracket- AND quote-aware: stops at a depth-0 comma or the call's own closing `)`, so a
    string/concat in a SIBLING argument never leaks into the check. `\\` escapes are honored
    inside string literals. Mirrors the ssti/ssrf first-arg extractors."""
    rest = line[open_paren + 1 :]
    depth = 0
    quote: str | None = None
    i = 0
    n = len(rest)
    while i < n:
        ch = rest[i]
        if quote is not None:
            if ch == "\\":
                i += 2  # skip the escaped char
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]  # the call's own closing paren
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:i]
        i += 1
    return rest


class SqlalchemyTextParameterizedGuard(Guard):
    id = "sqlalchemy-text-parameterized"
    title = "String-built SQL in text()/execute() — SQL injection"
    area = "Code safety"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared `reports.py`,
    # which several guards trip at once, so the file stays in `canary.py`'s base owned by no guard. The
    # ownership rule this follows is documented on `xxe_safe.py`.
    # reports.py: an f-string built into text() -> string-built-sql.
    canary_plant = CanaryPlant(expects=frozenset({"sqlalchemy-text-parameterized/string-built-sql"}))

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
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = strip_python_strings(read(f), filename=f)
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040), numbered on the text walked below (a form feed in a docstring
                # shifts the raw count, #1132).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, raw_line in enumerate(text.splitlines(), start=1):
                    if raw_line.lstrip().startswith("#") or i in pragmas:
                        continue
                    # Strip a trailing `#` comment (string-safe) so a `text("SELECT ...")` mention
                    # inside a trailing comment doesn't trip detection (the #362 class, #424).
                    line = strip_python_line_comment(raw_line)
                    # A call is injectable only if its OWN first argument interpolates; a
                    # string/format on a sibling argument is benign.
                    interp = any(
                        _INTERP_IN_ARG.search(_first_arg(line, m.end() - 1))
                        for m in _CALL.finditer(line)
                    )
                    if interp and _SQL_KW.search(line):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "This builds SQL by string interpolation (f-string / .format / "
                                    "concatenation) inside `text()`/`execute()`. The interpolated "
                                    "value is not bound, so it is SQL-injectable."
                                ),
                                remediation=(
                                    "Use bound parameters: `text(\"... WHERE col = :name\")` with a "
                                    "params dict, or `execute(stmt, {\"name\": value})`. Never "
                                    "f-string user input into SQL. If reviewed/static, suppress with "
                                    "`# security: allow-raw-sql`."
                                ),
                                rule="sqlalchemy-text-parameterized/string-built-sql",
                                standards=["OWASP:A03"],
                            )
                        )
        return out
