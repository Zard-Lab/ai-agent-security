"""Guard: check-then-insert with no lock/conflict guard — TOCTOU race (checklist §7, new item).

Sourced from Strix's `skills/vulnerabilities/race_conditions.md`. A "check-then-act" pattern —
a SELECT/ORM existence check immediately followed, in the same function, by an INSERT/ORM
write with no lock or conflict-handling signal in between — is a textbook TOCTOU race:

    existing = db.query(User).filter(User.email == email).first()
    if existing is None:
        db.add(User(email=email))     # two concurrent requests can BOTH reach here
        db.commit()                   # before either commits -> duplicate row

Two concurrent requests can both pass the existence check before either request's write
lands, producing a duplicate/invariant-violating row. This is the classic double-signup,
double-redemption, double-booking bug class — silent, hard to reproduce, and invisible to
single-threaded testing.

**Deliberately narrow scope.** Strix's fuller race-condition class needs synchronized,
concurrent HTTP requests to actually exploit the timing window — that is inherently dynamic
and out of reach for static analysis. This guard flags only the STATIC SHAPE: a clear
existence check followed by a clear write on the apparent same table, with no visible
mitigation in the enclosing function. It does not, and cannot, prove the race is exploitable
in practice (connection pooling, DB-level locking elsewhere, or ORM session semantics can
still make a flagged pattern safe in ways this guard cannot see).

**Detected pattern — `check-then-insert`** (MEDIUM):

Within one function:
  1. An existence check: raw SQL `SELECT ... FROM <table> ... WHERE ...`, or ORM
     `.query(Model).filter(...).first()` / `.filter_by(...).first()` / `.one_or_none()` /
     `.get(...)`, or Flask-SQLAlchemy-style `Model.query.filter(...).first()`, or
     Django-style `Model.objects.filter(...).first()`.
  2. Later in the SAME function, a write on the apparent SAME table/model: raw SQL
     `INSERT INTO <table>`, or ORM `session.add(Model(...))` (only counted when the
     function also calls `.commit()` somewhere — otherwise the row is never actually
     persisted, and staging alone isn't the race), or Django-style `Model.objects.create(...)`.
  3. No mitigation signal anywhere in the enclosing function: `ON CONFLICT`,
     `ON DUPLICATE KEY`, `SELECT ... FOR UPDATE` / `.with_for_update(`, an explicit
     transaction-isolation-level signal (`isolation_level=`, `SERIALIZABLE`,
     `REPEATABLE READ`), or a unique-constraint-catching exception name
     (`IntegrityError`, `UniqueViolation`) anywhere in the function. The mitigation check is
     WHOLE-FUNCTION, not just the window between check and write, so a try/except wrapping
     the whole check-then-insert block (a common real mitigation shape) is honored even
     though the `except` clause appears after the write.

Table/model names are compared after a naive normalization (lowercase, strip one trailing
`s`) so a raw `users` table and an ORM `User` model are recognized as the same target.

**Suppress:** `# security: allow-sql-race-check-then-insert` anywhere in a file silences the
check for that entire file.

OWASP:A04 (Insecure Design), CWE-367 (Time-of-check Time-of-use Race Condition).
Gated on `python`.
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
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-sql-race-check-then-insert"

_STANDARDS = ["OWASP:A04", "CWE-367"]

# -- existence-check patterns (group(1) captures the table/model name) ----------------------
_RAW_SELECT_CHECK = re.compile(
    r"\bSELECT\b[^\n;]*?\bFROM\s+[\"'`]?([A-Za-z_]\w*)[\"'`]?[^\n;]*?\bWHERE\b",
    re.IGNORECASE,
)
# db.query(Model).filter(...)/.filter_by(...)....first()/.one_or_none()
_ORM_QUERY_FIRST = re.compile(
    r"\.query\s*\(\s*([A-Za-z_]\w*)\s*\)[^\n]*?"
    r"\.(?:filter|filter_by)\s*\([^\n]*?\)[^\n]*?\.(?:first|one_or_none)\s*\(\s*\)",
    re.IGNORECASE,
)
# db.query(Model).get(...)
_ORM_QUERY_GET = re.compile(
    r"\.query\s*\(\s*([A-Za-z_]\w*)\s*\)[^\n]*?\.get\s*\(",
    re.IGNORECASE,
)
# Flask-SQLAlchemy style: Model.query.filter(...)/.filter_by(...)....first()/.one_or_none()
_ORM_MODEL_QUERY_FIRST = re.compile(
    r"\b([A-Za-z_]\w*)\.query\s*\.(?:filter|filter_by)\s*\([^\n]*?\)[^\n]*?"
    r"\.(?:first|one_or_none)\s*\(\s*\)",
    re.IGNORECASE,
)
# Django style: Model.objects.filter(...).first() — pairs with the Django write pattern below.
_ORM_OBJECTS_FILTER_FIRST = re.compile(
    r"\b([A-Za-z_]\w*)\.objects\.filter\s*\([^\n]*?\)[^\n]*?\.first\s*\(\s*\)",
    re.IGNORECASE,
)
_CHECK_PATTERNS = (
    _RAW_SELECT_CHECK, _ORM_QUERY_FIRST, _ORM_QUERY_GET, _ORM_MODEL_QUERY_FIRST,
    _ORM_OBJECTS_FILTER_FIRST,
)

# -- write patterns (group(1) captures the table/model name) --------------------------------
_RAW_INSERT = re.compile(r"\bINSERT\s+INTO\s+[\"'`]?([A-Za-z_]\w*)[\"'`]?", re.IGNORECASE)
# session.add(Model(...)) — only a "write" once paired with a .commit() somewhere in the
# function (checked separately); staging alone never reaches the database.
_ORM_ADD = re.compile(r"\.add\s*\(\s*([A-Za-z_]\w*)\s*\(", re.IGNORECASE)
_ORM_COMMIT = re.compile(r"\.commit\s*\(\s*\)", re.IGNORECASE)
# Django-style Model.objects.create(...)
_DJANGO_CREATE = re.compile(r"\b([A-Za-z_]\w*)\.objects\.create\s*\(", re.IGNORECASE)

# -- mitigation signals (whole enclosing function) -------------------------------------------
_MITIGATION_SIGNAL = re.compile(
    r"\bON\s+CONFLICT\b"
    r"|\bON\s+DUPLICATE\s+KEY\b"
    r"|\bFOR\s+UPDATE\b"
    r"|\bwith_for_update\s*\("
    r"|\bisolation_level\s*="
    r"|\bSERIALIZABLE\b"
    r"|\bREPEATABLE\s+READ\b"
    r"|\bIntegrityError\b"
    r"|\bUniqueViolation\b",
    re.IGNORECASE,
)

_DEF = re.compile(r"[ \t]*(?:async[ \t]+)?def[ \t]")


def _function_spans(lines: list[str]) -> list[tuple[int, int]]:
    """(start, end) line-index pairs for every `def`/`async def` block in `lines`.

    Indentation-based, mirroring `_enclosing_def_span`'s inner walk elsewhere in this guard
    package (e.g. `llm_json_output_unvalidated.py`) but enumerating every function rather than
    resolving one line's enclosing scope — this guard needs to walk each function's body in
    order to see the check-before-insert relationship. Nested functions get their own
    (overlapping) span; each is scanned independently, which is harmless — a check-then-insert
    entirely inside a nested function still fires once, from that nested span.
    """
    spans: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if not _DEF.match(line):
            continue
        indent = len(line) - len(line.lstrip())
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
                break
            j += 1
        spans.append((i, j))
    return spans


def _norm_table(name: str) -> str:
    """Lowercase + strip one trailing `s` — a naive singular/plural fold so a raw `users`
    table and an ORM `User` model are recognized as the same target. Documented heuristic,
    not a schema-aware resolution."""
    n = name.strip("\"'`").lower()
    if len(n) > 1 and n.endswith("s"):
        n = n[:-1]
    return n


def _match_check(line: str) -> str | None:
    for pat in _CHECK_PATTERNS:
        m = pat.search(line)
        if m:
            return _norm_table(m.group(1))
    return None


def _match_insert(line: str, commit_present: bool) -> str | None:
    m = _RAW_INSERT.search(line)
    if m:
        return _norm_table(m.group(1))
    m = _ORM_ADD.search(line)
    if m and commit_present:
        return _norm_table(m.group(1))
    m = _DJANGO_CREATE.search(line)
    if m:
        return _norm_table(m.group(1))
    return None


class SqlRaceCheckThenInsertGuard(Guard):
    id = "sql-race-check-then-insert"
    title = "Check-then-insert with no lock/conflict guard — TOCTOU race"
    area = "Database"

    # signup.py: db.query(User).filter(User.email == email).first() (no match) then
    # db.add(User(email=email)); db.commit() -> fires
    # sql-race-check-then-insert/check-then-insert (no ON CONFLICT/FOR UPDATE/IntegrityError
    # anywhere in signup()). Must NOT contain: allow-sql-race-check-then-insert pragma.
    canary_plant = CanaryPlant(
        files={
            "signup.py": (
                "def signup(db, email):\n"
                "    existing = db.query(User).filter(User.email == email).first()\n"
                "    if existing is not None:\n"
                "        raise ValueError('already registered')\n"
                "    db.add(User(email=email))\n"
                "    db.commit()\n"
            ),
        },
        expects=frozenset({"sql-race-check-then-insert/check-then-insert"}),
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
                rel_path = rel(root, f)
                if is_nonproduct_path(rel_path, profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                # Blank triple-quoted docstring content so anti-pattern examples in this
                # guard's own module docstring (or a target repo's docstrings) don't self-match.
                stripped = strip_python_strings(text, filename=f)
                lines = stripped.splitlines()
                for start, end in _function_spans(lines):
                    out.extend(self._scan_function(rel_path, lines, start, end))
        return out

    def _scan_function(
        self, rel_path: str, lines: list[str], start: int, end: int
    ) -> list[Finding]:
        findings: list[Finding] = []
        scope_text = "\n".join(lines[start:end])
        if _MITIGATION_SIGNAL.search(scope_text):
            return findings

        commit_present = any(_ORM_COMMIT.search(lines[i]) for i in range(start, end))
        checks: list[tuple[int, str]] = []

        for i in range(start, end):
            line = lines[i]
            if line.lstrip().startswith("#"):
                continue

            check_table = _match_check(line)
            if check_table is not None:
                checks.append((i, check_table))

            insert_table = _match_insert(line, commit_present)
            if insert_table is None or not checks:
                continue

            for check_idx, check_table in reversed(checks):
                if check_idx >= i:
                    continue
                if check_table != insert_table:
                    continue
                lineno = i + 1
                findings.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel_path}:{lineno}",
                    message=(
                        "This function checks whether a row already exists, then inserts a "
                        "new one, with no lock or conflict-handling signal anywhere in the "
                        "function. Two concurrent requests can both pass the existence check "
                        "before either write commits, producing a duplicate or invariant-"
                        "violating row (the classic double-signup / double-redemption / "
                        "double-booking TOCTOU race)."
                    ),
                    remediation=(
                        "Close the race at the database, not in application logic: add a "
                        "unique constraint plus `ON CONFLICT ... DO NOTHING`/`DO UPDATE` "
                        "(Postgres) or catch the resulting `IntegrityError`/`UniqueViolation` "
                        "and treat it as the 'already exists' case, or take a row lock "
                        "(`SELECT ... FOR UPDATE` / `.with_for_update()`) before the check. "
                        "Reviewed and intentional? suppress with "
                        "`# security: allow-sql-race-check-then-insert`."
                    ),
                    rule="sql-race-check-then-insert/check-then-insert",
                    standards=list(_STANDARDS),
                ))
                break
        return findings
