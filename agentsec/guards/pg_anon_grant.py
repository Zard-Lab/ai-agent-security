"""Guard: GRANT to anon/public role in PostgreSQL/Supabase SQL files (§7 — Database Security).

In Supabase (and vanilla PostgreSQL with RLS), the `anon` and `public` roles are
inherited by every unauthenticated request.  Granting table-level or schema-level
permissions to these roles means that any visitor — before they log in — has direct
read or write access to the granted objects, bypassing Row Level Security entirely.

The pattern that triggers this guard:

    GRANT SELECT ON TABLE users TO anon;     -- HIGH: anon = unauthenticated callers
    GRANT ALL    ON SCHEMA app  TO public;   -- HIGH: public = every PG principal incl. anon

False positives are kept low by requiring the TO keyword to be followed immediately
by `anon` or `public` as a standalone word.  Grants to other roles — `authenticated`,
`service_role`, named application roles — are **not** flagged, and REVOKE statements
are not flagged.

**Detection approach:**
1. Blank SQL block comments (`/* ... */`) and line comments (`-- ...`) to spaces so a suppressed
   or commented-out GRANT does not produce a spurious finding. Blanked, not deleted: deleting a
   multi-line `/* … */` header took its newlines with it and shifted every later finding's line
   number up (#442).
2. Scan the blanked text line-by-line for lines matching:
       GRANT\\s+.+\\s+ON\\s+.+\\s+TO\\s+(?:anon|public)\\b   (case-insensitive)
3. One Finding per matching line.

**Checklist item:** `7-no-grant-to-anon-public`

**Suppress:** Add a `-- security: allow-pg-anon-grant` comment anywhere in a .sql file (e.g.
at the top) to silence this check for that file only.  Use only when the
grant is intentional and Row Level Security policies are confirmed in place on every
affected table.
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
    read,
    rel,
    sql_code_lines,
    strip_sql_comments,
)

_PRAGMA = "security: allow-pg-anon-grant"

_STANDARDS = ["OWASP:A01", "CIS:6.3"]

# GRANT <privileges> ON <object> TO anon|public, detected as three ordered keyword hits
# (see `_grants_to_anon`) instead of one `GRANT\s+.+\s+ON\s+.+\s+TO\s+…` regex — two
# unbounded greedy `.+` runs backtrack quadratically on a hostile long line (issue #419).
# Case-insensitive so `grant`, `Grant`, `GRANT` all match.
_GRANT_KW = re.compile(r"\bGRANT\s", re.IGNORECASE)
_ON_TOKEN = re.compile(r"\sON\s", re.IGNORECASE)
_TO_ANON = re.compile(r"\sTO\s+(?:anon|public)\b", re.IGNORECASE)
# A GRANT EXECUTE ON FUNCTION/ROUTINE/PROCEDURE is an RPC-call grant, NOT direct
# table/schema access — it does not "bypass RLS" (the function body still runs under
# its own definer/invoker rules). Calibrate those to MEDIUM with an accurate message;
# table/schema/sequence grants stay HIGH (real RLS-bypass for unauthenticated callers).
_ON_FUNCTION = re.compile(r"\bON\s+(?:ALL\s+)?(?:FUNCTION|ROUTINE|PROCEDURE)S?\b", re.IGNORECASE)
# `GRANT USAGE ON SCHEMA` only grants namespace access (needed for the anon RPC pattern),
# not table data — LOW. `GRANT ALL/CREATE ON SCHEMA` is NOT this and stays HIGH.
_GRANT_USAGE_SCHEMA = re.compile(r"\bGRANT\s+USAGE\s+ON\s+SCHEMA\b", re.IGNORECASE)
# The granted routine's bare name (drop schema + args), to cross-reference against definers.
_GRANT_FN_NAME = re.compile(
    r"\bON\s+(?:ALL\s+)?(?:FUNCTION|ROUTINE|PROCEDURE)S?\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?", re.IGNORECASE
)
# A function defined `SECURITY DEFINER` runs with the definer's privileges and BYPASSES the
# caller's RLS — so EXECUTE-to-anon on it IS a real RLS bypass (the `exec_sql` class), not a
# benign RPC. `SECURITY DEFINER` may sit in the header OR after the `$$…$$` body, so we scan
# from the function name up to the NEXT `CREATE …` (which would mis-attribute one function's
# definer clause to another). The scan is two bounded searches per function head — the old
# tempered `(?:(?!\bCREATE\s).)*?` lazy regex re-checked the lookahead per char per head,
# quadratic on hostile input (issue #419).
_DEFINER_FN_HEAD = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?\b",
    re.IGNORECASE,
)
_CREATE_KW = re.compile(r"\bCREATE\s", re.IGNORECASE)
_SECURITY_DEFINER = re.compile(
    r"\bSECURITY\s+DEFINER\b",
    re.IGNORECASE,
)


def _definer_fn_names(sql: str) -> set[str]:
    """Bare names of `SECURITY DEFINER` functions: for each `CREATE … FUNCTION <name>`,
    look for `SECURITY DEFINER` in the span up to the next `CREATE …` (spans are
    disjoint, so the whole scan is linear — issue #419)."""
    names: set[str] = set()
    for m in _DEFINER_FN_HEAD.finditer(sql):
        nxt = _CREATE_KW.search(sql, m.end())
        if _SECURITY_DEFINER.search(sql, m.end(), nxt.start() if nxt else len(sql)):
            names.add(m.group(1).lower())
    return names


def _grants_to_anon(line: str) -> bool:
    """`GRANT … ON … TO anon|public` on this line — three ordered, linear searches.

    Marginally laxer than the `GRANT\\s+.+\\s+ON\\s+.+\\s+TO\\s+…` regex it replaced: the old
    `.+` runs required ≥1 char between the keywords, so a privilege-list-less
    `GRANT  ON x TO anon` (invalid SQL — a privilege list is mandatory) now matches where it
    didn't before. FP-direction only, unreachable in real migrations (PR #430 review)."""
    g = _GRANT_KW.search(line)
    if g is None:
        return False
    o = _ON_TOKEN.search(line, g.end())
    if o is None:
        return False
    return _TO_ANON.search(line, o.end()) is not None


class PgAnonGrantGuard(Guard):
    id = "pg-anon-grant"
    title = "GRANT to anon/public role bypasses RLS for unauthenticated callers"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/grants.sql: GRANT ... TO anon / public -> fires pg-anon-grant/grant-to-anon-public.
    # (A separate SQL file so changes here cannot collide with the sql/schema.sql plants.)
    canary_plant = CanaryPlant(
        files={
            "sql/grants.sql": (
                "-- permissions\n"
                "GRANT SELECT ON TABLE users TO anon;\n"
                "GRANT INSERT ON TABLE messages TO public;\n"
            ),
        },
        expects=frozenset({"pg-anon-grant/grant-to-anon-public"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        sql_files = iter_files(root, (".sql",))
        # Pre-scan: names of SECURITY DEFINER functions across all SQL. EXECUTE-to-anon on one
        # of these bypasses RLS (the definer body runs privileged), so it escalates to HIGH.
        definer_fns: set[str] = set()
        for f in sql_files:
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="sql"):
                continue
            definer_fns |= _definer_fn_names(strip_sql_comments(raw))

        for f in sql_files:
            raw = read(f)
            # File-level pragma: skip the whole file if it opts out.
            if pragma_present(_PRAGMA, raw, dialect="sql"):
                continue
            # Blank comments before scanning so commented-out GRANTs are ignored. Line-aligned
            # with the raw file (#442): `strip_sql_comments(raw)` deletes a `/* … */` block's
            # newlines too, which reported every GRANT below a license header too high.
            for lineno, line in enumerate(sql_code_lines(raw), start=1):
                if not _grants_to_anon(line):
                    continue
                if _GRANT_USAGE_SCHEMA.search(line):
                    # Schema USAGE grants namespace access, not table data — and is needed for
                    # the anon RPC pattern. LOW, not the RLS-bypass HIGH. (GRANT ALL/CREATE ON
                    # SCHEMA is not USAGE and falls through to HIGH below.)
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="low",
                            title="GRANT USAGE ON SCHEMA to anon/public — namespace access, not table data",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "This grants the `anon`/`public` role USAGE on a schema — the ability to "
                                "reference objects in it, not to read or write any table. It is required "
                                "for the Supabase anon RPC pattern (calling functions in the schema). It "
                                "does not bypass RLS by itself; the tables under the schema still need RLS."
                            ),
                            remediation=(
                                "Usually intentional. Confirm every table in the schema has Row Level "
                                "Security enabled with scoped policies (USAGE alone exposes nothing). To "
                                "silence, add `-- security: allow-pg-anon-grant`."
                            ),
                            rule="pg-anon-grant/grant-to-anon-public",
                            standards=list(_STANDARDS),
                        )
                    )
                    continue
                if _ON_FUNCTION.search(line):
                    fn_match = _GRANT_FN_NAME.search(line)
                    fn_name = fn_match.group(1).lower() if fn_match else None
                    if fn_name and fn_name in definer_fns:
                        # EXECUTE to anon on a SECURITY DEFINER function: the body runs privileged
                        # and bypasses the caller's RLS — a real exposure (the `exec_sql` class).
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="GRANT EXECUTE to anon on a SECURITY DEFINER function — bypasses RLS",
                                location=f"{rel(root, f)}:{lineno}",
                                message=(
                                    f"This grants `anon`/`public` EXECUTE on `{fn_name}`, which is defined "
                                    "`SECURITY DEFINER` — its body runs with the definer's privileges and "
                                    "bypasses the caller's Row Level Security. An unauthenticated caller can "
                                    "read or write whatever the function touches, regardless of RLS policies "
                                    "(the `exec_sql`-class exposure). Confirm the body enforces its own "
                                    "authorization."
                                ),
                                remediation=(
                                    "Make the function `SECURITY INVOKER` (so RLS applies to the caller), or "
                                    "enforce explicit per-caller authorization inside the definer body, or "
                                    "grant EXECUTE only to authenticated roles. Intentional and audited? add "
                                    "`-- security: allow-pg-anon-grant`."
                                ),
                                rule="pg-anon-grant/grant-to-anon-public",
                                standards=list(_STANDARDS),
                            )
                        )
                        continue
                    # EXECUTE-on-function grant: anon can CALL the routine, but this is not
                    # direct table access and does not itself bypass RLS. Medium, accurate msg.
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="GRANT EXECUTE to anon/public — unauthenticated callers can run this routine",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "This GRANT lets the `anon`/`public` role EXECUTE a function/procedure. "
                                "Unauthenticated callers can invoke it (e.g. as a Supabase RPC). This is "
                                "not direct table access, but confirm the routine is RLS-aware: a "
                                "`SECURITY DEFINER` body can read/write tables regardless of the caller's "
                                "RLS, so anon-callable definer functions need careful, scoped logic."
                            ),
                            remediation=(
                                "Grant EXECUTE only to authenticated roles unless the routine is "
                                "intentionally public. If public, ensure it is `SECURITY INVOKER` (or a "
                                "definer body that enforces its own authorization) and never returns more "
                                "than an unauthenticated caller should see. Intentional? add "
                                "`-- security: allow-pg-anon-grant`."
                            ),
                            rule="pg-anon-grant/grant-to-anon-public",
                            standards=list(_STANDARDS),
                        )
                    )
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="GRANT to anon/public role bypasses RLS for unauthenticated callers",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "This GRANT gives the `anon` or `public` PostgreSQL role direct "
                            "table/schema access. In Supabase (and standard PG deployments), "
                            "every unauthenticated request runs as `anon`, which inherits "
                            "`public`. A GRANT at this level bypasses Row Level Security — "
                            "unauthenticated callers can read or write the granted objects "
                            "regardless of any RLS policies on the table."
                        ),
                        remediation=(
                            "Remove the GRANT and ensure Row Level Security is enabled on "
                            "every affected table (`ALTER TABLE t ENABLE ROW LEVEL SECURITY`). "
                            "Grant only to authenticated application roles (e.g. `authenticated`, "
                            "`service_role`, or a named role). If the grant is intentional "
                            "(e.g. a public read-only table with RLS policies enforced), add "
                            "`-- security: allow-pg-anon-grant` to the file and confirm RLS "
                            "policies are in place."
                        ),
                        rule="pg-anon-grant/grant-to-anon-public",
                        standards=list(_STANDARDS),
                    )
                )
        return out
