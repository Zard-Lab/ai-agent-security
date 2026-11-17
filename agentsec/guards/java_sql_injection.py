"""Guard: Java SQL query built from string concatenation, not parameterized (checklist 3b-sql-parameterized).

JDBC's `Statement`/`PreparedStatement` sinks (`.executeQuery(...)`/`.executeUpdate(...)`/
`.execute(...)` on a `Statement`, `Connection.prepareStatement(...)`) and Hibernate's
`Session.createQuery(...)`/`.createSQLQuery(...)` all treat the query-text argument as opaque SQL,
sent to the driver/ORM verbatim. The safe idiom is a STATIC query string with `?` placeholders,
with untrusted values bound afterward as SEPARATE parameters:

    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
    ps.setString(1, userId);                                            // safe — parameterized

The vulnerable pattern bakes the value straight into the query TEXT itself via Java's `+` string
concatenation operator, either inline at the call site or through an intermediate variable:

    stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);                     // injectable
    String sql = "SELECT * FROM users WHERE id = " + userId;
    stmt.executeQuery(sql);                                                            // injectable

Once the value is part of the query string, the driver/ORM has no placeholder to bind against —
this is classic SQL injection (CWE-89): read/write arbitrary rows, bypass a `WHERE`-clause auth
check, in the worst case chain further statements depending on driver/DB support.

This is the Java-side counterpart to `go-sql-injection` (Go/`database/sql`) and `js-sql-injection`
(JS/Node) — same threat shape, different call surface. Sourced from Find Security Bugs' real rule
set (`SQL_INJECTION_JDBC` and its siblings `SQL_INJECTION_HIBERNATE`/`SQL_INJECTION_JPA`/
`SQL_INJECTION_SPRING_JDBC`, sink lists `injection-sinks/sql-jdbc.txt` etc. — cited for provenance
only; detection logic and test fixtures here are original, developed independently against the
pattern description, not copied or derived from that (Java) source).

Fires HIGH under a single rule, **`concatenated-query`**, on two distinct shapes — both require the
call's own query argument to look like real SQL (a quoted string starting with `SELECT `/`INSERT `/
`UPDATE `/`DELETE `, case-insensitive) AND to be built with `+` concatenation, not a receiver-name
heuristic. This is the deliberate precision choice: rather than trying to tell a `Statement`/`stmt`
receiver apart from an unrelated object that happens to expose an `.execute(...)` method (a job
queue, a shell-command wrapper, a test double), the guard requires the ARGUMENT ITSELF to read as
SQL. A `.execute(cmd)` call on an unrelated object almost never has an argument shaped like
`"SELECT ... " + x` — that shape is what makes this SQL, not the receiver's name.

  1. **Inline** — the concatenation happens directly inside the sink call's own first argument:
     `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)`.
  2. **Variable, short lookback** — `String sql = "SELECT ... " + userId;` assigned on one of the
     up-to-5 lines immediately before a line that passes that same bare identifier as the sink
     call's first argument. Deliberately SHORT and textual (same-file, same-function-ish
     proximity) — not dataflow. A concatenated query assigned further back, threaded through a
     second variable, or built across a method/return boundary is not traced; see "Known bypasses"
     in the design doc.

A `?`-placeholder `PreparedStatement` with no concatenation, or a fully static literal query
string, never matches either shape (no `+`) and stays silent — the safe idiom is not flagged.

Suppress an audited case (e.g. a query confirmed to concatenate only fixed, internal constants —
never attacker-reachable input) with `// security: allow-java-sql-injection` on the sink call's own
line, or — for the variable-lookback shape — on the assignment line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    java_scan_dirs,
    read,
    rel,
    strip_java_comments,
)

_PRAGMA = "security: allow-java-sql-injection"

_STANDARDS = ["CWE-89", "OWASP:A03"]

# JDBC Statement-family (`.executeQuery`/`.executeUpdate`/`.execute`), `Connection.prepareStatement`,
# and Hibernate `Session.createQuery`/`.createSQLQuery` — every one of these takes the query text as
# its OWN first positional argument, so no per-method arg-index mapping is needed (unlike Go's
# Context-vs-non-Context split). The leading `.` requires a method call on some receiver, not a
# bare/unrelated function sharing the name.
_SINK_CALL = re.compile(
    r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createSQLQuery)\s*\("
)

# A quoted string that reads as real SQL (starts with a SELECT/INSERT/UPDATE/DELETE keyword,
# case-insensitive — real-world code is not always uppercase) followed by `+` concatenation. This
# is the precision gate: matching the ARGUMENT's own shape, not the receiver's name, so an unrelated
# `.execute(...)` call on some other object (whose argument is never SQL-shaped) does not false-fire.
_SQL_CONCAT = re.compile(
    r'"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\n]*"\s*\+', re.IGNORECASE
)

# `[<type>] <ident> = "SELECT ..." + ...;` — a query built via concatenation and assigned to a
# variable, one physical line (the common Java idiom: `String sql = "..." + x;`). Captures the
# identifier so a LATER bare-identifier sink call can be matched back to this assignment.
_SQL_ASSIGN = re.compile(
    r'^\s*(?:[A-Za-z_]\w*(?:<[^>]*>)?(?:\[\])?\s+)?(\w+)\s*=\s*'
    r'"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\n]*"\s*\+',
    re.IGNORECASE,
)
_BARE_IDENT = re.compile(r"^[A-Za-z_]\w*$")

# How many lines above a bare-identifier sink call to look back for its concatenated-SQL assignment.
# Deliberately short and textual — not dataflow. See module docstring, shape 2.
_LOOKBACK_LINES = 5


def _first_arg(line: str, open_paren: int) -> str:
    """The sink call's own first positional argument, starting just after `open_paren`.

    Bracket- AND quote-aware: stops at a depth-0 comma or the call's own closing `)`, so a further
    `.setString(1, userId)`-style sibling call or a nested `func(a, b)` argument's own comma never
    desyncs the extraction, and a quoted `)`/`,` inside a string literal (a SQL string delimiter,
    e.g. `"... WHERE id = '"`) does not end the argument early. Java has only `"` (string) and `'`
    (char) literal delimiters — no raw/backtick/triple-quoted form in scope here (same residual as
    `strip_java_comments`). Ported from the identical extractor shape in `js_sql_injection.py` /
    `go_sql_injection.py`, narrowed to Java's two quote delimiters."""
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
        elif ch in "'\"":
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


class JavaSqlInjectionGuard(Guard):
    id = "java-sql-injection"
    title = "SQL query built from string concatenation (Java)"
    area = "Code safety"

    # JavaSqlQuery.java: inline concatenation into stmt.executeQuery(...) -> fires
    # java-sql-injection/concatenated-query.
    canary_plant = CanaryPlant(
        files={
            "JavaSqlQuery.java": (
                "import java.sql.*;\n\n"
                "class UserDao {\n"
                "    ResultSet lookup(Statement stmt, String userId) throws SQLException {\n"
                '        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n'
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-sql-injection/concatenated-query"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "java" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in java_scan_dirs(root, profile):
            for f in iter_files(d, (".java",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if not text:
            return out
        # Two views, index-aligned (strip_java_comments preserves line count and every newline
        # boundary): `view_lines` keeps ONLY the comments so the pragma (itself a `//` comment) is
        # visible and a string quoting it is blank (#424), `code_lines` has comments blanked so a vulnerable pattern appearing only in a
        # `//` comment or a `/** */` Javadoc block never fires.
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        code_lines = strip_java_comments(text).splitlines()
        for i, code_line in enumerate(code_lines):
            lineno = i + 1
            for m in _SINK_CALL.finditer(code_line):
                arg = _first_arg(code_line, m.end() - 1)
                evidence_lineno = lineno
                if _SQL_CONCAT.search(arg):
                    pass  # inline shape — fires below
                else:
                    ident = arg.strip()
                    if not _BARE_IDENT.match(ident):
                        continue
                    lo = max(0, i - _LOOKBACK_LINES)
                    found = False
                    for j in range(i - 1, lo - 1, -1):
                        am = _SQL_ASSIGN.match(code_lines[j])
                        if am and am.group(1) == ident:
                            evidence_lineno = j + 1
                            found = True
                            break
                    if not found:
                        continue
                if _PRAGMA in view_lines[lineno - 1]:
                    continue
                if evidence_lineno != lineno and _PRAGMA in view_lines[evidence_lineno - 1]:
                    continue
                out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This SQL query is built by string concatenation and passed to a JDBC "
                "Statement/PreparedStatement or Hibernate Session query method. The "
                "concatenated value is baked into the query text before the driver/ORM ever "
                "sees it, so it cannot be bound as a parameter — this is SQL-injectable (CWE-89)."
            ),
            remediation=(
                "Use a parameterized query: pass a STATIC SQL string with `?` placeholders to "
                "`Connection.prepareStatement(...)` and bind values afterward with "
                "`PreparedStatement.setString`/`setInt`/etc — "
                '`PreparedStatement ps = conn.prepareStatement("... WHERE id = ?"); '
                "ps.setString(1, userId);`. For Hibernate, use a named/positional parameter "
                "(`:id`) with `Query.setParameter(...)` instead of concatenating into the HQL/SQL "
                "string. If this concatenation is confirmed to combine only fixed, internal "
                "constants — never attacker-reachable input — suppress with "
                "`// security: allow-java-sql-injection`."
            ),
            rule="java-sql-injection/concatenated-query",
            standards=list(_STANDARDS),
        )
